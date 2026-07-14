package main

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	gatewayclient "github.com/dewebprotocol/malt-client/transport"
	"github.com/dewebprotocol/malt-client/unixfs"
	cid "github.com/ipfs/go-cid"
)

type addInput struct {
	Original string
	AbsPath  string
	BaseName string
	Info     fs.FileInfo
	Symlink  bool
}

type addMountedInput struct {
	Input     addInput
	MountBase string
}

type addBuildResult struct {
	Root             *unixfs.StagedNode
	Files            int
	Bytes            int64
	ImmutableObjects int
	MALTObjects      int
	MALTMaps         int
	MALTLists        int
	ArcSets          int
	Arcs             int
	SymlinkRoots     int
}

func materializeSymlinkDirectoryBoundary(ctx context.Context, remote *gatewayclient.Client, casClient addCASClient, localPath string, seen map[string]struct{}) (cid.Cid, int, int64, *addMaterializeResult, int, error) {
	info, err := os.Stat(localPath)
	if err != nil {
		return cid.Undef, 0, 0, nil, 0, fmt.Errorf("stat symlink directory %s: %w", localPath, err)
	}
	if !info.IsDir() {
		return cid.Undef, 0, 0, nil, 0, fmt.Errorf("symlink target is not a directory: %s", localPath)
	}
	if seen == nil {
		seen = make(map[string]struct{})
	}
	staged := unixfs.NewStagedDirectory()
	files, bytesUploaded, listObjects, nestedMat, nestedSymlinks, err := stageHierarchicalDirectoryChildren(ctx, staged, casClient, remote, localPath, "", seen)
	if err != nil {
		return cid.Undef, 0, 0, nil, 0, err
	}
	mat, err := materializeDirectory(ctx, remote, casClient, staged)
	if err != nil {
		return cid.Undef, 0, 0, nil, 0, err
	}
	mat.MALTObjects += nestedMat.MALTObjects + listObjects
	mat.MALTMaps += nestedMat.MALTMaps
	mat.MALTLists += nestedMat.MALTLists + listObjects
	mat.ArcSets += nestedMat.ArcSets + listObjects
	mat.Arcs += nestedMat.Arcs
	return mat.Key, files, bytesUploaded, mat, nestedSymlinks, nil
}

func stageHierarchicalDirectoryChildren(ctx context.Context, root *unixfs.StagedNode, casClient addCASClient, remote *gatewayclient.Client, localDir string, mountBase string, seen map[string]struct{}) (int, int64, int, *addMaterializeResult, int, error) {
	cycleKey, err := filepath.EvalSymlinks(localDir)
	if err != nil {
		cycleKey, err = filepath.Abs(localDir)
		if err != nil {
			return 0, 0, 0, nil, 0, fmt.Errorf("resolve directory %s: %w", localDir, err)
		}
	}
	if _, ok := seen[cycleKey]; ok {
		return 0, 0, 0, nil, 0, fmt.Errorf("symlink cycle detected at %s", localDir)
	}
	seen[cycleKey] = struct{}{}
	defer delete(seen, cycleKey)

	entries, err := os.ReadDir(localDir)
	if err != nil {
		return 0, 0, 0, nil, 0, fmt.Errorf("read directory %s: %w", localDir, err)
	}
	var files int
	var bytesUploaded int64
	var listObjects int
	nestedMat := &addMaterializeResult{}
	var symlinkRoots int
	for _, entry := range entries {
		childLocal := filepath.Join(localDir, entry.Name())
		childPath := unixfs.CanonicalStagedPath(path.Join(mountBase, entry.Name()))
		if entry.Type()&fs.ModeSymlink != 0 {
			info, err := os.Stat(childLocal)
			if err != nil {
				return 0, 0, 0, nil, 0, fmt.Errorf("stat symlink target %s: %w", childLocal, err)
			}
			if info.IsDir() {
				key, dirFiles, dirBytes, mat, nestedSymlinkCount, err := materializeSymlinkDirectoryBoundary(ctx, remote, casClient, childLocal, seen)
				if err != nil {
					return 0, 0, 0, nil, 0, err
				}
				if err := unixfs.SetStagedMapDirectory(root, childPath, key); err != nil {
					return 0, 0, 0, nil, 0, err
				}
				files += dirFiles
				bytesUploaded += dirBytes
				addMaterializeStats(nestedMat, mat)
				symlinkRoots += 1 + nestedSymlinkCount
				continue
			}
			if !info.Mode().IsRegular() {
				return 0, 0, 0, nil, 0, fmt.Errorf("non-regular symlink target is not supported: %s", childLocal)
			}
			fileBytes, childLists, err := stageSingleFile(ctx, root, casClient, remote, childLocal, childPath)
			if err != nil {
				return 0, 0, 0, nil, 0, err
			}
			files++
			bytesUploaded += fileBytes
			listObjects += childLists
			continue
		}
		info, err := os.Stat(childLocal)
		if err != nil {
			return 0, 0, 0, nil, 0, fmt.Errorf("stat %s: %w", childLocal, err)
		}
		if info.IsDir() {
			unixfs.EnsureStagedDirectory(root, childPath)
			childFiles, childBytes, childLists, childMat, childSymlinks, err := stageHierarchicalDirectoryChildren(ctx, root, casClient, remote, childLocal, childPath, seen)
			if err != nil {
				return 0, 0, 0, nil, 0, err
			}
			files += childFiles
			bytesUploaded += childBytes
			listObjects += childLists
			addMaterializeStats(nestedMat, childMat)
			symlinkRoots += childSymlinks
			continue
		}
		if !info.Mode().IsRegular() {
			return 0, 0, 0, nil, 0, fmt.Errorf("non-regular file is not supported: %s", childLocal)
		}
		fileBytes, childLists, err := stageSingleFile(ctx, root, casClient, remote, childLocal, childPath)
		if err != nil {
			return 0, 0, 0, nil, 0, err
		}
		files++
		bytesUploaded += fileBytes
		listObjects += childLists
	}
	return files, bytesUploaded, listObjects, nestedMat, symlinkRoots, nil
}

func buildAddStagingTree(ctx context.Context, casClient addCASClient, remote *gatewayclient.Client, rawInputs []string, opts addBuildOptions) (*addBuildResult, error) {
	inputs, err := collectAddInputs(rawInputs)
	if err != nil {
		return nil, err
	}
	mounted, err := mountAddInputs(inputs, opts)
	if err != nil {
		return nil, err
	}

	batcher := asAddCASBatcher(casClient)
	root := unixfs.NewStagedDirectory()
	var files int
	var bytesUploaded int64
	var maltObjects int
	var maltMaps int
	var maltLists int
	var directLists int
	var arcSets int
	var arcs int
	var symlinkRoots int

	for _, item := range mounted {
		if item.Input.Info.IsDir() {
			if item.Input.Symlink {
				key, dirFiles, dirBytes, mat, nestedSymlinks, err := materializeSymlinkDirectoryBoundary(ctx, remote, batcher, item.Input.AbsPath, nil)
				if err != nil {
					return nil, err
				}
				if err := unixfs.SetStagedMapDirectory(root, item.MountBase, key); err != nil {
					return nil, err
				}
				files += dirFiles
				bytesUploaded += dirBytes
				maltObjects += mat.MALTObjects
				maltMaps += mat.MALTMaps
				maltLists += mat.MALTLists
				arcSets += mat.ArcSets
				arcs += mat.Arcs
				symlinkRoots += 1 + nestedSymlinks
				continue
			}
			dirFiles, dirBytes, dirLists, dirMat, dirSymlinks, err := stageDirectoryInput(ctx, root, batcher, remote, item, opts.Ignore)
			if err != nil {
				return nil, err
			}
			files += dirFiles
			bytesUploaded += dirBytes
			maltLists += dirLists
			directLists += dirLists
			maltObjects += dirMat.MALTObjects
			maltMaps += dirMat.MALTMaps
			maltLists += dirMat.MALTLists
			arcSets += dirMat.ArcSets
			arcs += dirMat.Arcs
			symlinkRoots += dirSymlinks
			continue
		}
		if item.Input.Symlink {
			fileBytes, listObjects, err := stageSingleFile(ctx, root, batcher, remote, item.Input.AbsPath, item.MountBase)
			if err != nil {
				return nil, err
			}
			files++
			bytesUploaded += fileBytes
			maltLists += listObjects
			directLists += listObjects
			continue
		}
		fileBytes, listObjects, err := stageSingleFile(ctx, root, batcher, remote, item.Input.AbsPath, item.MountBase)
		if err != nil {
			return nil, err
		}
		files++
		bytesUploaded += fileBytes
		maltLists += listObjects
		directLists += listObjects
	}
	if err := batcher.Flush(ctx); err != nil {
		return nil, fmt.Errorf("flush staged CAS batch: %w", err)
	}

	return &addBuildResult{
		Root:             root,
		Files:            files,
		Bytes:            bytesUploaded,
		ImmutableObjects: batcher.UploadedCount(),
		MALTObjects:      maltObjects + directLists,
		MALTMaps:         maltMaps,
		MALTLists:        maltLists,
		ArcSets:          arcSets + directLists,
		Arcs:             arcs,
		SymlinkRoots:     symlinkRoots,
	}, nil
}

func collectAddInputs(rawInputs []string) ([]addInput, error) {
	out := make([]addInput, 0, len(rawInputs))
	for _, raw := range rawInputs {
		abs, err := filepath.Abs(raw)
		if err != nil {
			return nil, fmt.Errorf("resolve path %q: %w", raw, err)
		}
		info, err := os.Lstat(abs)
		if err != nil {
			return nil, fmt.Errorf("stat %q: %w", raw, err)
		}
		isSymlink := info.Mode()&os.ModeSymlink != 0
		if isSymlink {
			info, err = os.Stat(abs)
			if err != nil {
				return nil, fmt.Errorf("stat symlink target %q: %w", raw, err)
			}
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return nil, fmt.Errorf("only regular files and directories are supported: %s", raw)
		}
		out = append(out, addInput{
			Original: raw,
			AbsPath:  abs,
			BaseName: filepath.Base(abs),
			Info:     info,
			Symlink:  isSymlink,
		})
	}
	return out, nil
}

func mountAddInputs(inputs []addInput, opts addBuildOptions) ([]addMountedInput, error) {
	prefix := unixfs.CanonicalStagedPath(opts.Prefix)
	if opts.Wrap && len(inputs) > 1 && strings.TrimSpace(opts.WrapName) == "" {
		return nil, fmt.Errorf("--wrap-name is required when --wrap is used with multiple inputs")
	}
	if opts.Wrap && len(inputs) == 1 && inputs[0].Info.IsDir() {
		return nil, fmt.Errorf("single directory input does not support extra wrapping")
	}

	seen := make(map[string]struct{})
	out := make([]addMountedInput, 0, len(inputs))
	for _, in := range inputs {
		mount := in.BaseName
		if opts.Wrap {
			wrapName := strings.TrimSpace(opts.WrapName)
			if wrapName == "" {
				wrapName = in.BaseName
			}
			mount = path.Join(unixfs.CanonicalStagedPath(wrapName), in.BaseName)
		}
		if prefix != "" {
			mount = path.Join(prefix, mount)
		}
		mount = unixfs.CanonicalStagedPath(mount)
		if mount == "" {
			return nil, fmt.Errorf("invalid mount path for input %q", in.Original)
		}
		if _, ok := seen[mount]; ok {
			return nil, fmt.Errorf("duplicate mounted target path %q", mount)
		}
		seen[mount] = struct{}{}
		out = append(out, addMountedInput{
			Input:     in,
			MountBase: mount,
		})
	}
	return out, nil
}

func stageDirectoryInput(ctx context.Context, root *unixfs.StagedNode, casClient addCASClient, remote *gatewayclient.Client, item addMountedInput, ignoreOpts addIgnoreOptions) (int, int64, int, *addMaterializeResult, int, error) {
	mountBase := item.MountBase
	unixfs.EnsureStagedDirectory(root, mountBase)
	ignoreFilter, err := newAddIgnoreFilter(item.Input.AbsPath, ignoreOpts)
	if err != nil {
		return 0, 0, 0, nil, 0, err
	}

	var files int
	var bytesUploaded int64
	var listObjects int
	symlinkMat := &addMaterializeResult{}
	var symlinkRoots int
	err = filepath.WalkDir(item.Input.AbsPath, func(current string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if current != item.Input.AbsPath {
			ignored, err := ignoreFilter.Ignored(current, d.IsDir())
			if err != nil {
				return err
			}
			if ignored {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		if d.IsDir() {
			if err := ignoreFilter.LoadDirectoryRules(current); err != nil {
				return err
			}
		}
		if current != item.Input.AbsPath {
			if d.Type()&fs.ModeSymlink != 0 {
				rel, err := filepath.Rel(item.Input.AbsPath, current)
				if err != nil {
					return fmt.Errorf("compute relative path %q: %w", current, err)
				}
				targetPath := unixfs.CanonicalStagedPath(path.Join(mountBase, filepath.ToSlash(rel)))
				info, err := os.Stat(current)
				if err != nil {
					return fmt.Errorf("stat symlink target %s: %w", current, err)
				}
				if info.IsDir() {
					key, dirFiles, dirBytes, mat, nestedSymlinks, err := materializeSymlinkDirectoryBoundary(ctx, remote, casClient, current, nil)
					if err != nil {
						return err
					}
					if err := unixfs.SetStagedMapDirectory(root, targetPath, key); err != nil {
						return err
					}
					files += dirFiles
					bytesUploaded += dirBytes
					addMaterializeStats(symlinkMat, mat)
					symlinkRoots += 1 + nestedSymlinks
					return nil
				}
				if !info.Mode().IsRegular() {
					return fmt.Errorf("non-regular symlink target is not supported: %s", current)
				}
				fileBytes, childLists, err := stageSingleFile(ctx, root, casClient, remote, current, targetPath)
				if err != nil {
					return err
				}
				files++
				bytesUploaded += fileBytes
				listObjects += childLists
				return nil
			}
		}

		rel, err := filepath.Rel(item.Input.AbsPath, current)
		if err != nil {
			return fmt.Errorf("compute relative path %q: %w", current, err)
		}
		if rel == "." {
			return nil
		}
		targetPath := unixfs.CanonicalStagedPath(path.Join(mountBase, filepath.ToSlash(rel)))
		if targetPath == "" {
			return nil
		}

		if d.IsDir() {
			unixfs.EnsureStagedDirectory(root, targetPath)
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("stat %s: %w", current, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("non-regular file is not supported: %s", current)
		}

		fileBytes, childLists, err := stageSingleFile(ctx, root, casClient, remote, current, targetPath)
		if err != nil {
			return err
		}
		files++
		bytesUploaded += fileBytes
		listObjects += childLists
		return nil
	})
	if err != nil {
		return 0, 0, 0, nil, 0, err
	}
	return files, bytesUploaded, listObjects, symlinkMat, symlinkRoots, nil
}

func stageSingleFile(ctx context.Context, root *unixfs.StagedNode, casClient addCASClient, remote *gatewayclient.Client, localPath string, targetPath string) (int64, int, error) {
	targetPath = unixfs.CanonicalStagedPath(targetPath)
	if targetPath == "" {
		return 0, 0, fmt.Errorf("target path must not be empty")
	}

	info, err := os.Stat(localPath)
	if err != nil {
		return 0, 0, fmt.Errorf("stat %s: %w", localPath, err)
	}
	if !info.Mode().IsRegular() {
		return 0, 0, fmt.Errorf("not a regular file: %s", localPath)
	}

	f, err := os.Open(localPath)
	if err != nil {
		return 0, 0, fmt.Errorf("open %s: %w", localPath, err)
	}
	defer f.Close()

	key, listBacked, err := unixfs.MaterializeStagedFilePayload(ctx, casClient, remote, f, info.Size(), addFixedChunkSize)
	if err != nil {
		return 0, 0, fmt.Errorf("materialize file payload for %s: %w", localPath, err)
	}
	listObjects := 0
	if listBacked {
		listObjects = 1
	}

	if err := unixfs.SetStagedFile(root, targetPath, key); err != nil {
		return 0, 0, err
	}
	return info.Size(), listObjects, nil
}

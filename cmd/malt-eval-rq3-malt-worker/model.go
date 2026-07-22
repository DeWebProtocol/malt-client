package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	clientcas "github.com/dewebprotocol/malt-client/internal/cas"
	"github.com/dewebprotocol/malt-client/merkledag/rq3baseline"
	"github.com/dewebprotocol/malt-client/transport"
	unixfsmodel "github.com/dewebprotocol/malt-client/unixfs/model"
	"github.com/dewebprotocol/malt/auth/arcset"
	materializer "github.com/dewebprotocol/malt/auth/arcset/materializer"
	"github.com/dewebprotocol/malt/auth/commitment"
	listsemantic "github.com/dewebprotocol/malt/auth/semantic/list/tree"
	"github.com/dewebprotocol/malt/auth/semantic/mapping"
	mappingradix "github.com/dewebprotocol/malt/auth/semantic/mapping/radix"
	"github.com/dewebprotocol/malt/mutation"
	cid "github.com/ipfs/go-cid"
)

const (
	categoryLogicalPayload = "logical-changed-payload"
	categoryCASMetadata    = "cas-structural-metadata"
	modeSidecarSchema      = "malt-eval-rq3-file-mode/v1"
)

type logicalFile struct {
	data   []byte
	mode   uint32
	digest string
}

type classifiedBlock struct {
	block    transport.Block
	category string
	cause    string
	suffix   string
}

type semanticObject struct {
	logicalID string
	kind      arcset.Kind
	root      cid.Cid
	entries   *arcset.CanonicalArcSet
	commit    mutation.CommitDescriptor
	// refs maps canonical coordinate bytes to the desired child object's
	// logical ID. CAS targets deliberately do not appear here.
	refs map[string]string
}

type hybridGraph struct {
	root        cid.Cid
	topID       string
	objects     map[string]*semanticObject
	order       []string
	manifests   map[string]classifiedBlock
	directories map[string]*directoryIndex
}

type graphBuilder struct {
	chunkBytes uint64
	scheme     commitment.IndexCommitment
	store      materializer.NodeStore
}

type directoryNode struct {
	path  string
	dirs  map[string]*directoryNode
	files map[string]string
}

type directoryIndex struct {
	children map[string]directoryChild
}

type directoryChild struct {
	logicalID string
	kind      arcset.TargetKind
	path      string
}

type fileChange struct {
	path   string
	before *logicalFile
	after  *logicalFile
}

func initialLogicalState(snapshot rq3baseline.Snapshot, chunkBytes uint64) (map[string]logicalFile, []classifiedBlock, error) {
	state := make(map[string]logicalFile, len(snapshot.Files))
	blocks := make([]classifiedBlock, 0)
	for _, file := range snapshot.Files {
		data, err := decodeFrozenPayload(file.PayloadBase64)
		if err != nil || file.Mode == nil {
			return nil, nil, fmt.Errorf("decode prevalidated snapshot file %q: %w", file.Path, err)
		}
		value := logicalFile{data: data, mode: *file.Mode, digest: file.PayloadSHA256}
		state[file.Path] = value
		fileBlocks, err := fileCASBlocks(value, true, chunkBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("normalize snapshot file %q: %w", file.Path, err)
		}
		blocks = append(blocks, fileBlocks...)
	}
	return state, blocks, nil
}

// applyFrozenCommit executes the already baseline-validated source semantics
// in their frozen order. CAS attempts retain intermediate full-result payloads
// even though one client root closes the complete commit.
func applyFrozenCommit(state map[string]logicalFile, commit rq3baseline.Commit, chunkBytes uint64, changedChunksOnly bool) ([]classifiedBlock, int64, []fileChange, error) {
	blocks := make([]classifiedBlock, 0)
	var logicalPayloadBytes int64
	before := make(map[string]*logicalFile)
	capture := func(path string) {
		if _, captured := before[path]; captured {
			return
		}
		if file, exists := state[path]; exists {
			copy := file
			copy.data = append([]byte(nil), file.data...)
			before[path] = &copy
		} else {
			before[path] = nil
		}
	}
	for index, change := range commit.Mutations {
		capture(change.Path)
		if change.Destination != "" {
			capture(change.Destination)
		}
		old := state[change.Path]
		switch change.Kind {
		case rq3baseline.MutationInsert, rq3baseline.MutationReplace, rq3baseline.MutationAppend:
			data, err := decodeFrozenPayload(change.PayloadBase64)
			if err != nil || change.Mode == nil {
				return nil, 0, nil, fmt.Errorf("mutation[%d] decode payload: %w", index, err)
			}
			next := logicalFile{data: data, mode: *change.Mode, digest: change.PayloadSHA256}
			includeMode := change.Kind == rq3baseline.MutationInsert || old.mode != next.mode
			fileBlocks, err := fileCASBlocks(next, includeMode, chunkBytes)
			if err != nil {
				return nil, 0, nil, fmt.Errorf("mutation[%d] normalize file: %w", index, err)
			}
			blocks = append(blocks, fileBlocks...)
			var changed int64
			switch change.Kind {
			case rq3baseline.MutationInsert:
				changed = int64(len(next.data))
			case rq3baseline.MutationAppend:
				changed = int64(len(next.data) - len(old.data))
			case rq3baseline.MutationReplace:
				if changedChunksOnly {
					changed, err = changedFixedChunkBytes(old.data, next.data, chunkBytes)
				} else {
					changed = int64(len(next.data))
				}
			}
			if err != nil {
				return nil, 0, nil, fmt.Errorf("mutation[%d] logical payload accounting: %w", index, err)
			}
			if changed < 0 || logicalPayloadBytes > int64(^uint64(0)>>1)-changed {
				return nil, 0, nil, fmt.Errorf("mutation[%d] logical payload accounting overflow", index)
			}
			logicalPayloadBytes += changed
			state[change.Path] = next

		case rq3baseline.MutationModeChange:
			if change.Mode == nil {
				return nil, 0, nil, fmt.Errorf("mutation[%d] mode is absent after semantic prevalidation", index)
			}
			old.mode = *change.Mode
			state[change.Path] = old
			modeBlock, err := modeCASBlock(old.mode)
			if err != nil {
				return nil, 0, nil, err
			}
			blocks = append(blocks, modeBlock)

		case rq3baseline.MutationDelete:
			delete(state, change.Path)

		case rq3baseline.MutationRename, rq3baseline.MutationMove:
			delete(state, change.Path)
			state[change.Destination] = old

		default:
			return nil, 0, nil, fmt.Errorf("mutation[%d] kind %q escaped semantic prevalidation", index, change.Kind)
		}
	}
	paths := make([]string, 0, len(before))
	for path := range before {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	changes := make([]fileChange, 0, len(paths))
	for _, path := range paths {
		var after *logicalFile
		if file, exists := state[path]; exists {
			copy := file
			copy.data = append([]byte(nil), file.data...)
			after = &copy
		}
		if logicalFileEqual(before[path], after) {
			continue
		}
		changes = append(changes, fileChange{path: path, before: before[path], after: after})
	}
	return blocks, logicalPayloadBytes, changes, nil
}

func logicalFileEqual(a, b *logicalFile) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.mode == b.mode && a.digest == b.digest && slices.Equal(a.data, b.data)
}

func changedFixedChunkBytes(before, after []byte, chunkBytes uint64) (int64, error) {
	if chunkBytes == 0 || chunkBytes > uint64(^uint(0)>>1) {
		return 0, fmt.Errorf("chunk size is outside host bounds")
	}
	size := int(chunkBytes)
	var total int64
	for offset := 0; offset < len(after); offset += size {
		end := min(len(after), offset+size)
		unchanged := end <= len(before) && slices.Equal(before[offset:end], after[offset:end])
		if unchanged {
			continue
		}
		if total > int64(^uint64(0)>>1)-int64(end-offset) {
			return 0, fmt.Errorf("changed chunk bytes overflow")
		}
		total += int64(end - offset)
	}
	return total, nil
}

func decodeFrozenPayload(encoded string) ([]byte, error) {
	value, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(value) != encoded {
		return nil, fmt.Errorf("payload is not canonical standard base64")
	}
	return value, nil
}

func fileCASBlocks(file logicalFile, includeMode bool, chunkBytes uint64) ([]classifiedBlock, error) {
	if chunkBytes == 0 {
		// The snapshot caller fills its registered chunk size after decoding the
		// run envelope; zero here is only a construction guard.
		return nil, fmt.Errorf("fixed chunk size is zero")
	}
	result := make([]classifiedBlock, 0, (len(file.data)+int(chunkBytes)-1)/int(chunkBytes)+1)
	for offset := 0; offset < len(file.data); offset += int(chunkBytes) {
		end := min(len(file.data), offset+int(chunkBytes))
		result = append(result, classifiedBlock{
			block:    transport.Block{Codec: cid.Raw, Data: append([]byte(nil), file.data[offset:end]...)},
			category: categoryLogicalPayload, cause: "fixed-width-file-chunk", suffix: "payload",
		})
	}
	if includeMode {
		mode, err := modeCASBlock(file.mode)
		if err != nil {
			return nil, err
		}
		result = append(result, mode)
	}
	return result, nil
}

func modeCASBlock(mode uint32) (classifiedBlock, error) {
	wire := struct {
		SchemaVersion string `json:"schema_version"`
		FileKind      string `json:"file_kind"`
		Mode          uint32 `json:"mode"`
	}{SchemaVersion: modeSidecarSchema, FileKind: rq3baseline.FileKindRegular, Mode: mode}
	raw, err := json.Marshal(wire)
	if err != nil {
		return classifiedBlock{}, err
	}
	return classifiedBlock{
		block: transport.Block{Codec: cid.Raw, Data: raw}, category: categoryCASMetadata,
		cause: "file-mode-sidecar", suffix: "mode-sidecar",
	}, nil
}

func (b graphBuilder) build(ctx context.Context, files map[string]logicalFile) (*hybridGraph, error) {
	if b.chunkBytes == 0 || b.chunkBytes > uint64(^uint(0)>>1) || b.scheme == nil || b.store == nil {
		return nil, fmt.Errorf("hybrid graph builder is incomplete")
	}
	rootDir := &directoryNode{path: "", dirs: map[string]*directoryNode{}, files: map[string]string{}}
	filePaths := make([]string, 0, len(files))
	for filePath := range files {
		filePaths = append(filePaths, filePath)
	}
	slices.Sort(filePaths)
	for _, filePath := range filePaths {
		segments := strings.Split(filePath, "/")
		current := rootDir
		for index, segment := range segments[:len(segments)-1] {
			next := current.dirs[segment]
			if next == nil {
				dirPath := strings.Join(segments[:index+1], "/")
				next = &directoryNode{path: dirPath, dirs: map[string]*directoryNode{}, files: map[string]string{}}
				current.dirs[segment] = next
			}
			current = next
		}
		current.files[segments[len(segments)-1]] = filePath
	}

	result := &hybridGraph{
		topID: objectLogicalID("dir", ""), objects: make(map[string]*semanticObject),
		manifests: make(map[string]classifiedBlock), directories: make(map[string]*directoryIndex),
	}
	listSemantics, err := listsemantic.NewList(b.scheme, b.store)
	if err != nil {
		return nil, err
	}
	mapSemantics, err := mappingradix.NewMap(b.scheme, b.store)
	if err != nil {
		return nil, err
	}
	for _, filePath := range filePaths {
		file := files[filePath]
		chunks, err := chunkCIDs(file.data, b.chunkBytes)
		if err != nil {
			return nil, fmt.Errorf("normalize fixed list %q: %w", filePath, err)
		}
		root, err := listSemantics.CommitFixed(ctx, objectNamespace("file", filePath), chunks, b.chunkBytes, uint64(len(file.data)))
		if err != nil {
			return nil, fmt.Errorf("commit fixed list %q: %w", filePath, err)
		}
		entries := make([]arcset.ArcEntry, len(chunks))
		for index, chunk := range chunks {
			entries[index] = arcset.ArcEntry{Coordinate: arcset.NewListCoordinateUint64(uint64(index)), Target: arcset.NewCASTarget(chunk)}
		}
		canonical, err := arcset.NewCanonicalArcSet(arcset.KindList, entries)
		if err != nil {
			return nil, err
		}
		logicalID := objectLogicalID("file", filePath)
		result.objects[logicalID] = &semanticObject{
			logicalID: logicalID, kind: arcset.KindList, root: root, entries: canonical,
			commit: mutation.CommitDescriptor{FixedList: &mutation.FixedListCommit{TotalSize: uint64(len(file.data)), ChunkSize: b.chunkBytes}},
			refs:   map[string]string{},
		}
		result.order = append(result.order, logicalID)
	}

	var buildDirectory func(*directoryNode) (cid.Cid, error)
	buildDirectory = func(directory *directoryNode) (cid.Cid, error) {
		names := make([]string, 0, len(directory.dirs)+len(directory.files))
		for name := range directory.dirs {
			names = append(names, name)
		}
		for name := range directory.files {
			names = append(names, name)
		}
		slices.Sort(names)
		childRoots := make(map[string]cid.Cid, len(names))
		childKinds := make(map[string]arcset.TargetKind, len(names))
		childIDs := make(map[string]string, len(names))
		index := &directoryIndex{children: make(map[string]directoryChild, len(names))}
		for _, name := range names {
			if child := directory.dirs[name]; child != nil {
				childRoot, err := buildDirectory(child)
				if err != nil {
					return cid.Undef, err
				}
				childRoots[name], childKinds[name] = childRoot, arcset.TargetKindMap
				childIDs[name] = objectLogicalID("dir", child.path)
				index.children[name] = directoryChild{logicalID: childIDs[name], kind: arcset.TargetKindMap, path: child.path}
				continue
			}
			filePath := directory.files[name]
			object := result.objects[objectLogicalID("file", filePath)]
			childRoots[name], childKinds[name], childIDs[name] = object.root, arcset.TargetKindList, object.logicalID
			index.children[name] = directoryChild{logicalID: object.logicalID, kind: arcset.TargetKindList, path: filePath}
		}
		result.directories[directory.path] = index

		manifestRaw, err := unixfsmodel.DirectoryManifestPayload(names)
		if err != nil {
			return cid.Undef, fmt.Errorf("encode directory manifest %q: %w", directory.path, err)
		}
		manifest := classifiedBlock{
			block:    transport.Block{Codec: unixfsmodel.DirectoryManifestCodec, Data: manifestRaw},
			category: categoryCASMetadata, cause: "directory-manifest", suffix: "directory-manifest",
		}
		manifestCID, err := clientcas.CIDForBlock(manifest.block)
		if err != nil {
			return cid.Undef, err
		}
		result.manifests[directory.path] = manifest

		entries := make([]arcset.ArcEntry, 0, 1+len(names)*2)
		refs := make(map[string]string, len(names))
		manifestCoordinate, err := arcset.NewMapCoordinate("meta/manifest")
		if err != nil {
			return cid.Undef, err
		}
		entries = append(entries, arcset.ArcEntry{Coordinate: manifestCoordinate, Target: arcset.NewCASTarget(manifestCID)})
		for _, name := range names {
			encodedName := base64.RawURLEncoding.EncodeToString([]byte(name))
			coordinate, err := arcset.NewMapCoordinate("entry/" + encodedName)
			if err != nil {
				return cid.Undef, err
			}
			var target arcset.TargetRef
			if childKinds[name] == arcset.TargetKindMap {
				target = arcset.NewMapTarget(childRoots[name])
			} else {
				target = arcset.NewListTarget(childRoots[name])
			}
			entries = append(entries, arcset.ArcEntry{Coordinate: coordinate, Target: target})
			refs[string(coordinate.Bytes())] = childIDs[name]
			if filePath, ok := directory.files[name]; ok {
				mode, err := modeCASBlock(files[filePath].mode)
				if err != nil {
					return cid.Undef, err
				}
				modeCID, err := clientcas.CIDForBlock(mode.block)
				if err != nil {
					return cid.Undef, err
				}
				modeCoordinate, err := arcset.NewMapCoordinate("mode/" + encodedName)
				if err != nil {
					return cid.Undef, err
				}
				entries = append(entries, arcset.ArcEntry{Coordinate: modeCoordinate, Target: arcset.NewCASTarget(modeCID)})
			}
		}
		canonical, err := arcset.NewCanonicalArcSet(arcset.KindMap, entries)
		if err != nil {
			return cid.Undef, err
		}
		values := make(map[arcset.Path]cid.Cid, canonical.Len())
		for _, entry := range canonical.Entries() {
			values[arcset.CanonicalizePath(entry.Coordinate.String())] = entry.Target.CID()
		}
		root, err := mapSemantics.Commit(ctx, objectNamespace("dir", directory.path), mapping.NewViewFromPaths(values))
		if err != nil {
			return cid.Undef, fmt.Errorf("commit directory map %q: %w", directory.path, err)
		}
		logicalID := objectLogicalID("dir", directory.path)
		result.objects[logicalID] = &semanticObject{
			logicalID: logicalID, kind: arcset.KindMap, root: root, entries: canonical, refs: refs,
		}
		result.order = append(result.order, logicalID)
		return root, nil
	}
	root, err := buildDirectory(rootDir)
	if err != nil {
		return nil, err
	}
	result.root = root
	return result, nil
}

// buildNext updates only changed file objects and their ancestor directories.
// The full build() path is reserved for initial construction and an untimed,
// independent correctness oracle.
func (b graphBuilder) buildNext(ctx context.Context, old *hybridGraph, files map[string]logicalFile, changes []fileChange) (*hybridGraph, error) {
	if old == nil || len(changes) == 0 || b.chunkBytes == 0 || b.scheme == nil || b.store == nil {
		return nil, fmt.Errorf("incremental hybrid graph planner is incomplete")
	}
	result := &hybridGraph{
		topID: old.topID, objects: make(map[string]*semanticObject, len(old.objects)+len(changes)),
		manifests:   make(map[string]classifiedBlock, len(old.manifests)),
		directories: make(map[string]*directoryIndex, len(old.directories)+len(changes)),
		order:       make([]string, 0, len(changes)*4),
	}
	for key, object := range old.objects {
		result.objects[key] = object
	}
	for key, manifest := range old.manifests {
		result.manifests[key] = manifest
	}
	for key, index := range old.directories {
		result.directories[key] = index
	}
	mutable := make(map[string]struct{})
	mutableDirectory := func(path string) *directoryIndex {
		if _, ok := mutable[path]; ok {
			return result.directories[path]
		}
		prior := result.directories[path]
		next := &directoryIndex{children: map[string]directoryChild{}}
		if prior != nil {
			next.children = make(map[string]directoryChild, len(prior.children))
			for name, child := range prior.children {
				next.children[name] = child
			}
		}
		result.directories[path] = next
		mutable[path] = struct{}{}
		return next
	}
	affectedDirectories := map[string]struct{}{"": {}}
	markAncestors := func(filePath string) {
		parent, _ := splitParentBase(filePath)
		for {
			affectedDirectories[parent] = struct{}{}
			if parent == "" {
				return
			}
			parent, _ = splitParentBase(parent)
		}
	}

	// Remove old file bindings first so moves and batch updates can then add
	// their complete post-image without observing mutation order artifacts.
	for _, change := range changes {
		markAncestors(change.path)
		if change.before == nil {
			continue
		}
		parent, name := splitParentBase(change.path)
		delete(mutableDirectory(parent).children, name)
		delete(result.objects, objectLogicalID("file", change.path))
	}

	listSemantics, err := listsemantic.NewList(b.scheme, b.store)
	if err != nil {
		return nil, err
	}
	for _, change := range changes {
		if change.after == nil {
			continue
		}
		segments := strings.Split(change.path, "/")
		parent := ""
		for index, name := range segments[:len(segments)-1] {
			directoryPath := strings.Join(segments[:index+1], "/")
			if result.directories[directoryPath] == nil {
				mutableDirectory(directoryPath)
			}
			mutableDirectory(parent).children[name] = directoryChild{
				logicalID: objectLogicalID("dir", directoryPath), kind: arcset.TargetKindMap, path: directoryPath,
			}
			affectedDirectories[parent] = struct{}{}
			affectedDirectories[directoryPath] = struct{}{}
			parent = directoryPath
		}
		object, err := b.buildFileObject(ctx, listSemantics, change.path, *change.after)
		if err != nil {
			return nil, err
		}
		result.objects[object.logicalID] = object
		result.order = append(result.order, object.logicalID)
		mutableDirectory(parent).children[segments[len(segments)-1]] = directoryChild{
			logicalID: object.logicalID, kind: arcset.TargetKindList, path: change.path,
		}
	}

	directoryPaths := make([]string, 0, len(affectedDirectories))
	for path := range affectedDirectories {
		directoryPaths = append(directoryPaths, path)
	}
	slices.SortFunc(directoryPaths, compareDirectoryDeepestFirst)
	for _, directoryPath := range directoryPaths {
		if directoryPath == "" {
			continue
		}
		index := result.directories[directoryPath]
		if index == nil || len(index.children) != 0 {
			continue
		}
		delete(result.directories, directoryPath)
		delete(result.objects, objectLogicalID("dir", directoryPath))
		delete(result.manifests, directoryPath)
		parent, name := splitParentBase(directoryPath)
		delete(mutableDirectory(parent).children, name)
		affectedDirectories[parent] = struct{}{}
	}

	// Recompute surviving affected directories bottom-up so every parent sees
	// the exact new root of each changed child while untouched subtrees remain
	// pointer-identical to the prior graph.
	directoryPaths = directoryPaths[:0]
	for path := range affectedDirectories {
		if result.directories[path] != nil {
			directoryPaths = append(directoryPaths, path)
		}
	}
	slices.SortFunc(directoryPaths, compareDirectoryDeepestFirst)
	mapSemantics, err := mappingradix.NewMap(b.scheme, b.store)
	if err != nil {
		return nil, err
	}
	for _, directoryPath := range directoryPaths {
		object, manifest, err := b.buildDirectoryObject(ctx, mapSemantics, directoryPath, result.directories[directoryPath], files, result.objects)
		if err != nil {
			return nil, err
		}
		result.objects[object.logicalID] = object
		result.manifests[directoryPath] = manifest
		result.order = append(result.order, object.logicalID)
	}
	top := result.objects[result.topID]
	if top == nil {
		return nil, fmt.Errorf("incremental planner removed the top directory")
	}
	result.root = top.root
	return result, nil
}

func (b graphBuilder) buildFileObject(ctx context.Context, semantics *listsemantic.TreeList, filePath string, file logicalFile) (*semanticObject, error) {
	chunks, err := chunkCIDs(file.data, b.chunkBytes)
	if err != nil {
		return nil, fmt.Errorf("normalize fixed list %q: %w", filePath, err)
	}
	root, err := semantics.CommitFixed(ctx, objectNamespace("file", filePath), chunks, b.chunkBytes, uint64(len(file.data)))
	if err != nil {
		return nil, fmt.Errorf("commit fixed list %q: %w", filePath, err)
	}
	entries := make([]arcset.ArcEntry, len(chunks))
	for index, chunk := range chunks {
		entries[index] = arcset.ArcEntry{Coordinate: arcset.NewListCoordinateUint64(uint64(index)), Target: arcset.NewCASTarget(chunk)}
	}
	canonical, err := arcset.NewCanonicalArcSet(arcset.KindList, entries)
	if err != nil {
		return nil, err
	}
	logicalID := objectLogicalID("file", filePath)
	return &semanticObject{
		logicalID: logicalID, kind: arcset.KindList, root: root, entries: canonical,
		commit: mutation.CommitDescriptor{FixedList: &mutation.FixedListCommit{TotalSize: uint64(len(file.data)), ChunkSize: b.chunkBytes}},
		refs:   map[string]string{},
	}, nil
}

func (b graphBuilder) buildDirectoryObject(ctx context.Context, semantics *mappingradix.Map, directoryPath string, index *directoryIndex, files map[string]logicalFile, objects map[string]*semanticObject) (*semanticObject, classifiedBlock, error) {
	names := make([]string, 0, len(index.children))
	for name := range index.children {
		names = append(names, name)
	}
	slices.Sort(names)
	manifestRaw, err := unixfsmodel.DirectoryManifestPayload(names)
	if err != nil {
		return nil, classifiedBlock{}, fmt.Errorf("encode directory manifest %q: %w", directoryPath, err)
	}
	manifest := classifiedBlock{
		block:    transport.Block{Codec: unixfsmodel.DirectoryManifestCodec, Data: manifestRaw},
		category: categoryCASMetadata, cause: "directory-manifest", suffix: "directory-manifest",
	}
	manifestCID, err := clientcas.CIDForBlock(manifest.block)
	if err != nil {
		return nil, classifiedBlock{}, err
	}
	entries := make([]arcset.ArcEntry, 0, 1+len(names)*2)
	refs := make(map[string]string, len(names))
	manifestCoordinate, err := arcset.NewMapCoordinate("meta/manifest")
	if err != nil {
		return nil, classifiedBlock{}, err
	}
	entries = append(entries, arcset.ArcEntry{Coordinate: manifestCoordinate, Target: arcset.NewCASTarget(manifestCID)})
	for _, name := range names {
		child := index.children[name]
		childObject := objects[child.logicalID]
		if childObject == nil {
			return nil, classifiedBlock{}, fmt.Errorf("directory %q child %q has no semantic object", directoryPath, name)
		}
		encodedName := base64.RawURLEncoding.EncodeToString([]byte(name))
		coordinate, err := arcset.NewMapCoordinate("entry/" + encodedName)
		if err != nil {
			return nil, classifiedBlock{}, err
		}
		var target arcset.TargetRef
		if child.kind == arcset.TargetKindMap {
			target = arcset.NewMapTarget(childObject.root)
		} else {
			target = arcset.NewListTarget(childObject.root)
		}
		entries = append(entries, arcset.ArcEntry{Coordinate: coordinate, Target: target})
		refs[string(coordinate.Bytes())] = child.logicalID
		if child.kind == arcset.TargetKindList {
			file, ok := files[child.path]
			if !ok {
				return nil, classifiedBlock{}, fmt.Errorf("directory %q file child %q is absent from logical state", directoryPath, child.path)
			}
			mode, err := modeCASBlock(file.mode)
			if err != nil {
				return nil, classifiedBlock{}, err
			}
			modeCID, err := clientcas.CIDForBlock(mode.block)
			if err != nil {
				return nil, classifiedBlock{}, err
			}
			modeCoordinate, err := arcset.NewMapCoordinate("mode/" + encodedName)
			if err != nil {
				return nil, classifiedBlock{}, err
			}
			entries = append(entries, arcset.ArcEntry{Coordinate: modeCoordinate, Target: arcset.NewCASTarget(modeCID)})
		}
	}
	canonical, err := arcset.NewCanonicalArcSet(arcset.KindMap, entries)
	if err != nil {
		return nil, classifiedBlock{}, err
	}
	values := make(map[arcset.Path]cid.Cid, canonical.Len())
	for _, entry := range canonical.Entries() {
		values[arcset.CanonicalizePath(entry.Coordinate.String())] = entry.Target.CID()
	}
	root, err := semantics.Commit(ctx, objectNamespace("dir", directoryPath), mapping.NewViewFromPaths(values))
	if err != nil {
		return nil, classifiedBlock{}, fmt.Errorf("commit directory map %q: %w", directoryPath, err)
	}
	logicalID := objectLogicalID("dir", directoryPath)
	return &semanticObject{logicalID: logicalID, kind: arcset.KindMap, root: root, entries: canonical, refs: refs}, manifest, nil
}

func splitParentBase(value string) (string, string) {
	index := strings.LastIndexByte(value, '/')
	if index < 0 {
		return "", value
	}
	return value[:index], value[index+1:]
}

func compareDirectoryDeepestFirst(a, b string) int {
	depth := func(value string) int {
		if value == "" {
			return 0
		}
		return strings.Count(value, "/") + 1
	}
	if depth(a) != depth(b) {
		return depth(b) - depth(a)
	}
	return strings.Compare(a, b)
}

func chunkCIDs(data []byte, chunkBytes uint64) ([]cid.Cid, error) {
	if chunkBytes == 0 || chunkBytes > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("chunk size is outside host bounds")
	}
	chunks := make([]cid.Cid, 0, (len(data)+int(chunkBytes)-1)/int(chunkBytes))
	for offset := 0; offset < len(data); offset += int(chunkBytes) {
		end := min(len(data), offset+int(chunkBytes))
		key, err := clientcas.CIDForBlock(clientcas.Block{Codec: cid.Raw, Data: data[offset:end]})
		if err != nil {
			return nil, err
		}
		chunks = append(chunks, key)
	}
	return chunks, nil
}

func objectLogicalID(kind, value string) string {
	digest := sha256.Sum256([]byte(kind + "\x00" + value))
	return kind + "-" + hex.EncodeToString(digest[:12])
}

func objectNamespace(kind, value string) string {
	digest := sha256.Sum256([]byte("rq3-hybrid\x00" + kind + "\x00" + value))
	return "rq3-" + hex.EncodeToString(digest[:16])
}

func mapEntriesByCoordinate(value *arcset.CanonicalArcSet) map[string]arcset.ArcEntry {
	result := make(map[string]arcset.ArcEntry, value.Len())
	for _, entry := range value.Entries() {
		result[string(entry.Coordinate.Bytes())] = entry
	}
	return result
}

func listIndex(entry arcset.ArcEntry) (uint64, error) {
	value, err := strconv.ParseUint(entry.Coordinate.String(), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("decode canonical list coordinate: %w", err)
	}
	return value, nil
}

func manifestChanges(oldGraph, newGraph *hybridGraph) []classifiedBlock {
	paths := make([]string, 0, len(newGraph.manifests))
	for dirPath := range newGraph.manifests {
		paths = append(paths, dirPath)
	}
	slices.Sort(paths)
	result := make([]classifiedBlock, 0)
	for _, dirPath := range paths {
		current := newGraph.manifests[dirPath]
		prior, exists := oldGraph.manifests[dirPath]
		if !exists || prior.block.Codec != current.block.Codec || !slices.Equal(prior.block.Data, current.block.Data) {
			result = append(result, current)
		}
	}
	return result
}

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	clientcas "github.com/dewebprotocol/malt-client/internal/cas"
	"github.com/dewebprotocol/malt-client/transport"
	unixfsmodel "github.com/dewebprotocol/malt-client/unixfs/model"
	"github.com/dewebprotocol/malt/auth/arcset"
	"github.com/dewebprotocol/malt/mutation"
	cid "github.com/ipfs/go-cid"
)

// hybridBlueprint is the output-free logical graph retained by the measured
// writer path. It contains literal payload/metadata CIDs and logical child
// references, but no commitment roots. The sole commitment computation for a
// measured commit therefore occurs inside clientroot.Session.Execute.
type hybridBlueprint struct {
	topID       string
	objects     map[string]*semanticBlueprint
	order       []string
	manifests   map[string]classifiedBlock
	directories map[string]*directoryIndex
}

type semanticBlueprint struct {
	logicalID string
	kind      arcset.Kind
	entries   []blueprintEntry
	commit    mutation.CommitDescriptor
	digest    string
}

type blueprintEntry struct {
	coordinate arcset.CanonicalCoordinate
	literal    *arcset.TargetRef
	childID    string
	childKind  arcset.TargetKind
}

func buildBlueprint(files map[string]logicalFile, chunkBytes uint64) (*hybridBlueprint, error) {
	if chunkBytes == 0 || chunkBytes > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("blueprint fixed chunk size is outside host bounds")
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

	result := &hybridBlueprint{
		topID: objectLogicalID("dir", ""), objects: make(map[string]*semanticBlueprint),
		manifests: make(map[string]classifiedBlock), directories: make(map[string]*directoryIndex),
	}
	for _, filePath := range filePaths {
		object, err := buildFileBlueprint(filePath, files[filePath], chunkBytes)
		if err != nil {
			return nil, err
		}
		result.objects[object.logicalID] = object
		result.order = append(result.order, object.logicalID)
	}

	var buildDirectory func(*directoryNode) error
	buildDirectory = func(directory *directoryNode) error {
		names := make([]string, 0, len(directory.dirs)+len(directory.files))
		for name := range directory.dirs {
			names = append(names, name)
		}
		for name := range directory.files {
			names = append(names, name)
		}
		slices.Sort(names)
		index := &directoryIndex{children: make(map[string]directoryChild, len(names))}
		for _, name := range names {
			if child := directory.dirs[name]; child != nil {
				if err := buildDirectory(child); err != nil {
					return err
				}
				logicalID := objectLogicalID("dir", child.path)
				index.children[name] = directoryChild{logicalID: logicalID, kind: arcset.TargetKindMap, path: child.path}
				continue
			}
			filePath := directory.files[name]
			index.children[name] = directoryChild{
				logicalID: objectLogicalID("file", filePath), kind: arcset.TargetKindList, path: filePath,
			}
		}
		result.directories[directory.path] = index
		object, manifest, err := buildDirectoryBlueprint(directory.path, index, files, result.objects)
		if err != nil {
			return err
		}
		result.objects[object.logicalID] = object
		result.manifests[directory.path] = manifest
		result.order = append(result.order, object.logicalID)
		return nil
	}
	if err := buildDirectory(rootDir); err != nil {
		return nil, err
	}
	return result, nil
}

// buildBlueprintNext updates only changed file blueprints and their ancestor
// directories. It retains complete logical vectors without performing any
// commitment operation or full-snapshot rebuild in the measured phase.
func buildBlueprintNext(old *hybridBlueprint, files map[string]logicalFile, changes []fileChange, chunkBytes uint64) (*hybridBlueprint, error) {
	if old == nil || len(changes) == 0 || chunkBytes == 0 {
		return nil, fmt.Errorf("incremental output-free blueprint planner is incomplete")
	}
	result := &hybridBlueprint{
		topID: old.topID, objects: make(map[string]*semanticBlueprint, len(old.objects)+len(changes)),
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

	for _, change := range changes {
		markAncestors(change.path)
		if change.before == nil {
			continue
		}
		parent, name := splitParentBase(change.path)
		delete(mutableDirectory(parent).children, name)
		delete(result.objects, objectLogicalID("file", change.path))
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
		object, err := buildFileBlueprint(change.path, *change.after, chunkBytes)
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

	directoryPaths = directoryPaths[:0]
	for path := range affectedDirectories {
		if result.directories[path] != nil {
			directoryPaths = append(directoryPaths, path)
		}
	}
	slices.SortFunc(directoryPaths, compareDirectoryDeepestFirst)
	for _, directoryPath := range directoryPaths {
		object, manifest, err := buildDirectoryBlueprint(directoryPath, result.directories[directoryPath], files, result.objects)
		if err != nil {
			return nil, err
		}
		result.objects[object.logicalID] = object
		result.manifests[directoryPath] = manifest
		result.order = append(result.order, object.logicalID)
	}
	if result.objects[result.topID] == nil {
		return nil, fmt.Errorf("incremental blueprint removed the top directory")
	}
	return result, nil
}

func buildFileBlueprint(filePath string, file logicalFile, chunkBytes uint64) (*semanticBlueprint, error) {
	chunks, err := chunkCIDs(file.data, chunkBytes)
	if err != nil {
		return nil, fmt.Errorf("normalize fixed-list blueprint %q: %w", filePath, err)
	}
	entries := make([]blueprintEntry, len(chunks))
	for index, chunk := range chunks {
		target := arcset.NewCASTarget(chunk)
		entries[index] = blueprintEntry{coordinate: arcset.NewListCoordinateUint64(uint64(index)), literal: &target}
	}
	object := &semanticBlueprint{
		logicalID: objectLogicalID("file", filePath), kind: arcset.KindList, entries: entries,
		commit: mutation.CommitDescriptor{FixedList: &mutation.FixedListCommit{TotalSize: uint64(len(file.data)), ChunkSize: chunkBytes}},
	}
	if err := finalizeBlueprint(object, nil); err != nil {
		return nil, err
	}
	return object, nil
}

func buildDirectoryBlueprint(directoryPath string, index *directoryIndex, files map[string]logicalFile, objects map[string]*semanticBlueprint) (*semanticBlueprint, classifiedBlock, error) {
	if index == nil {
		return nil, classifiedBlock{}, fmt.Errorf("directory blueprint %q has no retained index", directoryPath)
	}
	names := make([]string, 0, len(index.children))
	for name := range index.children {
		names = append(names, name)
	}
	slices.Sort(names)
	manifestRaw, err := unixfsmodel.DirectoryManifestPayload(names)
	if err != nil {
		return nil, classifiedBlock{}, fmt.Errorf("encode directory blueprint manifest %q: %w", directoryPath, err)
	}
	manifest := classifiedBlock{
		block:    transport.Block{Codec: unixfsmodel.DirectoryManifestCodec, Data: manifestRaw},
		category: categoryCASMetadata, cause: "directory-manifest", suffix: "directory-manifest",
	}
	manifestCID, err := clientcas.CIDForBlock(manifest.block)
	if err != nil {
		return nil, classifiedBlock{}, err
	}
	manifestCoordinate, err := arcset.NewMapCoordinate("meta/manifest")
	if err != nil {
		return nil, classifiedBlock{}, err
	}
	manifestTarget := arcset.NewCASTarget(manifestCID)
	entries := []blueprintEntry{{coordinate: manifestCoordinate, literal: &manifestTarget}}
	for _, name := range names {
		child := index.children[name]
		if objects[child.logicalID] == nil {
			return nil, classifiedBlock{}, fmt.Errorf("directory blueprint %q child %q has no object", directoryPath, name)
		}
		encodedName := base64.RawURLEncoding.EncodeToString([]byte(name))
		coordinate, err := arcset.NewMapCoordinate("entry/" + encodedName)
		if err != nil {
			return nil, classifiedBlock{}, err
		}
		entries = append(entries, blueprintEntry{
			coordinate: coordinate, childID: child.logicalID, childKind: child.kind,
		})
		if child.kind != arcset.TargetKindList {
			continue
		}
		file, ok := files[child.path]
		if !ok {
			return nil, classifiedBlock{}, fmt.Errorf("directory blueprint %q file child %q is absent", directoryPath, child.path)
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
		modeTarget := arcset.NewCASTarget(modeCID)
		entries = append(entries, blueprintEntry{coordinate: modeCoordinate, literal: &modeTarget})
	}
	object := &semanticBlueprint{logicalID: objectLogicalID("dir", directoryPath), kind: arcset.KindMap, entries: entries}
	if err := finalizeBlueprint(object, objects); err != nil {
		return nil, classifiedBlock{}, err
	}
	return object, manifest, nil
}

func finalizeBlueprint(object *semanticBlueprint, objects map[string]*semanticBlueprint) error {
	if object == nil || object.logicalID == "" || object.kind != arcset.KindMap && object.kind != arcset.KindList {
		return fmt.Errorf("semantic blueprint is incomplete")
	}
	slices.SortFunc(object.entries, func(a, b blueprintEntry) int {
		return bytes.Compare(a.coordinate.Bytes(), b.coordinate.Bytes())
	})
	type digestEntry struct {
		Coordinate  string `json:"coordinate"`
		TargetKind  string `json:"target_kind"`
		TargetCID   string `json:"target_cid,omitempty"`
		ChildDigest string `json:"child_digest,omitempty"`
	}
	wire := struct {
		Kind    arcset.Kind               `json:"kind"`
		Commit  mutation.CommitDescriptor `json:"commit"`
		Entries []digestEntry             `json:"entries"`
	}{Kind: object.kind, Commit: object.commit, Entries: make([]digestEntry, len(object.entries))}
	seen := make(map[string]struct{}, len(object.entries))
	for index, entry := range object.entries {
		coordinate := hex.EncodeToString(entry.coordinate.Bytes())
		if _, duplicate := seen[coordinate]; duplicate {
			return fmt.Errorf("blueprint %q has duplicate coordinate %s", object.logicalID, coordinate)
		}
		seen[coordinate] = struct{}{}
		wire.Entries[index].Coordinate = coordinate
		if entry.literal != nil {
			if entry.childID != "" || !entry.literal.CID().Defined() {
				return fmt.Errorf("blueprint %q has an invalid literal entry", object.logicalID)
			}
			wire.Entries[index].TargetKind = string(entry.literal.Kind())
			wire.Entries[index].TargetCID = entry.literal.CID().String()
			continue
		}
		child := objects[entry.childID]
		if child == nil || child.digest == "" || entry.childKind != arcset.TargetKindMap && entry.childKind != arcset.TargetKindList {
			return fmt.Errorf("blueprint %q has an invalid child entry", object.logicalID)
		}
		wire.Entries[index].TargetKind = string(entry.childKind)
		wire.Entries[index].ChildDigest = child.digest
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(encoded)
	object.digest = hex.EncodeToString(digest[:])
	return nil
}

func blueprintManifestChanges(old, next *hybridBlueprint) []classifiedBlock {
	paths := make([]string, 0, len(next.manifests))
	for path := range next.manifests {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	result := make([]classifiedBlock, 0)
	for _, path := range paths {
		current := next.manifests[path]
		prior, exists := old.manifests[path]
		if !exists || prior.block.Codec != current.block.Codec || !slices.Equal(prior.block.Data, current.block.Data) {
			result = append(result, current)
		}
	}
	return result
}

func semanticTarget(kind arcset.TargetKind, root cid.Cid) (arcset.TargetRef, error) {
	switch kind {
	case arcset.TargetKindMap:
		return arcset.NewMapTarget(root), nil
	case arcset.TargetKindList:
		return arcset.NewListTarget(root), nil
	default:
		return arcset.TargetRef{}, fmt.Errorf("unsupported semantic target kind %q", kind)
	}
}

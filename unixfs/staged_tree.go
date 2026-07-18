package unixfs

import (
	"fmt"
	"path"
	"strings"

	unixfsmodel "github.com/dewebprotocol/malt-client/unixfs/model"
	cid "github.com/ipfs/go-cid"
)

const (
	StagedKindDirectory    = "dir"
	StagedKindFile         = "file"
	StagedKindMapDirectory = "mapdir"
)

// StagedNode is a mutable UnixFS directory tree used by batch-oriented
// materializers before writing map/list roots. It captures layout shape only;
// filesystem traversal and transport stay in the caller.
type StagedNode struct {
	Kind        string
	StorageKind string
	Key         cid.Cid
	Chunks      []cid.Cid
	Children    map[string]*StagedNode
	Changed     bool
}

// ParseCanonicalStagedPath applies the UnixFS application path policy and
// rejects any spelling that CanonicalStagedPath would change. Callers that
// mutate staged trees use this lossless form so distinct input names cannot
// collapse into the same child binding.
func ParseCanonicalStagedPath(raw string) ([]string, error) {
	segments, err := unixfsmodel.ParsePath(raw)
	if err != nil {
		return nil, err
	}
	for _, segment := range segments {
		if strings.TrimSpace(segment) != segment {
			return nil, fmt.Errorf("%w: path segment is not losslessly canonical: %q", unixfsmodel.ErrInvalidPath, segment)
		}
	}
	if strings.Join(segments, "/") != raw || CanonicalStagedPath(raw) != raw {
		return nil, fmt.Errorf("%w: path is not in losslessly canonical staging form: %q", unixfsmodel.ErrInvalidPath, raw)
	}
	return segments, nil
}

// NewStagedDirectory creates an empty staged directory node.
func NewStagedDirectory() *StagedNode {
	return &StagedNode{
		Kind:     StagedKindDirectory,
		Children: make(map[string]*StagedNode),
	}
}

// EnsureStagedDirectory creates or replaces the staged node at p with a
// directory and returns it.
func EnsureStagedDirectory(root *StagedNode, p string) *StagedNode {
	root.Changed = true
	if p == "" {
		return root
	}
	segments := SplitStagedPath(p)
	cur := root
	for _, seg := range segments {
		child, ok := cur.Children[seg]
		if !ok {
			child = NewStagedDirectory()
			child.Changed = true
			cur.Children[seg] = child
		}
		if child.Kind != StagedKindDirectory {
			child = NewStagedDirectory()
			child.Changed = true
			cur.Children[seg] = child
		}
		cur.Changed = true
		cur = child
	}
	return cur
}

// SetStagedFile sets p to a file node pointing at key.
func SetStagedFile(root *StagedNode, p string, key cid.Cid) error {
	segments, err := ParseCanonicalStagedPath(p)
	if err != nil {
		return err
	}
	if len(segments) == 0 {
		return fmt.Errorf("file path must not be empty")
	}
	parentPath := strings.Join(segments[:len(segments)-1], "/")
	parent := EnsureStagedDirectory(root, parentPath)
	name := segments[len(segments)-1]

	if existing, ok := parent.Children[name]; ok {
		if existing.Kind == StagedKindFile && existing.Key.Equals(key) {
			return nil
		}
	}
	parent.Children[name] = &StagedNode{
		Kind:        StagedKindFile,
		Key:         key,
		StorageKind: unixfsmodel.StorageKindFromCID(key),
		Changed:     true,
	}
	parent.Changed = true
	return nil
}

// EnsureStagedFile replaces p with a raw file node and returns it.
func EnsureStagedFile(root *StagedNode, p string) *StagedNode {
	segments := SplitStagedPath(p)
	if len(segments) == 0 {
		return nil
	}
	parentPath := path.Dir(p)
	if parentPath == "." {
		parentPath = ""
	}
	parent := EnsureStagedDirectory(root, parentPath)
	name := segments[len(segments)-1]
	node := &StagedNode{
		Kind:        StagedKindFile,
		StorageKind: "raw",
		Changed:     true,
	}
	parent.Children[name] = node
	parent.Changed = true
	return node
}

// SetStagedMapDirectory sets p to an already-materialized map directory root.
func SetStagedMapDirectory(root *StagedNode, p string, key cid.Cid) error {
	segments, err := ParseCanonicalStagedPath(p)
	if err != nil {
		return err
	}
	if len(segments) == 0 {
		return fmt.Errorf("map directory path must not be empty")
	}
	parentPath := strings.Join(segments[:len(segments)-1], "/")
	parent := EnsureStagedDirectory(root, parentPath)
	name := segments[len(segments)-1]
	parent.Children[name] = &StagedNode{
		Kind:        StagedKindMapDirectory,
		StorageKind: "map",
		Key:         key,
		Changed:     true,
	}
	parent.Changed = true
	return nil
}

// MergeStagedNodes overlays staged changes onto an existing staged tree.
func MergeStagedNodes(existing *StagedNode, staged *StagedNode) *StagedNode {
	if staged == nil {
		return existing
	}
	if existing == nil {
		return staged
	}
	if staged.Kind != StagedKindDirectory {
		if existing.Kind == staged.Kind && existing.Key.Equals(staged.Key) {
			return existing
		}
		return staged
	}
	if existing.Kind != StagedKindDirectory {
		return staged
	}
	for name, child := range staged.Children {
		mergedChild := MergeStagedNodes(existing.Children[name], child)
		if existing.Children[name] != mergedChild {
			existing.Changed = true
		}
		if mergedChild != nil && mergedChild.Changed {
			existing.Changed = true
		}
		existing.Children[name] = mergedChild
	}
	return existing
}

// SplitStagedPath canonicalizes p and returns its path segments.
func SplitStagedPath(p string) []string {
	clean := CanonicalStagedPath(p)
	if clean == "" {
		return nil
	}
	parts := strings.Split(clean, "/")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		out = append(out, part)
	}
	return out
}

// CanonicalStagedPath normalizes a caller-provided UnixFS staging path.
func CanonicalStagedPath(raw string) string {
	p := strings.TrimSpace(raw)
	p = strings.ReplaceAll(p, "\\", "/")
	p = path.Clean("/" + p)
	p = strings.TrimPrefix(p, "/")
	if p == "." {
		return ""
	}
	return p
}

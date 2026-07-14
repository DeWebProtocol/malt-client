package merkledagimport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	mdag "github.com/ipfs/boxo/ipld/merkledag"
	unixfsio "github.com/ipfs/boxo/ipld/unixfs/io"
	cid "github.com/ipfs/go-cid"
	ipld "github.com/ipfs/go-ipld-format"
	mh "github.com/multiformats/go-multihash"
)

// Editor incrementally mutates a UnixFS directory DAG backed by Store.
type Editor struct {
	dag   ipld.DAGService
	opts  Options
	build cid.Prefix
	root  ipld.Node
}

// NewEditor creates an incremental UnixFS DAG editor.
func NewEditor(store Store, opts Options) (*Editor, error) {
	if store == nil {
		return nil, fmt.Errorf("store is nil")
	}
	opts = normalizeOptions(opts)
	if err := validateOptions(opts); err != nil {
		return nil, err
	}
	editor := &Editor{
		dag:   NewDAGService(store),
		opts:  opts,
		build: cid.Prefix{Version: 1, Codec: cid.DagProtobuf, MhType: mh.SHA2_256, MhLength: -1},
	}
	return editor, nil
}

// Root returns the current root CID string, or an empty string before the first
// materialized directory.
func (e *Editor) Root() string {
	if e == nil || e.root == nil {
		return ""
	}
	return e.root.Cid().String()
}

// PutFile writes or replaces one file in the current DAG.
func (e *Editor) PutFile(ctx context.Context, filePath string, data []byte, mode fs.FileMode) error {
	clean, parts, err := cleanPathParts(filePath)
	if err != nil {
		return err
	}
	importer := pathImporter{
		dag:   e.dag,
		opts:  e.opts,
		build: e.build,
	}
	fileNode, err := importer.importFileReader(ctx, clean, bytes.NewReader(data), virtualFileMode(mode), time.Time{})
	if err != nil {
		return err
	}
	root, err := e.putFile(ctx, e.root, parts, fileNode)
	if err != nil {
		return err
	}
	e.root = root
	return nil
}

// RemoveFile removes one file from the current DAG and prunes empty parent
// directories.
func (e *Editor) RemoveFile(ctx context.Context, filePath string) error {
	_, parts, err := cleanPathParts(filePath)
	if err != nil {
		return err
	}
	if e.root == nil {
		return fmt.Errorf("remove %s: %w", filePath, os.ErrNotExist)
	}
	root, _, err := e.removeFile(ctx, e.root, parts)
	if err != nil {
		return err
	}
	e.root = root
	return nil
}

func (e *Editor) putFile(ctx context.Context, node ipld.Node, parts []string, fileNode ipld.Node) (ipld.Node, error) {
	dir, err := e.directoryForNode(node)
	if err != nil {
		return nil, err
	}
	name := parts[0]
	if len(parts) == 1 {
		if err := dir.AddChild(ctx, name, fileNode); err != nil {
			return nil, err
		}
		return e.storeDirectory(ctx, dir)
	}
	child, err := dir.Find(ctx, name)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		child = nil
	}
	nextChild, err := e.putFile(ctx, child, parts[1:], fileNode)
	if err != nil {
		return nil, err
	}
	if err := dir.AddChild(ctx, name, nextChild); err != nil {
		return nil, err
	}
	return e.storeDirectory(ctx, dir)
}

func (e *Editor) removeFile(ctx context.Context, node ipld.Node, parts []string) (ipld.Node, bool, error) {
	dir, err := e.directoryForNode(node)
	if err != nil {
		return nil, false, err
	}
	name := parts[0]
	if len(parts) == 1 {
		if err := dir.RemoveChild(ctx, name); err != nil {
			return nil, false, err
		}
		next, err := e.storeDirectory(ctx, dir)
		if err != nil {
			return nil, false, err
		}
		empty, err := directoryIsEmpty(ctx, dir)
		return next, empty, err
	}
	child, err := dir.Find(ctx, name)
	if err != nil {
		return nil, false, err
	}
	nextChild, removeChild, err := e.removeFile(ctx, child, parts[1:])
	if err != nil {
		return nil, false, err
	}
	if removeChild {
		if err := dir.RemoveChild(ctx, name); err != nil {
			return nil, false, err
		}
	} else {
		if err := dir.AddChild(ctx, name, nextChild); err != nil {
			return nil, false, err
		}
	}
	next, err := e.storeDirectory(ctx, dir)
	if err != nil {
		return nil, false, err
	}
	empty, err := directoryIsEmpty(ctx, dir)
	return next, empty, err
}

func (e *Editor) directoryForNode(node ipld.Node) (unixfsio.Directory, error) {
	if node == nil {
		return e.newDirectory()
	}
	switch e.opts.DirLayout {
	case DirLayoutBasic:
		protoNode, ok := node.(*mdag.ProtoNode)
		if !ok {
			return nil, fmt.Errorf("basic directory root %s is not dag-pb", node.Cid())
		}
		dir := unixfsio.NewBasicDirectoryFromNode(e.dag, protoNode.Copy().(*mdag.ProtoNode))
		dir.SetCidBuilder(e.build)
		return dir, nil
	case DirLayoutHAMT:
		dir, err := unixfsio.NewHAMTDirectoryFromNode(e.dag, node)
		if err != nil {
			return nil, err
		}
		dir.SetCidBuilder(e.build)
		return dir, nil
	case DirLayoutAdaptive:
		dir, err := unixfsio.NewDirectoryFromNode(e.dag, node)
		if err != nil {
			return nil, err
		}
		dir.SetCidBuilder(e.build)
		return dir, nil
	default:
		return nil, fmt.Errorf("unsupported merkle-dag unixfs directory layout %q", e.opts.DirLayout)
	}
}

func (e *Editor) newDirectory() (unixfsio.Directory, error) {
	importer := pathImporter{
		dag:   e.dag,
		opts:  e.opts,
		build: e.build,
	}
	return importer.newDirectory()
}

func (e *Editor) storeDirectory(ctx context.Context, dir unixfsio.Directory) (ipld.Node, error) {
	node, err := dir.GetNode()
	if err != nil {
		return nil, err
	}
	if err := e.dag.Add(ctx, node); err != nil {
		return nil, err
	}
	return node, nil
}

func directoryIsEmpty(ctx context.Context, dir unixfsio.Directory) (bool, error) {
	links, err := dir.Links(ctx)
	if err != nil {
		return false, err
	}
	return len(links) == 0, nil
}

func cleanPathParts(raw string) (string, []string, error) {
	clean, err := cleanVirtualPath(raw)
	if err != nil {
		return "", nil, err
	}
	parts := strings.Split(clean, "/")
	if len(parts) == 0 || parts[0] == "" {
		return "", nil, fmt.Errorf("invalid virtual file path %q", raw)
	}
	return clean, parts, nil
}

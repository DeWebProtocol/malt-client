package merkledagimport

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	casmemory "github.com/dewebprotocol/malt-client/internal/cas/memory"
	merkledag "github.com/ipfs/boxo/ipld/merkledag"
	unixfs "github.com/ipfs/boxo/ipld/unixfs"
	cid "github.com/ipfs/go-cid"
)

type swappingPathFilter struct {
	root        string
	backup      string
	replacement string
}

func (f *swappingPathFilter) LoadDirectoryRules(localDir string) error {
	if filepath.Clean(localDir) != filepath.Clean(f.root) {
		return nil
	}
	if err := os.Rename(f.root, f.backup); err != nil {
		return err
	}
	return os.Symlink(f.replacement, f.root)
}

func (*swappingPathFilter) Ignored(string, bool) (bool, error) {
	return false, nil
}

func TestImportFileStoresUnixFSDAG(t *testing.T) {
	ctx := context.Background()
	casClient := casmemory.New()
	file := filepath.Join(t.TempDir(), "hello.txt")
	if err := os.WriteFile(file, []byte("hello merkle dag"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	result, err := ImportPath(ctx, casClient, file, Options{
		Model:      ModelUnixFS,
		FileLayout: FileLayoutBalanced,
		DirLayout:  DirLayoutBasic,
		ChunkSize:  4,
	})
	if err != nil {
		t.Fatalf("import file: %v", err)
	}
	if result.Root == "" {
		t.Fatal("root should not be empty")
	}
	if result.Files != 1 {
		t.Fatalf("files = %d, want 1", result.Files)
	}
	if result.Bytes != int64(len("hello merkle dag")) {
		t.Fatalf("bytes = %d, want %d", result.Bytes, len("hello merkle dag"))
	}
	root, err := cid.Decode(result.Root)
	if err != nil {
		t.Fatalf("decode root: %v", err)
	}
	if _, err := casClient.Get(ctx, root); err != nil {
		t.Fatalf("root block should be stored in CAS: %v", err)
	}
}

func TestImportDirectoryStoresHAMTUnixFSDAG(t *testing.T) {
	ctx := context.Background()
	casClient := casmemory.New()
	root := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(filepath.Join(root, "docs"), 0o755); err != nil {
		t.Fatalf("mkdir docs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("readme"), 0o644); err != nil {
		t.Fatalf("write readme: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "docs", "guide.txt"), []byte("guide"), 0o644); err != nil {
		t.Fatalf("write guide: %v", err)
	}

	result, err := ImportPath(ctx, casClient, root, Options{
		Model:      ModelUnixFS,
		FileLayout: FileLayoutBalanced,
		DirLayout:  DirLayoutHAMT,
		ChunkSize:  4,
	})
	if err != nil {
		t.Fatalf("import directory: %v", err)
	}
	if result.Files != 2 {
		t.Fatalf("files = %d, want 2", result.Files)
	}
	if result.Bytes != int64(len("readme")+len("guide")) {
		t.Fatalf("bytes = %d", result.Bytes)
	}
	rootCID, err := cid.Decode(result.Root)
	if err != nil {
		t.Fatalf("decode root: %v", err)
	}
	if rootCID.Type() != cid.DagProtobuf {
		t.Fatalf("root codec = %d, want dag-pb", rootCID.Type())
	}
	if _, err := casClient.Get(ctx, rootCID); err != nil {
		t.Fatalf("directory root should be stored in CAS: %v", err)
	}
}

func TestImportFilesStoresVirtualHAMTUnixFSDAG(t *testing.T) {
	ctx := context.Background()
	casClient := casmemory.New()

	result, err := ImportFiles(ctx, casClient, []File{
		{Path: "README.md", Data: []byte("readme"), Mode: 0o644},
		{Path: "docs/guide.txt", Data: []byte("guide"), Mode: 0o644},
	}, Options{
		Model:      ModelUnixFS,
		FileLayout: FileLayoutBalanced,
		DirLayout:  DirLayoutHAMT,
		ChunkSize:  4,
	})
	if err != nil {
		t.Fatalf("import virtual files: %v", err)
	}
	if result.Files != 2 {
		t.Fatalf("files = %d, want 2", result.Files)
	}
	if result.Bytes != int64(len("readme")+len("guide")) {
		t.Fatalf("bytes = %d", result.Bytes)
	}
	rootCID, err := cid.Decode(result.Root)
	if err != nil {
		t.Fatalf("decode root: %v", err)
	}
	if rootCID.Type() != cid.DagProtobuf {
		t.Fatalf("root codec = %d, want dag-pb", rootCID.Type())
	}
	if _, err := casClient.Get(ctx, rootCID); err != nil {
		t.Fatalf("directory root should be stored in CAS: %v", err)
	}
}

func TestImportRejectsTopLevelLayout(t *testing.T) {
	ctx := context.Background()
	casClient := casmemory.New()
	file := filepath.Join(t.TempDir(), "hello.txt")
	if err := os.WriteFile(file, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	if _, err := ImportPath(ctx, casClient, file, Options{
		Model:  ModelUnixFS,
		Layout: "balanced",
	}); err == nil {
		t.Fatal("expected top-level layout to be rejected")
	}
}

func TestImportRejectsNilStoreAndVirtualFileDirectoryConflicts(t *testing.T) {
	if _, err := ImportPath(context.Background(), nil, "ignored", Options{}); err == nil {
		t.Fatal("ImportPath accepted a nil store")
	}
	if _, err := ImportFiles(context.Background(), nil, nil, Options{}); err == nil {
		t.Fatal("ImportFiles accepted a nil store")
	}

	store := casmemory.New()
	for _, files := range [][]File{
		{{Path: "a", Data: []byte("file")}, {Path: "a/b", Data: []byte("child")}},
		{{Path: "a/b", Data: []byte("child")}, {Path: "a", Data: []byte("file")}},
	} {
		if _, err := ImportFiles(context.Background(), store, files, Options{}); err == nil {
			t.Fatalf("ImportFiles accepted a file/directory collision: %#v", files)
		}
	}
}

func TestImportFilesPreservesValidWhitespaceInNames(t *testing.T) {
	ctx := context.Background()
	store := casmemory.New()
	result, err := ImportFiles(ctx, store, []File{{
		Path: " docs / report .txt ",
		Data: []byte("content"),
	}}, Options{DirLayout: DirLayoutBasic})
	if err != nil {
		t.Fatalf("ImportFiles rejected a valid whitespace-bearing path: %v", err)
	}
	if result.Root == "" {
		t.Fatal("root is empty")
	}
	root, err := cid.Parse(result.Root)
	if err != nil {
		t.Fatal(err)
	}
	node, err := NewDAGService(store).Get(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := node.ResolveLink([]string{" docs ", " report .txt "}); err != nil {
		t.Fatalf("resolve whitespace-bearing path: %v", err)
	}
}

func TestImportDirectoryEncodesSymlinkWithoutFollowingIt(t *testing.T) {
	ctx := context.Background()
	casClient := casmemory.New()
	base := t.TempDir()
	root := filepath.Join(base, "repo")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "outside-secret.txt")
	if err := os.WriteFile(outside, []byte("must not be imported"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join("..", filepath.Base(outside))
	linkPath := filepath.Join(root, "external-link")
	if err := os.Symlink(target, linkPath); err != nil {
		t.Skipf("symlinks are not supported on this platform: %v", err)
	}

	result, err := ImportPath(ctx, casClient, root, Options{
		Model:      ModelUnixFS,
		FileLayout: FileLayoutBalanced,
		DirLayout:  DirLayoutBasic,
	})
	if err != nil {
		t.Fatalf("import directory: %v", err)
	}
	if result.Files != 1 || result.Bytes != int64(len(target)) {
		t.Fatalf("result = %#v, want one symlink and target-byte accounting", result)
	}

	rootCID, err := cid.Decode(result.Root)
	if err != nil {
		t.Fatal(err)
	}
	dag := NewDAGService(casClient)
	rootNode, err := dag.Get(ctx, rootCID)
	if err != nil {
		t.Fatal(err)
	}
	link, remaining, err := rootNode.ResolveLink([]string{"external-link"})
	if err != nil {
		t.Fatalf("resolve symlink node: %v", err)
	}
	if len(remaining) != 0 {
		t.Fatalf("unresolved symlink path = %v", remaining)
	}
	linkNode, err := dag.Get(ctx, link.Cid)
	if err != nil {
		t.Fatalf("load symlink node: %v", err)
	}
	fsNode, err := unixfs.FSNodeFromBytes(linkNode.(*merkledag.ProtoNode).Data())
	if err != nil {
		t.Fatalf("decode unixfs symlink: %v", err)
	}
	if fsNode.Type() != unixfs.TSymlink || string(fsNode.Data()) != target {
		t.Fatalf("symlink = type %v target %q, want %v %q", fsNode.Type(), fsNode.Data(), unixfs.TSymlink, target)
	}
}

func TestImportDirectoryStaysAnchoredWhenInputPathIsReplaced(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("renaming an open directory has different Windows semantics")
	}
	ctx := context.Background()
	store := casmemory.New()
	base := t.TempDir()
	root := filepath.Join(base, "repo")
	backup := filepath.Join(base, "repo-original")
	replacement := filepath.Join(base, "replacement")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(replacement, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "data.txt"), []byte("inside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(replacement, "data.txt"), []byte("outside secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := ImportPath(ctx, store, root, Options{
		DirLayout: DirLayoutBasic,
		Ignore: &swappingPathFilter{
			root:        root,
			backup:      backup,
			replacement: replacement,
		},
	})
	if err != nil {
		t.Fatalf("import anchored directory: %v", err)
	}
	if result.Files != 1 || result.Bytes != int64(len("inside")) {
		t.Fatalf("result = %#v, importer followed replacement path", result)
	}

	rootCID, err := cid.Parse(result.Root)
	if err != nil {
		t.Fatal(err)
	}
	dag := NewDAGService(store)
	rootNode, err := dag.Get(ctx, rootCID)
	if err != nil {
		t.Fatal(err)
	}
	link, _, err := rootNode.ResolveLink([]string{"data.txt"})
	if err != nil {
		t.Fatal(err)
	}
	fileNode, err := dag.Get(ctx, link.Cid)
	if err != nil {
		t.Fatal(err)
	}
	fsNode, err := unixfs.FSNodeFromBytes(fileNode.(*merkledag.ProtoNode).Data())
	if err != nil {
		t.Fatal(err)
	}
	if got := string(fsNode.Data()); got != "inside" {
		t.Fatalf("imported bytes = %q, want original directory bytes", got)
	}
}

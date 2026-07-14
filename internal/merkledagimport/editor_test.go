package merkledagimport

import (
	"context"
	"testing"

	casmemory "github.com/dewebprotocol/malt-client/internal/cas/memory"
	cid "github.com/ipfs/go-cid"
)

func TestEditorUpdatesAndRemovesUnixFSFiles(t *testing.T) {
	ctx := context.Background()
	store := casmemory.New()
	editor, err := NewEditor(store, Options{DirLayout: DirLayoutBasic, ChunkSize: 4})
	if err != nil {
		t.Fatal(err)
	}
	if err := editor.PutFile(ctx, "docs/guide.txt", []byte("first"), 0o644); err != nil {
		t.Fatal(err)
	}
	first := editor.Root()
	if first == "" {
		t.Fatal("first root is empty")
	}
	if err := editor.PutFile(ctx, "docs/guide.txt", []byte("second"), 0o644); err != nil {
		t.Fatal(err)
	}
	second := editor.Root()
	if second == first {
		t.Fatal("replacing file content did not change the Merkle DAG root")
	}
	key, err := cid.Parse(second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, key); err != nil {
		t.Fatalf("updated root block is not in CAS: %v", err)
	}
	if err := editor.RemoveFile(ctx, "docs/guide.txt"); err != nil {
		t.Fatal(err)
	}
	if editor.Root() == second {
		t.Fatal("removing the file did not change the Merkle DAG root")
	}
}

func TestEditorRejectsTraversal(t *testing.T) {
	editor, err := NewEditor(casmemory.New(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := editor.PutFile(context.Background(), "../escape.txt", []byte("bad"), 0o644); err == nil {
		t.Fatal("editor accepted parent-directory traversal")
	}
}

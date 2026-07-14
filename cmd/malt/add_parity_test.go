package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	casmemory "github.com/dewebprotocol/malt-client/internal/cas/memory"
)

func TestNormalizeAddBuildOptionsAcrossTargets(t *testing.T) {
	tests := []struct {
		name           string
		in             addBuildOptions
		wantTarget     string
		wantLayout     string
		wantFileLayout string
		wantDirLayout  string
		wantErr        bool
	}{
		{name: "MALT defaults", wantTarget: addTargetMALT, wantLayout: addLayoutHybrid},
		{name: "MALT hybrid", in: addBuildOptions{Target: addTargetMALT, Layout: addLayoutHybrid}, wantTarget: addTargetMALT, wantLayout: addLayoutHybrid},
		{
			name:       "Merkle DAG defaults",
			in:         addBuildOptions{Target: "merkledag", Model: addModelUnixFS},
			wantTarget: addTargetMerkleDAG, wantFileLayout: addFileLayoutBalanced, wantDirLayout: addDirLayoutAdaptive,
		},
		{
			name:       "Merkle DAG explicit layouts",
			in:         addBuildOptions{Target: addTargetMerkleDAG, FileLayout: addFileLayoutTrickle, DirLayout: addDirLayoutHAMT},
			wantTarget: addTargetMerkleDAG, wantFileLayout: addFileLayoutTrickle, wantDirLayout: addDirLayoutHAMT,
		},
		{name: "reject former MALT flat alias", in: addBuildOptions{Target: addTargetMALT, Layout: "flat"}, wantErr: true},
		{name: "reject former MALT hierarchical alias", in: addBuildOptions{Target: addTargetMALT, Layout: "hierarchical"}, wantErr: true},
		{name: "reject MALT HAMT", in: addBuildOptions{Target: addTargetMALT, Layout: "hamt"}, wantErr: true},
		{name: "reject Merkle DAG top-level layout", in: addBuildOptions{Target: addTargetMerkleDAG, Layout: addLayoutHybrid}, wantErr: true},
		{name: "reject unknown target", in: addBuildOptions{Target: "other"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeAddBuildOptions(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Target != tt.wantTarget || got.Layout != tt.wantLayout || got.FileLayout != tt.wantFileLayout || got.DirLayout != tt.wantDirLayout {
				t.Fatalf("normalized options = %#v", got)
			}
		})
	}
}

func TestMountAddInputsKeepsApplicationPathPolicyInClient(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "a.txt")
	second := filepath.Join(root, "b.txt")
	writeTestFile(t, first, "a")
	writeTestFile(t, second, "b")

	inputs, err := collectAddInputs([]string{first, second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mountAddInputs(inputs, addBuildOptions{Wrap: true}); err == nil {
		t.Fatal("multi-input wrap without --wrap-name should fail")
	}
	mounted, err := mountAddInputs(inputs, addBuildOptions{Prefix: "/repo//", Wrap: true, WrapName: "bundle"})
	if err != nil {
		t.Fatal(err)
	}
	if mounted[0].MountBase != "repo/bundle/a.txt" || mounted[1].MountBase != "repo/bundle/b.txt" {
		t.Fatalf("mounted paths = %q, %q", mounted[0].MountBase, mounted[1].MountBase)
	}
}

func TestMerkleDAGAddUsesGatewayCASAndIgnorePolicy(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repo")
	writeTestFile(t, filepath.Join(root, ".gitignore"), "ignored/\n")
	writeTestFile(t, filepath.Join(root, "ignored", "drop.txt"), "drop")
	writeTestFile(t, filepath.Join(root, "keep", "hello.txt"), "hello")

	store := casmemory.New()
	result, err := addInputsWithUnixFS(context.Background(), nil, store, []string{root}, "", addBuildOptions{
		Target:     addTargetMerkleDAG,
		Model:      addModelUnixFS,
		FileLayout: addFileLayoutBalanced,
		DirLayout:  addDirLayoutBasic,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Files != 2 {
		t.Fatalf("imported files = %d, want 2 (.gitignore and keep/hello.txt)", result.Files)
	}
	if result.NewRoot == "" {
		t.Fatal("Merkle DAG root is empty")
	}
	if _, err := store.Get(context.Background(), mustParseCID(t, result.NewRoot)); err != nil {
		t.Fatalf("root block missing from CAS: %v", err)
	}
}

func TestMerkleDAGSummaryDoesNotClaimMALTObjects(t *testing.T) {
	got := formatAddSummary(addSummary{Target: addTargetMerkleDAG, Files: 2, Bytes: 5, NewRoot: "bafy-root"})
	if !strings.Contains(got, "Merkle DAG UnixFS") || strings.Contains(got, "MALT objects") {
		t.Fatalf("summary = %q", got)
	}
}

func writeTestFile(t *testing.T, name, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

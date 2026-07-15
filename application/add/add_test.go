package add

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/dewebprotocol/malt-client/application"
	casmemory "github.com/dewebprotocol/malt-client/internal/cas/memory"
	"github.com/dewebprotocol/malt-client/trust"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

func TestNormalizeOptionsAcrossTargets(t *testing.T) {
	tests := []struct {
		name           string
		in             Options
		wantTarget     string
		wantLayout     string
		wantFileLayout string
		wantDirLayout  string
		wantErr        bool
	}{
		{name: "MALT defaults", wantTarget: TargetMALT, wantLayout: LayoutHybrid},
		{name: "MALT hybrid", in: Options{Target: TargetMALT, Layout: LayoutHybrid}, wantTarget: TargetMALT, wantLayout: LayoutHybrid},
		{name: "Merkle DAG defaults", in: Options{Target: "merkledag", Model: ModelUnixFS}, wantTarget: TargetMerkleDAG, wantFileLayout: FileLayoutBalanced, wantDirLayout: DirLayoutAdaptive},
		{name: "Merkle DAG explicit layouts", in: Options{Target: TargetMerkleDAG, FileLayout: FileLayoutTrickle, DirLayout: DirLayoutHAMT}, wantTarget: TargetMerkleDAG, wantFileLayout: FileLayoutTrickle, wantDirLayout: DirLayoutHAMT},
		{name: "reject former MALT flat alias", in: Options{Target: TargetMALT, Layout: "flat"}, wantErr: true},
		{name: "reject former MALT hierarchical alias", in: Options{Target: TargetMALT, Layout: "hierarchical"}, wantErr: true},
		{name: "reject MALT HAMT", in: Options{Target: TargetMALT, Layout: "hamt"}, wantErr: true},
		{name: "reject Merkle DAG top-level layout", in: Options{Target: TargetMerkleDAG, Layout: LayoutHybrid}, wantErr: true},
		{name: "reject unknown target", in: Options{Target: "other"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeOptions(tt.in)
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

func TestMountInputsKeepsApplicationPathPolicyOutOfCLI(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "a.txt")
	second := filepath.Join(root, "b.txt")
	writeTestFile(t, first, "a")
	writeTestFile(t, second, "b")

	inputs, err := collectAddInputs([]string{first, second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mountAddInputs(inputs, Options{Wrap: true}); err == nil {
		t.Fatal("multi-input wrap without wrap name should fail")
	}
	mounted, err := mountAddInputs(inputs, Options{Prefix: "/repo//", Wrap: true, WrapName: "bundle"})
	if err != nil {
		t.Fatal(err)
	}
	if mounted[0].MountBase != "repo/bundle/a.txt" || mounted[1].MountBase != "repo/bundle/b.txt" {
		t.Fatalf("mounted paths = %q, %q", mounted[0].MountBase, mounted[1].MountBase)
	}
}

func TestRunMerkleDAGUsesCASAndIgnorePolicy(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repo")
	writeTestFile(t, filepath.Join(root, ".gitignore"), "ignored/\n")
	writeTestFile(t, filepath.Join(root, "ignored", "drop.txt"), "drop")
	writeTestFile(t, filepath.Join(root, "keep", "hello.txt"), "hello")

	store := casmemory.New()
	execution, err := Run(context.Background(), nil, nil, store, Request{
		Inputs:  []string{root},
		Options: Options{Target: TargetMerkleDAG, Model: ModelUnixFS, FileLayout: FileLayoutBalanced, DirLayout: DirLayoutBasic},
	})
	if err != nil {
		t.Fatal(err)
	}
	if execution.Result.Files != 2 {
		t.Fatalf("imported files = %d, want 2", execution.Result.Files)
	}
	if execution.Result.NewRoot == "" {
		t.Fatal("Merkle DAG root is empty")
	}
	if _, err := store.Get(context.Background(), mustParseCID(t, execution.Result.NewRoot)); err != nil {
		t.Fatalf("root block missing from CAS: %v", err)
	}
}

func TestRunRecordsAliasResultAsCandidateWithoutAcceptance(t *testing.T) {
	accepted := testCID(t, "accepted")
	candidate := testCID(t, "candidate")
	store, err := trust.Open(filepath.Join(t.TempDir(), "roots.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Trust("docs", accepted.String(), "unixfs", "", "test"); err != nil {
		t.Fatal(err)
	}
	roots, _ := application.NewRoots(store)
	materialize := func(_ context.Context, _ Gateway, _ addCASClient, _ []string, root string, _ addBuildOptions) (*addUnixFSResult, error) {
		if root != accepted.String() {
			t.Fatalf("materializer root = %s, want %s", root, accepted)
		}
		return &addUnixFSResult{NewRoot: candidate.String(), Files: 1}, nil
	}
	execution, err := run(t.Context(), roots, nil, casmemory.New(), Request{
		Inputs: []string{"unused"}, Alias: "docs", Options: Options{Target: TargetMALT},
	}, materialize)
	if err != nil {
		t.Fatal(err)
	}
	if execution.BaseRoot != accepted.String() || execution.Alias != "docs" {
		t.Fatalf("execution = %#v", execution)
	}
	record, _ := store.Get("docs")
	if record.AcceptedRoot != accepted.String() || len(record.Candidates) != 1 || record.Candidates[0].Root != candidate.String() {
		t.Fatalf("add use case changed trust unexpectedly: %#v", record)
	}
}

func TestRunTreatsCIDShapedAliasAsAliasAndRecordsCandidate(t *testing.T) {
	alias := testCID(t, "cid-shaped-alias").String()
	accepted := testCID(t, "accepted-for-cid-shaped-alias")
	candidate := testCID(t, "candidate-for-cid-shaped-alias")
	store, err := trust.Open(filepath.Join(t.TempDir(), "roots.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Trust(alias, accepted.String(), "unixfs", "", "test"); err != nil {
		t.Fatal(err)
	}
	roots, err := application.NewRoots(store)
	if err != nil {
		t.Fatal(err)
	}
	materialize := func(_ context.Context, _ Gateway, _ addCASClient, _ []string, root string, _ addBuildOptions) (*addUnixFSResult, error) {
		if root != accepted.String() {
			t.Fatalf("materializer root = %s, want alias's accepted root %s", root, accepted)
		}
		return &addUnixFSResult{NewRoot: candidate.String(), Files: 1}, nil
	}
	execution, err := run(t.Context(), roots, nil, casmemory.New(), Request{
		Inputs: []string{"unused"}, Alias: alias, Options: Options{Target: TargetMALT},
	}, materialize)
	if err != nil {
		t.Fatal(err)
	}
	if execution.BaseRoot != accepted.String() || execution.Alias != alias {
		t.Fatalf("execution = %#v, want accepted alias selection", execution)
	}
	record, err := store.Get(alias)
	if err != nil {
		t.Fatal(err)
	}
	if record.AcceptedRoot != accepted.String() || len(record.Candidates) != 1 || record.Candidates[0].Root != candidate.String() || record.Candidates[0].BaseRoot != accepted.String() {
		t.Fatalf("CID-shaped alias candidate recording = %#v", record)
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

func mustParseCID(t *testing.T, raw string) cid.Cid {
	t.Helper()
	value, err := cid.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func testCID(t *testing.T, body string) cid.Cid {
	t.Helper()
	hash, err := mh.Sum([]byte(body), mh.SHA2_256, -1)
	if err != nil {
		t.Fatal(err)
	}
	return cid.NewCidV1(cid.Raw, hash)
}

package add

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/dewebprotocol/malt-client/application"
	casmemory "github.com/dewebprotocol/malt-client/internal/cas/memory"
	"github.com/dewebprotocol/malt-client/trust"
	unixfs "github.com/dewebprotocol/malt-client/unixfs"
	"github.com/dewebprotocol/malt/mutation"
	"github.com/dewebprotocol/malt/protocol"
	"github.com/dewebprotocol/malt/wire/maltcid"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

func TestClassifyStagedTargetFailsClosed(t *testing.T) {
	mapRoot, err := maltcid.NewMapKZGCid(make([]byte, maltcid.KZGCommitmentSize))
	if err != nil {
		t.Fatal(err)
	}
	listRoot, err := maltcid.NewListIPACid(make([]byte, maltcid.IPACommitmentSize))
	if err != nil {
		t.Fatal(err)
	}
	raw := testCID(t, "raw")
	invalidHash, err := mh.Sum([]byte("not a commitment"), mh.SHA2_256, -1)
	if err != nil {
		t.Fatal(err)
	}
	invalidTypedRoot := cid.NewCidV1(maltcid.CodecMaltMapKZG, invalidHash)
	unknownCodec := cid.NewCidV1(0x320002, invalidHash)
	identityCommitment, err := mh.Encode(make([]byte, maltcid.KZGCommitmentSize), mh.IDENTITY)
	if err != nil {
		t.Fatal(err)
	}
	unknownBackend := cid.NewCidV1(0x3011ff, identityCommitment)
	unknownVersion := cid.NewCidV1(0x302101, identityCommitment)

	for name, test := range map[string]struct {
		target      cid.Cid
		wantKind    string
		wantStorage string
		wantErr     bool
	}{
		"map":                {target: mapRoot, wantKind: unixfs.StagedKindDirectory, wantStorage: "map"},
		"list":               {target: listRoot, wantKind: unixfs.StagedKindFile, wantStorage: "list"},
		"raw":                {target: raw, wantKind: unixfs.StagedKindFile, wantStorage: "raw"},
		"invalid typed root": {target: invalidTypedRoot, wantErr: true},
		"unknown codec":      {target: unknownCodec, wantErr: true},
		"unknown backend":    {target: unknownBackend, wantErr: true},
		"unknown version":    {target: unknownVersion, wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			kind, storage, err := classifyStagedTarget(test.target)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected unsupported CID error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if kind != test.wantKind || storage != test.wantStorage {
				t.Fatalf("classification = (%q, %q), want (%q, %q)", kind, storage, test.wantKind, test.wantStorage)
			}
		})
	}
}

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
	single, err := mountAddInputs(inputs[:1], Options{Wrap: true})
	if err != nil {
		t.Fatal(err)
	}
	if single[0].MountBase != "a.txt/a.txt" {
		t.Fatalf("empty wrap name no longer used the existing single-input default: %q", single[0].MountBase)
	}
}

func TestMountInputsRejectsReservedAndNonPortableTargets(t *testing.T) {
	root := t.TempDir()
	reserved := filepath.Join(root, "@payload")
	regular := filepath.Join(root, "file.txt")
	writeTestFile(t, reserved, "reserved")
	writeTestFile(t, regular, "regular")

	reservedInputs, err := collectAddInputs([]string{reserved})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mountAddInputs(reservedInputs, Options{}); err == nil {
		t.Fatal("mounted reserved @payload input")
	}
	regularInputs, err := collectAddInputs([]string{regular})
	if err != nil {
		t.Fatal(err)
	}
	for name, opts := range map[string]Options{
		"parent prefix":      {Prefix: "../escape"},
		"backslash prefix":   {Prefix: `repo\nested`},
		"reserved prefix":    {Prefix: "repo/@payload"},
		"multi-segment wrap": {Wrap: true, WrapName: "bundle/nested"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := mountAddInputs(regularInputs, opts); err == nil {
				t.Fatalf("mountAddInputs accepted options %#v", opts)
			}
		})
	}
}

func TestValidateStagedPathRejectsLossyWhitespaceCanonicalization(t *testing.T) {
	for _, target := range []string{" file", "file ", "   ", " @payload", "dir/ child", "dir/child "} {
		t.Run(target, func(t *testing.T) {
			if err := validateStagedPath(target); err == nil {
				t.Fatalf("validateStagedPath accepted lossy path %q", target)
			}
		})
	}
	for _, target := range []string{"file", "file name", "dir/file name"} {
		if err := validateStagedPath(target); err != nil {
			t.Fatalf("validateStagedPath rejected canonical path %q: %v", target, err)
		}
	}
}

func TestBuildAddStagingTreeRejectsNonEmptyLossyPrefixAndWrapBeforeWrite(t *testing.T) {
	input := filepath.Join(t.TempDir(), "file.txt")
	writeTestFile(t, input, "payload")
	for name, opts := range map[string]Options{
		"whitespace prefix":          {Prefix: "   "},
		"padded prefix":              {Prefix: " repo "},
		"separator-only prefix":      {Prefix: "///"},
		"whitespace prefix segment":  {Prefix: "repo/ child"},
		"internal prefix whitespace": {Prefix: "repo name"},
		"whitespace-only segment":    {Prefix: "repo/ /child"},
		"whitespace wrap":            {Wrap: true, WrapName: "   "},
		"padded wrap":                {Wrap: true, WrapName: " bundle "},
	} {
		t.Run(name, func(t *testing.T) {
			blocks := &countingAddCAS{inner: casmemory.New()}
			remote := &countingAddGateway{}
			if _, err := buildAddStagingTree(t.Context(), blocks, remote, []string{input}, opts); err == nil {
				t.Fatalf("buildAddStagingTree accepted options %#v", opts)
			}
			if blocks.puts != 0 || remote.calls != 0 {
				t.Fatalf("invalid options performed writes: CAS=%d Gateway=%d", blocks.puts, remote.calls)
			}
		})
	}
}

func TestBuildAddStagingTreeRejectsWhitespaceNameCollisionBeforeWrite(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repo")
	writeTestFile(t, filepath.Join(root, "file"), "canonical")
	writeTestFile(t, filepath.Join(root, "file "), "would collide after trimming")
	blocks := &countingAddCAS{inner: casmemory.New()}
	remote := &countingAddGateway{}
	if _, err := buildAddStagingTree(t.Context(), blocks, remote, []string{root}, Options{}); err == nil {
		t.Fatal("buildAddStagingTree accepted lossy whitespace filenames")
	}
	if blocks.puts != 0 || remote.calls != 0 {
		t.Fatalf("invalid tree performed writes: CAS=%d Gateway=%d", blocks.puts, remote.calls)
	}
}

func TestBuildAddStagingTreeRejectsWhitespacePrefixedReservedNameBeforeWrite(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repo")
	writeTestFile(t, filepath.Join(root, " @payload"), "would become reserved after trimming")
	blocks := &countingAddCAS{inner: casmemory.New()}
	remote := &countingAddGateway{}
	if _, err := buildAddStagingTree(t.Context(), blocks, remote, []string{root}, Options{}); err == nil {
		t.Fatal("buildAddStagingTree accepted whitespace-prefixed @payload")
	}
	if blocks.puts != 0 || remote.calls != 0 {
		t.Fatalf("invalid tree performed writes: CAS=%d Gateway=%d", blocks.puts, remote.calls)
	}
}

func TestStageSingleFileRejectsReservedTargetBeforeUpload(t *testing.T) {
	local := filepath.Join(t.TempDir(), "payload.txt")
	writeTestFile(t, local, "payload")
	blocks := &countingAddCAS{inner: casmemory.New()}
	if _, _, err := stageSingleFile(t.Context(), unixfs.NewStagedDirectory(), blocks, nil, local, "@payload"); err == nil {
		t.Fatal("stageSingleFile accepted reserved target")
	}
	if blocks.puts != 0 {
		t.Fatalf("invalid target uploaded %d blocks", blocks.puts)
	}
}

func TestBuildAddStagingTreeRejectsPOSIXBackslashName(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows cannot create a file with a backslash in one path segment")
	}
	root := filepath.Join(t.TempDir(), "repo")
	writeTestFile(t, filepath.Join(root, `a\b`), "backslash")
	writeTestFile(t, filepath.Join(root, "a", "b"), "nested")
	blocks := &countingAddCAS{inner: casmemory.New()}
	if _, err := buildAddStagingTree(t.Context(), blocks, nil, []string{root}, Options{}); err == nil {
		t.Fatal("buildAddStagingTree rewrote a POSIX backslash filename")
	}
	if blocks.puts != 0 {
		t.Fatalf("invalid tree uploaded %d blocks", blocks.puts)
	}
}

func TestBuildAddStagingTreePreflightsWholeTreeBeforeWrite(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows cannot create a file with a backslash in one path segment")
	}
	root := filepath.Join(t.TempDir(), "repo")
	writeTestFile(t, filepath.Join(root, "a-large.bin"), string(make([]byte, addFixedChunkSize+1)))
	writeTestFile(t, filepath.Join(root, `z\bad`), "invalid later entry")
	blocks := &countingAddCAS{inner: casmemory.New()}
	remote := &countingAddGateway{}
	if _, err := buildAddStagingTree(t.Context(), blocks, remote, []string{root}, Options{}); err == nil {
		t.Fatal("buildAddStagingTree accepted invalid later entry")
	}
	if blocks.puts != 0 || remote.calls != 0 {
		t.Fatalf("preflight allowed writes before later validation failure: CAS=%d Gateway=%d", blocks.puts, remote.calls)
	}
}

func TestBuildAddStagingTreePreflightPreservesIgnoreSemantics(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows cannot create a file with a backslash in one path segment")
	}
	root := filepath.Join(t.TempDir(), "repo")
	writeTestFile(t, filepath.Join(root, ".gitignore"), "ignored/\n")
	writeTestFile(t, filepath.Join(root, "keep.txt"), "keep")
	writeTestFile(t, filepath.Join(root, "ignored", `z\bad`), "ignored invalid name")
	blocks := &countingAddCAS{inner: casmemory.New()}
	result, err := buildAddStagingTree(t.Context(), blocks, nil, []string{root}, Options{})
	if err != nil {
		t.Fatalf("ignored invalid path changed staging semantics: %v", err)
	}
	if result.Files != 2 {
		t.Fatalf("staged files = %d, want .gitignore and keep.txt", result.Files)
	}
}

func TestBuildAddStagingTreePreflightsSymlinkDirectoryBeforeWrite(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory symlink setup is not portable to Windows")
	}
	target := filepath.Join(t.TempDir(), "target")
	writeTestFile(t, filepath.Join(target, "a-large.bin"), string(make([]byte, addFixedChunkSize+1)))
	writeTestFile(t, filepath.Join(target, `z\bad`), "invalid later entry")
	root := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "linked")); err != nil {
		t.Skipf("directory symlinks are unavailable: %v", err)
	}
	blocks := &countingAddCAS{inner: casmemory.New()}
	remote := &countingAddGateway{}
	if _, err := buildAddStagingTree(t.Context(), blocks, remote, []string{root}, Options{}); err == nil {
		t.Fatal("buildAddStagingTree accepted invalid entry inside symlink directory")
	}
	if blocks.puts != 0 || remote.calls != 0 {
		t.Fatalf("symlink preflight allowed writes before validation failure: CAS=%d Gateway=%d", blocks.puts, remote.calls)
	}
}

func TestBuildAddStagingTreePreflightsSymlinkCycleBeforeWrite(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory symlink setup is not portable to Windows")
	}
	root := filepath.Join(t.TempDir(), "repo")
	writeTestFile(t, filepath.Join(root, "a-large.bin"), string(make([]byte, addFixedChunkSize+1)))
	if err := os.Symlink(root, filepath.Join(root, "loop")); err != nil {
		t.Skipf("directory symlinks are unavailable: %v", err)
	}
	blocks := &countingAddCAS{inner: casmemory.New()}
	remote := &countingAddGateway{}
	if _, err := buildAddStagingTree(t.Context(), blocks, remote, []string{root}, Options{}); err == nil {
		t.Fatal("buildAddStagingTree accepted a symlink cycle")
	}
	if blocks.puts != 0 || remote.calls != 0 {
		t.Fatalf("cycle preflight allowed writes: CAS=%d Gateway=%d", blocks.puts, remote.calls)
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

type countingAddCAS struct {
	inner *casmemory.Store
	puts  int
}

type countingAddGateway struct {
	calls int
}

func (g *countingAddGateway) Resolve(context.Context, protocol.ResolveRequest) (*protocol.ResolveResult, error) {
	g.calls++
	return nil, os.ErrInvalid
}

func (g *countingAddGateway) Read(context.Context, protocol.ReadRequest) (*protocol.ReadResult, error) {
	g.calls++
	return nil, os.ErrInvalid
}

func (g *countingAddGateway) CreateStagedRoot(context.Context, map[string]string) (cid.Cid, error) {
	g.calls++
	return cid.Undef, os.ErrInvalid
}

func (g *countingAddGateway) CreateFixedListBaseRoot(context.Context) (cid.Cid, error) {
	g.calls++
	return cid.Undef, os.ErrInvalid
}

func (g *countingAddGateway) ApplyFixedListPayloadMutation(context.Context, mutation.SemanticMutation) (cid.Cid, error) {
	g.calls++
	return cid.Undef, os.ErrInvalid
}

func (c *countingAddCAS) Put(ctx context.Context, data []byte) (cid.Cid, error) {
	c.puts++
	return c.inner.Put(ctx, data)
}

func (c *countingAddCAS) PutWithCodec(ctx context.Context, data []byte, codec uint64) (cid.Cid, error) {
	c.puts++
	return c.inner.PutWithCodec(ctx, data, codec)
}

func (c *countingAddCAS) Get(ctx context.Context, key cid.Cid) ([]byte, error) {
	return c.inner.Get(ctx, key)
}

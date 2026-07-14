package unixfs_test

import (
	"bytes"
	"context"
	"testing"

	casmemory "github.com/dewebprotocol/malt-client/internal/cas/memory"
	unixfs "github.com/dewebprotocol/malt-client/unixfs/sdk"
	"github.com/dewebprotocol/malt/auth/arcset"
	materialmemory "github.com/dewebprotocol/malt/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt/execution"
	runtimegraph "github.com/dewebprotocol/malt/graph/runtime"
	"github.com/dewebprotocol/malt/mutation"
	"github.com/dewebprotocol/malt/protocol"
	cid "github.com/ipfs/go-cid"
)

type realRemote struct {
	scope  string
	graph  *runtimegraph.RuntimeGraph
	exec   *execution.Executor
	blocks *casmemory.Store
	reads  []protocol.ReadRequest
}

func newRealRemote(t *testing.T) *realRemote {
	t.Helper()
	const scope = "verified-unixfs-test"
	graph, err := runtimegraph.NewGraph(scope, materialmemory.New(true), runtimegraph.WithNamespace(scope))
	if err != nil {
		t.Fatal(err)
	}
	executor, err := execution.NewExecutor(execution.Options{Scope: scope, Resolver: graph, Maps: graph.Semantic(), Lists: graph.ListSemantic(), Writer: graph.Writer()})
	if err != nil {
		t.Fatal(err)
	}
	return &realRemote{scope: scope, graph: graph, exec: executor, blocks: casmemory.New()}
}

func (r *realRemote) Resolve(ctx context.Context, request protocol.ResolveRequest) (*protocol.ResolveResult, error) {
	core, err := request.Core()
	if err != nil {
		return nil, err
	}
	result, err := r.exec.Resolve(ctx, core)
	if err != nil {
		return nil, err
	}
	wire, err := protocol.NewResolveResult(result)
	return &wire, err
}

func (r *realRemote) Read(ctx context.Context, request protocol.ReadRequest) (*protocol.ReadResult, error) {
	r.reads = append(r.reads, request)
	core, err := request.Core()
	if err != nil {
		return nil, err
	}
	result, err := r.exec.Read(ctx, core)
	if err != nil {
		return nil, err
	}
	wire, err := protocol.NewReadResult(result)
	return &wire, err
}

func (r *realRemote) Get(ctx context.Context, key cid.Cid) ([]byte, error) {
	return r.blocks.Get(ctx, key)
}

func (r *realRemote) Put(ctx context.Context, data []byte) (cid.Cid, error) {
	return r.blocks.Put(ctx, data)
}

func (r *realRemote) CreateStagedRoot(ctx context.Context, bindings map[string]string) (cid.Cid, error) {
	values := make(map[string]cid.Cid, len(bindings))
	for path, raw := range bindings {
		value, err := cid.Parse(raw)
		if err != nil {
			return cid.Undef, err
		}
		values[path] = value
	}
	set, err := arcset.NewArcSet(values)
	if err != nil {
		return cid.Undef, err
	}
	return r.graph.Writer().CreateStructure(ctx, r.scope, set)
}

func (r *realRemote) CreateFixedListBaseRoot(ctx context.Context) (cid.Cid, error) {
	empty, err := cid.Parse("bafkqaaa")
	if err != nil {
		return cid.Undef, err
	}
	return r.CreateStagedRoot(ctx, map[string]string{"@payload": empty.String()})
}

func (r *realRemote) ApplyFixedListPayloadMutation(ctx context.Context, value mutation.SemanticMutation) (cid.Cid, error) {
	receipt, err := r.exec.Apply(ctx, value)
	if err != nil {
		return cid.Undef, err
	}
	return receipt.NewRoot, nil
}

func materializeTree(t *testing.T, remote *realRemote, files map[string][]byte, chunkSize int) cid.Cid {
	t.Helper()
	root := unixfs.NewStagedDirectory()
	for path, data := range files {
		payload, _, err := unixfs.MaterializeStagedFilePayload(t.Context(), remote, remote, bytes.NewReader(data), int64(len(data)), chunkSize)
		if err != nil {
			t.Fatalf("materialize payload %s: %v", path, err)
		}
		if err := unixfs.SetStagedFile(root, path, payload); err != nil {
			t.Fatal(err)
		}
	}
	result, err := unixfs.MaterializeStagedDirectory(t.Context(), remote, remote, root)
	if err != nil {
		t.Fatal(err)
	}
	return result.Key
}

func TestVerifiedReaderBindsDirectoryRawAndLargeListPayloads(t *testing.T) {
	remote := newRealRemote(t)
	large := bytes.Repeat([]byte("0123456789abcdef"), 1024)
	root := materializeTree(t, remote, map[string][]byte{
		"docs/small.txt": []byte("small payload"),
		"docs/large.bin": large,
	}, 64)
	reader, err := unixfs.NewReader(unixfs.ReaderOptions{Remote: remote, Blocks: remote})
	if err != nil {
		t.Fatal(err)
	}

	dir, err := reader.Stat(t.Context(), root, "docs")
	if err != nil {
		t.Fatal(err)
	}
	if dir.Kind != unixfs.StagedKindDirectory || len(dir.Entries) != 2 || dir.PayloadBinding == nil {
		t.Fatalf("directory stat = %#v", dir)
	}

	small, err := reader.ReadFile(t.Context(), root, "docs/small.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(small.Body) != "small payload" || small.Resolution == nil || small.Read != nil {
		t.Fatalf("raw read = %#v body=%q", small, small.Body)
	}

	remote.reads = nil
	stat, err := reader.Stat(t.Context(), root, "docs/large.bin")
	if err != nil {
		t.Fatal(err)
	}
	if stat.Size != uint64(len(large)) || stat.ChunkSize != 64 || stat.StorageKind != "list" {
		t.Fatalf("large stat = %#v", stat)
	}
	if len(remote.reads) != 1 || remote.reads[0].Query.Start == nil || *remote.reads[0].Query.Start != 0 || remote.reads[0].Query.End == nil || *remote.reads[0].Query.End != 1 {
		t.Fatalf("large stat did not use a bounded metadata query: %#v", remote.reads)
	}
	if len(stat.MetadataRead.RangeSegments) != 1 {
		t.Fatalf("metadata query returned %d segments, want 1", len(stat.MetadataRead.RangeSegments))
	}

	remote.reads = nil
	ranged, err := reader.ReadFileRange(t.Context(), root, "docs/large.bin", 61, 131)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ranged.Body, large[61:192]) {
		t.Fatal("verified list range bytes differ")
	}
	if ranged.Resolution == nil || ranged.Read == nil || ranged.Read.ProofList.Root.String() != ranged.Target.String() {
		t.Fatalf("resolve-to-read continuity was not retained: %#v", ranged)
	}
	if len(remote.reads) != 2 || remote.reads[1].Root != ranged.Resolution.Target.String() {
		t.Fatalf("range read was not issued against resolved list root: %#v", remote.reads)
	}
	full, err := reader.ReadFile(t.Context(), root, "docs/large.bin")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(full.Body, large) {
		t.Fatal("full list-backed body differs")
	}
}

type tamperedRemote struct{ *realRemote }

func (r tamperedRemote) Resolve(ctx context.Context, request protocol.ResolveRequest) (*protocol.ResolveResult, error) {
	result, err := r.realRemote.Resolve(ctx, request)
	if err != nil {
		return nil, err
	}
	wrong, _ := cid.Parse("bafkqaaa")
	result.Target = wrong.String()
	return result, nil
}

type corruptBlocks struct{ inner *realRemote }

func (b corruptBlocks) Get(context.Context, cid.Cid) ([]byte, error) { return []byte("corrupt"), nil }

type splicedReadRemote struct {
	*realRemote
	other cid.Cid
}

func (r splicedReadRemote) Read(ctx context.Context, request protocol.ReadRequest) (*protocol.ReadResult, error) {
	request.Root = r.other.String()
	return r.realRemote.Read(ctx, request)
}

func TestVerifiedReaderRejectsTamperedResultAndPayloadBytes(t *testing.T) {
	remote := newRealRemote(t)
	root := materializeTree(t, remote, map[string][]byte{"file.txt": []byte("authentic")}, 64)
	reader, err := unixfs.NewReader(unixfs.ReaderOptions{Remote: tamperedRemote{remote}, Blocks: remote})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadFile(t.Context(), root, "file.txt"); err == nil {
		t.Fatal("reader accepted a target not bound by the resolve ProofList")
	}

	reader, err = unixfs.NewReader(unixfs.ReaderOptions{Remote: remote, Blocks: corruptBlocks{inner: remote}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadFile(t.Context(), root, "file.txt"); err == nil {
		t.Fatal("reader accepted payload bytes that do not match the authenticated CID")
	}
}

func TestVerifiedReaderRejectsResolveToReadCrossRootSplice(t *testing.T) {
	remote := newRealRemote(t)
	firstRoot := materializeTree(t, remote, map[string][]byte{"file.bin": bytes.Repeat([]byte("first"), 40)}, 32)
	secondRoot := materializeTree(t, remote, map[string][]byte{"file.bin": bytes.Repeat([]byte("other"), 40)}, 32)
	baseReader, err := unixfs.NewReader(unixfs.ReaderOptions{Remote: remote, Blocks: remote})
	if err != nil {
		t.Fatal(err)
	}
	other, err := baseReader.Resolve(t.Context(), secondRoot, "file.bin")
	if err != nil {
		t.Fatal(err)
	}
	reader, err := unixfs.NewReader(unixfs.ReaderOptions{Remote: splicedReadRemote{realRemote: remote, other: other.Target}, Blocks: remote})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadFileRange(t.Context(), firstRoot, "file.bin", 0, 10); err == nil {
		t.Fatal("reader accepted a valid list proof from an unrelated resolved root")
	}
}

func TestVerifiedWriterRemoveProducesUncheckedCandidateWithoutChangingBase(t *testing.T) {
	remote := newRealRemote(t)
	root := materializeTree(t, remote, map[string][]byte{
		"keep.txt":        []byte("keep"),
		"docs/remove.txt": []byte("remove"),
	}, 64)
	writer, err := unixfs.NewWriter(unixfs.WriterOptions{
		Remote: remote,
		Blocks: remote,
		Roots:  remote,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := writer.RemovePath(t.Context(), root, "docs/remove.txt")
	if err != nil {
		t.Fatal(err)
	}
	if result.Accepted || !result.BaseRoot.Equals(root) || result.CandidateRoot.Equals(root) {
		t.Fatalf("remove result = %#v", result)
	}
	if _, err := writer.Stat(t.Context(), root, "docs/remove.txt"); err != nil {
		t.Fatalf("base root was mutated: %v", err)
	}
	if _, err := writer.Stat(t.Context(), result.CandidateRoot, "docs/remove.txt"); err == nil {
		t.Fatal("removed path still resolves from candidate root")
	}
	kept, err := writer.ReadFile(t.Context(), result.CandidateRoot, "keep.txt")
	if err != nil || string(kept.Body) != "keep" {
		t.Fatalf("candidate lost retained file: body=%q err=%v", keptBody(kept), err)
	}
}

func keptBody(result *unixfs.ReadResult) []byte {
	if result == nil {
		return nil
	}
	return result.Body
}

var _ unixfs.Remote = (*realRemote)(nil)
var _ unixfs.BlockStore = (*realRemote)(nil)
var _ unixfs.StagedRootCreator = (*realRemote)(nil)

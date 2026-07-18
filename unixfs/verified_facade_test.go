package unixfs_test

import (
	"bytes"
	"context"
	"testing"

	casmemory "github.com/dewebprotocol/malt-client/internal/cas/memory"
	unixfs "github.com/dewebprotocol/malt-client/unixfs"
	"github.com/dewebprotocol/malt/auth/arcset"
	materialmemory "github.com/dewebprotocol/malt/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt/execution"
	runtimegraph "github.com/dewebprotocol/malt/graph/runtime"
	"github.com/dewebprotocol/malt/mutation"
	"github.com/dewebprotocol/malt/protocol"
	"github.com/dewebprotocol/malt/wire/maltcid"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

type realRemote struct {
	scope  string
	graph  *runtimegraph.RuntimeGraph
	exec   *execution.Executor
	blocks *casmemory.Store
	reads  []protocol.ReadRequest
}

type countingWriterRemote struct {
	inner         *realRemote
	remoteCalls   int
	blockCalls    int
	rootCalls     int
	mutationCalls int
}

func (r *countingWriterRemote) Resolve(ctx context.Context, request protocol.ResolveRequest) (*protocol.ResolveResult, error) {
	r.remoteCalls++
	return r.inner.Resolve(ctx, request)
}

func (r *countingWriterRemote) Read(ctx context.Context, request protocol.ReadRequest) (*protocol.ReadResult, error) {
	r.remoteCalls++
	return r.inner.Read(ctx, request)
}

func (r *countingWriterRemote) Get(ctx context.Context, key cid.Cid) ([]byte, error) {
	r.blockCalls++
	return r.inner.Get(ctx, key)
}

func (r *countingWriterRemote) Put(ctx context.Context, data []byte) (cid.Cid, error) {
	r.blockCalls++
	return r.inner.Put(ctx, data)
}

func (r *countingWriterRemote) CreateStagedRoot(ctx context.Context, bindings map[string]string) (cid.Cid, error) {
	r.rootCalls++
	return r.inner.CreateStagedRoot(ctx, bindings)
}

func (r *countingWriterRemote) CreateFixedListBaseRoot(ctx context.Context) (cid.Cid, error) {
	r.mutationCalls++
	return r.inner.CreateFixedListBaseRoot(ctx)
}

func (r *countingWriterRemote) ApplyFixedListPayloadMutation(ctx context.Context, value mutation.SemanticMutation) (cid.Cid, error) {
	r.mutationCalls++
	return r.inner.ApplyFixedListPayloadMutation(ctx, value)
}

func (r *countingWriterRemote) reset() {
	r.remoteCalls = 0
	r.blockCalls = 0
	r.rootCalls = 0
	r.mutationCalls = 0
}

func (r *countingWriterRemote) calls() int {
	return r.remoteCalls + r.blockCalls + r.rootCalls + r.mutationCalls
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
	return r.graph.StructureCreator().CreateStructure(ctx, r.scope, set)
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

func TestVerifiedReaderFetchesEachAuthenticatedRangeBlockOnce(t *testing.T) {
	remote := newRealRemote(t)
	chunk := []byte("0123456789abcdef")
	body := bytes.Repeat(chunk, 8)
	root := materializeTree(t, remote, map[string][]byte{"repeated.bin": body}, len(chunk))
	blocks := &countingBlocks{inner: remote, gets: make(map[string]int)}
	reader, err := unixfs.NewReader(unixfs.ReaderOptions{Remote: remote, Blocks: blocks})
	if err != nil {
		t.Fatal(err)
	}

	result, err := reader.ReadFileRange(t.Context(), root, "repeated.bin", 0, uint64(len(body)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result.Body, body) {
		t.Fatal("verified repeated-chunk body differs")
	}
	if result.Read == nil || len(result.Read.RangeSegments) < 2 {
		t.Fatalf("range fixture did not produce multiple segments: %#v", result.Read)
	}
	unique := make(map[string]struct{})
	for _, raw := range result.Read.RangeSegments {
		unique[raw] = struct{}{}
	}
	if len(unique) >= len(result.Read.RangeSegments) {
		t.Fatalf("range fixture did not reuse a chunk CID: %v", result.Read.RangeSegments)
	}
	for raw := range unique {
		key, err := cid.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := blocks.gets[key.KeyString()]; got != 1 {
			t.Fatalf("authenticated range block %s fetched %d times, want 1", key, got)
		}
	}
}

func TestMaterializeStagedDirectoryRejectsNonCanonicalChild(t *testing.T) {
	payload, err := cid.Parse("bafkqaaa")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"@payload", " @payload", " file", "file ", "   "} {
		t.Run(name, func(t *testing.T) {
			remote := newRealRemote(t)
			root := unixfs.NewStagedDirectory()
			root.Children[name] = &unixfs.StagedNode{
				Kind: unixfs.StagedKindFile,
				Key:  payload,
			}
			if _, err := unixfs.MaterializeStagedDirectory(t.Context(), remote, remote, root); err == nil {
				t.Fatalf("MaterializeStagedDirectory accepted non-canonical child %q", name)
			}
		})
	}
}

func TestVerifiedReaderRejectsAuthenticatedUnknownTargetCodec(t *testing.T) {
	remote := newRealRemote(t)
	digest, err := mh.Sum([]byte("not a commitment"), mh.SHA2_256, -1)
	if err != nil {
		t.Fatal(err)
	}
	// The codec claims to be a map/KZG root, but the non-identity multihash
	// makes it an invalid typed root. A valid parent proof may authenticate this
	// opaque value, but the UnixFS client must not reinterpret it as raw bytes.
	unknown := cid.NewCidV1(maltcid.CodecMaltMapKZG, digest)
	root, err := remote.CreateStagedRoot(t.Context(), map[string]string{"file.txt": unknown.String()})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := unixfs.NewReader(unixfs.ReaderOptions{Remote: remote, Blocks: remote})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Stat(t.Context(), root, "file.txt"); err == nil {
		t.Fatal("stat accepted an authenticated target with an invalid typed-root encoding")
	}
	if _, err := reader.ReadFile(t.Context(), root, "file.txt"); err == nil {
		t.Fatal("read accepted an authenticated target with an invalid typed-root encoding")
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

type countingBlocks struct {
	inner *realRemote
	gets  map[string]int
}

func (b *countingBlocks) Get(ctx context.Context, key cid.Cid) ([]byte, error) {
	b.gets[key.KeyString()]++
	return b.inner.Get(ctx, key)
}

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

func TestVerifiedWriterAddsDirectoryRawAndStreamedListWithoutTrustingCandidate(t *testing.T) {
	remote := newRealRemote(t)
	writer, err := unixfs.NewWriter(unixfs.WriterOptions{
		Remote:    remote,
		Blocks:    remote,
		Roots:     remote,
		ChunkSize: 32,
	})
	if err != nil {
		t.Fatal(err)
	}

	empty, err := writer.EmptyDirectory(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if empty.Accepted || !empty.CandidateRoot.Defined() {
		t.Fatalf("empty result = %#v", empty)
	}
	directory, err := writer.AddDirectory(t.Context(), empty.CandidateRoot, "docs/generated")
	if err != nil {
		t.Fatal(err)
	}
	if directory.Accepted || !directory.BaseRoot.Equals(empty.CandidateRoot) {
		t.Fatalf("directory result = %#v", directory)
	}
	raw, err := writer.AddFile(t.Context(), directory.CandidateRoot, "docs/readme.txt", []byte("verified raw"))
	if err != nil {
		t.Fatal(err)
	}
	largeBody := bytes.Repeat([]byte("streamed-list-"), 20)
	large, err := writer.AddFileSized(t.Context(), raw.CandidateRoot, "docs/large.bin", bytes.NewReader(largeBody), int64(len(largeBody)))
	if err != nil {
		t.Fatal(err)
	}
	if large.Accepted || large.Size != uint64(len(largeBody)) || large.CandidateRoot.Equals(raw.CandidateRoot) {
		t.Fatalf("large result = %#v", large)
	}
	read, err := writer.ReadFile(t.Context(), large.CandidateRoot, "docs/large.bin")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(read.Body, largeBody) || read.ChunkSize != 32 {
		t.Fatalf("streamed body mismatch: size=%d chunk=%d", len(read.Body), read.ChunkSize)
	}
	if _, err := writer.Stat(t.Context(), large.CandidateRoot, "docs/generated"); err != nil {
		t.Fatalf("created directory missing from candidate: %v", err)
	}
	if _, err := writer.Stat(t.Context(), raw.CandidateRoot, "docs/large.bin"); err == nil {
		t.Fatal("base root was changed when streamed candidate was created")
	}
}

func TestVerifiedWriterRejectsMismatchedStreamSizeAndDirectoryReplacement(t *testing.T) {
	remote := newRealRemote(t)
	root := materializeTree(t, remote, map[string][]byte{"file": []byte("payload")}, 32)
	writer, err := unixfs.NewWriter(unixfs.WriterOptions{Remote: remote, Blocks: remote, Roots: remote, ChunkSize: 32})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.AddFileSized(t.Context(), root, "other", bytes.NewReader([]byte("short")), 12); err == nil {
		t.Fatal("writer accepted a short stream")
	}
	if _, err := writer.AddFileSized(t.Context(), root, "other", bytes.NewReader([]byte("too long")), 3); err == nil {
		t.Fatal("writer accepted an overlong stream")
	}
	if _, err := writer.AddDirectory(t.Context(), root, "file/child"); err == nil {
		t.Fatal("writer replaced an existing file with a directory")
	}
}

func TestVerifiedWriterRejectsNonCanonicalPathsBeforeAnyIO(t *testing.T) {
	remote := newRealRemote(t)
	root := materializeTree(t, remote, map[string][]byte{"file": []byte("payload")}, 32)
	counting := &countingWriterRemote{inner: remote}
	writer, err := unixfs.NewWriter(unixfs.WriterOptions{Remote: counting, Blocks: counting, Roots: counting, Lists: counting, ChunkSize: 32})
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		run  func() error
	}{
		{name: "file collision after trimming", run: func() error {
			_, err := writer.AddFile(t.Context(), root, " file ", []byte("replacement"))
			return err
		}},
		{name: "directory trailing space", run: func() error {
			_, err := writer.AddDirectory(t.Context(), root, "dir ")
			return err
		}},
		{name: "streamed file leading space", run: func() error {
			_, err := writer.AddFileStream(t.Context(), root, " file", bytes.NewReader([]byte("replacement")))
			return err
		}},
		{name: "remove trailing space", run: func() error {
			_, err := writer.RemovePath(t.Context(), root, "file ")
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			counting.reset()
			if err := test.run(); err == nil {
				t.Fatal("writer accepted a non-canonical path")
			}
			if got := counting.calls(); got != 0 {
				t.Fatalf("non-canonical path performed I/O: remote=%d block=%d root=%d mutation=%d", counting.remoteCalls, counting.blockCalls, counting.rootCalls, counting.mutationCalls)
			}
		})
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
var _ unixfs.FixedListPayloadWriter = (*realRemote)(nil)
var _ unixfs.Remote = (*countingWriterRemote)(nil)
var _ unixfs.BlockStore = (*countingWriterRemote)(nil)
var _ unixfs.StagedRootCreator = (*countingWriterRemote)(nil)
var _ unixfs.FixedListPayloadWriter = (*countingWriterRemote)(nil)

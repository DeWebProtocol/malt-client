package merkledag_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	clientcas "github.com/dewebprotocol/malt-client/internal/cas"
	casmemory "github.com/dewebprotocol/malt-client/internal/cas/memory"
	"github.com/dewebprotocol/malt-client/merkledag"
	merkledagimport "github.com/dewebprotocol/malt-client/merkledag/importer"
	client "github.com/dewebprotocol/malt-client/transport"
	unixfsio "github.com/ipfs/boxo/ipld/unixfs/io"
	cid "github.com/ipfs/go-cid"
	car "github.com/ipld/go-car/v2"
	carstorage "github.com/ipld/go-car/v2/storage"
	mh "github.com/multiformats/go-multihash"
)

type rq1MerkleDAGFixture struct {
	store    *casmemory.Store
	root     cid.Cid
	segments []string
	payload  []byte
	evidence []merkledag.MerkleDAGBlock
}

func newRQ1MerkleDAGFixture(t *testing.T) rq1MerkleDAGFixture {
	t.Helper()
	store := casmemory.New()
	payload := []byte("locally verified CAR and Direct CAS payload")
	imported, err := merkledagimport.ImportFiles(t.Context(), store, []merkledagimport.File{
		{Path: "docs/file.txt", Data: payload, Mode: 0o644},
	}, merkledagimport.Options{
		Model: merkledagimport.ModelUnixFS, FileLayout: merkledagimport.FileLayoutBalanced,
		DirLayout: merkledagimport.DirLayoutBasic, ChunkSize: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	root, err := cid.Parse(imported.Root)
	if err != nil {
		t.Fatal(err)
	}
	segments := []string{"docs", "file.txt"}
	recording := newRecordingCAS(store)
	node, dag := replayTestPath(t, recording, root, segments)
	reader, err := unixfsio.NewDagReader(t.Context(), node, dag)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(reader); err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	return rq1MerkleDAGFixture{
		store: store, root: root, segments: segments, payload: payload, evidence: recording.evidence(),
	}
}

func writeCARv1(t *testing.T, roots []cid.Cid, evidence []merkledag.MerkleDAGBlock, opts ...car.Option) []byte {
	t.Helper()
	var encoded bytes.Buffer
	options := append([]car.Option{car.WriteAsCarV1(true)}, opts...)
	writable, err := carstorage.NewWritable(&encoded, roots, options...)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range evidence {
		key, err := cid.Parse(item.CID)
		if err != nil {
			t.Fatal(err)
		}
		if err := writable.Put(t.Context(), key.KeyString(), item.Data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writable.Finalize(); err != nil {
		t.Fatal(err)
	}
	return encoded.Bytes()
}

func TestMerkleDAGCARReadLocallyVerifiesPathAndPayload(t *testing.T) {
	fixture := newRQ1MerkleDAGFixture(t)
	request := merkledag.MerkleDAGReadRequest{
		Profile: merkledag.MerkleDAGReadProfile, Root: fixture.root.String(), Segments: fixture.segments,
	}
	encoded := writeCARv1(t, []cid.Cid{fixture.root}, fixture.evidence)
	result, err := merkledag.VerifyMerkleDAGCARRead(t.Context(), request, encoded)
	if err != nil {
		t.Fatalf("verify selective CAR: %v", err)
	}
	if !bytes.Equal(result.Data, fixture.payload) {
		t.Fatalf("payload = %q, want %q", result.Data, fixture.payload)
	}
	if !result.Root.Equals(fixture.root) || !result.Target.Defined() || result.Kind != "file" {
		t.Fatalf("locally derived identity = root %s target %s kind %q", result.Root, result.Target, result.Kind)
	}
	if result.Metrics.CARBytes != uint64(len(encoded)) || result.Metrics.CARBlocks != uint64(len(fixture.evidence)) {
		t.Fatalf("CAR metrics = %+v", result.Metrics)
	}
	if result.Metrics.CriticalSequentialRounds != 1 || result.Metrics.BlocksVerified != uint64(len(fixture.evidence)) {
		t.Fatalf("verification metrics = %+v", result.Metrics)
	}
	if result.Metrics.CIDVerifyDurationNS == 0 || result.Metrics.PayloadBindingDurationNS == 0 ||
		result.Metrics.PayloadBindingDurationNS > result.Metrics.CIDVerifyDurationNS {
		t.Fatalf("CAR verification phase accounting = %+v", result.Metrics)
	}
}

func TestMerkleDAGCARClientUsesFixedRouteAndCountsOneNetworkRound(t *testing.T) {
	fixture := newRQ1MerkleDAGFixture(t)
	encoded := writeCARv1(t, []cid.Cid{fixture.root}, fixture.evidence)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/compat/merkledag/car/read" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("request content type = %q", got)
		}
		w.Header().Set("Content-Type", merkledag.MerkleDAGCARReadMediaType)
		_, _ = w.Write(encoded)
	}))
	defer server.Close()

	remote, err := client.NewWithBaseURL(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	compatibility, err := merkledag.New(remote)
	if err != nil {
		t.Fatal(err)
	}
	result, err := compatibility.ReadMerkleDAGCARVerified(t.Context(), fixture.root, fixture.segments)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result.Data, fixture.payload) || result.Metrics.NetworkRequests != 1 {
		t.Fatalf("CAR result = data %q metrics %+v", result.Data, result.Metrics)
	}
}

func TestMerkleDAGCARReadRejectsHostileBundles(t *testing.T) {
	fixture := newRQ1MerkleDAGFixture(t)
	request := merkledag.MerkleDAGReadRequest{
		Profile: merkledag.MerkleDAGReadProfile, Root: fixture.root.String(), Segments: fixture.segments,
	}
	otherRoot := mustBlockCID(t, []byte("other root"))
	extra := []byte("unrequested block")
	extraCID := mustBlockCID(t, extra)
	unsupportedData := []byte("unsupported codec")
	unsupportedHash, err := mh.Sum(unsupportedData, mh.SHA2_256, -1)
	if err != nil {
		t.Fatal(err)
	}
	unsupportedRoot := cid.NewCidV1(0x9999, unsupportedHash)

	t.Run("wrong root", func(t *testing.T) {
		encoded := writeCARv1(t, []cid.Cid{otherRoot}, fixture.evidence)
		assertCARReadRejected(t, request, encoded, "caller-selected root")
	})
	t.Run("multiple roots", func(t *testing.T) {
		encoded := writeCARv1(t, []cid.Cid{fixture.root, otherRoot}, fixture.evidence)
		assertCARReadRejected(t, request, encoded, "exactly")
	})
	t.Run("missing required block", func(t *testing.T) {
		encoded := writeCARv1(t, []cid.Cid{fixture.root}, fixture.evidence[:len(fixture.evidence)-1])
		assertCARReadRejected(t, request, encoded, "missing block")
	})
	t.Run("duplicate block", func(t *testing.T) {
		duplicated := append([]merkledag.MerkleDAGBlock(nil), fixture.evidence...)
		duplicated = append(duplicated, fixture.evidence[len(fixture.evidence)-1])
		encoded := writeCARv1(t, []cid.Cid{fixture.root}, duplicated, car.AllowDuplicatePuts(true))
		assertCARReadRejected(t, request, encoded, "duplicate")
	})
	t.Run("unused block", func(t *testing.T) {
		evidence := append([]merkledag.MerkleDAGBlock(nil), fixture.evidence...)
		evidence = append(evidence, merkledag.MerkleDAGBlock{CID: extraCID.String(), Codec: extraCID.Type(), Data: extra})
		encoded := writeCARv1(t, []cid.Cid{fixture.root}, evidence)
		assertCARReadRejected(t, request, encoded, "unused block")
	})
	t.Run("CID content mismatch", func(t *testing.T) {
		evidence := append([]merkledag.MerkleDAGBlock(nil), fixture.evidence...)
		evidence[0].Data = append([]byte(nil), evidence[0].Data...)
		evidence[0].Data[0] ^= 0xff
		encoded := writeCARv1(t, []cid.Cid{fixture.root}, evidence)
		assertCARReadRejected(t, request, encoded, "content integrity")
	})
	t.Run("unsupported codec", func(t *testing.T) {
		evidence := []merkledag.MerkleDAGBlock{{CID: unsupportedRoot.String(), Codec: unsupportedRoot.Type(), Data: unsupportedData}}
		encoded := writeCARv1(t, []cid.Cid{unsupportedRoot}, evidence)
		unsupportedRequest := request
		unsupportedRequest.Root = unsupportedRoot.String()
		unsupportedRequest.Segments = []string{}
		assertCARReadRejected(t, unsupportedRequest, encoded, "unsupported")
	})
	t.Run("malformed truncated stream", func(t *testing.T) {
		encoded := writeCARv1(t, []cid.Cid{fixture.root}, fixture.evidence)
		assertCARReadRejected(t, request, encoded[:len(encoded)-1], "decode")
	})
	t.Run("wrong path", func(t *testing.T) {
		encoded := writeCARv1(t, []cid.Cid{fixture.root}, fixture.evidence)
		invalid := request
		invalid.Segments = []string{"docs", "missing.txt"}
		assertCARReadRejected(t, invalid, encoded, "path")
	})
	t.Run("range contract", func(t *testing.T) {
		encoded := writeCARv1(t, []cid.Cid{fixture.root}, fixture.evidence)
		invalid := request
		offset := uint64(1)
		invalid.Offset = &offset
		assertCARReadRejected(t, invalid, encoded, "complete payload")
	})
}

func assertCARReadRejected(t *testing.T, request merkledag.MerkleDAGReadRequest, encoded []byte, contains string) {
	t.Helper()
	_, err := merkledag.VerifyMerkleDAGCARRead(t.Context(), request, encoded)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(contains)) {
		t.Fatalf("CAR verifier error = %v, want substring %q", err, contains)
	}
}

type hostileBlockGetter struct {
	mu       sync.Mutex
	get      func(context.Context, cid.Cid) ([]byte, error)
	requests []cid.Cid
}

func (g *hostileBlockGetter) Get(ctx context.Context, key cid.Cid) ([]byte, error) {
	g.mu.Lock()
	g.requests = append(g.requests, key)
	g.mu.Unlock()
	return g.get(ctx, key)
}

func TestDirectCASReadLocallyVerifiesOnDemandBlocksAndRange(t *testing.T) {
	fixture := newRQ1MerkleDAGFixture(t)
	getter := &hostileBlockGetter{get: fixture.store.Get}
	offset, length := uint64(4), uint64(19)
	result, err := merkledag.ReadMerkleDAGDirectCASVerified(
		t.Context(), getter, fixture.root, fixture.segments, &offset, &length,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result.Data, fixture.payload[offset:offset+length]) {
		t.Fatalf("range = %q, want %q", result.Data, fixture.payload[offset:offset+length])
	}
	if result.Metrics.CASGetRequests == 0 || result.Metrics.CASGetRequests != result.Metrics.NetworkRequests {
		t.Fatalf("Direct CAS metrics = %+v", result.Metrics)
	}
	if result.Metrics.CriticalSequentialRounds != result.Metrics.CASGetRequests || result.Metrics.CASBytes == 0 {
		t.Fatalf("Direct CAS dependency metrics = %+v", result.Metrics)
	}
	if result.Metrics.BlocksVerified != result.Metrics.CASGetRequests {
		t.Fatalf("Direct CAS must hash every fetched CID exactly once: %+v", result.Metrics)
	}
	if result.Metrics.CIDVerifyDurationNS == 0 || result.Metrics.PayloadBindingDurationNS == 0 ||
		result.Metrics.PayloadBindingDurationNS > result.Metrics.CIDVerifyDurationNS {
		t.Fatalf("Direct CAS verification phase accounting = %+v", result.Metrics)
	}
	getter.mu.Lock()
	defer getter.mu.Unlock()
	seen := make(map[string]bool)
	for _, key := range getter.requests {
		if seen[key.KeyString()] {
			t.Fatalf("Direct CAS fetched CID %s more than once", key)
		}
		seen[key.KeyString()] = true
	}
}

func TestDirectCASReadRejectsHostileSourcesAndPaths(t *testing.T) {
	fixture := newRQ1MerkleDAGFixture(t)
	t.Run("wrong CID bytes", func(t *testing.T) {
		getter := &hostileBlockGetter{get: func(ctx context.Context, key cid.Cid) ([]byte, error) {
			data, err := fixture.store.Get(ctx, key)
			if err != nil {
				return nil, err
			}
			if key.Equals(fixture.root) {
				data[0] ^= 0xff
			}
			return data, nil
		}}
		_, err := merkledag.ReadMerkleDAGDirectCASVerified(t.Context(), getter, fixture.root, fixture.segments, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "does not match CID") {
			t.Fatalf("wrong-CID source error = %v", err)
		}
	})
	t.Run("missing block", func(t *testing.T) {
		getter := &hostileBlockGetter{get: func(context.Context, cid.Cid) ([]byte, error) {
			return nil, errors.New("not found")
		}}
		_, err := merkledag.ReadMerkleDAGDirectCASVerified(t.Context(), getter, fixture.root, fixture.segments, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("missing source error = %v", err)
		}
	})
	t.Run("wrong path", func(t *testing.T) {
		getter := &hostileBlockGetter{get: fixture.store.Get}
		_, err := merkledag.ReadMerkleDAGDirectCASVerified(t.Context(), getter, fixture.root, []string{"missing"}, nil, nil)
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "path") {
			t.Fatalf("wrong path error = %v", err)
		}
	})
	t.Run("malformed typed path", func(t *testing.T) {
		getter := &hostileBlockGetter{get: fixture.store.Get}
		_, err := merkledag.ReadMerkleDAGDirectCASVerified(t.Context(), getter, fixture.root, nil, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "segments field is required") {
			t.Fatalf("nil path error = %v", err)
		}
	})
	t.Run("unsupported root codec", func(t *testing.T) {
		data := []byte("unsupported")
		hash, err := mh.Sum(data, mh.SHA2_256, -1)
		if err != nil {
			t.Fatal(err)
		}
		root := cid.NewCidV1(0x9999, hash)
		getter := &hostileBlockGetter{get: func(context.Context, cid.Cid) ([]byte, error) { return data, nil }}
		_, err = merkledag.ReadMerkleDAGDirectCASVerified(t.Context(), getter, root, []string{}, nil, nil)
		if err == nil || !strings.Contains(err.Error(), "unsupported") {
			t.Fatalf("unsupported codec error = %v", err)
		}
		getter.mu.Lock()
		defer getter.mu.Unlock()
		if len(getter.requests) != 0 {
			t.Fatalf("unsupported root triggered %d CAS GETs", len(getter.requests))
		}
	})
}

func TestMerkleDAGCARTransportRejectsWrongMediaType(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("not a CAR"))
	}))
	defer server.Close()
	remote, err := client.NewWithBaseURL(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = remote.PostMerkleDAGCARRead(t.Context(), []byte(`{}`))
	if err == nil || !strings.Contains(err.Error(), "content type") {
		t.Fatalf("wrong media type error = %v", err)
	}
}

var _ merkledag.BlockGetter = (*hostileBlockGetter)(nil)
var _ clientcas.Reader = (*casmemory.Store)(nil)

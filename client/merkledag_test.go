package client_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	client "github.com/dewebprotocol/malt-client/client"
	casmemory "github.com/dewebprotocol/malt-client/internal/cas/memory"
	"github.com/dewebprotocol/malt-client/internal/merkledagimport"
	unixfsio "github.com/ipfs/boxo/ipld/unixfs/io"
	cid "github.com/ipfs/go-cid"
	ipld "github.com/ipfs/go-ipld-format"
	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	"github.com/ipld/go-ipld-prime/codec/dagjson"
	cidlink "github.com/ipld/go-ipld-prime/linking/cid"
	"github.com/ipld/go-ipld-prime/node/basicnode"
	mh "github.com/multiformats/go-multihash"
)

type recordingCAS struct {
	mu    sync.Mutex
	inner *casmemory.Store
	order []cid.Cid
	data  map[string][]byte
}

func newRecordingCAS(inner *casmemory.Store) *recordingCAS {
	return &recordingCAS{inner: inner, data: make(map[string][]byte)}
}

func (s *recordingCAS) Get(ctx context.Context, key cid.Cid) ([]byte, error) {
	data, err := s.inner.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[key.KeyString()]; !ok {
		s.order = append(s.order, key)
		s.data[key.KeyString()] = append([]byte(nil), data...)
	}
	return data, nil
}

func (s *recordingCAS) PutWithCodec(ctx context.Context, data []byte, codec uint64) (cid.Cid, error) {
	return s.inner.PutWithCodec(ctx, data, codec)
}

func (s *recordingCAS) evidence() []client.MerkleDAGBlock {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]client.MerkleDAGBlock, 0, len(s.order))
	for _, key := range s.order {
		out = append(out, client.MerkleDAGBlock{CID: key.String(), Codec: key.Type(), Data: append([]byte(nil), s.data[key.KeyString()]...)})
	}
	return out
}

func replayTestPath(t *testing.T, store *recordingCAS, root cid.Cid, segments []string) (ipld.Node, ipld.DAGService) {
	t.Helper()
	dag := merkledagimport.NewDAGService(store)
	node, err := dag.Get(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	remaining := append([]string(nil), segments...)
	for len(remaining) > 0 {
		link, rest, err := unixfsio.ResolveUnixfsOnce(t.Context(), dag, node, remaining)
		if err != nil {
			t.Fatal(err)
		}
		node, err = dag.Get(t.Context(), link.Cid)
		if err != nil {
			t.Fatal(err)
		}
		remaining = rest
	}
	return node, dag
}

func TestMerkleDAGCompatibilityVerifierReplaysPathAndFileRange(t *testing.T) {
	store := casmemory.New()
	payload := []byte("authenticated merkle dag payload")
	imported, err := merkledagimport.ImportFiles(t.Context(), store, []merkledagimport.File{{Path: "docs/file.txt", Data: payload, Mode: 0o644}}, merkledagimport.Options{
		Model: merkledagimport.ModelUnixFS, FileLayout: merkledagimport.FileLayoutBalanced, DirLayout: merkledagimport.DirLayoutBasic, ChunkSize: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	root, err := cid.Parse(imported.Root)
	if err != nil {
		t.Fatal(err)
	}
	segments := []string{"docs", "file.txt"}

	resolveStore := newRecordingCAS(store)
	node, _ := replayTestPath(t, resolveStore, root, segments)
	resolveRequest := client.MerkleDAGResolveRequest{Profile: client.MerkleDAGResolveProfile, Root: root.String(), Segments: segments}
	resolveResponse := client.MerkleDAGResolveResponse{Profile: client.MerkleDAGResolveProfile, Target: node.Cid().String(), Kind: "file", Blocks: resolveStore.evidence()}
	if err := client.VerifyMerkleDAGResolve(t.Context(), resolveRequest, resolveResponse); err != nil {
		t.Fatalf("verify resolve: %v", err)
	}

	readStore := newRecordingCAS(store)
	node, dag := replayTestPath(t, readStore, root, segments)
	reader, err := unixfsio.NewDagReader(t.Context(), node, dag)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	offset, length := uint64(3), uint64(11)
	if _, err := reader.Seek(int64(offset), io.SeekStart); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(reader, body); err != nil {
		t.Fatal(err)
	}
	readRequest := client.MerkleDAGReadRequest{Profile: client.MerkleDAGReadProfile, Root: root.String(), Segments: segments, Offset: &offset, Length: &length}
	readResponse := client.MerkleDAGReadResponse{
		Profile: client.MerkleDAGReadProfile, Target: node.Cid().String(), Kind: "file", TotalSize: reader.Size(), Offset: offset, Length: length, Data: body, Blocks: readStore.evidence(),
	}
	if err := client.VerifyMerkleDAGRead(t.Context(), readRequest, readResponse); err != nil {
		t.Fatalf("verify read: %v", err)
	}

	tampered := readResponse
	tampered.Data = append([]byte(nil), readResponse.Data...)
	tampered.Data[0] ^= 0xff
	if err := client.VerifyMerkleDAGRead(t.Context(), readRequest, tampered); err == nil {
		t.Fatal("read verifier accepted tampered response bytes")
	}

	tampered = readResponse
	tampered.Blocks = append([]client.MerkleDAGBlock(nil), readResponse.Blocks...)
	tampered.Blocks[0].Data = append([]byte(nil), tampered.Blocks[0].Data...)
	tampered.Blocks[0].Data[0] ^= 0xff
	if err := client.VerifyMerkleDAGRead(t.Context(), readRequest, tampered); err == nil {
		t.Fatal("read verifier accepted evidence bytes that do not match their CID")
	}
}

func TestMerkleDAGVerifiedClientPreservesEmptyRootIdentitySegments(t *testing.T) {
	payload := []byte("root file")
	root := mustBlockCID(t, payload)
	evidence := []client.MerkleDAGBlock{{CID: root.String(), Codec: root.Type(), Data: payload}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/compat/merkledag/resolve":
			var request client.MerkleDAGResolveRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.Segments == nil || len(request.Segments) != 0 {
				t.Fatalf("root resolve segments = %#v, want non-nil empty", request.Segments)
			}
			_ = json.NewEncoder(w).Encode(client.MerkleDAGResolveResponse{Profile: client.MerkleDAGResolveProfile, Target: root.String(), Kind: "file", Blocks: evidence})
		case "/v1/compat/merkledag/read":
			var request client.MerkleDAGReadRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			if request.Segments == nil || len(request.Segments) != 0 {
				t.Fatalf("root read segments = %#v, want non-nil empty", request.Segments)
			}
			_ = json.NewEncoder(w).Encode(client.MerkleDAGReadResponse{Profile: client.MerkleDAGReadProfile, Target: root.String(), Kind: "file", TotalSize: uint64(len(payload)), Length: uint64(len(payload)), Data: payload, Blocks: evidence})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	transport, err := client.NewWithBaseURL(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.ResolveMerkleDAGVerified(t.Context(), root, []string{}); err != nil {
		t.Fatalf("verified root resolve: %v", err)
	}
	result, err := transport.ReadMerkleDAGVerified(t.Context(), root, []string{}, nil, nil)
	if err != nil {
		t.Fatalf("verified root read: %v", err)
	}
	if string(result.Data) != string(payload) {
		t.Fatalf("root read data = %q", result.Data)
	}
}

func TestMerkleDAGResolveVerifierReplaysDAGCBORLinksAndRejectsUnusedEvidence(t *testing.T) {
	payload := []byte("linked raw payload")
	target := mustBlockCID(t, payload)
	builder := basicnode.Prototype.Map.NewBuilder()
	assembler, err := builder.BeginMap(1)
	if err != nil {
		t.Fatal(err)
	}
	if err := assembler.AssembleKey().AssignString("file"); err != nil {
		t.Fatal(err)
	}
	if err := assembler.AssembleValue().AssignLink(cidlink.Link{Cid: target}); err != nil {
		t.Fatal(err)
	}
	if err := assembler.Finish(); err != nil {
		t.Fatal(err)
	}
	var encoded bytes.Buffer
	if err := dagcbor.Encode(builder.Build(), &encoded); err != nil {
		t.Fatal(err)
	}
	hash, err := mh.Sum(encoded.Bytes(), mh.SHA2_256, -1)
	if err != nil {
		t.Fatal(err)
	}
	root := cid.NewCidV1(cid.DagCBOR, hash)
	request := client.MerkleDAGResolveRequest{Profile: client.MerkleDAGResolveProfile, Root: root.String(), Segments: []string{"file"}}
	response := client.MerkleDAGResolveResponse{
		Profile: client.MerkleDAGResolveProfile,
		Target:  target.String(),
		Kind:    "file",
		Blocks: []client.MerkleDAGBlock{
			{CID: root.String(), Codec: cid.DagCBOR, Data: encoded.Bytes()},
			{CID: target.String(), Codec: cid.Raw, Data: payload},
		},
	}
	if err := client.VerifyMerkleDAGResolve(t.Context(), request, response); err != nil {
		t.Fatalf("verify DAG-CBOR link traversal: %v", err)
	}
	unused := mustBlockCID(t, []byte("unused"))
	response.Blocks = append(response.Blocks, client.MerkleDAGBlock{CID: unused.String(), Codec: cid.Raw, Data: []byte("unused")})
	if err := client.VerifyMerkleDAGResolve(t.Context(), request, response); err == nil {
		t.Fatal("resolve verifier accepted unused evidence")
	}
}

func TestMerkleDAGResolveVerifierReplaysDAGJSONLinks(t *testing.T) {
	payload := []byte("linked raw payload")
	target := mustBlockCID(t, payload)
	builder := basicnode.Prototype.Map.NewBuilder()
	assembler, err := builder.BeginMap(1)
	if err != nil {
		t.Fatal(err)
	}
	if err := assembler.AssembleKey().AssignString("file"); err != nil {
		t.Fatal(err)
	}
	if err := assembler.AssembleValue().AssignLink(cidlink.Link{Cid: target}); err != nil {
		t.Fatal(err)
	}
	if err := assembler.Finish(); err != nil {
		t.Fatal(err)
	}
	var encoded bytes.Buffer
	if err := dagjson.Encode(builder.Build(), &encoded); err != nil {
		t.Fatal(err)
	}
	hash, err := mh.Sum(encoded.Bytes(), mh.SHA2_256, -1)
	if err != nil {
		t.Fatal(err)
	}
	root := cid.NewCidV1(cid.DagJSON, hash)
	request := client.MerkleDAGResolveRequest{Profile: client.MerkleDAGResolveProfile, Root: root.String(), Segments: []string{"file"}}
	response := client.MerkleDAGResolveResponse{
		Profile: client.MerkleDAGResolveProfile,
		Target:  target.String(),
		Kind:    "file",
		Blocks: []client.MerkleDAGBlock{
			{CID: root.String(), Codec: cid.DagJSON, Data: encoded.Bytes()},
			{CID: target.String(), Codec: cid.Raw, Data: payload},
		},
	}
	if err := client.VerifyMerkleDAGResolve(t.Context(), request, response); err != nil {
		t.Fatalf("verify DAG-JSON resolve: %v", err)
	}
}

func TestMerkleDAGResolveTreatsTypedDAGCBORMapSegmentsAsOpaqueKeys(t *testing.T) {
	payload := []byte("opaque-coordinate target")
	target := mustBlockCID(t, payload)
	for _, test := range []struct {
		name string
		key  string
	}{
		{name: "dot", key: "."},
		{name: "parent", key: ".."},
		{name: "slash", key: "a/b"},
		{name: "empty", key: ""},
		{name: "nul", key: "\x00"},
	} {
		t.Run(test.name, func(t *testing.T) {
			builder := basicnode.Prototype.Map.NewBuilder()
			assembler, err := builder.BeginMap(1)
			if err != nil {
				t.Fatal(err)
			}
			if err := assembler.AssembleKey().AssignString(test.key); err != nil {
				t.Fatal(err)
			}
			if err := assembler.AssembleValue().AssignLink(cidlink.Link{Cid: target}); err != nil {
				t.Fatal(err)
			}
			if err := assembler.Finish(); err != nil {
				t.Fatal(err)
			}
			var encoded bytes.Buffer
			if err := dagcbor.Encode(builder.Build(), &encoded); err != nil {
				t.Fatal(err)
			}
			hash, err := mh.Sum(encoded.Bytes(), mh.SHA2_256, -1)
			if err != nil {
				t.Fatal(err)
			}
			root := cid.NewCidV1(cid.DagCBOR, hash)
			request := client.MerkleDAGResolveRequest{
				Profile: client.MerkleDAGResolveProfile,
				Root:    root.String(), Segments: []string{test.key},
			}
			response := client.MerkleDAGResolveResponse{
				Profile: client.MerkleDAGResolveProfile, Target: target.String(), Kind: "file",
				Blocks: []client.MerkleDAGBlock{
					{CID: root.String(), Codec: cid.DagCBOR, Data: encoded.Bytes()},
					{CID: target.String(), Codec: cid.Raw, Data: payload},
				},
			}
			if err := client.VerifyMerkleDAGResolve(t.Context(), request, response); err != nil {
				t.Fatalf("verify opaque key %q: %v", test.key, err)
			}
		})
	}
}

func TestMerkleDAGVerifierEnforcesProfileResourceLimits(t *testing.T) {
	root := mustBlockCID(t, []byte("root"))
	request := client.MerkleDAGResolveRequest{Profile: client.MerkleDAGResolveProfile, Root: root.String(), Segments: []string{}}
	response := client.MerkleDAGResolveResponse{Profile: client.MerkleDAGResolveProfile, Target: root.String(), Kind: "file"}
	for name, segments := range map[string][]string{
		"missing":   nil,
		"too many":  make([]string, 257),
		"too long":  {strings.Repeat("x", 1025)},
		"non UTF-8": {string([]byte{0xff})},
	} {
		t.Run("segments "+name, func(t *testing.T) {
			invalid := request
			invalid.Segments = segments
			if err := client.VerifyMerkleDAGResolve(t.Context(), invalid, response); err == nil {
				t.Fatalf("accepted invalid typed segments %#v", segments)
			}
		})
	}
	response.Blocks = make([]client.MerkleDAGBlock, 4097)
	if err := client.VerifyMerkleDAGResolve(t.Context(), request, response); err == nil {
		t.Fatal("resolve verifier accepted more than 4096 evidence blocks")
	}

	shared := make([]byte, 8193)
	response.Blocks = make([]client.MerkleDAGBlock, 4096)
	for i := range response.Blocks {
		response.Blocks[i].Data = shared
	}
	if err := client.VerifyMerkleDAGResolve(t.Context(), request, response); err == nil {
		t.Fatal("resolve verifier accepted more than 32 MiB of raw evidence")
	}

	readRequest := client.MerkleDAGReadRequest{Profile: client.MerkleDAGReadProfile, Root: root.String(), Segments: []string{}}
	readResponse := client.MerkleDAGReadResponse{
		Profile: client.MerkleDAGReadProfile, Target: root.String(), Kind: "file", Length: (16 << 20) + 1,
		Blocks: []client.MerkleDAGBlock{{CID: root.String(), Codec: cid.Raw, Data: []byte("root")}},
	}
	if err := client.VerifyMerkleDAGRead(t.Context(), readRequest, readResponse); err == nil {
		t.Fatal("read verifier accepted a response above the 16 MiB profile limit")
	}
}

func TestMerkleDAGTransportBoundsBlockSliceDuringDecode(t *testing.T) {
	root := mustBlockCID(t, []byte("root"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"profile":"merkledag.resolve/v0alpha1","target":"`+root.String()+`","kind":"file","blocks":[`)
		for i := 0; i < 100_000; i++ {
			if i > 0 {
				_, _ = io.WriteString(w, ",")
			}
			_, _ = io.WriteString(w, `{"cid":"","codec":0,"data":""}`)
		}
		_, _ = io.WriteString(w, `]}`)
	}))
	defer server.Close()

	transport, err := client.NewWithBaseURL(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = transport.ResolveMerkleDAG(t.Context(), client.MerkleDAGResolveRequest{
		Profile:  client.MerkleDAGResolveProfile,
		Root:     root.String(),
		Segments: []string{},
	})
	if err == nil || !strings.Contains(err.Error(), "4096-block profile limit") {
		t.Fatalf("structurally amplified response error = %v", err)
	}
}

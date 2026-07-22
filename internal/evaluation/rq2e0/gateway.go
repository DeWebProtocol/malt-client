package rq2e0

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"

	clientcas "github.com/dewebprotocol/malt-client/internal/cas"
	"github.com/dewebprotocol/malt-client/internal/evaluation/rq2fixture"
	clienttransport "github.com/dewebprotocol/malt-client/transport"
	"github.com/dewebprotocol/malt/auth/arcset"
	materializermemory "github.com/dewebprotocol/malt/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt/auth/commitment"
	"github.com/dewebprotocol/malt/auth/commitment/ipa"
	"github.com/dewebprotocol/malt/auth/commitment/kzg"
	listtree "github.com/dewebprotocol/malt/auth/semantic/list/tree"
	"github.com/dewebprotocol/malt/auth/semantic/mapping"
	mappingradix "github.com/dewebprotocol/malt/auth/semantic/mapping/radix"
	"github.com/dewebprotocol/malt/mutation"
	"github.com/dewebprotocol/malt/protocol"
	clientwriter "github.com/dewebprotocol/malt/sdk/writer"
	"github.com/dewebprotocol/malt/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

// ConformanceGateway is an evaluator-owned deterministic HTTP oracle for one
// writer capability. The separately tested Gateway-owned E0 capability owns
// persistence/snapshot behavior; this oracle keeps writer correctness E0
// independent while still exercising the production transport and worker.
type ConformanceGateway struct {
	mu         sync.Mutex
	token      string
	views      map[string]mutation.UpdateView
	runtime    *clientwriter.Runtime
	server     *httptest.Server
	operations uint64
}

// NewConformanceGateway reconstructs the exact fixture complete state and
// rejects any mismatch with its frozen backend root before serving requests.
func NewConformanceGateway(fixture *rq2fixture.Fixture, backend, token string) (*ConformanceGateway, cid.Cid, error) {
	if fixture == nil || len(token) != 64 || backend != "kzg" && backend != "ipa" {
		return nil, cid.Undef, errors.New("invalid RQ2 writer conformance Gateway input")
	}
	view, scheme, err := buildFixtureView(context.Background(), fixture, backend)
	if err != nil {
		return nil, cid.Undef, err
	}
	runtime, err := clientwriter.NewRuntime(materializermemory.New(true), map[maltcid.BackendKind]commitment.IndexCommitment{maltcid.BackendKind(backend): scheme})
	if err != nil {
		return nil, cid.Undef, err
	}
	gateway := &ConformanceGateway{token: token, views: map[string]mutation.UpdateView{view.BaseRoot.String(): view}, runtime: runtime}
	gateway.server = httptest.NewServer(gateway)
	return gateway, view.BaseRoot, nil
}

func (g *ConformanceGateway) URL() string { return g.server.URL }

func (g *ConformanceGateway) Close() {
	if g != nil && g.server != nil {
		g.server.Close()
		g.server = nil
	}
}

func (g *ConformanceGateway) Operations() uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.operations
}

func (g *ConformanceGateway) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "private, no-store")
	switch {
	case request.URL.Path == "/healthz" && request.Method == http.MethodGet:
		_ = json.NewEncoder(response).Encode(map[string]any{"status": "ok", "evaluation_instance_token": g.token})
	case strings.HasPrefix(request.URL.Path, "/v1/roots/") && strings.HasSuffix(request.URL.Path, "/update-view") && request.Method == http.MethodGet:
		g.handleUpdateView(response, request)
	case request.URL.Path == "/v1/cas/batch" && request.Method == http.MethodPost:
		g.handleCASBatch(response, request)
	case request.URL.Path == "/v1/client-roots" && request.Method == http.MethodPost:
		g.handleClientRoot(response, request)
	default:
		http.NotFound(response, request)
	}
}

func (g *ConformanceGateway) handleUpdateView(response http.ResponseWriter, request *http.Request) {
	root := strings.TrimSuffix(strings.TrimPrefix(request.URL.Path, "/v1/roots/"), "/update-view")
	g.mu.Lock()
	view, exists := g.views[root]
	g.mu.Unlock()
	if !exists {
		http.Error(response, "unknown root", http.StatusNotFound)
		return
	}
	wire, err := protocol.NewUpdateView(view)
	if err != nil {
		http.Error(response, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(response).Encode(wire)
}

func (g *ConformanceGateway) handleCASBatch(response http.ResponseWriter, request *http.Request) {
	var submitted struct {
		Profile string `json:"profile"`
		Blocks  []struct {
			Codec uint64 `json:"codec"`
			Data  []byte `json:"data"`
		} `json:"blocks"`
	}
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&submitted); err != nil || submitted.Profile != clienttransport.CASPutBatchProfile || len(submitted.Blocks) == 0 || len(submitted.Blocks) > 64 {
		http.Error(response, "invalid CAS batch", http.StatusBadRequest)
		return
	}
	results := make([]map[string]string, len(submitted.Blocks))
	for index, block := range submitted.Blocks {
		key, err := clientcas.CIDForBlock(clientcas.Block{Codec: block.Codec, Data: block.Data})
		if err != nil {
			http.Error(response, err.Error(), http.StatusBadRequest)
			return
		}
		results[index] = map[string]string{"cid": key.String(), "status": "stored"}
	}
	response.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(response).Encode(map[string]any{"profile": clienttransport.CASPutBatchProfile, "results": results})
}

func (g *ConformanceGateway) handleClientRoot(response http.ResponseWriter, request *http.Request) {
	var submitted protocol.ClientRootBundle
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&submitted); err != nil {
		http.Error(response, err.Error(), http.StatusBadRequest)
		return
	}
	bundle, err := submitted.Core()
	if err != nil {
		http.Error(response, err.Error(), http.StatusBadRequest)
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	view, exists := g.views[bundle.View.BaseRoot.String()]
	if !exists || !view.BaseRoot.Equals(bundle.View.BaseRoot) {
		http.Error(response, "stale root", http.StatusConflict)
		return
	}
	verified, err := g.runtime.VerifyUpdateView(request.Context(), bundle.View)
	if err != nil {
		http.Error(response, err.Error(), http.StatusBadRequest)
		return
	}
	recomputed, err := g.runtime.ComputeBundle(request.Context(), bundle.OperationID, verified, bundle.Intent)
	if err != nil || !recomputed.Bundle.Candidate.Equals(bundle.Candidate) {
		http.Error(response, "client-root recomputation mismatch", http.StatusBadRequest)
		return
	}
	recomputedDigest, err := recomputed.Bundle.Digest()
	if err != nil {
		http.Error(response, err.Error(), http.StatusInternalServerError)
		return
	}
	bundleDigest, err := bundle.Digest()
	if err != nil || recomputedDigest != bundleDigest {
		http.Error(response, "client-root bundle digest mismatch", http.StatusBadRequest)
		return
	}
	g.views[bundle.Candidate.String()] = recomputed.NextView
	g.operations++
	receipt := mutation.MaterializationReceipt{
		Profile: mutation.MaterializationReceiptProfile, OperationID: bundle.OperationID,
		BaseRoot: bundle.View.BaseRoot, Candidate: bundle.Candidate, BundleDigest: bundleDigest,
		DurableBoundary: "gateway-client-root-atomic-v1",
	}
	wireReceipt, err := protocol.NewMaterializationReceipt(receipt, bundle)
	if err != nil {
		http.Error(response, err.Error(), http.StatusInternalServerError)
		return
	}
	for name, value := range map[string]string{
		"X-Malt-Client-Root-Old-State-Validation-Nanos": "1",
		"X-Malt-Client-Root-Gateway-Replay-Nanos":       "1",
		"X-Malt-Client-Root-Persist-Nanos":              "1",
		"X-Malt-Client-Root-Receipt-Nanos":              "1",
		"X-Malt-Client-Root-Durable-Boundary":           receipt.DurableBoundary,
		"X-Malt-Client-Root-Idempotent":                 "false",
		"Server-Timing":                                 "old-state-validation;dur=0.000001, gateway-replay;dur=0.000001, persist;dur=0.000001, receipt;dur=0.000001",
	} {
		response.Header().Set(name, value)
	}
	accounting, _ := json.Marshal(map[string]any{
		"profile": "gateway.client-root-write-accounting/v1", "available": false,
		"unavailable_reason": "writer-conformance-e0", "byte_method": "logical-kv-key-plus-value-bytes/v1", "categories": []any{},
	})
	response.Header().Set("X-Malt-Client-Root-Write-Accounting", base64.RawURLEncoding.EncodeToString(accounting))
	_ = json.NewEncoder(response).Encode(wireReceipt)
}

func buildFixtureView(ctx context.Context, fixture *rq2fixture.Fixture, backend string) (mutation.UpdateView, commitment.IndexCommitment, error) {
	var scheme commitment.IndexCommitment
	var err error
	if backend == "kzg" {
		scheme, err = kzg.NewScheme()
	} else {
		scheme, err = ipa.NewScheme()
	}
	if err != nil {
		return mutation.UpdateView{}, nil, err
	}
	store := materializermemory.New(true)
	lister, err := listtree.NewList(scheme, store)
	if err != nil {
		return mutation.UpdateView{}, nil, err
	}
	mapper, err := mappingradix.NewMap(scheme, store)
	if err != nil {
		return mutation.UpdateView{}, nil, err
	}
	bindings := make(map[string]cid.Cid, len(fixture.DirectFiles)+len(fixture.ListFiles))
	objects := make([]mutation.UpdateObject, 0, len(fixture.ListFiles)+1)
	listRoots := make(map[string]cid.Cid, len(fixture.ListFiles))
	for _, file := range fixture.DirectFiles {
		key, err := cid.Parse(file.CID)
		if err != nil {
			return mutation.UpdateView{}, nil, err
		}
		bindings[file.Path] = key
	}
	for index, file := range fixture.ListFiles {
		chunks := make([]cid.Cid, len(file.Chunks))
		entries := make([]arcset.ArcEntry, len(file.Chunks))
		for chunkIndex, chunk := range file.Chunks {
			key, err := cid.Parse(chunk.CID)
			if err != nil {
				return mutation.UpdateView{}, nil, err
			}
			chunks[chunkIndex] = key
			entries[chunkIndex] = arcset.ArcEntry{Coordinate: arcset.NewListCoordinateUint64(chunk.Index), Target: arcset.NewCASTarget(key)}
		}
		objectID := fmt.Sprintf("rq2-list-%03d", index)
		root, err := lister.CommitFixed(ctx, objectID, chunks, file.ChunkSize, file.TotalSize)
		if err != nil {
			return mutation.UpdateView{}, nil, err
		}
		canonical, err := arcset.NewCanonicalArcSet(arcset.KindList, entries)
		if err != nil {
			return mutation.UpdateView{}, nil, err
		}
		bindings[file.Path], listRoots[file.Path] = root, root
		objects = append(objects, mutation.UpdateObject{
			ObjectID: objectID, Root: root, Kind: arcset.KindList, Entries: canonical,
			Commit: mutation.CommitDescriptor{FixedList: &mutation.FixedListCommit{ChunkSize: file.ChunkSize, TotalSize: file.TotalSize}},
		})
	}
	root, err := mapper.Commit(ctx, "rq2-root", mapping.NewViewFrom(bindings))
	if err != nil {
		return mutation.UpdateView{}, nil, err
	}
	expected, err := fixture.Root(backend)
	if err != nil || !root.Equals(expected) {
		return mutation.UpdateView{}, nil, fmt.Errorf("reconstructed %s fixture root %s does not equal frozen root %s", backend, root, expected)
	}
	paths := make([]string, 0, len(bindings))
	for path := range bindings {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	rootEntries := make([]arcset.ArcEntry, len(paths))
	for index, path := range paths {
		coordinate, err := arcset.NewMapCoordinate(path)
		if err != nil {
			return mutation.UpdateView{}, nil, err
		}
		target := arcset.NewCASTarget(bindings[path])
		if listRoot, ok := listRoots[path]; ok {
			target = arcset.NewListTarget(listRoot)
		}
		rootEntries[index] = arcset.ArcEntry{Coordinate: coordinate, Target: target}
	}
	canonicalRoot, err := arcset.NewCanonicalArcSet(arcset.KindMap, rootEntries)
	if err != nil {
		return mutation.UpdateView{}, nil, err
	}
	objects = append(objects, mutation.UpdateObject{ObjectID: "rq2-root", Root: root, Kind: arcset.KindMap, Entries: canonicalRoot})
	view := mutation.UpdateView{
		Profile: mutation.UpdateViewProfile, StateProfile: mutation.StatefulCompleteVectorsProfile, BaseRoot: root,
		Bounds: mutation.UpdateViewBounds{MaxObjects: 4096, MaxTotalEntries: 65536, MaxDepth: 256}, Objects: objects,
	}
	if err := fixture.ValidateInitialView(view, backend); err != nil {
		return mutation.UpdateView{}, nil, err
	}
	return view, scheme, nil
}

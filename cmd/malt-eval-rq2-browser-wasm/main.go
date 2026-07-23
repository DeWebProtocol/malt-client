//go:build js && wasm

// Command malt-eval-rq2-browser-wasm is the real browser-side client-root
// writer. A minimal host page loads this artifact and calls its Promise-based
// JSON RPC. All update-view verification, normalization, commitment work,
// payload CID binding, exact receipt validation, and retained-root state live
// inside WebAssembly rather than in the native browser driver.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"syscall/js"
	"time"

	clientrootapp "github.com/dewebprotocol/malt-client/application/clientroot"
	"github.com/dewebprotocol/malt-client/internal/evaluation/rq2fixture"
	"github.com/dewebprotocol/malt-client/internal/evaluation/rq2metrics"
	"github.com/dewebprotocol/malt-client/internal/evaluation/rq2wire"
	"github.com/dewebprotocol/malt-client/transport"
	"github.com/dewebprotocol/malt/auth/arcset"
	materializermemory "github.com/dewebprotocol/malt/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt/auth/commitment"
	"github.com/dewebprotocol/malt/auth/commitment/ipa"
	"github.com/dewebprotocol/malt/auth/commitment/kzg"
	"github.com/dewebprotocol/malt/mutation"
	"github.com/dewebprotocol/malt/protocol"
	clientwriter "github.com/dewebprotocol/malt/sdk/writer"
	"github.com/dewebprotocol/malt/wire/maltcid"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

const (
	maxBrowserFixtureBytes = 32 << 20
)

var (
	registeredFunctions []js.Func
	state               browserWriter
)

type initializeRequest struct {
	GatewayBaseURL       string `json:"gateway_base_url"`
	GatewayInstanceToken string `json:"gateway_instance_token"`
	FixtureURL           string `json:"fixture_url"`
	Backend              string `json:"backend"`
}

type initializeResponse struct {
	ParameterLoadNS    uint64 `json:"parameter_load_ns"`
	ParameterLoadBytes uint64 `json:"parameter_load_bytes"`
	ParameterProfile   string `json:"parameter_profile"`
	ParameterSHA256    string `json:"parameter_sha256"`
	FixtureBytes       uint64 `json:"fixture_bytes"`
	FixtureSHA256      string `json:"fixture_sha256"`
}

type browserWriter struct {
	initialized  bool
	backend      string
	remote       *transport.Client
	app          *clientrootapp.Session
	fixture      *rq2fixture.Fixture
	source       map[string][]byte
	root         cid.Cid
	serial       uint64
	receiptCount uint64
	sessionID    string
}

type wasmRemote struct{ client *transport.Client }

func (r wasmRemote) FetchUpdateView(ctx context.Context, root cid.Cid, bounds *protocol.UpdateViewBounds) (clientrootapp.ViewEnvelope, error) {
	response, err := r.client.FetchUpdateView(ctx, root, bounds)
	if err != nil {
		return clientrootapp.ViewEnvelope{}, err
	}
	return clientrootapp.ViewEnvelope{View: response.View, WireBytes: response.WireBytes}, nil
}

func (r wasmRemote) SubmitClientRoot(ctx context.Context, bundle mutation.ClientRootBundle) (clientrootapp.ReceiptEnvelope, error) {
	response, err := r.client.SubmitClientRoot(ctx, bundle)
	if err != nil {
		return clientrootapp.ReceiptEnvelope{}, err
	}
	return clientrootapp.ReceiptEnvelope{
		Receipt: response.Receipt, RequestWireBytes: response.RequestWireBytes, ResponseWireBytes: response.ResponseWireBytes,
		RequestEncodingNS: response.RequestEncodingNS, ResponseVerifyNS: response.ResponseVerifyNS,
		Idempotent: response.Idempotent,
		Gateway: clientrootapp.GatewayPhaseMetrics{
			OldStateValidationNS: response.Gateway.OldStateValidationNS, GatewayReplayNS: response.Gateway.GatewayReplayNS,
			PersistNS: response.Gateway.PersistNS, ReceiptNS: response.Gateway.ReceiptNS,
		},
	}, nil
}

func main() {
	initialize := js.FuncOf(func(_ js.Value, args []js.Value) any {
		return newPromise(args, func(raw string) (string, error) {
			var request initializeRequest
			if err := strictJSON([]byte(raw), &request); err != nil {
				return "", err
			}
			result, err := state.initialize(request)
			if err != nil {
				return "", err
			}
			return marshalJSON(result)
		})
	})
	exchange := js.FuncOf(func(_ js.Value, args []js.Value) any {
		return newPromise(args, func(raw string) (string, error) {
			started := time.Now()
			var request rq2wire.WorkerRequest
			if err := strictJSON([]byte(raw), &request); err != nil {
				return "", err
			}
			if err := request.Validate(); err != nil {
				return "", err
			}
			record := state.exchange(request)
			result, err := marshalJSON(record)
			js.Global().Set("maltRQ2LastExecutionNS", durationNS(time.Since(started)))
			return result, err
		})
	})
	registeredFunctions = append(registeredFunctions, initialize, exchange)
	js.Global().Set("maltRQ2Initialize", initialize)
	js.Global().Set("maltRQ2Exchange", exchange)
	js.Global().Set("maltRQ2LastExecutionNS", uint64(0))
	js.Global().Set("maltRQ2WASMReady", true)
	select {}
}

func newPromise(args []js.Value, run func(string) (string, error)) js.Value {
	promise := js.Global().Get("Promise")
	if len(args) != 1 || args[0].Type() != js.TypeString {
		return promise.Call("reject", "RQ2 WASM RPC requires one JSON string")
	}
	raw := args[0].String()
	var executor js.Func
	executor = js.FuncOf(func(_ js.Value, callbacks []js.Value) any {
		resolve, reject := callbacks[0], callbacks[1]
		go func() {
			result, err := run(raw)
			if err != nil {
				reject.Invoke(err.Error())
				return
			}
			resolve.Invoke(result)
		}()
		return nil
	})
	value := promise.New(executor)
	executor.Release()
	return value
}

func (w *browserWriter) initialize(request initializeRequest) (initializeResponse, error) {
	if w.initialized {
		return initializeResponse{}, fmt.Errorf("RQ2 WASM writer is already initialized")
	}
	if request.Backend != "kzg" && request.Backend != "ipa" || request.GatewayBaseURL == "" || request.FixtureURL == "" || !canonicalSHA256(request.GatewayInstanceToken) {
		return initializeResponse{}, fmt.Errorf("RQ2 WASM initialization is incomplete")
	}
	fixture, err := fetchFixture(request.FixtureURL)
	if err != nil {
		return initializeResponse{}, err
	}
	sourceFixture, err := rq2fixture.Decode(fixture)
	if err != nil {
		return initializeResponse{}, err
	}
	operations := make([]string, 0, len(browserOperations))
	for operation := range browserOperations {
		operations = append(operations, operation)
	}
	if _, err := sourceFixture.Root(request.Backend); err != nil {
		return initializeResponse{}, err
	}
	if err := sourceFixture.RequireOperations(operations); err != nil {
		return initializeResponse{}, err
	}
	started := time.Now()
	var backend maltcid.BackendKind
	var scheme commitment.IndexCommitment
	if request.Backend == "kzg" {
		backend = maltcid.BackendKindKZG
		scheme, err = kzg.NewScheme()
	} else {
		backend = maltcid.BackendKindIPA
		scheme, err = ipa.NewScheme()
	}
	parameterLoadNS := durationNS(time.Since(started))
	if err != nil {
		return initializeResponse{}, fmt.Errorf("initialize %s parameters: %w", request.Backend, err)
	}
	parameterProfile, parameterSHA256, parameterBytes, ok := rq2wire.ParameterEvidence(request.Backend)
	if !ok {
		return initializeResponse{}, fmt.Errorf("commitment parameter provenance is unavailable")
	}
	remote, err := transport.New(transport.Options{
		BaseURL:    request.GatewayBaseURL,
		HTTPClient: &http.Client{Timeout: 24 * time.Hour},
	})
	if err != nil {
		return initializeResponse{}, err
	}
	health, err := remote.Health(context.Background())
	if err != nil || health.Status != "ok" || health.EvaluationInstanceToken != request.GatewayInstanceToken {
		return initializeResponse{}, fmt.Errorf("browser Gateway health did not echo the exact disposable instance token")
	}
	writerRuntime, err := clientwriter.NewRuntime(
		materializermemory.New(true),
		map[maltcid.BackendKind]commitment.IndexCommitment{backend: scheme},
	)
	if err != nil {
		return initializeResponse{}, err
	}
	app, err := clientrootapp.New(wasmRemote{client: remote}, writerRuntime)
	if err != nil {
		return initializeResponse{}, err
	}
	digest := sha256.Sum256(fixture)
	*w = browserWriter{
		initialized: true, backend: request.Backend, remote: remote, app: app,
		fixture: sourceFixture,
	}
	return initializeResponse{
		ParameterLoadNS: parameterLoadNS, ParameterLoadBytes: parameterBytes,
		ParameterProfile: parameterProfile, ParameterSHA256: parameterSHA256,
		FixtureBytes: uint64(len(fixture)), FixtureSHA256: hex.EncodeToString(digest[:]),
	}, nil
}

func fetchFixture(url string) ([]byte, error) {
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Cache-Control", "no-store")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch browser fixture: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.Contains(response.Header.Get("Cache-Control"), "no-store") {
		return nil, fmt.Errorf("browser fixture response is not a non-cacheable success")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxBrowserFixtureBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) == 0 || len(data) > maxBrowserFixtureBytes {
		return nil, fmt.Errorf("browser fixture size is outside 1..%d", maxBrowserFixtureBytes)
	}
	return data, nil
}

func (w *browserWriter) exchange(request rq2wire.WorkerRequest) rq2wire.WorkerRecord {
	if !w.initialized || request.ClientKind != rq2wire.ClientBrowserWASM || request.Backend != w.backend {
		return rq2wire.FailedRecord(request, "capability_unavailable", fmt.Errorf("WASM writer coordinate was not initialized"))
	}
	switch request.RecordKind {
	case rq2wire.RecordSessionStart:
		return w.start(request)
	case rq2wire.RecordMutation:
		return w.mutate(request)
	case rq2wire.RecordSessionEnd:
		return w.end(request)
	default:
		return rq2wire.FailedRecord(request, "input_invalid", fmt.Errorf("preflight is owned by the browser host"))
	}
}

var browserBounds = &protocol.UpdateViewBounds{MaxObjects: 4096, MaxTotalEntries: 65536, MaxDepth: 256}

func (w *browserWriter) start(request rq2wire.WorkerRequest) rq2wire.WorkerRecord {
	if w.root.Defined() || w.sessionID != "" {
		return rq2wire.FailedRecord(request, "session_state", fmt.Errorf("browser session already started"))
	}
	root, err := cid.Parse(request.ExpectedAcceptedRoot)
	if err != nil || string(maltcid.BackendKindOf(root)) != w.backend {
		return rq2wire.FailedRecord(request, "input_invalid", fmt.Errorf("browser root is not a typed %s root", w.backend))
	}
	if w.fixture == nil || request.FixtureID != w.fixture.FixtureID {
		return rq2wire.FailedRecord(request, "fixture_incompatible", fmt.Errorf("browser request fixture identity does not match the pinned source fixture"))
	}
	if _, err := w.app.Load(context.Background(), root, browserBounds); err != nil {
		return rq2wire.FailedRecord(request, classifyFailure(err), err)
	}
	view, err := w.app.SnapshotView()
	if err != nil || w.fixture.ValidateInitialView(view, w.backend) != nil {
		if err == nil {
			err = w.fixture.ValidateInitialView(view, w.backend)
		}
		return rq2wire.FailedRecord(request, "fixture_incompatible", err)
	}
	w.root, w.sessionID, w.source = root, request.SessionID, w.fixture.InitialSource()
	record := rq2wire.BaseRecord(request)
	record.Success = true
	record.Session = &rq2wire.SessionEvidence{AcceptedRoot: root.String()}
	return record
}

var browserOperations = map[string]struct{}{
	"document-edit-cid-binding-submit": {}, "list-append": {}, "list-replace": {}, "map-insert": {}, "map-replace": {},
}

func (w *browserWriter) mutate(request rq2wire.WorkerRequest) rq2wire.WorkerRecord {
	if _, ok := browserOperations[request.Operation]; !ok {
		return rq2wire.FailedRecord(request, "operation_unsupported", fmt.Errorf("unsupported browser operation %q", request.Operation))
	}
	if request.SessionID != w.sessionID || !w.root.Defined() || request.ExpectedAcceptedRoot != w.root.String() {
		return rq2wire.FailedRecord(request, "root_continuity", fmt.Errorf("browser request does not match retained root/session"))
	}
	mutationStarted := time.Now()
	load, err := w.app.Load(context.Background(), w.root, browserBounds)
	if err != nil {
		return rq2wire.FailedRecord(request, classifyFailure(err), err)
	}
	viewSnapshotStarted := time.Now()
	view, err := w.app.SnapshotView()
	viewSnapshotNS := durationNS(time.Since(viewSnapshotStarted))
	if err != nil {
		return rq2wire.FailedRecord(request, "verification_failed", err)
	}
	if err := w.fixture.ValidateViewAgainstSource(view, w.backend, w.source); err != nil {
		return rq2wire.FailedRecord(request, "fixture_incompatible", fmt.Errorf("browser source pre-image binding: %w", err))
	}
	operation, err := w.fixture.Operation(request.Operation)
	if err != nil {
		return rq2wire.FailedRecord(request, "fixture_incompatible", err)
	}
	prepared, err := w.prepare(operation)
	if err != nil {
		return rq2wire.FailedRecord(request, "fixture_incompatible", err)
	}
	payloadUpload, err := w.remote.PutBatchMeasured(context.Background(), []transport.Block{{Codec: cid.Raw, Data: prepared.payload}})
	results := payloadUpload.Results
	if err != nil || len(results) != 1 || !results[0].CID.Equals(prepared.payloadCID) {
		if err == nil {
			err = fmt.Errorf("browser CAS upload did not return the exact local payload CID")
		}
		return rq2wire.FailedRecord(request, classifyFailure(err), err)
	}
	intentPlanningStarted := time.Now()
	intent, err := planBrowserIntent(view, operation, prepared.payloadCID)
	intentPlanningNS := durationNS(time.Since(intentPlanningStarted))
	if err != nil {
		return rq2wire.FailedRecord(request, "intent_invalid", err)
	}
	result, err := w.app.Execute(context.Background(), operationID(request), intent)
	if err != nil {
		return rq2wire.FailedRecord(request, classifyFailure(err), err)
	}
	if result.Idempotent {
		return rq2wire.FailedRecord(request, "gateway_instance_reused", fmt.Errorf("disposable Gateway returned an idempotent client-root replay"))
	}
	mutationTotalNS := durationNS(time.Since(mutationStarted))
	postView, err := w.app.SnapshotView()
	if err != nil {
		return rq2wire.FailedRecord(request, "verification_failed", fmt.Errorf("snapshot browser post-image: %w", err))
	}
	if err := w.fixture.ValidateViewAgainstSource(postView, w.backend, prepared.postSource); err != nil {
		return rq2wire.FailedRecord(request, "verification_failed", fmt.Errorf("browser full source post-image oracle: %w", err))
	}
	encodedCandidate := result.Candidate.String()
	parsedCandidate, err := cid.Parse(encodedCandidate)
	if err != nil || !parsedCandidate.Equals(result.Candidate) {
		return rq2wire.FailedRecord(request, "verification_failed", fmt.Errorf("expected-root CID encoding did not round-trip"))
	}
	record := rq2wire.BaseRecord(request)
	record.Success = true
	metrics, err := browserMetrics(request.Operation, load, prepared, result.Metrics, viewSnapshotNS, intentPlanningNS, uint64(len(encodedCandidate)), payloadUpload, mutationTotalNS)
	if err != nil {
		return rq2wire.FailedRecord(request, "measurement_invalid", err)
	}
	record.Mutation = &rq2wire.MutationEvidence{
		Operation: request.Operation, PriorRoot: result.BaseRoot.String(), CandidateRoot: encodedCandidate,
		ReceiptRoot: result.Receipt.Candidate.String(), ReceiptAccepted: result.Receipt.Candidate.Equals(result.Candidate),
		UpdateViewSHA256: hex.EncodeToString(result.ViewDigest[:]), IntentSHA256: hex.EncodeToString(result.IntentDigest[:]),
		BundleSHA256: hex.EncodeToString(result.Receipt.BundleDigest[:]),
		Metrics:      metrics,
	}
	w.root = result.Receipt.Candidate
	w.source = prepared.postSource
	w.serial++
	w.receiptCount++
	return record
}

func (w *browserWriter) end(request rq2wire.WorkerRequest) rq2wire.WorkerRecord {
	if request.SessionID != w.sessionID || !w.root.Defined() || request.ExpectedAcceptedRoot != w.root.String() {
		return rq2wire.FailedRecord(request, "root_continuity", fmt.Errorf("browser session-end root does not match retained root"))
	}
	if err := w.app.Audit(context.Background()); err != nil {
		return rq2wire.FailedRecord(request, "audit_failed", err)
	}
	record := rq2wire.BaseRecord(request)
	record.Success = true
	record.Session = &rq2wire.SessionEvidence{AcceptedRoot: w.root.String(), ReceiptCount: w.receiptCount, AuditPassed: true}
	return record
}

type browserPayload struct {
	payload    []byte
	payloadCID cid.Cid
	postSource map[string][]byte
	scan       rq2wire.PhaseMeasurement
	chunk      rq2wire.PhaseMeasurement
	hash       rq2wire.PhaseMeasurement
}

func (w *browserWriter) prepare(operation rq2fixture.Operation) (browserPayload, error) {
	prepared := browserPayload{
		scan: rq2wire.NotApplicablePhase(), chunk: rq2wire.NotApplicablePhase(), hash: rq2wire.NotApplicablePhase(),
	}
	postSource, payloads, err := w.fixture.ApplySourceOperation(w.source, operation, w.serial)
	if err != nil || len(payloads) != 1 {
		if err == nil {
			err = fmt.Errorf("browser operation must produce exactly one changed payload")
		}
		return browserPayload{}, err
	}
	prepared.postSource, prepared.payload = postSource, payloads[0]
	if operation.Kind == rq2fixture.KindDocumentEdit {
		scanStarted := time.Now()
		body := append([]byte(nil), prepared.payload...)
		prepared.scan = measured(durationNS(time.Since(scanStarted)), uint64(len(body)), 1)
		chunkStarted := time.Now()
		chunkSize := 256 << 10
		chunkCount := max(1, (len(body)+chunkSize-1)/chunkSize)
		for offset := 0; offset < len(body); offset += chunkSize {
			_ = append([]byte(nil), body[offset:min(len(body), offset+chunkSize)]...)
		}
		prepared.chunk = measured(durationNS(time.Since(chunkStarted)), uint64(len(body)), uint64(chunkCount))
	}
	hashStarted := time.Now()
	digest, err := mh.Sum(prepared.payload, mh.SHA2_256, -1)
	if err != nil {
		return browserPayload{}, err
	}
	prepared.payloadCID = cid.NewCidV1(cid.Raw, digest)
	prepared.hash = measured(durationNS(time.Since(hashStarted)), uint64(len(prepared.payload)), 1)
	return prepared, nil
}

func browserMetrics(operation string, load clientrootapp.LoadMetrics, payload browserPayload, result clientrootapp.OperationMetrics, viewSnapshotNS, intentPlanningNS, expectedRootBytes uint64, payloadUpload transport.PutBatchMeasurement, mutationTotalNS uint64) (rq2wire.MutationMetrics, error) {
	phase := func(duration, bytes, count uint64) rq2wire.PhaseMeasurement {
		return measured(duration, bytes, max(uint64(1), count))
	}
	sdk := result.SDK
	externalNormalizationNS, err := rq2metrics.AddDurations(viewSnapshotNS, intentPlanningNS)
	if err != nil {
		return rq2wire.MutationMetrics{}, fmt.Errorf("external normalization timing: %w", err)
	}
	normalizationNS, err := rq2metrics.AddDurations(externalNormalizationNS, sdk.ViewNormalizationNS, sdk.IntentNormalizationNS)
	if err != nil {
		return rq2wire.MutationMetrics{}, fmt.Errorf("complete normalization timing: %w", err)
	}
	clientRootGenerationNS, err := rq2metrics.AddDurations(externalNormalizationNS, sdk.TotalNS)
	if err != nil {
		return rq2wire.MutationMetrics{}, fmt.Errorf("complete client-root generation timing: %w", err)
	}
	return rq2wire.MutationMetrics{
		TaxonomyProfile: rq2metrics.TaxonomyProfile,
		MutationTotal:   phase(mutationTotalNS, 0, 1),
		Scan:            payload.scan, Chunk: payload.chunk, Hash: payload.hash,
		UpdateView:       phase(load.UpdateViewFetchNS, load.UpdateViewWireBytes, 1),
		VerifyUpdateView: phase(load.VerifyUpdateViewNS, load.UpdateViewWireBytes, 1),
		Normalization:    phase(normalizationNS, 0, 4),
		CommitmentUpdate: phase(sdk.CommitmentUpdateNS, 0, 1), ExpectedRootEncoding: phase(sdk.ExpectedRootEncodingNS, expectedRootBytes, 1),
		RootComputation: phase(sdk.RootComputationNS, 0, 1), ClientRootGeneration: phase(clientRootGenerationNS, 0, 1),
		ClientRootBundle: phase(result.BundleEncodingNS, result.BundleWireBytes, 1),
		// Upload is only the payload CAS request round trip. Bundle request
		// bytes and receipt response bytes remain directionally separated.
		Upload:        phase(payloadUpload.RoundTripNS, payloadUpload.RequestWireBytes, 1),
		GatewayReplay: phase(result.Gateway.GatewayReplayNS, 0, 1), GatewayPersist: phase(result.Gateway.PersistNS, 0, 1),
		ReceiptCheck: phase(result.ReceiptCheckNS, result.ReceiptWireBytes, 1),
		CPUTotal:     rq2wire.NotApplicablePhase(), PeakMemory: rq2wire.NotApplicablePhase(),
		WASMDownload: rq2wire.NotApplicablePhase(), WASMInstantiate: rq2wire.NotApplicablePhase(), ParameterLoad: rq2wire.NotApplicablePhase(),
		FirstMutation: rq2wire.NotApplicablePhase(), JSWASMBoundary: rq2wire.NotApplicablePhase(),
	}, nil
}

func measured(duration, bytes, count uint64) rq2wire.PhaseMeasurement {
	return rq2wire.ObservedPhase(duration, bytes, count)
}

func planBrowserIntent(view mutation.UpdateView, operation rq2fixture.Operation, payload cid.Cid) (mutation.SemanticIntent, error) {
	root, err := browserRootObject(view)
	if err != nil {
		return mutation.SemanticIntent{}, err
	}
	target := root
	after := arcset.NewCASTarget(payload)
	var changes []mutation.IntentChange
	switch operation.Kind {
	case rq2fixture.KindDirectInsert:
		coordinate, err := arcset.NewMapCoordinate(operation.DestinationPath)
		if err != nil {
			return mutation.SemanticIntent{}, err
		}
		for _, entry := range root.Entries.Entries() {
			if bytes.Equal(entry.Coordinate.Bytes(), coordinate.Bytes()) {
				return mutation.SemanticIntent{}, fmt.Errorf("browser map destination %q already exists", operation.DestinationPath)
			}
		}
		changes = []mutation.IntentChange{{Coordinate: coordinate, After: &after}}
	case rq2fixture.KindDirectReplace, rq2fixture.KindDocumentEdit:
		entry, err := browserDirectEntryAt(root, operation.SourcePath)
		if err != nil {
			return mutation.SemanticIntent{}, err
		}
		before := entry.Target
		changes = []mutation.IntentChange{{Coordinate: entry.Coordinate, Before: &before, After: &after}}
	case rq2fixture.KindListAppend, rq2fixture.KindListReplace:
		target, err = browserListObjectForPath(view, operation.SourcePath)
		if err != nil {
			return mutation.SemanticIntent{}, err
		}
		if operation.Kind == rq2fixture.KindListAppend {
			changes = []mutation.IntentChange{{Coordinate: arcset.NewListCoordinateUint64(uint64(target.Entries.Len())), After: &after}}
			if target.Commit.FixedList != nil {
				descriptor := *target.Commit.FixedList
				target.Commit.FixedList = &descriptor
				if descriptor.ChunkSize == 0 || descriptor.TotalSize%descriptor.ChunkSize != 0 {
					return mutation.SemanticIntent{}, fmt.Errorf("browser fixed-list append has a partial final chunk")
				}
				target.Commit.FixedList.TotalSize += target.Commit.FixedList.ChunkSize
			}
		} else {
			if operation.ListIndex == nil || *operation.ListIndex >= uint64(target.Entries.Len()) {
				return mutation.SemanticIntent{}, fmt.Errorf("browser list replacement index is outside the current list")
			}
			entry := target.Entries.Entries()[*operation.ListIndex]
			before := entry.Target
			changes = []mutation.IntentChange{{Coordinate: entry.Coordinate, Before: &before, After: &after}}
		}
	default:
		return mutation.SemanticIntent{}, fmt.Errorf("unsupported browser operation kind %q", operation.Kind)
	}
	return browserPropagate(view, target, changes)
}

type browserParent struct {
	object mutation.UpdateObject
	entry  arcset.ArcEntry
}

func browserPropagate(view mutation.UpdateView, target mutation.UpdateObject, changes []mutation.IntentChange) (mutation.SemanticIntent, error) {
	objects := make(map[string]mutation.UpdateObject, len(view.Objects))
	parents := make(map[string][]browserParent)
	for _, object := range view.Objects {
		objects[object.Root.KeyString()] = object
	}
	for _, object := range view.Objects {
		for _, entry := range object.Entries.Entries() {
			if _, ok := objects[entry.Target.CID().KeyString()]; ok && maltcid.SemanticKindOf(entry.Target.CID()) != maltcid.SemanticKindUnknown {
				parents[entry.Target.CID().KeyString()] = append(parents[entry.Target.CID().KeyString()], browserParent{object: object, entry: entry})
			}
		}
	}
	transitions := make([]mutation.IntentTransition, 0, len(view.Objects))
	current, currentChanges := target, changes
	for step := 0; ; step++ {
		id := fmt.Sprintf("step-%03d", step)
		top := current.Root.Equals(view.BaseRoot)
		transition := mutation.IntentTransition{
			ID: id, ObjectID: current.ObjectID, OldRoot: current.Root, Kind: current.Kind,
			Backend: maltcid.BackendKindOf(current.Root), Changes: currentChanges, Commit: current.Commit,
		}
		if !top {
			transition.ExpectedUses = 1
		}
		transitions = append(transitions, transition)
		if top {
			return mutation.SemanticIntent{Profile: mutation.SemanticIntentProfile, BaseRoot: view.BaseRoot, Transitions: transitions, TopOutputID: id}, nil
		}
		edges := parents[current.Root.KeyString()]
		if len(edges) != 1 {
			return mutation.SemanticIntent{}, fmt.Errorf("browser target has %d parents", len(edges))
		}
		before := edges[0].entry.Target
		kind := arcset.TargetKindMap
		if current.Kind == arcset.KindList {
			kind = arcset.TargetKindList
		}
		currentChanges = []mutation.IntentChange{{Coordinate: edges[0].entry.Coordinate, Before: &before, OutputID: id, OutputKind: kind}}
		current = edges[0].object
		if step >= len(view.Objects) {
			return mutation.SemanticIntent{}, fmt.Errorf("browser parent chain does not close")
		}
	}
}

func browserRootObject(view mutation.UpdateView) (mutation.UpdateObject, error) {
	for _, object := range view.Objects {
		if object.Root.Equals(view.BaseRoot) {
			return object, nil
		}
	}
	return mutation.UpdateObject{}, fmt.Errorf("browser update view omits root object")
}

func browserDirectEntryAt(object mutation.UpdateObject, path string) (arcset.ArcEntry, error) {
	coordinate, err := arcset.NewMapCoordinate(path)
	if err != nil {
		return arcset.ArcEntry{}, err
	}
	for _, entry := range object.Entries.Entries() {
		if bytes.Equal(entry.Coordinate.Bytes(), coordinate.Bytes()) {
			if entry.Target.Kind() != arcset.TargetKindCAS || maltcid.SemanticKindOf(entry.Target.CID()) != maltcid.SemanticKindUnknown {
				return arcset.ArcEntry{}, fmt.Errorf("browser coordinate %q is not a direct CAS target", path)
			}
			return entry, nil
		}
	}
	return arcset.ArcEntry{}, fmt.Errorf("browser direct source coordinate %q is absent", path)
}

func browserListObjectForPath(view mutation.UpdateView, path string) (mutation.UpdateObject, error) {
	root, err := browserRootObject(view)
	if err != nil {
		return mutation.UpdateObject{}, err
	}
	coordinate, err := arcset.NewMapCoordinate(path)
	if err != nil {
		return mutation.UpdateObject{}, err
	}
	var listRoot cid.Cid
	for _, entry := range root.Entries.Entries() {
		if bytes.Equal(entry.Coordinate.Bytes(), coordinate.Bytes()) {
			if entry.Target.Kind() != arcset.TargetKindList || maltcid.SemanticKindOf(entry.Target.CID()) != maltcid.SemanticKindList {
				return mutation.UpdateObject{}, fmt.Errorf("browser coordinate %q is not a list target", path)
			}
			listRoot = entry.Target.CID()
			break
		}
	}
	if !listRoot.Defined() {
		return mutation.UpdateObject{}, fmt.Errorf("browser list source coordinate %q is absent", path)
	}
	for _, object := range view.Objects {
		if object.Root.Equals(listRoot) && object.Kind == arcset.KindList {
			return object, nil
		}
	}
	return mutation.UpdateObject{}, fmt.Errorf("browser list source %q omits its complete object", path)
}

func canonicalSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			if char < 'a' || char > 'f' {
				return false
			}
		}
	}
	return true
}

func operationID(request rq2wire.WorkerRequest) string {
	digest := sha256.Sum256([]byte(request.WorkerID + "\x00" + request.SessionID + "\x00" + request.RequestID + "\x00" + request.Operation))
	return "rq2-" + hex.EncodeToString(digest[:16])
}

func classifyFailure(err error) string {
	var transportError *transport.Error
	if errors.As(err, &transportError) {
		return "gateway_rejected"
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return "client_root_failed"
}

func durationNS(value time.Duration) uint64 {
	if value <= 0 {
		return 0
	}
	return uint64(value)
}

func strictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("JSON contains trailing data")
	}
	return nil
}

func marshalJSON(value any) (string, error) {
	data, err := json.Marshal(value)
	return string(data), err
}

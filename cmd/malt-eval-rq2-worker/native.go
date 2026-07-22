package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	clientrootapp "github.com/dewebprotocol/malt-client/application/clientroot"
	"github.com/dewebprotocol/malt-client/internal/evaluation/rq2fixture"
	"github.com/dewebprotocol/malt-client/internal/evaluation/rq2metrics"
	"github.com/dewebprotocol/malt-client/transport"
	materializermemory "github.com/dewebprotocol/malt/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt/auth/commitment"
	"github.com/dewebprotocol/malt/auth/commitment/ipa"
	"github.com/dewebprotocol/malt/auth/commitment/kzg"
	"github.com/dewebprotocol/malt/mutation"
	"github.com/dewebprotocol/malt/protocol"
	clientwriter "github.com/dewebprotocol/malt/sdk/writer"
	"github.com/dewebprotocol/malt/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

var nativeOperations = map[string]struct{}{
	"append": {}, "batch-sync": {}, "create-small-file": {}, "delete-directory-entry": {},
	"insert-directory-entry": {}, "modify-small-file": {}, "move": {}, "rename": {},
	"replace-large-file-chunk": {},
}

var evaluationBounds = &protocol.UpdateViewBounds{
	MaxObjects: 4096, MaxTotalEntries: 65536, MaxDepth: 256,
}

type nativeSession struct {
	config    workerConfig
	remote    *transport.Client
	app       *clientrootapp.Session
	fixture   *rq2fixture.Fixture
	workspace *nativeWorkspace
	root      cid.Cid
	serial    uint64
}

type remoteAdapter struct{ client *transport.Client }

func (r remoteAdapter) FetchUpdateView(ctx context.Context, root cid.Cid, bounds *protocol.UpdateViewBounds) (clientrootapp.ViewEnvelope, error) {
	response, err := r.client.FetchUpdateView(ctx, root, bounds)
	if err != nil {
		return clientrootapp.ViewEnvelope{}, err
	}
	return clientrootapp.ViewEnvelope{View: response.View, WireBytes: response.WireBytes}, nil
}

func (r remoteAdapter) SubmitClientRoot(ctx context.Context, bundle mutation.ClientRootBundle) (clientrootapp.ReceiptEnvelope, error) {
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
		WriteAccounting: mapWriteAccounting(response.WriteAccounting, response.WriteAccountingWireBytes),
	}, nil
}

func mapWriteAccounting(source transport.ClientRootWriteAccounting, wireBytes uint64) clientrootapp.GatewayWriteAccounting {
	result := clientrootapp.GatewayWriteAccounting{
		Profile: source.Profile, Available: source.Available, UnavailableReason: source.UnavailableReason,
		ByteMethod: source.ByteMethod, ObjectLedgerSHA256: source.ObjectLedgerSHA256, WireBytes: wireBytes,
		Categories: make([]clientrootapp.GatewayWriteCategoryAccounting, len(source.Categories)),
	}
	for index, category := range source.Categories {
		result.Categories[index] = clientrootapp.GatewayWriteCategoryAccounting{
			Category: category.Category, AttemptedWrites: category.AttemptedWrites, AttemptedBytes: category.AttemptedBytes,
			AttemptedNewWrites: category.AttemptedNewWrites, AttemptedNewBytes: category.AttemptedNewBytes,
			AttemptedReplacementWrites: category.AttemptedReplacementWrites, AttemptedReplacementBytes: category.AttemptedReplacementBytes,
			AttemptedSameValueWrites: category.AttemptedSameValueWrites, AttemptedSameValueBytes: category.AttemptedSameValueBytes,
			AttemptedDeleteWrites: category.AttemptedDeleteWrites, AttemptedDeleteBytes: category.AttemptedDeleteBytes,
			NewlyPersistedWrites: category.NewlyPersistedWrites, GrossNewBytes: category.GrossNewBytes,
			NewWrites: category.NewWrites, NewBytes: category.NewBytes, ReplacedWrites: category.ReplacedWrites,
			ReplacementNewBytes: category.ReplacementNewBytes, ReplacementReclaimedBytes: category.ReplacementReclaimedBytes,
			SameValueWrites: category.SameValueWrites, DeletedWrites: category.DeletedWrites,
			DeletedReclaimedBytes: category.DeletedReclaimedBytes, ReclaimedBytes: category.ReclaimedBytes, NetBytes: category.NetBytes,
		}
	}
	return result
}

func newNativeSession(config workerConfig, remote *transport.Client, fixture *rq2fixture.Fixture) (*nativeSession, error) {
	if config.clientKind != clientNative || config.lifecycle != lifecycleNativeLong {
		return nil, fmt.Errorf("native worker requires native-long-lived coordinate")
	}
	var backend maltcid.BackendKind
	var scheme commitment.IndexCommitment
	var err error
	switch config.backend {
	case "kzg":
		backend = maltcid.BackendKindKZG
		scheme, err = kzg.NewScheme()
	case "ipa":
		backend = maltcid.BackendKindIPA
		scheme, err = ipa.NewScheme()
	}
	if err != nil {
		return nil, fmt.Errorf("initialize %s commitment backend: %w", config.backend, err)
	}
	runtime, err := clientwriter.NewRuntime(
		materializermemory.New(true),
		map[maltcid.BackendKind]commitment.IndexCommitment{backend: scheme},
	)
	if err != nil {
		return nil, err
	}
	app, err := clientrootapp.New(remoteAdapter{client: remote}, runtime)
	if err != nil {
		return nil, err
	}
	operations := make([]string, 0, len(nativeOperations))
	for operation := range nativeOperations {
		operations = append(operations, operation)
	}
	if fixture == nil {
		return nil, fmt.Errorf("native RQ2 source fixture is nil")
	}
	if _, err := fixture.Root(config.backend); err != nil {
		return nil, err
	}
	if err := fixture.RequireOperations(operations); err != nil {
		return nil, err
	}
	return &nativeSession{config: config, remote: remote, app: app, fixture: fixture}, nil
}

func (n *nativeSession) close() error {
	if n == nil {
		return nil
	}
	return n.workspace.close()
}

func (w *worker) startSession(request workerRequest) workerRecord {
	w.state = recordMutation
	if w.native == nil {
		return failedRecord(request, "capability_unavailable", fmt.Errorf("native capability did not pass preflight"))
	}
	root, err := cid.Parse(request.ExpectedAcceptedRoot)
	if err != nil || string(maltcid.BackendKindOf(root)) != w.config.backend {
		return failedRecord(request, "input_invalid", fmt.Errorf("session root is not a typed %s MALT root", w.config.backend))
	}
	ctx, cancel := context.WithTimeout(context.Background(), w.config.requestTimeout)
	defer cancel()
	if _, err := w.native.app.Load(ctx, root, evaluationBounds); err != nil {
		return failedRecord(request, classifyNativeFailure(err), fmt.Errorf("load initial update view: %w", err))
	}
	view, err := w.native.app.SnapshotView()
	if err != nil {
		return failedRecord(request, "verification_failed", err)
	}
	if err := w.native.fixture.ValidateInitialView(view, w.config.backend); err != nil {
		return failedRecord(request, "fixture_incompatible", err)
	}
	workspace, err := newNativeWorkspace(w.native.fixture)
	if err != nil {
		return failedRecord(request, "fixture_incompatible", fmt.Errorf("create native UnixFS workspace: %w", err))
	}
	if w.native.workspace != nil {
		_ = w.native.workspace.close()
	}
	w.native.workspace = workspace
	w.native.root = root
	record := baseRecord(request)
	record.Success = true
	record.Session = &sessionEvidence{AcceptedRoot: root.String()}
	return record
}

func (w *worker) mutate(request workerRequest) workerRecord {
	if _, ok := nativeOperations[request.Operation]; !ok {
		return failedRecord(request, "operation_unsupported", fmt.Errorf("unsupported native operation %q", request.Operation))
	}
	if w.native == nil || !w.native.root.Defined() || request.ExpectedAcceptedRoot != w.native.root.String() {
		return failedRecord(request, "root_continuity", fmt.Errorf("mutation expected root does not match retained session root"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), w.config.requestTimeout)
	defer cancel()
	usageBefore, err := readProcessUsage()
	if err != nil {
		return failedRecord(request, "measurement_unavailable", err)
	}
	mutationStarted := time.Now()
	load, err := w.native.app.Load(ctx, w.native.root, evaluationBounds)
	if err != nil {
		return failedRecord(request, classifyNativeFailure(err), fmt.Errorf("refresh update view: %w", err))
	}
	viewSnapshotStarted := time.Now()
	view, err := w.native.app.SnapshotView()
	viewSnapshotNS := durationNS(time.Since(viewSnapshotStarted))
	if err != nil {
		return failedRecord(request, "verification_failed", err)
	}
	currentSource, err := w.native.workspace.snapshot()
	if err != nil {
		return failedRecord(request, "fixture_incompatible", fmt.Errorf("scan native source pre-image: %w", err))
	}
	if err := w.native.fixture.ValidateViewAgainstSource(view, w.config.backend, currentSource); err != nil {
		return failedRecord(request, "fixture_incompatible", fmt.Errorf("native source pre-image binding: %w", err))
	}
	operation, err := w.native.fixture.Operation(request.Operation)
	if err != nil {
		return failedRecord(request, "fixture_incompatible", err)
	}
	prepared, err := prepareNativeOperation(operation, w.native.fixture, w.native.workspace, w.native.serial)
	if err != nil {
		return failedRecord(request, "fixture_incompatible", err)
	}
	var payloadUpload transport.PutBatchMeasurement
	if len(prepared.blocks) > 0 {
		payloadUpload, err = w.native.remote.PutBatchMeasured(ctx, prepared.blocks)
		if err != nil {
			return failedRecord(request, classifyNativeFailure(err), fmt.Errorf("upload operation payloads: %w", err))
		}
		results := payloadUpload.Results
		if len(results) != len(prepared.cids) {
			return failedRecord(request, "transport_invalid", fmt.Errorf("CAS batch returned a mismatched result count"))
		}
		for index := range results {
			if !results[index].CID.Equals(prepared.cids[index]) {
				return failedRecord(request, "transport_invalid", fmt.Errorf("CAS result %d does not match locally hashed payload", index))
			}
		}
	}
	intentPlanningStarted := time.Now()
	intent, err := planNativeIntent(view, operation, prepared.cids)
	intentPlanningNS := durationNS(time.Since(intentPlanningStarted))
	if err != nil {
		return failedRecord(request, "fixture_incompatible", err)
	}
	operationID := exactOperationID(request)
	result, err := w.native.app.Execute(ctx, operationID, intent)
	if err != nil {
		return failedRecord(request, classifyNativeFailure(err), err)
	}
	if result.Idempotent {
		return failedRecord(request, "gateway_instance_reused", fmt.Errorf("disposable Gateway returned an idempotent client-root replay"))
	}
	mutationTotalNS := durationNS(time.Since(mutationStarted))
	usageAfter, err := readProcessUsage()
	if err != nil || usageAfter.peakRSSBytes == 0 {
		return failedRecord(request, "measurement_unavailable", fmt.Errorf("read process usage after mutation: %w", err))
	}
	cpuNS := usageAfter.cpuNS - min(usageAfter.cpuNS, usageBefore.cpuNS)
	postView, err := w.native.app.SnapshotView()
	if err != nil {
		return failedRecord(request, "verification_failed", fmt.Errorf("snapshot native post-image: %w", err))
	}
	postSource, err := w.native.workspace.snapshot()
	if err != nil {
		return failedRecord(request, "fixture_incompatible", fmt.Errorf("scan native source post-image: %w", err))
	}
	if err := w.native.fixture.ValidateViewAgainstSource(postView, w.config.backend, postSource); err != nil {
		return failedRecord(request, "verification_failed", fmt.Errorf("native full source post-image oracle: %w", err))
	}
	encodedCandidate, err := encodeExpectedRoot(result.Candidate)
	if err != nil {
		return failedRecord(request, "verification_failed", err)
	}
	bundleDigest := result.Receipt.BundleDigest
	record := baseRecord(request)
	record.Success = true
	metrics, err := nativeMetrics(load, prepared, result.Metrics, viewSnapshotNS, intentPlanningNS, uint64(len(encodedCandidate)), payloadUpload, mutationTotalNS, cpuNS, usageAfter.peakRSSBytes)
	if err != nil {
		return failedRecord(request, "measurement_invalid", err)
	}
	if err := validateNativeMetricTaxonomy(metrics); err != nil {
		return failedRecord(request, "measurement_invalid", err)
	}
	record.Mutation = &mutationEvidence{
		Operation: request.Operation, PriorRoot: result.BaseRoot.String(), CandidateRoot: encodedCandidate,
		ReceiptRoot: result.Receipt.Candidate.String(), ReceiptAccepted: result.Receipt.Candidate.Equals(result.Candidate),
		UpdateViewSHA256: hex.EncodeToString(result.ViewDigest[:]), IntentSHA256: hex.EncodeToString(result.IntentDigest[:]),
		BundleSHA256: hex.EncodeToString(bundleDigest[:]),
		Metrics:      metrics,
	}
	w.native.root = result.Receipt.Candidate
	w.native.serial++
	w.receiptCount++
	return record
}

func (w *worker) endSession(request workerRequest) workerRecord {
	w.state = "finished"
	if w.native == nil || !w.native.root.Defined() || request.ExpectedAcceptedRoot != w.native.root.String() {
		return failedRecord(request, "root_continuity", fmt.Errorf("session-end root does not match retained exact receipt root"))
	}
	ctx, cancel := context.WithTimeout(context.Background(), w.config.requestTimeout)
	defer cancel()
	if err := w.native.app.Audit(ctx); err != nil {
		return failedRecord(request, "audit_failed", err)
	}
	record := baseRecord(request)
	record.Success = true
	record.Session = &sessionEvidence{AcceptedRoot: w.native.root.String(), ReceiptCount: w.receiptCount, AuditPassed: true}
	return record
}

func nativeMetrics(load clientrootapp.LoadMetrics, prepared preparedPayloads, operation clientrootapp.OperationMetrics, viewSnapshotNS, intentPlanningNS, expectedRootBytes uint64, payloadUpload transport.PutBatchMeasurement, mutationTotalNS, cpuNS, peakRSS uint64) (mutationMetrics, error) {
	phase := func(duration, bytes, count uint64) phaseMeasurement {
		return observedPhase(duration, bytes, max(uint64(1), count))
	}
	upload := notApplicablePhase()
	if len(prepared.blocks) > 0 {
		upload = phase(payloadUpload.RoundTripNS, payloadUpload.RequestWireBytes, uint64(len(prepared.blocks)))
	}
	sdk := operation.SDK
	externalNormalizationNS, err := rq2metrics.AddDurations(viewSnapshotNS, intentPlanningNS)
	if err != nil {
		return mutationMetrics{}, fmt.Errorf("external normalization timing: %w", err)
	}
	normalizationNS, err := rq2metrics.AddDurations(externalNormalizationNS, sdk.ViewNormalizationNS, sdk.IntentNormalizationNS)
	if err != nil {
		return mutationMetrics{}, fmt.Errorf("complete normalization timing: %w", err)
	}
	clientRootGenerationNS, err := rq2metrics.AddDurations(externalNormalizationNS, sdk.TotalNS)
	if err != nil {
		return mutationMetrics{}, fmt.Errorf("complete client-root generation timing: %w", err)
	}
	return mutationMetrics{
		TaxonomyProfile: rq2metrics.TaxonomyProfile,
		MutationTotal:   phase(mutationTotalNS, 0, 1),
		Scan:            prepared.scan, Chunk: prepared.chunk, Hash: prepared.hash,
		UpdateView:           phase(load.UpdateViewFetchNS, load.UpdateViewWireBytes, 1),
		VerifyUpdateView:     phase(load.VerifyUpdateViewNS, load.UpdateViewWireBytes, 1),
		Normalization:        phase(normalizationNS, 0, 4),
		CommitmentUpdate:     phase(sdk.CommitmentUpdateNS, 0, 1),
		ExpectedRootEncoding: phase(sdk.ExpectedRootEncodingNS, expectedRootBytes, 1),
		RootComputation:      phase(sdk.RootComputationNS, 0, 1),
		ClientRootGeneration: phase(clientRootGenerationNS, 0, 1),
		ClientRootBundle:     phase(operation.BundleEncodingNS, operation.BundleWireBytes, 1),
		// Upload is only the payload CAS request round trip. Bundle request
		// bytes and receipt response bytes remain directionally separated.
		Upload:         upload,
		GatewayReplay:  phase(operation.Gateway.GatewayReplayNS, 0, 1),
		GatewayPersist: phase(operation.Gateway.PersistNS, 0, 1),
		ReceiptCheck:   phase(operation.ReceiptCheckNS, operation.ReceiptWireBytes, 1),
		CPUTotal:       phase(cpuNS, 0, 1), PeakMemory: phase(0, peakRSS, 1),
		WASMDownload: notApplicablePhase(), WASMInstantiate: notApplicablePhase(), ParameterLoad: notApplicablePhase(),
		FirstMutation: notApplicablePhase(), JSWASMBoundary: notApplicablePhase(),
	}, nil
}

func validateNativeMetricTaxonomy(metrics mutationMetrics) error {
	values := make(map[string]rq2metrics.Observation, 23)
	for _, metric := range []struct {
		name  string
		value phaseMeasurement
	}{
		{"mutation_total", metrics.MutationTotal}, {"scan", metrics.Scan}, {"chunk", metrics.Chunk}, {"hash", metrics.Hash},
		{"update_view", metrics.UpdateView}, {"verify_update_view", metrics.VerifyUpdateView}, {"normalization", metrics.Normalization},
		{"commitment_update", metrics.CommitmentUpdate}, {"expected_root_encoding", metrics.ExpectedRootEncoding},
		{"root_computation", metrics.RootComputation}, {"client_root_generation", metrics.ClientRootGeneration},
		{"client_root_bundle", metrics.ClientRootBundle}, {"upload", metrics.Upload}, {"gateway_replay", metrics.GatewayReplay},
		{"gateway_persist", metrics.GatewayPersist}, {"receipt_check", metrics.ReceiptCheck}, {"cpu_total", metrics.CPUTotal},
		{"peak_memory", metrics.PeakMemory}, {"wasm_download", metrics.WASMDownload}, {"wasm_instantiate", metrics.WASMInstantiate},
		{"parameter_load", metrics.ParameterLoad}, {"first_mutation", metrics.FirstMutation}, {"js_wasm_boundary", metrics.JSWASMBoundary},
	} {
		values[metric.name] = rq2metrics.Observation{Applicable: metric.value.Applicable, DurationNS: metric.value.DurationNS}
	}
	return rq2metrics.Validate(metrics.TaxonomyProfile, values, false, false)
}

func encodeExpectedRoot(candidate cid.Cid) (string, error) {
	encoded := candidate.String()
	parsed, err := cid.Parse(encoded)
	if err != nil || !parsed.Equals(candidate) {
		return "", fmt.Errorf("expected-root CID encoding did not round-trip")
	}
	return encoded, nil
}

func exactOperationID(request workerRequest) string {
	value := request.WorkerID + "\x00" + request.SessionID + "\x00" + request.RequestID + "\x00" + request.Operation
	digest := mutationDigest([]byte(value))
	return "rq2-" + hex.EncodeToString(digest[:16])
}

func classifyNativeFailure(err error) string {
	if err == nil {
		return "unknown"
	}
	if _, ok := err.(*transport.Error); ok {
		return "gateway_rejected"
	}
	if contextCanceled(err) {
		return "timeout"
	}
	return "client_root_failed"
}

func contextCanceled(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func durationNS(value time.Duration) uint64 {
	if value <= 0 {
		return 0
	}
	return uint64(value)
}

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"slices"
	"strconv"
	"time"

	clientrootapp "github.com/dewebprotocol/malt-client/application/clientroot"
	"github.com/dewebprotocol/malt-client/merkledag/rq3baseline"
	"github.com/dewebprotocol/malt-client/transport"
	"github.com/dewebprotocol/malt/auth/arcset"
	materializermemory "github.com/dewebprotocol/malt/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt/auth/commitment"
	"github.com/dewebprotocol/malt/auth/commitment/kzg"
	"github.com/dewebprotocol/malt/mutation"
	"github.com/dewebprotocol/malt/protocol"
	clientwriter "github.com/dewebprotocol/malt/sdk/writer"
	"github.com/dewebprotocol/malt/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

const (
	healthCASAccounting = "cas.put-batch-disposition/v1"
	healthCASIsolation  = "gateway-process-serialized"
)

type workerConfig struct {
	gatewayBaseURL              string
	instanceToken               string
	bootstrapAuthorizationToken string
	requestTimeout              time.Duration
	initialRoot                 string
}

type campaignWorker struct {
	config workerConfig
	remote *transport.Client
}

type clientRootRemote struct{ client *transport.Client }

func (r clientRootRemote) FetchUpdateView(ctx context.Context, root cid.Cid, bounds *protocol.UpdateViewBounds) (clientrootapp.ViewEnvelope, error) {
	response, err := r.client.FetchUpdateView(ctx, root, bounds)
	if err != nil {
		return clientrootapp.ViewEnvelope{}, err
	}
	return clientrootapp.ViewEnvelope{View: response.View, WireBytes: response.WireBytes}, nil
}

func (r clientRootRemote) SubmitClientRoot(ctx context.Context, bundle mutation.ClientRootBundle) (clientrootapp.ReceiptEnvelope, error) {
	response, err := r.client.SubmitClientRoot(ctx, bundle)
	if err != nil {
		return clientrootapp.ReceiptEnvelope{}, err
	}
	accounting := clientrootapp.GatewayWriteAccounting{
		Profile: response.WriteAccounting.Profile, Available: response.WriteAccounting.Available,
		UnavailableReason: response.WriteAccounting.UnavailableReason, ByteMethod: response.WriteAccounting.ByteMethod,
		ObjectLedgerSHA256: response.WriteAccounting.ObjectLedgerSHA256, WireBytes: response.WriteAccountingWireBytes,
		Categories: make([]clientrootapp.GatewayWriteCategoryAccounting, len(response.WriteAccounting.Categories)),
	}
	for index, category := range response.WriteAccounting.Categories {
		accounting.Categories[index] = clientrootapp.GatewayWriteCategoryAccounting{
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
	return clientrootapp.ReceiptEnvelope{
		Receipt: response.Receipt, RequestWireBytes: response.RequestWireBytes, ResponseWireBytes: response.ResponseWireBytes,
		RequestEncodingNS: response.RequestEncodingNS, ResponseVerifyNS: response.ResponseVerifyNS,
		Idempotent: response.Idempotent,
		Gateway: clientrootapp.GatewayPhaseMetrics{
			OldStateValidationNS: response.Gateway.OldStateValidationNS, GatewayReplayNS: response.Gateway.GatewayReplayNS,
			PersistNS: response.Gateway.PersistNS, ReceiptNS: response.Gateway.ReceiptNS,
		},
		WriteAccounting: accounting,
	}, nil
}

func newCampaignWorker(config workerConfig) (*campaignWorker, error) {
	client, err := transport.New(transport.Options{
		BaseURL:    config.gatewayBaseURL,
		HTTPClient: &http.Client{Timeout: config.requestTimeout},
	})
	if err != nil {
		return nil, err
	}
	return &campaignWorker{config: config, remote: client}, nil
}

func (w *campaignWorker) validateHealth(ctx context.Context) error {
	checkCtx, cancel := context.WithTimeout(ctx, w.config.requestTimeout)
	defer cancel()
	health, err := w.remote.Health(checkCtx)
	if err != nil {
		return fmt.Errorf("Gateway health: %w", err)
	}
	if health.Status != "ok" || health.EvaluationInstanceToken != w.config.instanceToken ||
		health.BlobBackend != "embedded" || health.ArcTableMode != "versioned" ||
		health.CommitmentProfile != "kzg" || health.CommitmentBackends != "ipa,kzg" ||
		health.EvaluationCASWriteAccounting != healthCASAccounting || health.EvaluationCASWriteIsolation != healthCASIsolation ||
		health.ClientRootWriteAccounting != gatewayAccountingProfile || health.ClientRootExactAcceptance != "true" ||
		health.EvaluationClientRootBootstrap != transport.EvaluationClientRootBootstrapProfile {
		return fmt.Errorf("Gateway health does not expose the exact disposable embedded/versioned/KZG evaluation boundary")
	}
	return nil
}

func (w *campaignWorker) run(ctx context.Context, spec runSpec) (*runResult, error) {
	if !validRunCoordinate(spec.PassMode, spec.RunPhase, spec.ClusterID, spec.RunIndex) {
		return nil, fmt.Errorf("invalid raw RQ3 pass/run/cluster coordinate")
	}
	if err := validateWorkloadIdentity(spec.Workload); err != nil {
		return nil, err
	}
	if err := validateFrozenCommitListBinding(spec); err != nil {
		return nil, err
	}
	if w.config.initialRoot != spec.InitialRoot {
		return nil, fmt.Errorf("-initial-root and run.initial_root do not match")
	}
	if spec.InitialRoot != "" {
		return nil, fmt.Errorf("nonempty initial_root cannot fairly account the frozen snapshot; a clean disposable Gateway is required")
	}
	if err := w.validateHealth(ctx); err != nil {
		return nil, err
	}

	baselineSpec := rq3baseline.RunSpec{
		System: rq3baseline.SystemMerkleDAGUnixFS,
		Layout: rq3baseline.LayoutSpec{
			Model: "unixfs", FileLayout: "balanced", DirectoryLayout: "basic",
			Chunking:   rq3baseline.ChunkingSpec{Algorithm: "fixed", SizeBytes: int(spec.Workload.ChunkBytes)},
			HAMTFanout: 0, RawFileLeaf: boolPointer(true),
		},
		Snapshot: spec.Snapshot, Commits: spec.Commits,
	}
	sourceAccounting, err := rq3baseline.ValidateAndAccountSource(baselineSpec)
	if err != nil {
		return nil, fmt.Errorf("frozen workload semantic prevalidation: %w", err)
	}
	if len(sourceAccounting) != len(spec.Commits)+1 {
		return nil, fmt.Errorf("semantic prevalidation returned mismatched source accounting")
	}

	scheme, err := kzg.NewScheme()
	if err != nil {
		return nil, fmt.Errorf("initialize local KZG: %w", err)
	}
	setupBuilder := graphBuilder{chunkBytes: spec.Workload.ChunkBytes, scheme: scheme, store: materializermemory.New(true)}
	oracleBuilder := graphBuilder{chunkBytes: spec.Workload.ChunkBytes, scheme: scheme, store: materializermemory.New(true)}
	runtime, err := clientwriter.NewRuntime(
		materializermemory.New(true), map[maltcid.BackendKind]commitment.IndexCommitment{maltcid.BackendKindKZG: scheme},
	)
	if err != nil {
		return nil, err
	}
	session, err := clientrootapp.New(clientRootRemote{client: w.remote}, runtime)
	if err != nil {
		return nil, err
	}

	result := &runResult{
		SchemaVersion: runResultSchema, CapabilityID: capabilityID, System: systemMALTKZG,
		PassMode: spec.PassMode, RunPhase: spec.RunPhase, ClusterID: spec.ClusterID, RunIndex: spec.RunIndex,
		Workload: spec.Workload, Commits: make([]commitRecord, 0, len(sourceAccounting)), WriteEvents: []writeEvent{},
	}
	roles := make(map[string]string)

	// A single canonical empty top object is the evaluator-only setup needed to
	// obtain an authenticated base. It is not a separately timed workload
	// operation: the frozen snapshot below is the first real operation and uses
	// the same client-root product path as every subsequent commit. Its durable
	// allocations are nevertheless real state in the clean Gateway directory,
	// so the accounting pass attributes them to the first snapshot commit and
	// marks their causes as canonical-empty setup. This keeps the logical ledger
	// reconcilable with physical state without contaminating snapshot latency.
	setupState := map[string]logicalFile{}
	setupBlueprint, err := buildBlueprint(setupState, spec.Workload.ChunkBytes)
	if err != nil {
		return nil, fmt.Errorf("build canonical empty setup blueprint: %w", err)
	}
	setupGraph, err := setupBuilder.build(ctx, setupState)
	if err != nil {
		return nil, fmt.Errorf("build canonical empty setup root: %w", err)
	}
	setupObject := setupGraph.objects[setupGraph.topID]
	if len(setupGraph.objects) != 1 || len(setupGraph.order) != 1 || setupGraph.order[0] != setupGraph.topID ||
		len(setupBlueprint.objects) != 1 || len(setupBlueprint.order) != 1 || setupBlueprint.order[0] != setupBlueprint.topID ||
		setupGraph.topID != setupBlueprint.topID || setupObject == nil || !setupGraph.root.Equals(setupObject.root) {
		return nil, fmt.Errorf("canonical empty setup must contain exactly one authenticated top object")
	}
	setupSink := &runResult{PassMode: spec.PassMode, WriteEvents: []writeEvent{}}
	if err := uploadClassifiedBlocks(ctx, w.remote, spec.Snapshot.CommitID, sortedManifestBlocks(setupGraph), roles, setupSink); err != nil {
		return nil, fmt.Errorf("upload canonical empty setup metadata: %w", err)
	}
	if _, _, err := w.bootstrapGraph(ctx, spec.Snapshot.CommitID, setupGraph, setupSink); err != nil {
		return nil, fmt.Errorf("bootstrap canonical empty setup root: %w", err)
	}
	attributeCanonicalEmptySetup(result, setupSink, spec.Snapshot.CommitID)

	snapshotStarted := time.Now()
	_, err = session.Load(ctx, setupGraph.root, evaluationBounds())
	if err != nil {
		return nil, fmt.Errorf("load canonical empty setup root: %w", err)
	}
	state, snapshotBlocks, err := initialLogicalState(spec.Snapshot, spec.Workload.ChunkBytes)
	if err != nil {
		return nil, err
	}
	snapshotBlueprint, err := buildBlueprint(state, spec.Workload.ChunkBytes)
	if err != nil {
		return nil, fmt.Errorf("plan output-free snapshot blueprint: %w", err)
	}
	view, err := session.SnapshotView()
	if err != nil {
		return nil, err
	}
	snapshotIntent, err := blueprintIntent(view, setupGraph, setupBlueprint, snapshotBlueprint, spec.Snapshot.CommitID)
	if err != nil {
		return nil, fmt.Errorf("plan output-free snapshot intent: %w", err)
	}
	snapshotBlocks = append(snapshotBlocks, blueprintManifestChanges(setupBlueprint, snapshotBlueprint)...)
	if err := uploadClassifiedBlocks(ctx, w.remote, spec.Snapshot.CommitID, snapshotBlocks, roles, result); err != nil {
		return nil, err
	}
	snapshotOperation, err := session.Execute(ctx, operationID(spec.Snapshot.CommitID, 0), snapshotIntent)
	if err != nil {
		return nil, fmt.Errorf("execute exact snapshot client root: %w", err)
	}
	snapshotClientNS := durationNanos(time.Since(snapshotStarted))
	if snapshotOperation.Idempotent || !snapshotOperation.Receipt.Candidate.Equals(snapshotOperation.Candidate) {
		return nil, fmt.Errorf("snapshot Gateway receipt does not match the locally computed candidate")
	}
	if spec.PassMode == "accounting" {
		if err := result.appendGatewayAccounting(spec.Snapshot.CommitID, accountingFromApplication(snapshotOperation.Metrics.WriteAccounting)); err != nil {
			return nil, err
		}
	}
	replayNS, err := evaluatorNanos(snapshotOperation.Metrics.Gateway.GatewayReplayNS)
	if err != nil {
		return nil, fmt.Errorf("snapshot Gateway replay duration: %w", err)
	}
	persistNS, err := evaluatorNanos(snapshotOperation.Metrics.Gateway.PersistNS)
	if err != nil {
		return nil, fmt.Errorf("snapshot Gateway persist duration: %w", err)
	}
	snapshotOracle, err := oracleBuilder.build(ctx, state)
	if err != nil || !snapshotOracle.root.Equals(snapshotOperation.Candidate) {
		if err == nil {
			err = fmt.Errorf("candidate %s differs from independent oracle %s", snapshotOperation.Candidate, snapshotOracle.root)
		}
		return nil, fmt.Errorf("untimed independent snapshot oracle: %w", err)
	}
	logical := sourceAccounting[0]
	result.Commits = append(result.Commits, commitRecord{
		Order: 0, CommitID: spec.Snapshot.CommitID, Root: snapshotOperation.Candidate.String(), HistoryRootsRetained: 1,
		NonWorkloadSetupRootsRetained: 1,
		LogicalObjectsChanged:         logical.LogicalObjectsChanged, LogicalBindingsChanged: logical.LogicalBindingsChanged,
		LogicalPayloadBytes: logical.AdapterPayloadInputBytes, AdapterPayloadInputBytes: logical.AdapterPayloadInputBytes,
		ClientComputeWallNS: snapshotClientNS,
		GatewayReplayWallNS: replayNS, GatewayPersistWallNS: persistNS,
		OracleUnmeasured: true,
	})
	graph := snapshotOracle
	blueprint := snapshotBlueprint
	changedChunksOnly := spec.Workload.Kind == "git-first-parent" || isControlledListHistory(spec)
	for index, commit := range spec.Commits {
		operationStarted := time.Now()
		blocks, canonicalPayloadBytes, changes, err := applyFrozenCommit(state, commit, spec.Workload.ChunkBytes, changedChunksOnly)
		if err != nil {
			return nil, err
		}
		nextBlueprint, err := buildBlueprintNext(blueprint, state, changes, spec.Workload.ChunkBytes)
		if err != nil {
			return nil, err
		}
		view, err := session.SnapshotView()
		if err != nil {
			return nil, err
		}
		intent, err := blueprintIntent(view, graph, blueprint, nextBlueprint, commit.CommitID)
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, blueprintManifestChanges(blueprint, nextBlueprint)...)
		if err := uploadClassifiedBlocks(ctx, w.remote, commit.CommitID, blocks, roles, result); err != nil {
			return nil, err
		}
		operation, err := session.Execute(ctx, operationID(commit.CommitID, uint32(index+1)), intent)
		if err != nil {
			return nil, fmt.Errorf("execute exact client root for %q: %w", commit.CommitID, err)
		}
		clientNS := durationNanos(time.Since(operationStarted))
		if operation.Idempotent || !operation.Receipt.Candidate.Equals(operation.Candidate) {
			return nil, fmt.Errorf("Gateway receipt for %q does not match the locally computed candidate", commit.CommitID)
		}
		if spec.PassMode == "accounting" {
			if err := result.appendGatewayAccounting(commit.CommitID, accountingFromApplication(operation.Metrics.WriteAccounting)); err != nil {
				return nil, err
			}
		}
		gatewayReplayNS, err := evaluatorNanos(operation.Metrics.Gateway.GatewayReplayNS)
		if err != nil {
			return nil, fmt.Errorf("Gateway replay duration for %q: %w", commit.CommitID, err)
		}
		gatewayPersistNS, err := evaluatorNanos(operation.Metrics.Gateway.PersistNS)
		if err != nil {
			return nil, fmt.Errorf("Gateway persist duration for %q: %w", commit.CommitID, err)
		}
		logical = sourceAccounting[index+1]
		oracleGraph, err := oracleBuilder.build(ctx, state)
		if err != nil {
			return nil, fmt.Errorf("untimed full-build oracle for %q: %w", commit.CommitID, err)
		}
		if !oracleGraph.root.Equals(operation.Candidate) {
			return nil, fmt.Errorf("single-compute candidate for %q does not match the untimed independent full-build oracle", commit.CommitID)
		}
		result.Commits = append(result.Commits, commitRecord{
			Order: uint32(index + 1), CommitID: commit.CommitID, ParentRoot: graph.root.String(), Root: operation.Candidate.String(),
			HistoryRootsRetained: uint32(index + 2), NonWorkloadSetupRootsRetained: 1,
			LogicalObjectsChanged:  logical.LogicalObjectsChanged,
			LogicalBindingsChanged: logical.LogicalBindingsChanged, LogicalPayloadBytes: canonicalPayloadBytes,
			AdapterPayloadInputBytes: logical.AdapterPayloadInputBytes,
			ClientComputeWallNS:      clientNS, GatewayReplayWallNS: gatewayReplayNS,
			GatewayPersistWallNS: gatewayPersistNS, OracleUnmeasured: true,
		})
		graph = oracleGraph
		blueprint = nextBlueprint
	}
	if err := session.Audit(ctx); err != nil {
		return nil, fmt.Errorf("audit retained client-root session: %w", err)
	}
	if spec.PassMode == "timing" && len(result.WriteEvents) != 0 {
		return nil, fmt.Errorf("timing pass retained byte-accounting events")
	}
	if err := postMeasurementBaselineConformance(ctx, baselineSpec, result, rq3baseline.Run); err != nil {
		return nil, err
	}
	return result, nil
}

// validateFrozenCommitListBinding closes the last source-to-worker identity
// hop. The evaluator derives this digest from the controlled workload or the
// exact Git first-parent trace; the worker independently recomputes it from
// the snapshot and commit sequence it is about to execute.
func validateFrozenCommitListBinding(spec runSpec) error {
	commitIDs := make([]string, 0, len(spec.Commits)+1)
	commitIDs = append(commitIDs, spec.Snapshot.CommitID)
	for _, commit := range spec.Commits {
		commitIDs = append(commitIDs, commit.CommitID)
	}
	encoded, err := json.Marshal(struct {
		Commits []string `json:"commits"`
	}{Commits: commitIDs})
	if err != nil {
		return fmt.Errorf("encode frozen commit-list binding: %w", err)
	}
	digest := sha256.Sum256(encoded)
	if hex.EncodeToString(digest[:]) != spec.Workload.CommitListSHA256 {
		return fmt.Errorf("frozen snapshot/commit sequence does not match workload commit_list_sha256")
	}
	return nil
}

type baselineRunner func(context.Context, rq3baseline.RunSpec) (*rq3baseline.RunResult, error)

// postMeasurementBaselineConformance deliberately runs only after the MALT
// session has produced every commit and passed its retained-state audit. The
// UnixFS adapter is therefore never a one-sided prewarm for measured MALT.
func postMeasurementBaselineConformance(ctx context.Context, spec rq3baseline.RunSpec, result *runResult, runBaseline baselineRunner) error {
	if result == nil || len(result.Commits) != len(spec.Commits)+1 {
		return fmt.Errorf("MALT measurements are incomplete before baseline conformance")
	}
	baseline, err := runBaseline(ctx, spec)
	if err != nil {
		return fmt.Errorf("post-measurement frozen workload baseline conformance: %w", err)
	}
	if len(baseline.Records) != len(result.Commits) {
		return fmt.Errorf("post-measurement baseline conformance returned a mismatched commit count")
	}
	for index, record := range baseline.Records {
		commit := result.Commits[index]
		if record.CommitID != commit.CommitID || record.LogicalObjectsChanged != commit.LogicalObjectsChanged ||
			record.LogicalBindingsChanged != commit.LogicalBindingsChanged || record.AdapterPayloadInputBytes != commit.AdapterPayloadInputBytes ||
			commit.HistoryRootsRetained != uint32(index+1) || commit.NonWorkloadSetupRootsRetained != 1 {
			return fmt.Errorf("post-measurement baseline conformance mismatch at commit %q", commit.CommitID)
		}
	}
	return nil
}

func boolPointer(value bool) *bool { return &value }

func validRunCoordinate(passMode, runPhase, clusterID string, runIndex int) bool {
	if !canonicalEvaluatorID(clusterID) || runIndex < 0 {
		return false
	}
	if passMode == "accounting" {
		return runPhase == "accounting" && runIndex == 0
	}
	return passMode == "timing" && (runPhase == "feasibility" || runPhase == "measured")
}

func isControlledListHistory(spec runSpec) bool {
	return spec.Workload.Kind == "controlled" && spec.Workload.ControlledStructure == "list"
}

func (w *campaignWorker) bootstrapGraph(ctx context.Context, commitID string, graph *hybridGraph, result *runResult) (int64, int64, error) {
	seenRoots := make(map[string]struct{}, len(graph.objects))
	var replayTotal, persistTotal uint64
	for order, logicalID := range graph.order {
		object := graph.objects[logicalID]
		if _, duplicate := seenRoots[object.root.KeyString()]; duplicate {
			continue
		}
		seenRoots[object.root.KeyString()] = struct{}{}
		entries := make([]transport.EvaluationBootstrapEntry, object.entries.Len())
		for index, entry := range object.entries.Entries() {
			entries[index].Target = entry.Target.CID()
			if object.kind == arcset.KindMap {
				coordinate := entry.Coordinate.String()
				entries[index].Path = &coordinate
			} else {
				coordinate, err := listIndex(entry)
				if err != nil {
					return 0, 0, err
				}
				entries[index].Index = &coordinate
			}
		}
		bootstrap, err := w.remote.BootstrapEvaluationObject(ctx, w.config.bootstrapAuthorizationToken, transport.EvaluationBootstrapObject{
			OperationID: operationID(commitID+"-bootstrap-"+strconv.Itoa(order), uint32(order)),
			Kind:        object.kind, Backend: maltcid.BackendKindKZG, ExpectedRoot: object.root,
			Entries: entries, Commit: object.commit,
		})
		if err != nil {
			return 0, 0, fmt.Errorf("bootstrap hybrid object %q: %w", logicalID, err)
		}
		if result.PassMode == "accounting" {
			if err := result.appendGatewayAccounting(commitID, accountingFromTransport(bootstrap.WriteAccounting)); err != nil {
				return 0, 0, err
			}
		}
		if replayTotal > math.MaxUint64-bootstrap.ReplayNanos || persistTotal > math.MaxUint64-bootstrap.PersistNanos {
			return 0, 0, fmt.Errorf("bootstrap phase duration overflow")
		}
		replayTotal += bootstrap.ReplayNanos
		persistTotal += bootstrap.PersistNanos
	}
	if replayTotal > math.MaxInt64 || persistTotal > math.MaxInt64 {
		return 0, 0, fmt.Errorf("bootstrap phase duration exceeds evaluator range")
	}
	return int64(replayTotal), int64(persistTotal), nil
}

func sortedManifestBlocks(graph *hybridGraph) []classifiedBlock {
	paths := make([]string, 0, len(graph.manifests))
	for value := range graph.manifests {
		paths = append(paths, value)
	}
	slices.Sort(paths)
	result := make([]classifiedBlock, len(paths))
	for index, value := range paths {
		result[index] = graph.manifests[value]
	}
	return result
}

func validateWorkloadIdentity(value workloadIdentity) error {
	if !canonicalEvaluatorID(value.ID) || (value.Kind != "controlled" && value.Kind != "git-first-parent") ||
		!canonicalSHA256(value.ArtifactSHA256) || !canonicalSHA256(value.SemanticSHA256) ||
		!canonicalSHA256(value.CommitListSHA256) || value.ChunkBytes == 0 || value.ChunkBytes > 16<<20 ||
		value.HistoryRetention != "all-roots" || (value.Kind == "controlled") != (value.ControlledCoordinate != nil) ||
		(value.Kind == "controlled" && value.ControlledStructure != "map" && value.ControlledStructure != "list") ||
		(value.Kind != "controlled" && value.ControlledStructure != "") || !validControlledCoordinate(value) {
		return fmt.Errorf("invalid RQ3 workload identity")
	}
	return nil
}

func validControlledCoordinate(value workloadIdentity) bool {
	if value.ControlledCoordinate == nil {
		return value.Kind != "controlled"
	}
	coordinate := value.ControlledCoordinate
	isRelocation := coordinate.Operation == "rename" || coordinate.Operation == "move"
	return value.Kind == "controlled" && canonicalEvaluatorID(coordinate.Operation) && coordinate.PathDepth > 0 &&
		coordinate.DirectoryWidth > 0 && coordinate.FileChunks > 0 && coordinate.BatchSize > 0 && coordinate.RenamedBindings >= 0 &&
		(coordinate.Operation == "subtree-rename") == (coordinate.RenamedBindings > 1) &&
		(!isRelocation || coordinate.RenamedBindings == 1) &&
		(isRelocation || coordinate.Operation == "subtree-rename" || coordinate.RenamedBindings == 0)
}

func canonicalEvaluatorID(value string) bool {
	if len(value) == 0 || len(value) > 128 || !lowerAlphaNumeric(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !lowerAlphaNumeric(character) && character != '.' && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func lowerAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func evaluationBounds() *protocol.UpdateViewBounds {
	return &protocol.UpdateViewBounds{
		MaxObjects: protocol.MaxClientRootObjects, MaxTotalEntries: protocol.MaxClientRootEntries,
		MaxDepth: protocol.MaxClientRootDepth,
	}
}

func operationID(commitID string, order uint32) string {
	return stableIntentID("rq3", fmt.Sprintf("%d\x00%s", order, commitID))
}

func durationNanos(value time.Duration) int64 {
	if value <= 0 {
		return 1
	}
	return value.Nanoseconds()
}

func addDuration(a int64, b uint64) (int64, error) {
	if b > math.MaxInt64 || a > math.MaxInt64-int64(b) {
		return 0, fmt.Errorf("client duration overflow")
	}
	return a + int64(b), nil
}

func evaluatorNanos(value uint64) (int64, error) {
	if value > math.MaxInt64 {
		return 0, fmt.Errorf("duration exceeds evaluator range")
	}
	return int64(value), nil
}

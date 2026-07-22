// Package clientroot owns the reusable native client-root workflow. It keeps
// untrusted transport, local candidate computation, durable acknowledgement,
// publication, and accepted-root policy as distinct boundaries.
package clientroot

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dewebprotocol/malt/mutation"
	"github.com/dewebprotocol/malt/protocol"
	clientwriter "github.com/dewebprotocol/malt/sdk/writer"
	cid "github.com/ipfs/go-cid"
)

// GatewayPhaseMetrics are untrusted service diagnostics copied from response
// headers. The exact materialization receipt, not these counters, controls
// whether a writer session may advance.
type GatewayPhaseMetrics struct {
	OldStateValidationNS uint64 `json:"old_state_validation_ns"`
	GatewayReplayNS      uint64 `json:"gateway_replay_ns"`
	PersistNS            uint64 `json:"persist_ns"`
	ReceiptNS            uint64 `json:"receipt_ns"`
}

// GatewayWriteAccounting is untrusted request-local logical KV accounting.
// Payload CAS and physical backend accounting remain separate evaluator inputs.
type GatewayWriteAccounting struct {
	Profile            string                           `json:"profile"`
	Available          bool                             `json:"available"`
	UnavailableReason  string                           `json:"unavailable_reason,omitempty"`
	ByteMethod         string                           `json:"byte_method"`
	ObjectLedgerSHA256 string                           `json:"object_ledger_sha256,omitempty"`
	Categories         []GatewayWriteCategoryAccounting `json:"categories"`
	WireBytes          uint64                           `json:"wire_bytes"`
}

type GatewayWriteCategoryAccounting struct {
	Category                   string `json:"category"`
	AttemptedWrites            uint64 `json:"attempted_writes"`
	AttemptedBytes             uint64 `json:"attempted_bytes"`
	AttemptedNewWrites         uint64 `json:"attempted_new_writes"`
	AttemptedNewBytes          uint64 `json:"attempted_new_bytes"`
	AttemptedReplacementWrites uint64 `json:"attempted_replacement_writes"`
	AttemptedReplacementBytes  uint64 `json:"attempted_replacement_bytes"`
	AttemptedSameValueWrites   uint64 `json:"attempted_same_value_writes"`
	AttemptedSameValueBytes    uint64 `json:"attempted_same_value_bytes"`
	AttemptedDeleteWrites      uint64 `json:"attempted_delete_writes"`
	AttemptedDeleteBytes       uint64 `json:"attempted_delete_bytes"`
	NewlyPersistedWrites       uint64 `json:"newly_persisted_writes"`
	GrossNewBytes              uint64 `json:"gross_new_bytes"`
	NewWrites                  uint64 `json:"new_writes"`
	NewBytes                   uint64 `json:"new_bytes"`
	ReplacedWrites             uint64 `json:"replaced_writes"`
	ReplacementNewBytes        uint64 `json:"replacement_new_bytes"`
	ReplacementReclaimedBytes  uint64 `json:"replacement_reclaimed_bytes"`
	SameValueWrites            uint64 `json:"same_value_writes"`
	DeletedWrites              uint64 `json:"deleted_writes"`
	DeletedReclaimedBytes      uint64 `json:"deleted_reclaimed_bytes"`
	ReclaimedBytes             uint64 `json:"reclaimed_bytes"`
	NetBytes                   int64  `json:"net_bytes"`
}

type ViewEnvelope struct {
	View      mutation.UpdateView
	WireBytes uint64
}

type ReceiptEnvelope struct {
	Receipt           mutation.MaterializationReceipt
	RequestWireBytes  uint64
	ResponseWireBytes uint64
	RequestEncodingNS uint64
	ResponseVerifyNS  uint64
	Idempotent        bool
	Gateway           GatewayPhaseMetrics
	WriteAccounting   GatewayWriteAccounting
}

// Remote is the narrow untrusted Gateway capability used by this workflow.
// Command/composition adapters map concrete HTTP transport values into these
// transport-neutral envelopes.
type Remote interface {
	FetchUpdateView(context.Context, cid.Cid, *protocol.UpdateViewBounds) (ViewEnvelope, error)
	SubmitClientRoot(context.Context, mutation.ClientRootBundle) (ReceiptEnvelope, error)
}

type LoadMetrics struct {
	UpdateViewFetchNS   uint64 `json:"update_view_fetch_ns"`
	UpdateViewWireBytes uint64 `json:"update_view_wire_bytes"`
	VerifyUpdateViewNS  uint64 `json:"verify_update_view_ns"`
}

type OperationMetrics struct {
	LocalRootComputationNS uint64                      `json:"local_root_computation_ns"`
	SDK                    clientwriter.ComputeMetrics `json:"sdk"`
	// SubmitRoundTripNS is an inclusive diagnostic around the complete Remote
	// call. It contains request encoding, the HTTP exchange, Gateway work, and
	// response verification; evaluators must not add it to those subphases.
	SubmitRoundTripNS uint64                 `json:"submit_round_trip_ns"`
	BundleWireBytes   uint64                 `json:"bundle_wire_bytes"`
	ReceiptWireBytes  uint64                 `json:"receipt_wire_bytes"`
	BundleEncodingNS  uint64                 `json:"bundle_encoding_ns"`
	ReceiptCheckNS    uint64                 `json:"receipt_check_ns"`
	Gateway           GatewayPhaseMetrics    `json:"gateway"`
	WriteAccounting   GatewayWriteAccounting `json:"write_accounting"`
}

type OperationResult struct {
	BaseRoot     cid.Cid
	Candidate    cid.Cid
	ViewDigest   [32]byte
	IntentDigest [32]byte
	Receipt      mutation.MaterializationReceipt
	Idempotent   bool
	Metrics      OperationMetrics
}

// Session retains verified state across mutations. A successful exact durable
// receipt advances writer state but never invokes accepted-root or publication
// policy. Only one prepare/submit transaction is allowed at a time.
type Session struct {
	mu     sync.Mutex
	remote Remote
	writer *clientwriter.Session
	loaded bool
	load   LoadMetrics
	view   mutation.UpdateView
}

func New(remote Remote, runtime *clientwriter.Runtime) (*Session, error) {
	if remote == nil {
		return nil, fmt.Errorf("client-root remote is nil")
	}
	writerSession, err := clientwriter.NewSession(runtime)
	if err != nil {
		return nil, err
	}
	return &Session{remote: remote, writer: writerSession}, nil
}

// Load fetches and independently verifies the complete old state. A failed
// load leaves any prior state unchanged.
func (s *Session) Load(ctx context.Context, root cid.Cid, bounds *protocol.UpdateViewBounds) (LoadMetrics, error) {
	if s == nil {
		return LoadMetrics{}, fmt.Errorf("client-root session is nil")
	}
	if !root.Defined() {
		return LoadMetrics{}, fmt.Errorf("client-root base is undefined")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	fetchStart := time.Now()
	envelope, err := s.remote.FetchUpdateView(ctx, root, bounds)
	fetchDuration := time.Since(fetchStart)
	if err != nil {
		return LoadMetrics{}, err
	}
	if !envelope.View.BaseRoot.Equals(root) {
		return LoadMetrics{}, fmt.Errorf("update-view base %s does not match requested root %s", envelope.View.BaseRoot, root)
	}
	verifyStart := time.Now()
	if err := s.writer.Load(ctx, envelope.View); err != nil {
		return LoadMetrics{}, fmt.Errorf("verify update view: %w", err)
	}
	metrics := LoadMetrics{
		UpdateViewFetchNS: durationNS(fetchDuration), UpdateViewWireBytes: envelope.WireBytes,
		VerifyUpdateViewNS: durationNS(time.Since(verifyStart)),
	}
	s.loaded = true
	s.load = metrics
	s.view = envelope.View
	return metrics, nil
}

func (s *Session) LoadMetrics() LoadMetrics {
	if s == nil {
		return LoadMetrics{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load
}

func (s *Session) BaseRoot() cid.Cid {
	if s == nil {
		return cid.Undef
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.loaded {
		return cid.Undef
	}
	return s.writer.BaseRoot()
}

// SnapshotView returns a canonical deep copy of the complete logical state
// retained by the writer. Application planners may use it to construct an
// output-free semantic intent; callers cannot mutate session state through the
// returned value.
func (s *Session) SnapshotView() (mutation.UpdateView, error) {
	if s == nil {
		return mutation.UpdateView{}, fmt.Errorf("client-root session is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.loaded {
		return mutation.UpdateView{}, fmt.Errorf("client-root session has no verified update view")
	}
	return mutation.NormalizeUpdateView(s.view)
}

// Execute computes and submits exactly one candidate. Failure at any point
// leaves the session base unchanged. Success advances only the retained writer
// state after validating the exact durable receipt.
func (s *Session) Execute(ctx context.Context, operationID string, intent mutation.SemanticIntent) (OperationResult, error) {
	if s == nil {
		return OperationResult{}, fmt.Errorf("client-root session is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.loaded {
		return OperationResult{}, fmt.Errorf("client-root session has no verified update view")
	}
	base := s.writer.BaseRoot()
	if !intent.BaseRoot.Equals(base) {
		return OperationResult{}, fmt.Errorf("semantic intent base %s is stale; writer base is %s", intent.BaseRoot, base)
	}
	computeStart := time.Now()
	prepared, err := s.writer.Prepare(ctx, operationID, intent)
	computeDuration := time.Since(computeStart)
	if err != nil {
		return OperationResult{}, fmt.Errorf("compute client root: %w", err)
	}
	if !s.writer.BaseRoot().Equals(base) {
		return OperationResult{}, fmt.Errorf("client writer advanced before durable receipt")
	}
	submitStart := time.Now()
	envelope, err := s.remote.SubmitClientRoot(ctx, prepared.Bundle)
	submitDuration := time.Since(submitStart)
	if err != nil {
		return OperationResult{}, err
	}
	receiptStarted := time.Now()
	if err := s.writer.AcceptReceipt(envelope.Receipt, prepared); err != nil {
		return OperationResult{}, fmt.Errorf("accept exact materialization receipt: %w", err)
	}
	receiptCheckNS := durationNS(time.Since(receiptStarted)) + envelope.ResponseVerifyNS
	if !s.writer.BaseRoot().Equals(prepared.Bundle.Candidate) {
		return OperationResult{}, fmt.Errorf("client writer did not advance to exact durable candidate")
	}
	s.view = prepared.NextView
	return OperationResult{
		BaseRoot: base, Candidate: prepared.Bundle.Candidate,
		ViewDigest: prepared.Bundle.ViewDigest, IntentDigest: prepared.Bundle.IntentDigest,
		Receipt: envelope.Receipt, Idempotent: envelope.Idempotent,
		Metrics: OperationMetrics{
			LocalRootComputationNS: durationNS(computeDuration), SubmitRoundTripNS: durationNS(submitDuration),
			SDK: prepared.Metrics, BundleWireBytes: envelope.RequestWireBytes, ReceiptWireBytes: envelope.ResponseWireBytes,
			BundleEncodingNS: envelope.RequestEncodingNS, ReceiptCheckNS: receiptCheckNS, Gateway: envelope.Gateway,
			WriteAccounting: envelope.WriteAccounting,
		},
	}, nil
}

// Audit independently recomputes the retained complete vectors. Evaluators
// call it after every measured long-lived session; audit failure invalidates
// the complete session rather than just its final operation.
func (s *Session) Audit(ctx context.Context) error {
	if s == nil {
		return fmt.Errorf("client-root session is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.loaded {
		return fmt.Errorf("client-root session has no verified update view")
	}
	return s.writer.Audit(ctx)
}

func durationNS(value time.Duration) uint64 {
	if value <= 0 {
		return 0
	}
	return uint64(value)
}

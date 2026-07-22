// Package rq2wire mirrors the evaluator-owned RQ2 JSONL contract without
// importing malt-evaluation. It is shared only by the browser host adapter and
// the real Go/WASM writer artifact built from this repository.
package rq2wire

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/dewebprotocol/malt-client/internal/evaluation/rq2metrics"
	"github.com/dewebprotocol/malt/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

const (
	WorkerRequestSchema = "malt-rq2-worker-request/v1"
	WorkerRecordSchema  = "malt-rq2-worker-record/v1"

	ClientNative      = "native"
	ClientBrowserWASM = "browser-wasm"

	LifecycleNativeLong    = "native-long-lived"
	LifecycleBrowserCold   = "browser-cold"
	LifecycleBrowserSteady = "browser-steady"
	LifecycleBrowserShort  = "browser-short-session"

	RecordPreflight    = "preflight"
	RecordSessionStart = "session-start"
	RecordMutation     = "mutation"
	RecordSessionEnd   = "session-end"

	PhaseObserved      = "observed"
	PhaseNotApplicable = "not-applicable"
)

var IDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)

type WorkerRequest struct {
	SchemaVersion        string `json:"schema_version"`
	WorkerID             string `json:"worker_id"`
	RequestID            string `json:"request_id"`
	RecordKind           string `json:"record_kind"`
	SessionID            string `json:"session_id"`
	ClientKind           string `json:"client_kind"`
	PlatformID           string `json:"platform_id"`
	Backend              string `json:"backend"`
	Lifecycle            string `json:"lifecycle"`
	FixtureID            string `json:"fixture_id"`
	Operation            string `json:"operation,omitempty"`
	Measured             bool   `json:"measured"`
	ExpectedAcceptedRoot string `json:"expected_accepted_root,omitempty"`
}

func (r WorkerRequest) Validate() error {
	if r.SchemaVersion != WorkerRequestSchema || !IDPattern.MatchString(r.WorkerID) || !IDPattern.MatchString(r.RequestID) ||
		!IDPattern.MatchString(r.SessionID) || !IDPattern.MatchString(r.PlatformID) || !IDPattern.MatchString(r.FixtureID) {
		return fmt.Errorf("invalid RQ2 worker request identity")
	}
	if err := ValidateCoordinate(r.ClientKind, r.Backend, r.Lifecycle); err != nil {
		return err
	}
	switch r.RecordKind {
	case RecordPreflight:
		if r.Operation != "" || r.Measured || r.ExpectedAcceptedRoot != "" {
			return fmt.Errorf("preflight request contains mutation/session state")
		}
	case RecordSessionStart, RecordSessionEnd:
		if r.Operation != "" || r.Measured || !ValidTypedRoot(r.ExpectedAcceptedRoot, r.Backend) {
			return fmt.Errorf("session request must bind one typed accepted root")
		}
	case RecordMutation:
		if !IDPattern.MatchString(r.Operation) || !ValidTypedRoot(r.ExpectedAcceptedRoot, r.Backend) {
			return fmt.Errorf("mutation request is incomplete")
		}
	default:
		return fmt.Errorf("unsupported RQ2 worker request kind %q", r.RecordKind)
	}
	return nil
}

type RuntimeEvidence struct {
	OS                      string `json:"os"`
	Architecture            string `json:"architecture"`
	LowPowerARM             bool   `json:"low_power_arm"`
	MachineDescriptorID     string `json:"machine_descriptor_id"`
	MachineDescriptorSHA256 string `json:"machine_descriptor_sha256"`
	BrowserEngine           string `json:"browser_engine,omitempty"`
	WASMSHA256              string `json:"wasm_sha256,omitempty"`
	ParameterProfile        string `json:"parameter_profile,omitempty"`
	ParameterSHA256         string `json:"parameter_sha256,omitempty"`
	ParameterInputBytes     uint64 `json:"parameter_input_bytes,omitempty"`
}

func ParameterEvidence(backend string) (profile, digest string, inputBytes uint64, ok bool) {
	switch backend {
	case "kzg":
		// go-kzg-4844 v1.1.0 embeds this exact trusted_setup.json as the
		// public initialization input consumed by NewContext4096Secure().
		return "go-kzg-4844-v1.1.0-trusted-setup-json", "0229b43f4fac9b17374809520eb621b5ee1a7f74547e7d36918e7d4b122e178d", 447354, true
	case "ipa":
		// go-ipa GenerateRandomPoints consumes this exact 19-byte seed;
		// VectorLength=256 is fixed code/configuration rather than loaded bytes.
		return "go-ipa-53bbb0ceb27a-seed-eth-verkle-oct-2021", "08c26364c812dffb5ba046479f25ca9afdc8ab39b0c89f37506cab988a96ac21", 19, true
	default:
		return "", "", 0, false
	}
}

type SessionEvidence struct {
	AcceptedRoot string `json:"accepted_root"`
	ReceiptCount uint64 `json:"receipt_count"`
	AuditPassed  bool   `json:"audit_passed"`
}

type PhaseMeasurement struct {
	Applicable bool   `json:"applicable"`
	Status     string `json:"status"`
	DurationNS uint64 `json:"duration_ns"`
	Bytes      uint64 `json:"bytes"`
	Count      uint64 `json:"count"`
}

func ObservedPhase(duration, bytes, count uint64) PhaseMeasurement {
	return PhaseMeasurement{Applicable: true, Status: PhaseObserved, DurationNS: duration, Bytes: bytes, Count: count}
}

func NotApplicablePhase() PhaseMeasurement {
	return PhaseMeasurement{Status: PhaseNotApplicable}
}

func (p PhaseMeasurement) validate(name string, required bool) error {
	if p.Applicable != required {
		return fmt.Errorf("phase %s applicable=%t, want %t", name, p.Applicable, required)
	}
	if !p.Applicable {
		if p.Status != PhaseNotApplicable {
			return fmt.Errorf("non-applicable phase %s has invalid status %q", name, p.Status)
		}
		if p.DurationNS != 0 || p.Bytes != 0 || p.Count != 0 {
			return fmt.Errorf("non-applicable phase %s has measurements", name)
		}
		return nil
	}
	if p.Status != PhaseObserved {
		return fmt.Errorf("applicable phase %s has status %q", name, p.Status)
	}
	if p.Count == 0 {
		return fmt.Errorf("applicable phase %s has no observation count", name)
	}
	return nil
}

type MutationMetrics struct {
	// TaxonomyProfile binds the executable aggregation contract. Duration
	// classes are frozen in rq2metrics; bytes/counts remain field-specific,
	// non-additive resource observations regardless of duration class.
	TaxonomyProfile      string           `json:"taxonomy_profile"`
	MutationTotal        PhaseMeasurement `json:"mutation_total"`
	Scan                 PhaseMeasurement `json:"scan"`
	Chunk                PhaseMeasurement `json:"chunk"`
	Hash                 PhaseMeasurement `json:"hash"`
	UpdateView           PhaseMeasurement `json:"update_view"`
	VerifyUpdateView     PhaseMeasurement `json:"verify_update_view"`
	Normalization        PhaseMeasurement `json:"normalization"`
	CommitmentUpdate     PhaseMeasurement `json:"commitment_update"`
	ExpectedRootEncoding PhaseMeasurement `json:"expected_root_encoding"`
	RootComputation      PhaseMeasurement `json:"root_computation"`
	ClientRootGeneration PhaseMeasurement `json:"client_root_generation"`
	ClientRootBundle     PhaseMeasurement `json:"client_root_bundle"`
	Upload               PhaseMeasurement `json:"upload"`
	GatewayReplay        PhaseMeasurement `json:"gateway_replay"`
	GatewayPersist       PhaseMeasurement `json:"gateway_persist"`
	ReceiptCheck         PhaseMeasurement `json:"receipt_check"`
	CPUTotal             PhaseMeasurement `json:"cpu_total"`
	PeakMemory           PhaseMeasurement `json:"peak_memory"`
	WASMDownload         PhaseMeasurement `json:"wasm_download"`
	WASMInstantiate      PhaseMeasurement `json:"wasm_instantiate"`
	ParameterLoad        PhaseMeasurement `json:"parameter_load"`
	FirstMutation        PhaseMeasurement `json:"first_mutation"`
	JSWASMBoundary       PhaseMeasurement `json:"js_wasm_boundary"`
}

func (m MutationMetrics) Validate(clientKind, backend, lifecycle, operation string) error {
	if m.TaxonomyProfile != rq2metrics.TaxonomyProfile {
		return fmt.Errorf("invalid RQ2 metric taxonomy profile %q", m.TaxonomyProfile)
	}
	scanChunkRequired, hashRequired := pipelineApplicability(clientKind, operation)
	for _, phase := range []struct {
		name     string
		value    PhaseMeasurement
		required bool
	}{{"scan", m.Scan, scanChunkRequired}, {"chunk", m.Chunk, scanChunkRequired}, {"hash", m.Hash, hashRequired}} {
		if err := phase.value.validate(phase.name, phase.required); err != nil {
			return err
		}
	}
	for _, phase := range []struct {
		name  string
		value PhaseMeasurement
	}{
		{"mutation_total", m.MutationTotal}, {"update_view", m.UpdateView}, {"verify_update_view", m.VerifyUpdateView}, {"normalization", m.Normalization},
		{"commitment_update", m.CommitmentUpdate}, {"expected_root_encoding", m.ExpectedRootEncoding}, {"root_computation", m.RootComputation},
		{"client_root_generation", m.ClientRootGeneration}, {"client_root_bundle", m.ClientRootBundle},
		{"gateway_replay", m.GatewayReplay}, {"gateway_persist", m.GatewayPersist}, {"receipt_check", m.ReceiptCheck},
		{"cpu_total", m.CPUTotal}, {"peak_memory", m.PeakMemory},
	} {
		if err := phase.value.validate(phase.name, true); err != nil {
			return err
		}
	}
	uploadRequired := clientKind == ClientBrowserWASM || clientKind == ClientNative &&
		operation != "delete-directory-entry" && operation != "move" && operation != "rename"
	if err := m.Upload.validate("upload", uploadRequired); err != nil {
		return err
	}
	if m.CommitmentUpdate.DurationNS > m.RootComputation.DurationNS {
		return fmt.Errorf("commitment_update is a nested root_computation subphase and cannot exceed it")
	}
	if m.MutationTotal.DurationNS == 0 || m.UpdateView.Bytes == 0 || m.ClientRootBundle.Bytes == 0 ||
		m.ReceiptCheck.Bytes == 0 || m.PeakMemory.Bytes == 0 || uploadRequired && m.Upload.Bytes == 0 {
		return fmt.Errorf("total latency and directional update/upload/bundle/receipt/memory accounting must be nonzero")
	}
	browser := clientKind == ClientBrowserWASM
	cold := lifecycle == LifecycleBrowserCold
	short := lifecycle == LifecycleBrowserShort
	coldObserved := cold || short && m.WASMDownload.Applicable
	for _, phase := range []struct {
		name     string
		value    PhaseMeasurement
		required bool
	}{
		{"wasm_download", m.WASMDownload, coldObserved}, {"wasm_instantiate", m.WASMInstantiate, coldObserved},
		{"parameter_load", m.ParameterLoad, coldObserved}, {"first_mutation", m.FirstMutation, coldObserved},
		{"js_wasm_boundary", m.JSWASMBoundary, browser},
	} {
		if err := phase.value.validate(phase.name, phase.required); err != nil {
			return err
		}
	}
	if coldObserved && (m.WASMDownload.Bytes == 0 || m.ParameterLoad.Bytes == 0) {
		return fmt.Errorf("cold WASM download and parameter byte accounting must be nonzero")
	}
	if coldObserved {
		_, _, inputBytes, ok := ParameterEvidence(backend)
		if !ok || m.ParameterLoad.Bytes != inputBytes {
			return fmt.Errorf("cold parameter-load bytes do not match the exact backend initialization input")
		}
	}
	return rq2metrics.Validate(m.TaxonomyProfile, m.durationObservations(), browser, coldObserved)
}

func pipelineApplicability(clientKind, operation string) (scanChunk, hash bool) {
	nativePayload := clientKind == ClientNative && operation != "delete-directory-entry" && operation != "move" && operation != "rename"
	return operation == "document-edit-cid-binding-submit" || nativePayload, clientKind == ClientBrowserWASM || nativePayload
}

func (m MutationMetrics) durationObservations() map[string]rq2metrics.Observation {
	result := make(map[string]rq2metrics.Observation, 23)
	for _, metric := range []struct {
		name  string
		value PhaseMeasurement
	}{
		{"mutation_total", m.MutationTotal}, {"scan", m.Scan}, {"chunk", m.Chunk}, {"hash", m.Hash},
		{"update_view", m.UpdateView}, {"verify_update_view", m.VerifyUpdateView}, {"normalization", m.Normalization},
		{"commitment_update", m.CommitmentUpdate}, {"expected_root_encoding", m.ExpectedRootEncoding},
		{"root_computation", m.RootComputation}, {"client_root_generation", m.ClientRootGeneration},
		{"client_root_bundle", m.ClientRootBundle}, {"upload", m.Upload}, {"gateway_replay", m.GatewayReplay},
		{"gateway_persist", m.GatewayPersist}, {"receipt_check", m.ReceiptCheck}, {"cpu_total", m.CPUTotal},
		{"peak_memory", m.PeakMemory}, {"wasm_download", m.WASMDownload}, {"wasm_instantiate", m.WASMInstantiate},
		{"parameter_load", m.ParameterLoad}, {"first_mutation", m.FirstMutation}, {"js_wasm_boundary", m.JSWASMBoundary},
	} {
		result[metric.name] = rq2metrics.Observation{Applicable: metric.value.Applicable, DurationNS: metric.value.DurationNS}
	}
	return result
}

type MutationEvidence struct {
	Operation        string          `json:"operation"`
	PriorRoot        string          `json:"prior_root"`
	CandidateRoot    string          `json:"candidate_root"`
	ReceiptRoot      string          `json:"receipt_root"`
	ReceiptAccepted  bool            `json:"receipt_accepted"`
	UpdateViewSHA256 string          `json:"update_view_sha256"`
	IntentSHA256     string          `json:"intent_sha256"`
	BundleSHA256     string          `json:"bundle_sha256"`
	Metrics          MutationMetrics `json:"metrics"`
}

type WorkerRecord struct {
	SchemaVersion string            `json:"schema_version"`
	WorkerID      string            `json:"worker_id"`
	RequestID     string            `json:"request_id"`
	RecordKind    string            `json:"record_kind"`
	SessionID     string            `json:"session_id"`
	ClientKind    string            `json:"client_kind"`
	PlatformID    string            `json:"platform_id"`
	Backend       string            `json:"backend"`
	Lifecycle     string            `json:"lifecycle"`
	FixtureID     string            `json:"fixture_id"`
	Measured      bool              `json:"measured"`
	Success       bool              `json:"success"`
	FailureClass  string            `json:"failure_class,omitempty"`
	Error         string            `json:"error,omitempty"`
	Capabilities  []string          `json:"capabilities,omitempty"`
	Runtime       *RuntimeEvidence  `json:"runtime,omitempty"`
	Session       *SessionEvidence  `json:"session,omitempty"`
	Mutation      *MutationEvidence `json:"mutation,omitempty"`
}

func BaseRecord(request WorkerRequest) WorkerRecord {
	return WorkerRecord{
		SchemaVersion: WorkerRecordSchema, WorkerID: request.WorkerID, RequestID: request.RequestID,
		RecordKind: request.RecordKind, SessionID: request.SessionID, ClientKind: request.ClientKind,
		PlatformID: request.PlatformID, Backend: request.Backend, Lifecycle: request.Lifecycle,
		FixtureID: request.FixtureID, Measured: request.Measured,
	}
}

func FailedRecord(request WorkerRequest, class string, err error) WorkerRecord {
	record := BaseRecord(request)
	record.FailureClass, record.Error = class, err.Error()
	return record
}

func (r WorkerRecord) Validate() error {
	if !IDPattern.MatchString(r.WorkerID) || !IDPattern.MatchString(r.RequestID) || !IDPattern.MatchString(r.SessionID) ||
		!IDPattern.MatchString(r.PlatformID) || !IDPattern.MatchString(r.FixtureID) || r.SchemaVersion != WorkerRecordSchema {
		return fmt.Errorf("invalid RQ2 worker record identity")
	}
	if err := ValidateCoordinate(r.ClientKind, r.Backend, r.Lifecycle); err != nil {
		return err
	}
	if !r.Success {
		if r.FailureClass == "" || r.Error == "" || r.Capabilities != nil || r.Runtime != nil || r.Session != nil || r.Mutation != nil {
			return fmt.Errorf("failed RQ2 worker record contains invalid evidence")
		}
		return nil
	}
	if r.FailureClass != "" || r.Error != "" {
		return fmt.Errorf("successful RQ2 worker record has failure metadata")
	}
	switch r.RecordKind {
	case RecordPreflight:
		if r.Measured || r.Runtime == nil || r.Session != nil || r.Mutation != nil || !slices.Equal(r.Capabilities, RequiredCapabilities(r.ClientKind, r.Backend)) {
			return fmt.Errorf("invalid RQ2 preflight evidence")
		}
		if !RuntimeIdentityValid(*r.Runtime) {
			return fmt.Errorf("RQ2 preflight machine descriptor provenance is incomplete")
		}
		if r.ClientKind == ClientBrowserWASM {
			profile, digest, inputBytes, ok := ParameterEvidence(r.Backend)
			if !ok || r.Runtime.ParameterProfile != profile || r.Runtime.ParameterSHA256 != digest || r.Runtime.ParameterInputBytes != inputBytes {
				return fmt.Errorf("browser preflight parameter provenance is not exact")
			}
		} else if r.Runtime.ParameterProfile != "" || r.Runtime.ParameterSHA256 != "" || r.Runtime.ParameterInputBytes != 0 {
			return fmt.Errorf("native preflight must not claim browser parameter-load provenance")
		}
	case RecordSessionStart:
		if r.Measured || r.Session == nil || r.Mutation != nil || r.Runtime != nil || r.Capabilities != nil ||
			!ValidTypedRoot(r.Session.AcceptedRoot, r.Backend) || r.Session.ReceiptCount != 0 || r.Session.AuditPassed {
			return fmt.Errorf("invalid RQ2 session-start evidence")
		}
	case RecordMutation:
		if r.Mutation == nil || r.Session != nil || r.Runtime != nil || r.Capabilities != nil {
			return fmt.Errorf("invalid RQ2 mutation evidence")
		}
		if !IDPattern.MatchString(r.Mutation.Operation) || !ValidTypedRoot(r.Mutation.PriorRoot, r.Backend) ||
			!ValidTypedRoot(r.Mutation.CandidateRoot, r.Backend) || r.Mutation.CandidateRoot != r.Mutation.ReceiptRoot || !r.Mutation.ReceiptAccepted {
			return fmt.Errorf("invalid RQ2 mutation roots")
		}
		for _, digest := range []string{r.Mutation.UpdateViewSHA256, r.Mutation.IntentSHA256, r.Mutation.BundleSHA256} {
			if !CanonicalSHA256(digest) {
				return fmt.Errorf("invalid RQ2 mutation digest")
			}
		}
		return r.Mutation.Metrics.Validate(r.ClientKind, r.Backend, r.Lifecycle, r.Mutation.Operation)
	case RecordSessionEnd:
		if r.Measured || r.Session == nil || r.Mutation != nil || r.Runtime != nil || r.Capabilities != nil ||
			!ValidTypedRoot(r.Session.AcceptedRoot, r.Backend) || !r.Session.AuditPassed {
			return fmt.Errorf("invalid RQ2 session-end evidence")
		}
	default:
		return fmt.Errorf("unsupported RQ2 record kind %q", r.RecordKind)
	}
	return nil
}

func RequiredCapabilities(clientKind, backend string) []string {
	values := []string{"client-root-bundle-v1", "exact-root-receipt-v1", "phase-metrics-v1", "update-view-v1"}
	if clientKind == ClientNative {
		values = append(values, "long-lived-session-v1", "native-writer-v1")
	} else if clientKind == ClientBrowserWASM {
		values = append(values, "wasm-cold-start-v1", "wasm-steady-session-v1", "wasm-writer-v1")
	}
	values = append(values, "commitment-"+backend+"-v1")
	slices.Sort(values)
	return values
}

func ValidateCoordinate(clientKind, backend, lifecycle string) error {
	if backend != "kzg" && backend != "ipa" {
		return fmt.Errorf("unsupported RQ2 backend %q", backend)
	}
	switch clientKind {
	case ClientNative:
		if lifecycle != LifecycleNativeLong {
			return fmt.Errorf("native client requires long-lived lifecycle")
		}
	case ClientBrowserWASM:
		if lifecycle != LifecycleBrowserCold && lifecycle != LifecycleBrowserSteady && lifecycle != LifecycleBrowserShort {
			return fmt.Errorf("browser client requires cold, steady, or short-session lifecycle")
		}
	default:
		return fmt.Errorf("unsupported RQ2 client kind %q", clientKind)
	}
	return nil
}

func ValidTypedRoot(value, backend string) bool {
	parsed, err := cid.Parse(value)
	return err == nil && maltcid.IsMaltCid(parsed) && string(maltcid.BackendKindOf(parsed)) == backend
}

func CanonicalSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func Bind(record WorkerRecord, request WorkerRequest) error {
	if record.WorkerID != request.WorkerID || record.RequestID != request.RequestID || record.RecordKind != request.RecordKind ||
		record.SessionID != request.SessionID || record.ClientKind != request.ClientKind || record.PlatformID != request.PlatformID ||
		record.Backend != request.Backend || record.Lifecycle != request.Lifecycle || record.FixtureID != request.FixtureID || record.Measured != request.Measured {
		return fmt.Errorf("RQ2 worker response does not bind request %q", request.RequestID)
	}
	if record.Success && request.RecordKind == RecordMutation && (record.Mutation == nil || record.Mutation.Operation != request.Operation || record.Mutation.PriorRoot != request.ExpectedAcceptedRoot) {
		return fmt.Errorf("RQ2 mutation response does not bind operation/prior root")
	}
	if record.Success && (request.RecordKind == RecordSessionStart || request.RecordKind == RecordSessionEnd) &&
		(record.Session == nil || record.Session.AcceptedRoot != request.ExpectedAcceptedRoot) {
		return fmt.Errorf("RQ2 session response does not bind expected root")
	}
	return nil
}

func RuntimeIdentityValid(runtime RuntimeEvidence) bool {
	return strings.TrimSpace(runtime.OS) != "" && strings.TrimSpace(runtime.Architecture) != "" &&
		IDPattern.MatchString(runtime.MachineDescriptorID) && CanonicalSHA256(runtime.MachineDescriptorSHA256)
}

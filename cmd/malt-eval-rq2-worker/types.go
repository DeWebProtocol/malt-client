package main

const (
	workerRequestSchema = "malt-rq2-worker-request/v1"
	workerRecordSchema  = "malt-rq2-worker-record/v1"

	clientNative      = "native"
	clientBrowserWASM = "browser-wasm"

	lifecycleNativeLong    = "native-long-lived"
	lifecycleBrowserCold   = "browser-cold"
	lifecycleBrowserSteady = "browser-steady"

	recordPreflight    = "preflight"
	recordSessionStart = "session-start"
	recordMutation     = "mutation"
	recordSessionEnd   = "session-end"

	phaseObserved      = "observed"
	phaseNotApplicable = "not-applicable"
)

type workerRequest struct {
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

type runtimeEvidence struct {
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

type sessionEvidence struct {
	AcceptedRoot string `json:"accepted_root"`
	ReceiptCount uint64 `json:"receipt_count"`
	AuditPassed  bool   `json:"audit_passed"`
}

type phaseMeasurement struct {
	Applicable bool   `json:"applicable"`
	Status     string `json:"status"`
	DurationNS uint64 `json:"duration_ns"`
	Bytes      uint64 `json:"bytes"`
	Count      uint64 `json:"count"`
}

func observedPhase(duration, bytes, count uint64) phaseMeasurement {
	return phaseMeasurement{Applicable: true, Status: phaseObserved, DurationNS: duration, Bytes: bytes, Count: count}
}

func notApplicablePhase() phaseMeasurement {
	return phaseMeasurement{Status: phaseNotApplicable}
}

type mutationMetrics struct {
	// TaxonomyProfile freezes duration aggregation classes. Bytes and counts are
	// field-specific resource observations and are never an additive breakdown.
	TaxonomyProfile      string           `json:"taxonomy_profile"`
	MutationTotal        phaseMeasurement `json:"mutation_total"`
	Scan                 phaseMeasurement `json:"scan"`
	Chunk                phaseMeasurement `json:"chunk"`
	Hash                 phaseMeasurement `json:"hash"`
	UpdateView           phaseMeasurement `json:"update_view"`
	VerifyUpdateView     phaseMeasurement `json:"verify_update_view"`
	Normalization        phaseMeasurement `json:"normalization"`
	CommitmentUpdate     phaseMeasurement `json:"commitment_update"`
	ExpectedRootEncoding phaseMeasurement `json:"expected_root_encoding"`
	RootComputation      phaseMeasurement `json:"root_computation"`
	ClientRootGeneration phaseMeasurement `json:"client_root_generation"`
	ClientRootBundle     phaseMeasurement `json:"client_root_bundle"`
	Upload               phaseMeasurement `json:"upload"`
	GatewayReplay        phaseMeasurement `json:"gateway_replay"`
	GatewayPersist       phaseMeasurement `json:"gateway_persist"`
	ReceiptCheck         phaseMeasurement `json:"receipt_check"`
	CPUTotal             phaseMeasurement `json:"cpu_total"`
	PeakMemory           phaseMeasurement `json:"peak_memory"`
	WASMDownload         phaseMeasurement `json:"wasm_download"`
	WASMInstantiate      phaseMeasurement `json:"wasm_instantiate"`
	ParameterLoad        phaseMeasurement `json:"parameter_load"`
	FirstMutation        phaseMeasurement `json:"first_mutation"`
	JSWASMBoundary       phaseMeasurement `json:"js_wasm_boundary"`
}

type mutationEvidence struct {
	Operation        string          `json:"operation"`
	PriorRoot        string          `json:"prior_root"`
	CandidateRoot    string          `json:"candidate_root"`
	ReceiptRoot      string          `json:"receipt_root"`
	ReceiptAccepted  bool            `json:"receipt_accepted"`
	UpdateViewSHA256 string          `json:"update_view_sha256"`
	IntentSHA256     string          `json:"intent_sha256"`
	BundleSHA256     string          `json:"bundle_sha256"`
	Metrics          mutationMetrics `json:"metrics"`
}

type workerRecord struct {
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
	Runtime       *runtimeEvidence  `json:"runtime,omitempty"`
	Session       *sessionEvidence  `json:"session,omitempty"`
	Mutation      *mutationEvidence `json:"mutation,omitempty"`
}

func baseRecord(request workerRequest) workerRecord {
	return workerRecord{
		SchemaVersion: workerRecordSchema, WorkerID: request.WorkerID, RequestID: request.RequestID,
		RecordKind: request.RecordKind, SessionID: request.SessionID, ClientKind: request.ClientKind,
		PlatformID: request.PlatformID, Backend: request.Backend, Lifecycle: request.Lifecycle,
		FixtureID: request.FixtureID, Measured: request.Measured,
	}
}

func failedRecord(request workerRequest, class string, err error) workerRecord {
	record := baseRecord(request)
	record.FailureClass = class
	record.Error = err.Error()
	return record
}

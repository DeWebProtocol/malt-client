// Package rq3baseline exposes the current hash-authenticated UnixFS write path
// as a narrow, deterministic evaluator primitive. It deliberately reports
// logical CAS accounting only; physical backend reconciliation belongs to the
// evaluator and gateway storage implementations.
package rq3baseline

const (
	WorkerRequestSchema     = "malt-rq3-hash-worker-request/v1"
	WorkerResponseSchema    = "malt-rq3-hash-worker-response/v1"
	RunResultSchema         = "malt-rq3-hash-run-result/v1"
	CapabilitySchema        = "malt-rq3-hash-capability/v1"
	MaximumJSONLRecordBytes = 64 << 20

	OperationCapabilities = "capabilities"
	OperationRun          = "run"

	SystemMerkleDAGUnixFS = "merkledag-unixfs"
	SystemHAMTUnixFS      = "hamt-unixfs"
	FileKindRegular       = "regular"

	MutationInsert     = "insert"
	MutationReplace    = "replace"
	MutationAppend     = "append"
	MutationDelete     = "delete"
	MutationRename     = "rename"
	MutationMove       = "move"
	MutationModeChange = "mode-change"
)

// WorkerRequest is one strict JSONL input record. Run must be absent for a
// capability request and present for a run request.
type WorkerRequest struct {
	SchemaVersion string   `json:"schema_version"`
	RequestID     string   `json:"request_id"`
	Operation     string   `json:"operation"`
	Run           *RunSpec `json:"run,omitempty"`
}

type WorkerResponse struct {
	SchemaVersion string        `json:"schema_version"`
	RequestID     string        `json:"request_id"`
	OK            bool          `json:"ok"`
	Capability    *Capabilities `json:"capability,omitempty"`
	Result        *RunResult    `json:"result,omitempty"`
	Error         *WorkerError  `json:"error,omitempty"`
}

type WorkerError struct {
	Code          string `json:"code"`
	Message       string `json:"message"`
	CapabilityGap string `json:"capability_gap,omitempty"`
}

// RunSpec keeps workload semantics separate from the selected hash baseline.
// Paths, payloads, modes, chunking, layouts, and commit boundaries are all
// explicit and therefore hashable before execution.
type RunSpec struct {
	System   string     `json:"system"`
	Layout   LayoutSpec `json:"layout"`
	Snapshot Snapshot   `json:"snapshot"`
	Commits  []Commit   `json:"commits"`
}

type LayoutSpec struct {
	Model           string       `json:"model"`
	FileLayout      string       `json:"file_layout"`
	DirectoryLayout string       `json:"directory_layout"`
	Chunking        ChunkingSpec `json:"chunking"`
	HAMTFanout      int          `json:"hamt_fanout"`
	RawFileLeaf     *bool        `json:"raw_file_leaf"`
}

type ChunkingSpec struct {
	Algorithm string `json:"algorithm"`
	SizeBytes int    `json:"size_bytes"`
}

type Snapshot struct {
	CommitID string       `json:"commit_id"`
	Files    []FrozenFile `json:"files"`
}

type FrozenFile struct {
	Path          string  `json:"path"`
	FileKind      string  `json:"file_kind"`
	PayloadBase64 string  `json:"payload_base64"`
	PayloadSHA256 string  `json:"payload_sha256"`
	Mode          *uint32 `json:"mode"`
}

type Commit struct {
	CommitID  string     `json:"commit_id"`
	Mutations []Mutation `json:"mutations"`
}

// Mutation carries the complete resulting payload for insert, replace, and
// append. Append additionally proves that the previous payload is a prefix of
// the supplied result. Delete, rename, and move carry an expected old digest.
// Mode is the resulting mode for operations that leave a file present.
// ExpectedOldMode and ExpectedOldSHA256 freeze the prior file state for every
// operation other than insert.
type Mutation struct {
	Kind              string  `json:"kind"`
	Path              string  `json:"path"`
	FileKind          string  `json:"file_kind"`
	Destination       string  `json:"destination,omitempty"`
	PayloadBase64     string  `json:"payload_base64,omitempty"`
	PayloadSHA256     string  `json:"payload_sha256,omitempty"`
	ExpectedOldSHA256 string  `json:"expected_old_sha256,omitempty"`
	ExpectedOldMode   *uint32 `json:"expected_old_mode,omitempty"`
	Mode              *uint32 `json:"mode,omitempty"`
}

type RunResult struct {
	SchemaVersion  string         `json:"schema_version"`
	CapabilityID   string         `json:"capability_id"`
	System         string         `json:"system"`
	WorkloadSHA256 string         `json:"workload_sha256"`
	Layout         LayoutSpec     `json:"layout"`
	Records        []CommitRecord `json:"records"`
}

type CommitRecord struct {
	CommitID               string `json:"commit_id"`
	ParentRoot             string `json:"parent_root,omitempty"`
	Root                   string `json:"root"`
	Snapshot               bool   `json:"snapshot"`
	LogicalObjectsChanged  int    `json:"logical_objects_changed"`
	LogicalBindingsChanged int    `json:"logical_bindings_changed"`
	LogicalPayloadBytes    int64  `json:"logical_payload_bytes"`
	// AdapterPayloadInputBytes is the source envelope presented to the
	// system-specific adapter: the complete snapshot bytes initially and the
	// complete post-image for insert/replace/append. Path-only, delete, and
	// mode-only mutations contribute zero. It is intentionally independent of
	// LogicalPayloadBytes.
	AdapterPayloadInputBytes int64               `json:"adapter_payload_input_bytes"`
	Mutations                []MutationExecution `json:"mutations"`
	CAS                      CASAccounting       `json:"cas"`
	ClientPhases             ClientPhases        `json:"client_phases"`
}

// SourceCommitAccounting is derived solely from the strict, system-neutral
// source envelope. It lets other adapters validate and account the exact same
// frozen workload without executing or warming the UnixFS baseline.
type SourceCommitAccounting struct {
	CommitID                 string
	LogicalObjectsChanged    int
	LogicalBindingsChanged   int
	AdapterPayloadInputBytes int64
}

type MutationExecution struct {
	Index                  int    `json:"index"`
	Kind                   string `json:"kind"`
	Path                   string `json:"path"`
	Destination            string `json:"destination,omitempty"`
	Translation            string `json:"translation"`
	LogicalObjectsChanged  int    `json:"logical_objects_changed"`
	LogicalBindingsChanged int    `json:"logical_bindings_changed"`
	LogicalPayloadBytes    int64  `json:"logical_payload_bytes"`
}

// CASAccounting counts Total objects once. A non-raw dag-pb leaf contributes
// one component-bearing object to both PayloadChunks and StructuralMetadata;
// therefore component object counts may overlap, while component byte counts
// always partition Total exactly.
type CASAccounting struct {
	Events             []CASWriteEvent    `json:"events"`
	Total              CategoryAccounting `json:"total"`
	PayloadChunks      CategoryAccounting `json:"payload_chunks"`
	StructuralMetadata CategoryAccounting `json:"structural_metadata"`
	Reads              CASReadAccounting  `json:"reads"`
}

type CASWriteEvent struct {
	Sequence                int    `json:"sequence"`
	CID                     string `json:"cid"`
	Codec                   uint64 `json:"codec"`
	Category                string `json:"category"`
	Bytes                   int64  `json:"bytes"`
	PayloadBytes            int64  `json:"payload_bytes"`
	StructuralMetadataBytes int64  `json:"structural_metadata_bytes"`
	Status                  string `json:"status"`
}

type CategoryAccounting struct {
	AttemptedObjects      int   `json:"attempted_objects"`
	AttemptedBytes        int64 `json:"attempted_bytes"`
	NewlyPersistedObjects int   `json:"newly_persisted_objects"`
	NewlyPersistedBytes   int64 `json:"newly_persisted_bytes"`
	AlreadyPresentObjects int   `json:"already_present_objects"`
	AlreadyPresentBytes   int64 `json:"already_present_bytes"`
	DuplicateObjects      int   `json:"duplicate_objects"`
	DuplicateBytes        int64 `json:"duplicate_bytes"`
}

type CASReadAccounting struct {
	Objects int   `json:"objects"`
	Bytes   int64 `json:"bytes"`
}

// Durations are wall-clock measurements, not CPU time. ClientComputeWallNanos
// is the complete local Editor path. CAS timings are nested within it, and the
// final field is only the non-negative remainder after those calls.
type ClientPhases struct {
	ClientComputeWallNanos              int64 `json:"client_compute_wall_nanos"`
	CASPutWallNanos                     int64 `json:"cas_put_wall_nanos"`
	CASGetWallNanos                     int64 `json:"cas_get_wall_nanos"`
	EditorOverheadExcludingCASWallNanos int64 `json:"editor_overhead_excluding_cas_wall_nanos"`
}

type Capabilities struct {
	SchemaVersion             string           `json:"schema_version"`
	CapabilityID              string           `json:"capability_id"`
	ExecutionPath             string           `json:"execution_path"`
	Systems                   []string         `json:"systems"`
	FileLayouts               []string         `json:"file_layouts"`
	DirectoryLayouts          []string         `json:"directory_layouts"`
	MutationKinds             []string         `json:"mutation_kinds"`
	AccountingCategories      []string         `json:"accounting_categories"`
	WriteStatuses             []string         `json:"write_statuses"`
	HistoricalRetention       string           `json:"historical_retention"`
	ExactAccountingConditions []string         `json:"exact_accounting_conditions"`
	ExecutionNotes            []string         `json:"execution_notes"`
	SafetyLimits              CapabilityLimits `json:"safety_limits"`
	Gaps                      []CapabilityGap  `json:"gaps"`
}

type CapabilityLimits struct {
	MaximumJSONLRecordBytes    int `json:"maximum_jsonl_record_bytes"`
	MaximumFiles               int `json:"maximum_files"`
	MaximumCommits             int `json:"maximum_commits"`
	MaximumMutations           int `json:"maximum_mutations"`
	MaximumDecodedPayloadBytes int `json:"maximum_decoded_payload_bytes"`
	MaximumProjectedChunks     int `json:"maximum_projected_chunks"`
	MaximumChunkSizeBytes      int `json:"maximum_chunk_size_bytes"`
}

type CapabilityGap struct {
	Code       string `json:"code"`
	FailClosed bool   `json:"fail_closed"`
	Detail     string `json:"detail"`
}

func Capability() Capabilities {
	return Capabilities{
		SchemaVersion:        CapabilitySchema,
		CapabilityID:         "rq3.hash-unixfs-logical.v1",
		ExecutionPath:        "merkledag/importer.Editor",
		Systems:              []string{SystemMerkleDAGUnixFS, SystemHAMTUnixFS},
		FileLayouts:          []string{"balanced", "trickle"},
		DirectoryLayouts:     []string{"basic", "hamt"},
		MutationKinds:        []string{MutationInsert, MutationReplace, MutationAppend, MutationDelete, MutationRename, MutationMove, MutationModeChange},
		AccountingCategories: []string{"payload_chunk", "cas_structural_metadata", "mixed_payload_and_structural_metadata"},
		WriteStatuses:        []string{"newly_persisted", "already_present", "duplicate_in_commit"},
		HistoricalRetention:  "all_blocks_for_all_emitted_roots",
		ExactAccountingConditions: []string{
			"fixed-size chunking is explicit",
			"HAMT fanout is an explicit power of two and multiple of 8 from 8 through 65536",
			"raw_file_leaf is explicit; raw blocks are payload and dag-pb UnixFS nodes are decoded to split embedded payload from protobuf and link metadata",
			"snapshot and mutations explicitly declare file_kind=regular, modes, and payload digests",
			"mode is an unsigned Unix permission value from 0001 through 0777",
		},
		ExecutionNotes: []string{
			"a commit emits one final root while all intermediate Editor writes remain included in attempted and newly-persisted accounting",
			"content-addressed roots may repeat when a frozen commit is a semantic same-value operation",
			"file rename and move execute as remove_file followed by put_file because that is the current Editor surface",
			"Git regular modes 100644 and 100755 map to 0644 and 0755; Git symlink mode 120000 fails closed",
		},
		SafetyLimits: CapabilityLimits{
			MaximumJSONLRecordBytes:    MaximumJSONLRecordBytes,
			MaximumFiles:               maxFiles,
			MaximumCommits:             maxCommits,
			MaximumMutations:           maxMutations,
			MaximumDecodedPayloadBytes: maxPayloadBytes,
			MaximumProjectedChunks:     maxProjectedChunks,
			MaximumChunkSizeBytes:      maxChunkSizeBytes,
		},
		Gaps: []CapabilityGap{
			{Code: "directory_subtree_mutation", FailClosed: true, Detail: "the current incremental Editor has file put/remove but no directory or subtree rename/move API"},
			{Code: "symlink_and_special_file_mutation", FailClosed: true, Detail: "the frozen evaluator primitive accepts regular files only"},
			{Code: "empty_snapshot", FailClosed: true, Detail: "the current Editor cannot materialize an empty directory root before the first file put"},
			{Code: "external_root_resume", FailClosed: true, Detail: "the current Editor cannot initialize from an externally supplied root; each run imports an explicit frozen snapshot"},
			{Code: "physical_backend_bytes", FailClosed: true, Detail: "this primitive reports deterministic logical CAS events only; physical WAL/LSM reconciliation requires a storage-owned evaluator"},
		},
	}
}

package transport

// HealthResponse is returned by the managed gateway health endpoint.
type HealthResponse struct {
	Status                        string `json:"status"`
	EvaluationInstanceToken       string `json:"evaluation_instance_token,omitempty"`
	KVBackend                     string `json:"kv_backend,omitempty"`
	BlobBackend                   string `json:"blob_backend,omitempty"`
	ArcTableMode                  string `json:"arctable_mode,omitempty"`
	CommitmentProfile             string `json:"default_commitment_backend,omitempty"`
	CommitmentBackends            string `json:"commitment_backends,omitempty"`
	EvaluationCASWriteAccounting  string `json:"evaluation_cas_write_accounting,omitempty"`
	EvaluationCASWriteIsolation   string `json:"evaluation_cas_write_isolation,omitempty"`
	ClientRootWriteAccounting     string `json:"client_root_write_accounting,omitempty"`
	ClientRootExactAcceptance     string `json:"client_root_exact_acceptance,omitempty"`
	EvaluationClientRootBootstrap string `json:"evaluation_client_root_bootstrap,omitempty"`
}

// SemanticMutationRequest materializes a root-relative semantic mutation.
type SemanticMutationRequest struct {
	Deltas []SemanticMutationDelta `json:"deltas"`
}

// SemanticMutationDelta applies coordinate-level changes to one semantic object.
type SemanticMutationDelta struct {
	Object       string                    `json:"object,omitempty"`
	ExpectedRoot string                    `json:"expected_root,omitempty"`
	Kind         string                    `json:"kind"`
	Changes      []SemanticMutationChange  `json:"changes"`
	Commit       *SemanticCommitDescriptor `json:"commit,omitempty"`
}

// SemanticMutationChange is one canonical coordinate transition.
type SemanticMutationChange struct {
	Path   string                  `json:"path,omitempty"`
	Index  *uint64                 `json:"index,omitempty"`
	Before *SemanticMutationTarget `json:"before,omitempty"`
	After  *SemanticMutationTarget `json:"after,omitempty"`
}

// SemanticMutationTarget is a typed mutation target CID.
type SemanticMutationTarget struct {
	Target     string `json:"target"`
	TargetKind string `json:"target_kind,omitempty"`
}

// SemanticCommitDescriptor records the commit profile for a delta.
type SemanticCommitDescriptor struct {
	FixedList *SemanticFixedListCommit `json:"fixed_list,omitempty"`
}

// SemanticFixedListCommit describes a measured fixed-width list commit.
type SemanticFixedListCommit struct {
	TotalSize uint64 `json:"total_size"`
	ChunkSize uint64 `json:"chunk_size"`
}

// SemanticMutationResponse is an untrusted writer mutation receipt. NewRoot
// and ResultRoot are candidates; receiving this value never accepts either
// root into the caller's trust policy.
type SemanticMutationResponse struct {
	BaseRoot        string `json:"base_root"`
	NewRoot         string `json:"new_root"`
	ResultRoot      string `json:"result_root,omitempty"`
	DeltaCount      int    `json:"delta_count"`
	ArcCount        int    `json:"arc_count"`
	MALTObjectCount int    `json:"malt_object_count,omitempty"`
	MapCount        int    `json:"map_count,omitempty"`
	ListCount       int    `json:"list_count,omitempty"`
}

// CreateStructureRequest creates a new structure from canonical bindings.
type CreateStructureRequest struct {
	Arcs map[string]string `json:"arcs"`
}

// CreateStructureResponse returns an untrusted candidate root.
type CreateStructureResponse struct {
	Root string `json:"root"`
}

type errorResponse struct {
	Error   string `json:"error,omitempty"`
	Message string `json:"message,omitempty"`
}

func (e errorResponse) messageText() string {
	if e.Message != "" {
		return e.Message
	}
	return e.Error
}

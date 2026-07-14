package transport

import (
	"context"
	"fmt"
	"time"
)

const GatewayMetricsProfile = "gateway.metrics/v0alpha1"

type OperationMetrics struct {
	Requests      uint64 `json:"requests"`
	Errors        uint64 `json:"errors"`
	DurationNanos uint64 `json:"duration_nanos"`
	ProofBytes    uint64 `json:"proof_bytes"`
	EvidenceBytes uint64 `json:"evidence_bytes"`
}

type CASMetrics struct {
	PutRequests uint64 `json:"put_requests"`
	GetRequests uint64 `json:"get_requests"`
	HasRequests uint64 `json:"has_requests"`
	Errors      uint64 `json:"errors"`
	BytesPut    uint64 `json:"bytes_put"`
	BytesGet    uint64 `json:"bytes_get"`
}

type ArcTableMetrics struct {
	GetRequests      uint64 `json:"get_requests"`
	BatchGetRequests uint64 `json:"batch_get_requests"`
	UpdateRequests   uint64 `json:"update_requests"`
	SnapshotRequests uint64 `json:"snapshot_requests"`
	IterateRequests  uint64 `json:"iterate_requests"`
	Errors           uint64 `json:"errors"`
}

// StorageMetrics is a logical, live-key accounting snapshot. It deliberately
// does not claim to report filesystem allocation, Badger value-log
// amplification, or bytes retained by an external CAS backend.
type StorageMetrics struct {
	Method             string `json:"method"`
	BlobBackend        string `json:"blob_backend"`
	ExternalCAS        bool   `json:"external_cas"`
	Keys               uint64 `json:"keys"`
	KeyBytes           uint64 `json:"key_bytes"`
	ValueBytes         uint64 `json:"value_bytes"`
	LogicalBytes       uint64 `json:"logical_bytes"`
	CASBlobBytes       uint64 `json:"cas_blob_bytes"`
	CASMetadataBytes   uint64 `json:"cas_metadata_bytes"`
	ArcTableBytes      uint64 `json:"arc_table_bytes"`
	ScopeMetadataBytes uint64 `json:"scope_metadata_bytes"`
	PublicationBytes   uint64 `json:"publication_bytes"`
	UnclassifiedBytes  uint64 `json:"unclassified_bytes"`
}

type MetricsSnapshot struct {
	Profile       string           `json:"profile"`
	GeneratedAt   time.Time        `json:"generated_at"`
	Resolve       OperationMetrics `json:"resolve"`
	Read          OperationMetrics `json:"read"`
	CompatResolve OperationMetrics `json:"merkledag_resolve"`
	CompatRead    OperationMetrics `json:"merkledag_read"`
	Mutation      OperationMetrics `json:"mutation"`
	Structure     OperationMetrics `json:"structure"`
	CAS           CASMetrics       `json:"cas"`
	ArcTable      ArcTableMetrics  `json:"arc_table"`
	Storage       *StorageMetrics  `json:"storage,omitempty"`
}

// Metrics returns a monotonic diagnostic snapshot. It is an observability
// input, never a proof or trust decision.
func (c *Client) Metrics(ctx context.Context) (*MetricsSnapshot, error) {
	return c.metrics(ctx, "/v1/diagnostics/metrics")
}

// MetricsWithStorage requests the optional O(live KV entries) logical storage
// scan in addition to monotonic counters. It is intended for controlled
// evaluation and operator diagnostics, not a high-frequency polling loop.
func (c *Client) MetricsWithStorage(ctx context.Context) (*MetricsSnapshot, error) {
	return c.metrics(ctx, "/v1/diagnostics/metrics?storage=logical")
}

func (c *Client) metrics(ctx context.Context, route string) (*MetricsSnapshot, error) {
	var snapshot MetricsSnapshot
	if err := c.do(ctx, "GET", route, nil, nil, &snapshot); err != nil {
		return nil, err
	}
	if snapshot.Profile != GatewayMetricsProfile {
		return nil, fmt.Errorf("unsupported gateway metrics profile %q", snapshot.Profile)
	}
	return &snapshot, nil
}

// Package capability defines transport-neutral, untrusted data-access
// capabilities consumed by the MALT local runtime. Implementations may use a
// Gateway, a peer, local storage, or a hybrid policy; none of these interfaces
// can mutate local trust state.
package capability

import (
	"context"
	"errors"

	"github.com/dewebprotocol/malt-core/mutation"
	"github.com/dewebprotocol/malt-core/protocol"
	cid "github.com/ipfs/go-cid"
)

// ErrNotFound reports that an immutable block is absent from a transport.
// Implementations wrap this sentinel so callers can distinguish absence from
// cancellation, corruption, and backend failures without depending on a
// concrete Gateway, peer, or local-store error type.
var ErrNotFound = errors.New("cas: block not found")

// ErrCorruptedBlock reports that bytes or a write receipt do not match the CID
// they claim. A transport must never expose mismatched bytes to its caller.
var ErrCorruptedBlock = errors.New("cas: returned block does not match requested CID")

// Native resolves and reads MALT objects. Results remain untrusted until the
// caller verifies them against its selected root.
type Native interface {
	Resolve(context.Context, protocol.ResolveRequest) (*protocol.ResolveResult, error)
	Read(context.Context, protocol.ReadRequest) (*protocol.ReadResult, error)
}

// CAS transfers immutable bytes. Get implementations must bind returned bytes
// to the requested CID; callers still enforce application-specific bindings.
type CAS interface {
	Put(context.Context, []byte) (cid.Cid, error)
	PutWithCodec(context.Context, []byte, uint64) (cid.Cid, error)
	Get(context.Context, cid.Cid) ([]byte, error)
	Has(context.Context, cid.Cid) (bool, error)
}

// Block is one immutable CAS write. Codec 0 is normalized to cid.Raw.
type Block struct {
	Data  []byte
	Codec uint64
}

// PutStatus describes how one immutable write was handled. The status is
// operational metadata only; the returned CID remains the authoritative
// binding and must match Block.
type PutStatus string

const (
	PutStatusStored             PutStatus = "stored"
	PutStatusAlreadyPresent     PutStatus = "already_present"
	PutStatusDuplicate          PutStatus = "duplicate"
	PutStatusNewlyPersisted     PutStatus = "newly_persisted"
	PutStatusDuplicateInRequest PutStatus = "duplicate_in_request"
)

// IsValidPutStatus reports whether status is part of the transport-neutral
// immutable-write receipt contract. Unknown remote or adapter values are
// malformed untrusted results and must be rejected as corruption.
func IsValidPutStatus(status PutStatus) bool {
	switch status {
	case PutStatusStored, PutStatusAlreadyPresent, PutStatusDuplicate,
		PutStatusNewlyPersisted, PutStatusDuplicateInRequest:
		return true
	default:
		return false
	}
}

// PutResult is the ordered result for one block in a batch write.
type PutResult struct {
	CID    cid.Cid
	Status PutStatus
}

// BatchCAS is the optional ordered batch extension shared by Gateway, local,
// peer, and hybrid transports. PutBatch must validate every input before it
// starts persistence. Once persistence has begun, a cancellation or backend
// failure may leave any verified subset stored; on error the returned results
// are unusable. Retrying the complete batch is safe because CAS writes are
// immutable and idempotent. Applications may use batching as an optimization
// but must preserve the single-block CAS semantics when it is unavailable.
type BatchCAS interface {
	CAS
	PutBatch(context.Context, []Block) ([]PutResult, error)
	HasBatch(context.Context, []cid.Cid) ([]bool, error)
}

// MutationResult is an untrusted candidate produced by executing a canonical
// semantic mutation. It carries no accepted/trusted state.
type MutationResult struct {
	BaseRoot        cid.Cid
	CandidateRoot   cid.Cid
	DeltaCount      int
	ArcCount        int
	MALTObjectCount int
	MapCount        int
	ListCount       int
}

// Mutations is the semantic writer capability shared by remote and local
// transports. A successful result is only a candidate for local verification.
type Mutations interface {
	ApplyMutation(context.Context, mutation.SemanticMutation) (MutationResult, error)
	CreateStructureCandidate(context.Context, map[string]string) (cid.Cid, error)
}

// DatasetBinding identifies a transport instance's selected logical dataset
// and branch independently from any URL or network topology.
type DatasetBinding struct {
	DatasetID string
	Branch    string
}

// DatasetBranch observes and updates one bound logical dataset branch. Every
// returned value is untrusted and must be validated against the exact request.
type DatasetBranch interface {
	DatasetBinding() DatasetBinding
	ObserveHead(context.Context) (*ObservedHead, error)
	ApplyCandidate(context.Context, ApplyRequest) (*ApplyResult, error)
}

// Authentication exposes typed V=0 queries with untrusted proof results.
type Authentication interface {
	Authenticate(context.Context, protocol.AuthenticationRequest) (*protocol.AuthenticationResult, error)
}

// AuthenticationWriter transfers complete candidate materialization. It has
// no authority to publish or accept a root.
type AuthenticationWriter interface {
	AuthenticationCandidate(context.Context, cid.Cid) (*protocol.AuthenticationCandidate, error)
	MaterializeAuthentication(context.Context, protocol.AuthenticationCandidate) (cid.Cid, error)
}

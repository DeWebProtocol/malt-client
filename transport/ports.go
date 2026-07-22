package transport

import (
	"context"

	"github.com/dewebprotocol/malt/mutation"
	"github.com/dewebprotocol/malt/protocol"
	cid "github.com/ipfs/go-cid"
)

// Native is the untrusted transport for MALT resolve/read contracts. A caller
// must verify every returned result against the original caller-selected root.
type Native interface {
	Resolve(context.Context, protocol.ResolveRequest) (*protocol.ResolveResult, error)
	Read(context.Context, protocol.ReadRequest) (*protocol.ReadResult, error)
}

// Mutations is the untrusted writer transport. Returned roots are candidates,
// never accepted roots.
type Mutations interface {
	ApplyRootSemanticMutation(context.Context, string, *SemanticMutationRequest) (*SemanticMutationResponse, error)
	CreateRootStructure(context.Context, map[string]string) (*CreateStructureResponse, error)
}

// CAS is the immutable byte transport. Implementations bind response bytes to
// requested or returned CIDs before exposing them.
type CAS interface {
	Put(context.Context, []byte) (cid.Cid, error)
	PutWithCodec(context.Context, []byte, uint64) (cid.Cid, error)
	Get(context.Context, cid.Cid) ([]byte, error)
	Has(context.Context, cid.Cid) (bool, error)
}

// Diagnostics exposes operator measurements only. It is never part of a
// client trust decision.
type Diagnostics interface {
	Health(context.Context) (*HealthResponse, error)
	Metrics(context.Context) (*MetricsSnapshot, error)
	MetricsWithStorage(context.Context) (*MetricsSnapshot, error)
}

// MerkleDAGProfile exposes only the two fixed compatibility routes. It does
// not permit application packages to select arbitrary gateway paths.
type MerkleDAGProfile interface {
	PostMerkleDAGResolve(context.Context, []byte) ([]byte, error)
	PostMerkleDAGRead(context.Context, []byte) ([]byte, error)
	PostMerkleDAGCARRead(context.Context, []byte) ([]byte, error)
}

// ClientRoot is the untrusted stateful-writer transport. Implementations
// return complete state candidates and exact durability receipts; callers
// independently verify both and keep trust promotion separate.
type ClientRoot interface {
	FetchUpdateView(context.Context, cid.Cid, *protocol.UpdateViewBounds) (*UpdateViewResponse, error)
	SubmitClientRoot(context.Context, mutation.ClientRootBundle) (*ClientRootResponse, error)
}

var (
	_ Native           = (*Client)(nil)
	_ Mutations        = (*Client)(nil)
	_ CAS              = (*Client)(nil)
	_ Diagnostics      = (*Client)(nil)
	_ MerkleDAGProfile = (*Client)(nil)
	_ ClientRoot       = (*Client)(nil)
)

package unixfs

import (
	"context"
	"fmt"

	"github.com/dewebprotocol/malt-client/transport"
	unixfsmodel "github.com/dewebprotocol/malt-client/unixfs/model"
	"github.com/dewebprotocol/malt/mutation"
	cid "github.com/ipfs/go-cid"
)

// MutationTransport is the narrow untrusted writer capability consumed by the
// UnixFS application. A successful response contains only a candidate root.
type MutationTransport interface {
	ApplySemanticMutation(context.Context, mutation.SemanticMutation) (*transport.SemanticMutationResponse, error)
}

// ApplyPlan translates a UnixFS application plan into a MALT semantic
// mutation without moving UnixFS semantics into the generic transport.
func ApplyPlan(ctx context.Context, remote MutationTransport, plan *unixfsmodel.MutationPlan, fallbackRoot cid.Cid) (*transport.SemanticMutationResponse, error) {
	if remote == nil {
		return nil, fmt.Errorf("unixfs mutation transport is nil")
	}
	if plan == nil {
		return nil, fmt.Errorf("unixfs mutation plan is nil")
	}
	return remote.ApplySemanticMutation(ctx, plan.CoreMutation(fallbackRoot))
}

var _ MutationTransport = (*transport.Client)(nil)

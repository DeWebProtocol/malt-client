package unixfs

import (
	"context"
	"fmt"

	"github.com/dewebprotocol/malt-client/transport"
	"github.com/dewebprotocol/malt/mutation"
	cid "github.com/ipfs/go-cid"
)

// GatewayMutationRemote is the untrusted gateway capability consumed by the
// UnixFS application adapter. Concrete HTTP response types remain private to
// this adapter and never cross the UnixFS application boundary.
type GatewayMutationRemote interface {
	ApplySemanticMutation(context.Context, mutation.SemanticMutation) (*transport.SemanticMutationResponse, error)
	CreatePayloadRoot(context.Context, map[string]string) (*transport.CreateStructureResponse, error)
}

// GatewayMutationAdapter translates generic gateway mutation receipts into
// UnixFS-owned candidate-root values and fixed-list writer operations.
type GatewayMutationAdapter struct {
	remote GatewayMutationRemote
}

func NewGatewayMutationAdapter(remote GatewayMutationRemote) (*GatewayMutationAdapter, error) {
	if remote == nil {
		return nil, fmt.Errorf("unixfs gateway mutation remote is nil")
	}
	return &GatewayMutationAdapter{remote: remote}, nil
}

func (a *GatewayMutationAdapter) ApplySemanticMutation(ctx context.Context, mut mutation.SemanticMutation) (CandidateRootReceipt, error) {
	if a == nil || a.remote == nil {
		return CandidateRootReceipt{}, fmt.Errorf("unixfs gateway mutation adapter is nil")
	}
	response, err := a.remote.ApplySemanticMutation(ctx, mut)
	if err != nil {
		return CandidateRootReceipt{}, err
	}
	if response == nil {
		return CandidateRootReceipt{}, fmt.Errorf("gateway returned a nil semantic mutation receipt")
	}
	candidate, err := cid.Parse(response.NewRoot)
	if err != nil {
		return CandidateRootReceipt{}, fmt.Errorf("decode gateway candidate root: %w", err)
	}
	return CandidateRootReceipt{BaseRoot: mut.BaseRoot, CandidateRoot: candidate, Accepted: false}, nil
}

func (a *GatewayMutationAdapter) CreateFixedListBaseRoot(ctx context.Context) (cid.Cid, error) {
	if a == nil || a.remote == nil {
		return cid.Undef, fmt.Errorf("unixfs gateway mutation adapter is nil")
	}
	response, err := a.remote.CreatePayloadRoot(ctx, nil)
	if err != nil {
		return cid.Undef, err
	}
	if response == nil {
		return cid.Undef, fmt.Errorf("gateway returned a nil fixed-list base-root receipt")
	}
	root, err := cid.Parse(response.Root)
	if err != nil {
		return cid.Undef, fmt.Errorf("decode fixed-list base root: %w", err)
	}
	return root, nil
}

func (a *GatewayMutationAdapter) ApplyFixedListPayloadMutation(ctx context.Context, mut mutation.SemanticMutation) (cid.Cid, error) {
	receipt, err := a.ApplySemanticMutation(ctx, mut)
	if err != nil {
		return cid.Undef, err
	}
	return receipt.CandidateRoot, nil
}

var _ MutationTransport = (*GatewayMutationAdapter)(nil)
var _ FixedListPayloadWriter = (*GatewayMutationAdapter)(nil)

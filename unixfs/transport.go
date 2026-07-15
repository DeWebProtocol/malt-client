package unixfs

import (
	"context"
	"fmt"

	unixfsmodel "github.com/dewebprotocol/malt-client/unixfs/model"
	"github.com/dewebprotocol/malt/mutation"
	cid "github.com/ipfs/go-cid"
)

// CandidateRootReceipt is the transport-neutral result of executing one
// semantic mutation. It is evidence of execution only: Accepted is always
// false and the candidate requires an explicit trust-policy action.
type CandidateRootReceipt struct {
	BaseRoot      cid.Cid `json:"base_root"`
	CandidateRoot cid.Cid `json:"candidate_root"`
	Accepted      bool    `json:"accepted"`
}

// MutationTransport is the narrow untrusted writer capability consumed by the
// UnixFS application. A successful response contains only a candidate root.
type MutationTransport interface {
	ApplySemanticMutation(context.Context, mutation.SemanticMutation) (CandidateRootReceipt, error)
}

// ApplyPlan translates a UnixFS application plan into a MALT semantic
// mutation without moving UnixFS semantics into the generic transport.
func ApplyPlan(ctx context.Context, remote MutationTransport, plan *unixfsmodel.MutationPlan, fallbackRoot cid.Cid) (CandidateRootReceipt, error) {
	if remote == nil {
		return CandidateRootReceipt{}, fmt.Errorf("unixfs mutation transport is nil")
	}
	if plan == nil {
		return CandidateRootReceipt{}, fmt.Errorf("unixfs mutation plan is nil")
	}
	mut := plan.CoreMutation(fallbackRoot)
	receipt, err := remote.ApplySemanticMutation(ctx, mut)
	if err != nil {
		return CandidateRootReceipt{}, err
	}
	if receipt.Accepted {
		return CandidateRootReceipt{}, fmt.Errorf("unixfs mutation transport marked an untrusted candidate as accepted")
	}
	if !receipt.BaseRoot.Equals(mut.BaseRoot) {
		return CandidateRootReceipt{}, fmt.Errorf("unixfs mutation receipt base root does not match the requested mutation")
	}
	if !receipt.CandidateRoot.Defined() {
		return CandidateRootReceipt{}, fmt.Errorf("unixfs mutation receipt candidate root is undefined")
	}
	return receipt, nil
}

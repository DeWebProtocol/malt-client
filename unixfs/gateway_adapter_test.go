package unixfs_test

import (
	"context"
	"testing"

	"github.com/dewebprotocol/malt-client/transport"
	"github.com/dewebprotocol/malt-client/unixfs"
	unixfsmodel "github.com/dewebprotocol/malt-client/unixfs/model"
	"github.com/dewebprotocol/malt/mutation"
	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

type mutationRemote struct {
	base      cid.Cid
	candidate cid.Cid
}

func (r mutationRemote) ApplySemanticMutation(_ context.Context, mut mutation.SemanticMutation) (*transport.SemanticMutationResponse, error) {
	if !mut.BaseRoot.Equals(r.base) {
		return &transport.SemanticMutationResponse{NewRoot: r.base.String()}, nil
	}
	return &transport.SemanticMutationResponse{NewRoot: r.candidate.String()}, nil
}
func (r mutationRemote) CreatePayloadRoot(context.Context, map[string]string) (*transport.CreateStructureResponse, error) {
	return &transport.CreateStructureResponse{Root: r.base.String()}, nil
}

func TestGatewayMutationAdapterReturnsUnacceptedTransportNeutralReceipt(t *testing.T) {
	base := adapterCID(t, "base")
	candidate := adapterCID(t, "candidate")
	adapter, err := unixfs.NewGatewayMutationAdapter(mutationRemote{base: base, candidate: candidate})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := adapter.ApplySemanticMutation(t.Context(), mutation.SemanticMutation{BaseRoot: base})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Accepted || !receipt.BaseRoot.Equals(base) || !receipt.CandidateRoot.Equals(candidate) {
		t.Fatalf("receipt = %#v", receipt)
	}
	listBase, err := adapter.CreateFixedListBaseRoot(t.Context())
	if err != nil || !listBase.Equals(base) {
		t.Fatalf("fixed-list base = %s err=%v", listBase, err)
	}
}

type acceptedMutationTransport struct{ receipt unixfs.CandidateRootReceipt }

func (t acceptedMutationTransport) ApplySemanticMutation(context.Context, mutation.SemanticMutation) (unixfs.CandidateRootReceipt, error) {
	return t.receipt, nil
}

func TestApplyPlanRejectsTransportClaimingCandidateAccepted(t *testing.T) {
	base := adapterCID(t, "base")
	candidate := adapterCID(t, "candidate")
	remote := acceptedMutationTransport{receipt: unixfs.CandidateRootReceipt{BaseRoot: base, CandidateRoot: candidate, Accepted: true}}
	plan := &unixfsmodel.MutationPlan{BaseRoot: base}
	if _, err := unixfs.ApplyPlan(t.Context(), remote, plan, cid.Undef); err == nil {
		t.Fatal("ApplyPlan accepted a transport receipt marked as accepted")
	}
}

func adapterCID(t *testing.T, body string) cid.Cid {
	t.Helper()
	hash, err := mh.Sum([]byte(body), mh.SHA2_256, -1)
	if err != nil {
		t.Fatal(err)
	}
	return cid.NewCidV1(cid.Raw, hash)
}

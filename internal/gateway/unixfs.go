package gateway

import (
	"context"
	"fmt"
	"strconv"

	api "github.com/dewebprotocol/malt-client/internal/api"
	unixfs "github.com/dewebprotocol/malt-client/unixfs/model"
	"github.com/dewebprotocol/malt/auth/arcset"
	"github.com/dewebprotocol/malt/mutation"
	cid "github.com/ipfs/go-cid"
)

// UnixFSClient composes UnixFS application plans with the executor mutation endpoint.
type UnixFSClient struct {
	client *Client
}

// UnixFS returns the client-side UnixFS application facade.
func (c *Client) UnixFS() *UnixFSClient {
	return &UnixFSClient{client: c}
}

// ApplyPlan materializes a client-side UnixFS plan through the executor mutation endpoint.
func (u *UnixFSClient) ApplyPlan(ctx context.Context, plan *unixfs.MutationPlan, fallbackRoot cid.Cid) (*api.SemanticMutationResponse, error) {
	if plan == nil {
		return nil, fmt.Errorf("unixfs mutation plan is nil")
	}
	return u.client.ApplySemanticMutation(ctx, plan.WriterMutation(fallbackRoot))
}

// ApplySemanticMutation materializes a writer mutation through the graph writer endpoint.
func (c *Client) ApplySemanticMutation(ctx context.Context, mut mutation.SemanticMutation) (*api.SemanticMutationResponse, error) {
	if !mut.BaseRoot.Defined() {
		return nil, fmt.Errorf("semantic mutation base root is undefined")
	}
	req, err := semanticMutationRequestFromCore(mut)
	if err != nil {
		return nil, err
	}
	return c.ApplyRootSemanticMutation(ctx, mut.BaseRoot.String(), req)
}

// CreateFixedListBaseRoot creates the temporary map root needed for fixed-list
// payload materialization.
func (c *Client) CreateFixedListBaseRoot(ctx context.Context) (cid.Cid, error) {
	resp, err := c.CreatePayloadRoot(ctx, nil)
	if err != nil {
		return cid.Undef, err
	}
	root, err := cid.Decode(resp.Root)
	if err != nil {
		return cid.Undef, fmt.Errorf("decode temporary root CID: %w", err)
	}
	return root, nil
}

// ApplyFixedListPayloadMutation applies a fixed-list payload writer mutation
// and returns the resulting list root.
func (c *Client) ApplyFixedListPayloadMutation(ctx context.Context, mut mutation.SemanticMutation) (cid.Cid, error) {
	resp, err := c.ApplySemanticMutation(ctx, mut)
	if err != nil {
		return cid.Undef, err
	}
	listRoot, err := cid.Decode(resp.NewRoot)
	if err != nil {
		return cid.Undef, fmt.Errorf("decode list root CID: %w", err)
	}
	return listRoot, nil
}

func semanticMutationRequestFromCore(mut mutation.SemanticMutation) (*api.SemanticMutationRequest, error) {
	req := &api.SemanticMutationRequest{
		Deltas: make([]api.SemanticMutationDelta, 0, len(mut.Deltas)),
	}
	for i, delta := range mut.Deltas {
		if delta.Changes == nil {
			return nil, fmt.Errorf("delta %d changes are nil", i)
		}
		out := api.SemanticMutationDelta{
			Kind:    string(delta.Kind),
			Changes: make([]api.SemanticMutationChange, 0, delta.Changes.Len()),
		}
		if delta.Object.Defined() {
			out.Object = delta.Object.String()
		}
		if delta.ExpectedRoot.Defined() {
			out.ExpectedRoot = delta.ExpectedRoot.String()
		}
		if delta.Commit.FixedList != nil {
			out.Commit = &api.SemanticCommitDescriptor{
				FixedList: &api.SemanticFixedListCommit{
					TotalSize: delta.Commit.FixedList.TotalSize,
					ChunkSize: delta.Commit.FixedList.ChunkSize,
				},
			}
		}
		for _, change := range delta.Changes.Changes() {
			changeReq, err := semanticMutationChangeFromWriter(delta.Kind, change)
			if err != nil {
				return nil, fmt.Errorf("delta %d: %w", i, err)
			}
			out.Changes = append(out.Changes, changeReq)
		}
		req.Deltas = append(req.Deltas, out)
	}
	return req, nil
}

func semanticMutationChangeFromWriter(kind arcset.Kind, change arcset.ArcChange) (api.SemanticMutationChange, error) {
	out := api.SemanticMutationChange{}
	switch kind {
	case arcset.KindMap:
		out.Path = change.Coordinate.String()
	case arcset.KindList:
		index, err := strconv.ParseUint(change.Coordinate.String(), 10, 64)
		if err != nil {
			return api.SemanticMutationChange{}, fmt.Errorf("invalid list coordinate %q: %w", change.Coordinate.String(), err)
		}
		out.Index = &index
	default:
		return api.SemanticMutationChange{}, fmt.Errorf("%w: %q", arcset.ErrInvalidKind, kind)
	}
	if change.Before != nil {
		out.Before = semanticMutationTargetFromWriter(*change.Before)
	}
	if change.After != nil {
		out.After = semanticMutationTargetFromWriter(*change.After)
	}
	return out, nil
}

func semanticMutationTargetFromWriter(target arcset.TargetRef) *api.SemanticMutationTarget {
	return &api.SemanticMutationTarget{
		Target:     target.CID().String(),
		TargetKind: string(target.Kind()),
	}
}

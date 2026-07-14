package transport

import (
	"context"
	"fmt"
	"strconv"

	"github.com/dewebprotocol/malt/auth/arcset"
	"github.com/dewebprotocol/malt/mutation"
	cid "github.com/ipfs/go-cid"
)

// ApplySemanticMutation materializes a semantic mutation. It does not accept
// the returned root into any local trust store.
func (c *Client) ApplySemanticMutation(ctx context.Context, mut mutation.SemanticMutation) (*SemanticMutationResponse, error) {
	if !mut.BaseRoot.Defined() {
		return nil, fmt.Errorf("semantic mutation base root is undefined")
	}
	req, err := semanticMutationRequestFromCore(mut)
	if err != nil {
		return nil, err
	}
	return c.ApplyRootSemanticMutation(ctx, mut.BaseRoot.String(), req)
}

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

func (c *Client) ApplyFixedListPayloadMutation(ctx context.Context, mut mutation.SemanticMutation) (cid.Cid, error) {
	resp, err := c.ApplySemanticMutation(ctx, mut)
	if err != nil {
		return cid.Undef, err
	}
	root, err := cid.Decode(resp.NewRoot)
	if err != nil {
		return cid.Undef, fmt.Errorf("decode list root CID: %w", err)
	}
	return root, nil
}

func semanticMutationRequestFromCore(mut mutation.SemanticMutation) (*SemanticMutationRequest, error) {
	req := &SemanticMutationRequest{Deltas: make([]SemanticMutationDelta, 0, len(mut.Deltas))}
	for i, delta := range mut.Deltas {
		if delta.Changes == nil {
			return nil, fmt.Errorf("delta %d changes are nil", i)
		}
		out := SemanticMutationDelta{Kind: string(delta.Kind), Changes: make([]SemanticMutationChange, 0, delta.Changes.Len())}
		if delta.Object.Defined() {
			out.Object = delta.Object.String()
		}
		if delta.ExpectedRoot.Defined() {
			out.ExpectedRoot = delta.ExpectedRoot.String()
		}
		if delta.Commit.FixedList != nil {
			out.Commit = &SemanticCommitDescriptor{FixedList: &SemanticFixedListCommit{TotalSize: delta.Commit.FixedList.TotalSize, ChunkSize: delta.Commit.FixedList.ChunkSize}}
		}
		for _, change := range delta.Changes.Changes() {
			converted, err := semanticMutationChangeFromCore(delta.Kind, change)
			if err != nil {
				return nil, fmt.Errorf("delta %d: %w", i, err)
			}
			out.Changes = append(out.Changes, converted)
		}
		req.Deltas = append(req.Deltas, out)
	}
	return req, nil
}

func semanticMutationChangeFromCore(kind arcset.Kind, change arcset.ArcChange) (SemanticMutationChange, error) {
	out := SemanticMutationChange{}
	switch kind {
	case arcset.KindMap:
		out.Path = change.Coordinate.String()
	case arcset.KindList:
		index, err := strconv.ParseUint(change.Coordinate.String(), 10, 64)
		if err != nil {
			return SemanticMutationChange{}, fmt.Errorf("invalid list coordinate %q: %w", change.Coordinate.String(), err)
		}
		out.Index = &index
	default:
		return SemanticMutationChange{}, fmt.Errorf("%w: %q", arcset.ErrInvalidKind, kind)
	}
	if change.Before != nil {
		out.Before = semanticMutationTargetFromCore(*change.Before)
	}
	if change.After != nil {
		out.After = semanticMutationTargetFromCore(*change.After)
	}
	return out, nil
}

func semanticMutationTargetFromCore(target arcset.TargetRef) *SemanticMutationTarget {
	return &SemanticMutationTarget{Target: target.CID().String(), TargetKind: string(target.Kind())}
}

package application

import (
	"context"
	"fmt"

	"github.com/dewebprotocol/malt-core/auth/engine"
	"github.com/dewebprotocol/malt-core/protocol"
	coresdk "github.com/dewebprotocol/malt-core/sdk/authentication"
	cid "github.com/ipfs/go-cid"
)

// Authentication composes explicit/accepted root selection with Core's typed
// SDK. AA implementations and layouts remain entirely owned by Core.
type Authentication struct {
	roots  *Roots
	remote AuthenticationRemote
	engine *engine.Engine
}

func NewAuthentication(roots *Roots, remote AuthenticationRemote, e *engine.Engine) (*Authentication, error) {
	if roots == nil || remote == nil || e == nil {
		return nil, fmt.Errorf("root selector, typed transport and authentication engine are required")
	}
	return &Authentication{roots, remote, e}, nil
}
func (a *Authentication) Read(ctx context.Context, selected string, q protocol.AuthenticationRequest) (*protocol.AuthenticationResult, error) {
	selection, err := a.roots.Select(selected)
	if err != nil {
		return nil, err
	}
	if q.Root != "" {
		root, err := cid.Decode(q.Root)
		if err != nil || !root.Equals(selection.Root) {
			return nil, fmt.Errorf("query Root differs from selected Root")
		}
	}
	q.Root = selection.Root.String()
	q.Profile = protocol.AuthenticationProfile
	result, err := a.remote.Authenticate(ctx, q)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, fmt.Errorf("nil authentication result")
	}
	valid, err := coresdk.Verify(a.engine, q, *result)
	if err != nil {
		return nil, fmt.Errorf("verify authentication locally: %w", err)
	}
	if !valid {
		return nil, fmt.Errorf("authentication proof is invalid")
	}
	return result, nil
}

// Store computes and sends a candidate. It never promotes a root or changes
// accepted/observed state. Previous is only an optional storage-lineage base.
func (a *Authentication) Store(ctx context.Context, state engine.State, previous cid.Cid) (protocol.AuthenticationCandidate, error) {
	writer, ok := a.remote.(AuthenticationCandidateWriter)
	if !ok {
		return protocol.AuthenticationCandidate{}, fmt.Errorf("typed candidate storage unavailable")
	}
	candidate, err := coresdk.Prepare(ctx, a.engine, state)
	if err != nil {
		return protocol.AuthenticationCandidate{}, err
	}
	if previous.Defined() {
		candidate.Previous = previous.String()
	}
	root, err := writer.MaterializeAuthentication(ctx, candidate)
	if err != nil {
		return protocol.AuthenticationCandidate{}, err
	}
	expected, _ := cid.Decode(candidate.Root)
	if !root.Equals(expected) {
		return protocol.AuthenticationCandidate{}, fmt.Errorf("materializer changed candidate Root")
	}
	return candidate, nil
}

// AuthenticationRemote is the untrusted capability consumed by this use case.
// Gateway and peer adapters satisfy it without application transport imports.
type AuthenticationRemote interface {
	Authenticate(context.Context, protocol.AuthenticationRequest) (*protocol.AuthenticationResult, error)
}
type AuthenticationCandidateWriter interface {
	MaterializeAuthentication(context.Context, protocol.AuthenticationCandidate) (cid.Cid, error)
}

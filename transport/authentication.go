package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/dewebprotocol/malt-core/protocol"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

// Authenticate returns typed, untrusted binding/traversal/range evidence.
// Application code must verify with Core against its caller-selected request.
func (c *Client) Authenticate(ctx context.Context, q protocol.AuthenticationRequest) (*protocol.AuthenticationResult, error) {
	if err := q.Validate(); err != nil {
		return nil, err
	}
	var raw json.RawMessage
	if err := c.doNative(ctx, http.MethodPost, "/v1/authentication/query", nil, q, &raw); err != nil {
		return nil, err
	}
	result, err := protocol.DecodeAuthenticationResult(raw)
	if err != nil {
		return nil, err
	}
	return &result, nil
}
func (c *Client) AuthenticationCandidate(ctx context.Context, root cid.Cid) (*protocol.AuthenticationCandidate, error) {
	if _, _, err := maltcid.ParseRoot(root); err != nil {
		return nil, err
	}
	var raw json.RawMessage
	if err := c.doNative(ctx, http.MethodGet, "/v1/authentication/candidates/"+url.PathEscape(root.String()), nil, nil, &raw); err != nil {
		return nil, err
	}
	result, err := protocol.DecodeAuthenticationCandidate(raw)
	if err != nil {
		return nil, err
	}
	returned, err := cid.Decode(result.Root)
	if err != nil || !returned.Equals(root) {
		return nil, fmt.Errorf("candidate view does not match selected Root")
	}
	return &result, nil
}
func (c *Client) MaterializeAuthentication(ctx context.Context, candidate protocol.AuthenticationCandidate) (cid.Cid, error) {
	expected, err := cid.Decode(candidate.Root)
	if err != nil {
		return cid.Undef, err
	}
	if _, _, err := maltcid.ParseRoot(expected); err != nil {
		return cid.Undef, err
	}
	if candidate.Profile != protocol.AuthenticationProfile {
		return cid.Undef, fmt.Errorf("unsupported authentication profile")
	}
	var receipt struct {
		Profile string `json:"profile"`
		Root    string `json:"root"`
	}
	if err := c.doNative(ctx, http.MethodPost, "/v1/authentication/candidates", nil, candidate, &receipt); err != nil {
		return cid.Undef, err
	}
	root, err := cid.Decode(receipt.Root)
	if err != nil || receipt.Profile != protocol.AuthenticationProfile || !root.Equals(expected) {
		return cid.Undef, fmt.Errorf("materialization receipt changed candidate Root")
	}
	return root, nil
}

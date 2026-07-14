// Package gateway provides the untrusted managed-gateway transport used by
// the trusted local MALT client.
package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	api "github.com/dewebprotocol/malt-client/internal/api"
	"github.com/dewebprotocol/malt-client/internal/cas"
	"github.com/dewebprotocol/malt/protocol"
	cid "github.com/ipfs/go-cid"
)

// Error is a structured managed-gateway API error.
type Error struct {
	StatusCode int
	Message    string
}

func (e *Error) Error() string {
	return fmt.Sprintf("gateway API error (%d): %s", e.StatusCode, e.Message)
}

// Client is a thin HTTP transport. It never establishes trust in a returned
// root, target, ProofList, or payload; callers verify those values locally.
type Client struct {
	baseURL string
	http    *http.Client
}

// NewWithBaseURL creates a gateway client from a base URL.
func NewWithBaseURL(baseURL string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http: &http.Client{
			Timeout: 5 * time.Minute,
		},
	}
}

// Health checks managed-gateway health.
func (c *Client) Health(ctx context.Context) (*api.HealthResponse, error) {
	var response api.HealthResponse
	if err := c.do(ctx, http.MethodGet, "/healthz", nil, nil, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// Put stores one immutable raw payload through the gateway-owned CAS backend.
func (c *Client) Put(ctx context.Context, data []byte) (cid.Cid, error) {
	return c.PutWithCodec(ctx, data, cid.Raw)
}

// PutWithCodec stores one immutable payload under the requested CID codec and
// rejects a gateway response that is not the canonical CID for those bytes.
func (c *Client) PutWithCodec(ctx context.Context, data []byte, codec uint64) (cid.Cid, error) {
	var response struct {
		CID string `json:"cid"`
	}
	if err := c.doRaw(ctx, http.MethodPost, "/v1/cas", map[string]string{
		"codec": strconv.FormatUint(cas.NormalizeCodec(codec), 10),
	}, "application/octet-stream", bytes.NewReader(data), &response); err != nil {
		return cid.Undef, err
	}
	got, err := cid.Parse(response.CID)
	if err != nil {
		return cid.Undef, fmt.Errorf("gateway returned invalid CAS CID: %w", err)
	}
	want, err := cas.CIDForBlock(cas.Block{Data: data, Codec: codec})
	if err != nil {
		return cid.Undef, err
	}
	if !got.Equals(want) {
		return cid.Undef, fmt.Errorf("gateway returned CAS CID %s, want %s", got, want)
	}
	return got, nil
}

// Get reads one immutable payload and validates its CID before returning it.
func (c *Client) Get(ctx context.Context, key cid.Cid) ([]byte, error) {
	u, err := c.endpoint("/v1/cas/" + url.PathEscape(key.String()))
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, c.responseError(resp)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	want, err := key.Prefix().Sum(data)
	if err != nil || !want.Equals(key) {
		return nil, fmt.Errorf("gateway CAS body does not match CID %s", key)
	}
	return data, nil
}

// Has checks whether the gateway CAS contains a payload.
func (c *Client) Has(ctx context.Context, key cid.Cid) (bool, error) {
	u, err := c.endpoint("/v1/cas/" + url.PathEscape(key.String()))
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u.String(), nil)
	if err != nil {
		return false, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, c.responseError(resp)
	}
	return true, nil
}

// Resolve executes the transport-neutral MALT resolve contract. The caller
// must verify the result against the original request and a trusted root.
func (c *Client) Resolve(ctx context.Context, request protocol.ResolveRequest) (*protocol.ResolveResult, error) {
	if err := request.Validate(); err != nil {
		return nil, err
	}
	var result protocol.ResolveResult
	if err := c.do(ctx, http.MethodPost, "/v1/resolve", nil, request, &result); err != nil {
		return nil, err
	}
	if err := result.Validate(); err != nil {
		return nil, fmt.Errorf("invalid resolve result: %w", err)
	}
	return &result, nil
}

// ResolveContract is retained as a source-compatible alias for Resolve.
func (c *Client) ResolveContract(ctx context.Context, request protocol.ResolveRequest) (*protocol.ResolveResult, error) {
	return c.Resolve(ctx, request)
}

// Read executes one transport-neutral primitive map/list read contract.
func (c *Client) Read(ctx context.Context, request protocol.ReadRequest) (*protocol.ReadResult, error) {
	if err := request.Validate(); err != nil {
		return nil, err
	}
	var result protocol.ReadResult
	if err := c.do(ctx, http.MethodPost, "/v1/read", nil, request, &result); err != nil {
		return nil, err
	}
	if err := result.Validate(); err != nil {
		return nil, fmt.Errorf("invalid read result: %w", err)
	}
	return &result, nil
}

// ReadContract is retained as a source-compatible alias for Read.
func (c *Client) ReadContract(ctx context.Context, request protocol.ReadRequest) (*protocol.ReadResult, error) {
	return c.Read(ctx, request)
}

// DiagnoseResolve asks the gateway to run its verifier for diagnostics only.
// Trust decisions must use the local MALT verifier.
func (c *Client) DiagnoseResolve(ctx context.Context, value protocol.ResolveVerification) (*protocol.VerificationResult, error) {
	var result protocol.VerificationResult
	if err := c.do(ctx, http.MethodPost, "/v1/verify/resolve", nil, value, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DiagnoseRead asks the gateway to run its verifier for diagnostics only.
func (c *Client) DiagnoseRead(ctx context.Context, value protocol.ReadVerification) (*protocol.VerificationResult, error) {
	var result protocol.VerificationResult
	if err := c.do(ctx, http.MethodPost, "/v1/verify/read", nil, value, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ApplyRootSemanticMutation asks the untrusted gateway to materialize a
// semantic mutation under an explicit root. The returned root is a candidate.
func (c *Client) ApplyRootSemanticMutation(ctx context.Context, root string, request *api.SemanticMutationRequest) (*api.SemanticMutationResponse, error) {
	var response api.SemanticMutationResponse
	if err := c.do(ctx, http.MethodPost, "/v1/roots/"+url.PathEscape(root)+"/mutations", nil, request, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// CreateRootStructure materializes a new structure from canonical bindings.
// The returned root is untrusted until checked or explicitly accepted.
func (c *Client) CreateRootStructure(ctx context.Context, arcs map[string]string) (*api.CreateStructureResponse, error) {
	var response api.CreateStructureResponse
	request := api.CreateStructureRequest{Arcs: arcs}
	if err := c.do(ctx, http.MethodPost, "/v1/roots", nil, &request, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// CreatePayloadRoot creates a minimal map root with an empty payload binding.
func (c *Client) CreatePayloadRoot(ctx context.Context, extras map[string]string) (*api.CreateStructureResponse, error) {
	arcs := make(map[string]string, len(extras)+1)
	for key, value := range extras {
		arcs[key] = value
	}
	arcs["@payload"] = "bafkqaaa"
	return c.CreateRootStructure(ctx, arcs)
}

func (c *Client) endpoint(route string) (*url.URL, error) {
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, err
	}
	u.Path = path.Join(u.Path, route)
	return u, nil
}

func (c *Client) responseError(resp *http.Response) error {
	var apiErr api.ErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiErr); err == nil {
		if message := apiErr.MessageText(); message != "" {
			return &Error{StatusCode: resp.StatusCode, Message: message}
		}
	}
	return &Error{StatusCode: resp.StatusCode, Message: http.StatusText(resp.StatusCode)}
}

func (c *Client) do(ctx context.Context, method, route string, query map[string]string, body, out any) error {
	u, err := c.endpoint(route)
	if err != nil {
		return err
	}
	values := u.Query()
	for key, value := range query {
		values.Set(key, value)
	}
	u.RawQuery = values.Encode()

	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.execute(req, out)
}

func (c *Client) doRaw(ctx context.Context, method, route string, query map[string]string, contentType string, body io.Reader, out any) error {
	u, err := c.endpoint(route)
	if err != nil {
		return err
	}
	values := u.Query()
	for key, value := range query {
		values.Set(key, value)
	}
	u.RawQuery = values.Encode()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return c.execute(req, out)
}

func (c *Client) execute(req *http.Request, out any) error {
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return c.responseError(resp)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

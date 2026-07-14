package client

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

// Options configures the public managed-gateway transport.
type Options struct {
	BaseURL               string
	HTTPClient            *http.Client
	MaxJSONResponseBytes  int64
	MaxBlobResponseBytes  int64
	MaxErrorResponseBytes int64
}

const (
	DefaultMaxJSONResponseBytes  int64 = 96 << 20
	DefaultMaxBlobResponseBytes  int64 = 64 << 20
	DefaultMaxErrorResponseBytes int64 = 1 << 20
)

// Client is a thin HTTP transport. It never establishes trust in a returned
// root, target, ProofList, or payload.
type Client struct {
	baseURL               string
	http                  *http.Client
	maxJSONResponseBytes  int64
	maxBlobResponseBytes  int64
	maxErrorResponseBytes int64
}

// New creates a transport from explicit options.
func New(opts Options) (*Client, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(opts.BaseURL), "/")
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid gateway base URL: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("gateway base URL must be absolute")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("gateway base URL must use http or https")
	}
	maxJSON, err := responseLimit(opts.MaxJSONResponseBytes, DefaultMaxJSONResponseBytes, "JSON")
	if err != nil {
		return nil, err
	}
	maxBlob, err := responseLimit(opts.MaxBlobResponseBytes, DefaultMaxBlobResponseBytes, "blob")
	if err != nil {
		return nil, err
	}
	maxError, err := responseLimit(opts.MaxErrorResponseBytes, DefaultMaxErrorResponseBytes, "error")
	if err != nil {
		return nil, err
	}
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Minute}
	}
	return &Client{
		baseURL: baseURL, http: httpClient,
		maxJSONResponseBytes: maxJSON, maxBlobResponseBytes: maxBlob, maxErrorResponseBytes: maxError,
	}, nil
}

// NewWithBaseURL creates a validated client with the default HTTP timeout.
func NewWithBaseURL(baseURL string) (*Client, error) {
	return New(Options{BaseURL: baseURL})
}

// Health checks managed-gateway health.
func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	var response HealthResponse
	if err := c.do(ctx, http.MethodGet, "/healthz", nil, nil, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// Put stores an immutable raw payload and checks the returned CID.
func (c *Client) Put(ctx context.Context, data []byte) (cid.Cid, error) {
	return c.PutWithCodec(ctx, data, cid.Raw)
}

// PutWithCodec stores an immutable payload under the requested CID codec and
// rejects a response that is not the canonical CID for those bytes.
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
	data, err := readBounded(resp.Body, c.maxBlobResponseBytes, "gateway CAS body")
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

// Resolve executes the transport-neutral resolve contract. The caller must
// locally verify the returned result against the original request.
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

// ResolveContract is a compatibility spelling for Resolve.
func (c *Client) ResolveContract(ctx context.Context, request protocol.ResolveRequest) (*protocol.ResolveResult, error) {
	return c.Resolve(ctx, request)
}

// Read executes one transport-neutral primitive map/list read contract. The
// caller must locally verify the returned result against the original request.
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

// ReadContract is a compatibility spelling for Read.
func (c *Client) ReadContract(ctx context.Context, request protocol.ReadRequest) (*protocol.ReadResult, error) {
	return c.Read(ctx, request)
}

// DiagnoseResolve asks the gateway to run its verifier for diagnostics only.
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
// semantic mutation. The returned root is always a candidate.
func (c *Client) ApplyRootSemanticMutation(ctx context.Context, root string, request *SemanticMutationRequest) (*SemanticMutationResponse, error) {
	var response SemanticMutationResponse
	if err := c.do(ctx, http.MethodPost, "/v1/roots/"+url.PathEscape(root)+"/mutations", nil, request, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// CreateRootStructure materializes a map from canonical bindings. The returned
// root is a candidate until independently accepted by the caller.
func (c *Client) CreateRootStructure(ctx context.Context, arcs map[string]string) (*CreateStructureResponse, error) {
	var response CreateStructureResponse
	request := CreateStructureRequest{Arcs: arcs}
	if err := c.do(ctx, http.MethodPost, "/v1/roots", nil, &request, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// CreateStagedRoot implements the UnixFS transport-neutral root creation port.
func (c *Client) CreateStagedRoot(ctx context.Context, arcs map[string]string) (cid.Cid, error) {
	response, err := c.CreateRootStructure(ctx, arcs)
	if err != nil {
		return cid.Undef, err
	}
	root, err := cid.Parse(response.Root)
	if err != nil {
		return cid.Undef, fmt.Errorf("gateway returned invalid created root: %w", err)
	}
	return root, nil
}

// CreatePayloadRoot creates a minimal map root with an empty payload binding.
func (c *Client) CreatePayloadRoot(ctx context.Context, extras map[string]string) (*CreateStructureResponse, error) {
	arcs := make(map[string]string, len(extras)+1)
	for key, value := range extras {
		arcs[key] = value
	}
	arcs["@payload"] = "bafkqaaa"
	return c.CreateRootStructure(ctx, arcs)
}

func (c *Client) endpoint(route string) (*url.URL, error) {
	if c == nil || c.http == nil {
		return nil, fmt.Errorf("gateway client is nil")
	}
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, err
	}
	u.Path = path.Join(u.Path, route)
	return u, nil
}

func (c *Client) responseError(resp *http.Response) error {
	data, err := readBounded(resp.Body, c.maxErrorResponseBytes, "gateway error response")
	if err != nil {
		return &Error{StatusCode: resp.StatusCode, Message: err.Error()}
	}
	var apiErr errorResponse
	if err := json.Unmarshal(data, &apiErr); err == nil {
		if message := apiErr.messageText(); message != "" {
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
		_, err := readBounded(resp.Body, c.maxJSONResponseBytes, "gateway response")
		return err
	}
	data, err := readBounded(resp.Body, c.maxJSONResponseBytes, "gateway JSON response")
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode gateway JSON response: %w", err)
	}
	return nil
}

func responseLimit(value, fallback int64, kind string) (int64, error) {
	if value < 0 {
		return 0, fmt.Errorf("maximum %s response size must not be negative", kind)
	}
	if value == 0 {
		return fallback, nil
	}
	return value, nil
}

func readBounded(reader io.Reader, limit int64, description string) ([]byte, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("%s limit is invalid", description)
	}
	readLimit := limit
	if limit < int64(^uint64(0)>>1) {
		readLimit++
	}
	data, err := io.ReadAll(io.LimitReader(reader, readLimit))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds %d-byte limit", description, limit)
	}
	return data, nil
}

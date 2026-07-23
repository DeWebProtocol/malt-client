package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
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
	BaseURL    string
	HTTPClient *http.Client
	// TenantBearerToken authenticates managed Bucket routes. BucketID selects
	// the Bucket-scoped native MALT and CAS endpoints.
	TenantBearerToken string
	BucketID          string
	// OperatorBearerToken is sent only by MetricsWithStorage. Non-loopback HTTP
	// base URLs are rejected when it is configured, and credentialed redirects
	// are never followed.
	OperatorBearerToken   string
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
	operatorBearerToken   string
	tenantBearerToken     string
	bucketID              string
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
	operatorToken := strings.TrimSpace(opts.OperatorBearerToken)
	if operatorToken != "" && parsed.Scheme != "https" && !isLoopbackGatewayHost(parsed.Hostname()) {
		return nil, fmt.Errorf("operator bearer token requires HTTPS or a loopback HTTP gateway base URL")
	}
	tenantToken := strings.TrimSpace(opts.TenantBearerToken)
	bucketID := strings.TrimSpace(opts.BucketID)
	if bucketID != "" && tenantToken == "" {
		return nil, fmt.Errorf("managed Bucket ID requires a tenant bearer token")
	}
	if tenantToken != "" && parsed.Scheme != "https" && !isLoopbackGatewayHost(parsed.Hostname()) {
		return nil, fmt.Errorf("tenant bearer token requires HTTPS or a loopback HTTP gateway base URL")
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
		baseURL: baseURL, http: httpClient, operatorBearerToken: operatorToken,
		tenantBearerToken: tenantToken, bucketID: bucketID,
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
	if err := c.doRawNative(ctx, http.MethodPost, "/v1/cas", map[string]string{
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
	if c == nil || c.bucketID == "" {
		return nil, fmt.Errorf("single-value CAS Get requires a configured managed Bucket")
	}
	u, err := c.endpoint(c.nativeRoute("/v1/cas/" + url.PathEscape(key.String())))
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.send(req, true)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		responseErr := c.responseError(resp)
		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("%w: %w", cas.ErrNotFound, responseErr)
		}
		return nil, responseErr
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
	if c == nil || c.bucketID == "" {
		return false, fmt.Errorf("single-value CAS Has requires a configured managed Bucket")
	}
	u, err := c.endpoint(c.nativeRoute("/v1/cas/" + url.PathEscape(key.String())))
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u.String(), nil)
	if err != nil {
		return false, err
	}
	resp, err := c.send(req, true)
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
	if err := c.doNative(ctx, http.MethodPost, "/v1/resolve", nil, request, &result); err != nil {
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
	if err := c.doNative(ctx, http.MethodPost, "/v1/read", nil, request, &result); err != nil {
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
	if err := c.doNative(ctx, http.MethodPost, "/v1/roots/"+url.PathEscape(root)+"/mutations", nil, request, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// CreateRootStructure materializes a map from canonical bindings. The returned
// root is a candidate until independently accepted by the caller.
func (c *Client) CreateRootStructure(ctx context.Context, arcs map[string]string) (*CreateStructureResponse, error) {
	var response CreateStructureResponse
	request := CreateStructureRequest{Arcs: arcs}
	if err := c.doNative(ctx, http.MethodPost, "/v1/roots", nil, &request, &response); err != nil {
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

func (c *Client) endpoint(route string) (*url.URL, error) {
	if c == nil || c.http == nil {
		return nil, fmt.Errorf("gateway client is nil")
	}
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, err
	}
	routeURL, err := url.Parse(route)
	if err != nil {
		return nil, err
	}
	u.Path = path.Join(u.Path, routeURL.Path)
	u.RawQuery = routeURL.RawQuery
	return u, nil
}

func (c *Client) nativeRoute(route string) string {
	if c == nil || c.bucketID == "" {
		return route
	}
	return "/v1/buckets/" + url.PathEscape(c.bucketID) + strings.TrimPrefix(route, "/v1")
}

func (c *Client) responseError(resp *http.Response) error {
	data, err := readBounded(resp.Body, c.maxErrorResponseBytes, "gateway error response")
	if err != nil {
		return &Error{StatusCode: resp.StatusCode, Message: err.Error()}
	}
	return responseErrorData(resp.StatusCode, data)
}

func responseErrorData(statusCode int, data []byte) error {
	var apiErr errorResponse
	if err := json.Unmarshal(data, &apiErr); err == nil {
		if message := apiErr.messageText(); message != "" {
			return &Error{StatusCode: statusCode, Message: message}
		}
	}
	return &Error{StatusCode: statusCode, Message: http.StatusText(statusCode)}
}

func (c *Client) do(ctx context.Context, method, route string, query map[string]string, body, out any) error {
	return c.doWithAuth(ctx, method, route, query, body, out, false)
}

func (c *Client) doNative(ctx context.Context, method, route string, query map[string]string, body, out any) error {
	return c.doWithAuth(ctx, method, c.nativeRoute(route), query, body, out, c.bucketID != "")
}

func (c *Client) doTenant(ctx context.Context, method, route string, body, out any) error {
	return c.doWithAuth(ctx, method, route, nil, body, out, true)
}

func (c *Client) doWithAuth(ctx context.Context, method, route string, query map[string]string, body, out any, tenantAuth bool) error {
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
	if tenantAuth {
		return c.executeTenant(req, out)
	}
	return c.execute(req, out)
}

func (c *Client) doRaw(ctx context.Context, method, route string, query map[string]string, contentType string, body io.Reader, out any) error {
	return c.doRawWithAuth(ctx, method, route, query, contentType, body, out, false)
}

func (c *Client) doRawNative(ctx context.Context, method, route string, query map[string]string, contentType string, body io.Reader, out any) error {
	return c.doRawWithAuth(ctx, method, c.nativeRoute(route), query, contentType, body, out, c.bucketID != "")
}

func (c *Client) doRawWithAuth(ctx context.Context, method, route string, query map[string]string, contentType string, body io.Reader, out any, tenantAuth bool) error {
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
	if tenantAuth {
		return c.executeTenant(req, out)
	}
	return c.execute(req, out)
}

// PostMerkleDAGResolve sends one request to the fixed Merkle-DAG resolve
// compatibility route. The request and response remain untrusted profile JSON;
// the merkledag application owns their strict codec and local replay.
func (c *Client) PostMerkleDAGResolve(ctx context.Context, request []byte) ([]byte, error) {
	return c.postProfileJSON(ctx, "/v1/compat/merkledag/resolve", request)
}

// PostMerkleDAGRead sends one request to the fixed Merkle-DAG read
// compatibility route. It cannot be used to address arbitrary gateway routes.
func (c *Client) PostMerkleDAGRead(ctx context.Context, request []byte) ([]byte, error) {
	return c.postProfileJSON(ctx, "/v1/compat/merkledag/read", request)
}

func (c *Client) postProfileJSON(ctx context.Context, route string, body []byte) ([]byte, error) {
	u, err := c.endpoint(c.nativeRoute(route))
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.send(req, c.bucketID != "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, c.responseError(resp)
	}
	return readBounded(resp.Body, c.maxJSONResponseBytes, "gateway profile JSON response")
}

func (c *Client) execute(req *http.Request, out any) error {
	return c.executeWithClient(c.http, req, out)
}

func (c *Client) executeTenant(req *http.Request, out any) error {
	if c.tenantBearerToken == "" {
		return fmt.Errorf("tenant bearer token is not configured")
	}
	req.Header.Set("Authorization", "Bearer "+c.tenantBearerToken)
	return c.executeCredentialed(req, out)
}

func (c *Client) send(req *http.Request, tenantAuth bool) (*http.Response, error) {
	if !tenantAuth {
		return c.http.Do(req)
	}
	if c.tenantBearerToken == "" {
		return nil, fmt.Errorf("tenant bearer token is not configured")
	}
	req.Header.Set("Authorization", "Bearer "+c.tenantBearerToken)
	httpClient := *c.http
	httpClient.CheckRedirect = func(next *http.Request, _ []*http.Request) error {
		return fmt.Errorf("refusing credentialed gateway redirect to %s", next.URL.Redacted())
	}
	return httpClient.Do(req)
}

func (c *Client) executeCredentialed(req *http.Request, out any) error {
	httpClient := *c.http
	httpClient.CheckRedirect = func(next *http.Request, _ []*http.Request) error {
		return fmt.Errorf("refusing credentialed gateway redirect to %s", next.URL.Redacted())
	}
	return c.executeWithClient(&httpClient, req, out)
}

func (c *Client) executeWithClient(httpClient *http.Client, req *http.Request, out any) error {
	resp, err := httpClient.Do(req)
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

func isLoopbackGatewayHost(host string) bool {
	if strings.EqualFold(strings.TrimSpace(host), "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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

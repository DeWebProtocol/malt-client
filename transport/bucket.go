package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	cid "github.com/ipfs/go-cid"
)

type Identity struct {
	TenantID     string `json:"tenant_id"`
	PrincipalID  string `json:"principal_id"`
	CredentialID string `json:"credential_id"`
}

type Bucket struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Name      string    `json:"name"`
	State     string    `json:"state"`
	Role      string    `json:"role"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type BucketRef struct {
	BucketID  string    `json:"bucket_id"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	State     string    `json:"state"`
	CommitID  string    `json:"commit_id,omitempty"`
	Root      string    `json:"root,omitempty"`
	Revision  uint64    `json:"revision"`
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type BucketCommit struct {
	ID           string    `json:"id"`
	BucketID     string    `json:"bucket_id"`
	Root         string    `json:"root"`
	Parents      []string  `json:"parents,omitempty"`
	BaseRoot     string    `json:"base_root,omitempty"`
	Author       string    `json:"author"`
	Credential   string    `json:"credential,omitempty"`
	ChangeSetCID string    `json:"change_set_cid,omitempty"`
	Message      string    `json:"message,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

type BucketConflict struct {
	Coordinate string `json:"coordinate"`
	Base       string `json:"base,omitempty"`
	Local      string `json:"local,omitempty"`
	Remote     string `json:"remote,omitempty"`
}

type BucketPushRequest struct {
	PushID               string `json:"push_id"`
	BaseCommit           string `json:"base_commit,omitempty"`
	BaseRoot             string `json:"base_root,omitempty"`
	CandidateRoot        string `json:"candidate_root"`
	ExpectedHeadRevision uint64 `json:"expected_head_revision"`
	ChangeSetCID         string `json:"change_set_cid,omitempty"`
	Message              string `json:"message,omitempty"`
}

type BucketPushResult struct {
	Status    string           `json:"status"`
	Head      BucketRef        `json:"head"`
	Commit    BucketCommit     `json:"commit"`
	Branch    *BucketRef       `json:"branch,omitempty"`
	MergeBase string           `json:"merge_base,omitempty"`
	Conflicts []BucketConflict `json:"conflicts,omitempty"`
}

func (c *Client) SelectedBucket() string {
	if c == nil {
		return ""
	}
	return c.bucketID
}

func (c *Client) Me(ctx context.Context) (*Identity, error) {
	var result Identity
	if err := c.doTenant(ctx, http.MethodGet, "/v1/me", nil, &result); err != nil {
		return nil, err
	}
	if result.TenantID == "" || result.PrincipalID == "" || result.CredentialID == "" {
		return nil, fmt.Errorf("gateway returned an invalid tenant identity")
	}
	return &result, nil
}

func (c *Client) ListBuckets(ctx context.Context) ([]Bucket, error) {
	var response struct {
		Buckets []Bucket `json:"buckets"`
	}
	if err := c.doTenant(ctx, http.MethodGet, "/v1/buckets", nil, &response); err != nil {
		return nil, err
	}
	for i, value := range response.Buckets {
		if value.ID == "" || value.TenantID == "" || value.Name == "" || value.Role == "" {
			return nil, fmt.Errorf("gateway returned invalid Bucket at index %d", i)
		}
	}
	return response.Buckets, nil
}

func (c *Client) CreateBucket(ctx context.Context, name string) (*Bucket, error) {
	var result Bucket
	if err := c.doTenant(ctx, http.MethodPost, "/v1/buckets", map[string]string{"name": name}, &result); err != nil {
		return nil, err
	}
	if result.ID == "" || result.TenantID == "" || result.Name == "" || result.Role == "" {
		return nil, fmt.Errorf("gateway returned an invalid Bucket")
	}
	return &result, nil
}

func (c *Client) BucketHead(ctx context.Context) (*BucketRef, error) {
	if err := c.requireSelectedBucket(); err != nil {
		return nil, err
	}
	var result BucketRef
	if err := c.doTenant(ctx, http.MethodGet, c.bucketRoute("/head"), nil, &result); err != nil {
		return nil, err
	}
	if err := c.validateRef(result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) BucketBranches(ctx context.Context) ([]BucketRef, error) {
	if err := c.requireSelectedBucket(); err != nil {
		return nil, err
	}
	var response struct {
		Branches []BucketRef `json:"branches"`
	}
	if err := c.doTenant(ctx, http.MethodGet, c.bucketRoute("/branches"), nil, &response); err != nil {
		return nil, err
	}
	for _, value := range response.Branches {
		if err := c.validateRef(value); err != nil {
			return nil, err
		}
	}
	return response.Branches, nil
}

func (c *Client) CreateBucketBranch(ctx context.Context, name, fromCommit string) (*BucketRef, error) {
	if err := c.requireSelectedBucket(); err != nil {
		return nil, err
	}
	var result BucketRef
	request := struct {
		Name       string `json:"name"`
		FromCommit string `json:"from_commit,omitempty"`
	}{Name: name, FromCommit: fromCommit}
	if err := c.doTenant(ctx, http.MethodPost, c.bucketRoute("/branches"), request, &result); err != nil {
		return nil, err
	}
	if err := c.validateRef(result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) PushBucket(ctx context.Context, request BucketPushRequest) (*BucketPushResult, error) {
	if err := c.requireSelectedBucket(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(request.PushID) == "" {
		return nil, fmt.Errorf("Bucket push ID is empty")
	}
	if _, err := cid.Parse(request.CandidateRoot); err != nil {
		return nil, fmt.Errorf("invalid candidate root: %w", err)
	}
	if (request.BaseCommit == "") != (request.BaseRoot == "") {
		return nil, fmt.Errorf("Bucket base commit and root must be supplied together")
	}
	if request.BaseRoot != "" {
		if _, err := cid.Parse(request.BaseRoot); err != nil {
			return nil, fmt.Errorf("invalid base root: %w", err)
		}
	}
	data, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	u, err := c.endpoint(c.bucketRoute("/push"))
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.send(req, true)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusConflict {
		return nil, c.responseError(resp)
	}
	body, err := readBounded(resp.Body, c.maxJSONResponseBytes, "gateway Bucket push response")
	if err != nil {
		return nil, err
	}
	var result BucketPushResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decode gateway Bucket push response: %w", err)
	}
	if err := c.validatePushResult(result, resp.StatusCode); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) bucketRoute(suffix string) string {
	if c == nil || c.bucketID == "" {
		return ""
	}
	return "/v1/buckets/" + url.PathEscape(c.bucketID) + suffix
}

func (c *Client) requireSelectedBucket() error {
	if c == nil || c.bucketID == "" {
		return fmt.Errorf("managed Bucket is not configured")
	}
	if c.tenantBearerToken == "" {
		return fmt.Errorf("tenant bearer token is not configured")
	}
	return nil
}

func (c *Client) validateRef(value BucketRef) error {
	if c.bucketID == "" {
		return fmt.Errorf("managed Bucket is not configured")
	}
	if value.BucketID != c.bucketID || value.Name == "" || value.Kind == "" || value.State == "" {
		return fmt.Errorf("gateway returned an invalid Bucket ref")
	}
	if value.CommitID == "" {
		if value.Root != "" || value.Revision != 0 {
			return fmt.Errorf("gateway returned an invalid empty Bucket ref")
		}
		return nil
	}
	if _, err := cid.Parse(value.Root); err != nil || value.Revision == 0 {
		return fmt.Errorf("gateway returned an invalid Bucket ref root")
	}
	return nil
}

func (c *Client) validatePushResult(value BucketPushResult, statusCode int) error {
	if err := c.validateRef(value.Head); err != nil {
		return err
	}
	if value.Commit.ID == "" || value.Commit.BucketID != c.bucketID {
		return fmt.Errorf("gateway returned an invalid Bucket commit")
	}
	if _, err := cid.Parse(value.Commit.Root); err != nil {
		return fmt.Errorf("gateway returned an invalid Bucket commit root")
	}
	switch value.Status {
	case "fast_forward", "merged":
		if statusCode != http.StatusCreated || value.Branch != nil {
			return fmt.Errorf("gateway returned an inconsistent successful Bucket push")
		}
	case "branched":
		if statusCode != http.StatusConflict || value.Branch == nil {
			return fmt.Errorf("gateway returned an inconsistent conflicted Bucket push")
		}
		if err := c.validateRef(*value.Branch); err != nil {
			return err
		}
	default:
		return fmt.Errorf("gateway returned unsupported Bucket push status %q", value.Status)
	}
	return nil
}

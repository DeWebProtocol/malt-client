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
	PushID        string `json:"push_id"`
	BaseCommit    string `json:"base_commit,omitempty"`
	BaseRoot      string `json:"base_root,omitempty"`
	CandidateRoot string `json:"candidate_root"`
	BaseRevision  uint64 `json:"base_revision"`
	ChangeSetCID  string `json:"change_set_cid,omitempty"`
	Message       string `json:"message,omitempty"`
}

type BucketPushResult struct {
	Status    string           `json:"status"`
	Head      BucketRef        `json:"head"`
	Candidate BucketCommit     `json:"candidate"`
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
	if err := ValidateBucketHead(c.bucketID, result); err != nil {
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
	request.PushID = strings.TrimSpace(request.PushID)
	request.BaseCommit = strings.TrimSpace(request.BaseCommit)
	request.BaseRoot = strings.TrimSpace(request.BaseRoot)
	request.CandidateRoot = strings.TrimSpace(request.CandidateRoot)
	request.ChangeSetCID = strings.TrimSpace(request.ChangeSetCID)
	request.Message = strings.TrimSpace(request.Message)
	if request.PushID == "" {
		return nil, fmt.Errorf("Bucket push ID is empty")
	}
	candidateRoot, err := cid.Parse(request.CandidateRoot)
	if err != nil {
		return nil, fmt.Errorf("invalid candidate root: %w", err)
	}
	request.CandidateRoot = candidateRoot.String()
	if (request.BaseCommit == "") != (request.BaseRoot == "") || (request.BaseCommit == "") != (request.BaseRevision == 0) {
		return nil, fmt.Errorf("Bucket base commit, root, and non-zero revision must be supplied together")
	}
	if request.BaseRoot != "" {
		baseRoot, err := cid.Parse(request.BaseRoot)
		if err != nil {
			return nil, fmt.Errorf("invalid base root: %w", err)
		}
		request.BaseRoot = baseRoot.String()
	}
	if request.ChangeSetCID != "" {
		changeSet, err := cid.Parse(request.ChangeSetCID)
		if err != nil {
			return nil, fmt.Errorf("invalid change-set CID: %w", err)
		}
		request.ChangeSetCID = changeSet.String()
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
	if resp.StatusCode == http.StatusConflict && result.Status != "branched" {
		return nil, responseErrorData(resp.StatusCode, body)
	}
	if err := c.validatePushResult(request, result, resp.StatusCode); err != nil {
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

// ValidateBucketHead verifies the endpoint-specific main ref contract. Commit
// IDs are intentionally opaque; only their binding to a root and ref
// generation is interpreted here.
func ValidateBucketHead(bucketID string, value BucketRef) error {
	if strings.TrimSpace(bucketID) == "" || value.BucketID != bucketID || value.Name != "main" || value.Kind != "main" || value.State != "open" {
		return fmt.Errorf("gateway returned an invalid Bucket main head")
	}
	if value.CommitID == "" {
		if value.Root != "" || value.Revision != 0 {
			return fmt.Errorf("gateway returned an invalid empty Bucket main head")
		}
		return nil
	}
	if value.Root == "" || value.Revision == 0 {
		return fmt.Errorf("gateway returned an invalid Bucket main head tuple")
	}
	if _, err := cid.Parse(value.Root); err != nil {
		return fmt.Errorf("gateway returned an invalid Bucket main head root")
	}
	return nil
}

func (c *Client) validatePushResult(request BucketPushRequest, value BucketPushResult, statusCode int) error {
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
	return ValidateBucketPushResult(c.bucketID, request, value)
}

// ValidateBucketPushResult binds an untrusted push result to the selected
// Bucket and the exact request. It is exported so synchronization adapters
// cannot accidentally clear durable work when supplied another Gateway
// implementation that bypasses Client's HTTP validation.
func ValidateBucketPushResult(bucketID string, request BucketPushRequest, value BucketPushResult) error {
	if err := ValidateBucketHead(bucketID, value.Head); err != nil {
		return err
	}
	if err := validateBucketCommit(bucketID, value.Candidate); err != nil {
		return fmt.Errorf("gateway returned an invalid Bucket candidate: %w", err)
	}
	if err := validateBucketCommit(bucketID, value.Commit); err != nil {
		return fmt.Errorf("gateway returned an invalid final Bucket commit: %w", err)
	}
	if value.Candidate.Root != request.CandidateRoot {
		return fmt.Errorf("gateway returned a Bucket candidate for a different root")
	}
	if value.Candidate.BaseRoot != request.BaseRoot {
		return fmt.Errorf("gateway returned a Bucket candidate for a different base root")
	}
	if value.Candidate.ChangeSetCID != request.ChangeSetCID || value.Candidate.Message != request.Message {
		return fmt.Errorf("gateway returned a Bucket candidate for different push metadata")
	}
	if !candidateParentsMatchRequest(value.Candidate, request, value.Status == "branched") {
		return fmt.Errorf("gateway returned a Bucket candidate with inconsistent parents")
	}

	switch value.Status {
	case "fast_forward":
		if value.Branch != nil || len(value.Conflicts) != 0 || value.MergeBase != "" || value.Head.CommitID == "" {
			return fmt.Errorf("gateway returned an inconsistent fast-forward Bucket push")
		}
		if !equalBucketCommit(value.Candidate, value.Commit) || value.Commit.Root != request.CandidateRoot {
			return fmt.Errorf("gateway returned a fast-forward result for a different candidate")
		}
		if !refPointsToCommit(value.Head, value.Commit) {
			return fmt.Errorf("gateway returned a fast-forward head that does not point to the final commit")
		}
	case "merged":
		if value.Branch != nil || len(value.Conflicts) != 0 || value.Candidate.ID == value.Commit.ID || value.Head.CommitID == "" {
			return fmt.Errorf("gateway returned an inconsistent merged Bucket push")
		}
		if value.MergeBase != request.BaseRoot {
			return fmt.Errorf("gateway returned a merge result for a different base")
		}
		if len(value.Commit.Parents) != 2 || value.Commit.Parents[0] == "" || value.Commit.Parents[0] == value.Candidate.ID || value.Commit.Parents[1] != value.Candidate.ID {
			return fmt.Errorf("gateway returned a merge commit with inconsistent parents")
		}
		if value.Commit.BaseRoot == "" {
			return fmt.Errorf("gateway returned a merge commit without its remote base root")
		}
		if !refPointsToCommit(value.Head, value.Commit) {
			return fmt.Errorf("gateway returned a merged head that does not point to the final commit")
		}
	case "branched":
		if value.Branch == nil || !equalBucketCommit(value.Candidate, value.Commit) || len(value.Conflicts) == 0 || value.MergeBase != request.BaseRoot {
			return fmt.Errorf("gateway returned an inconsistent conflicted Bucket push")
		}
		if err := validateConflictRef(bucketID, *value.Branch); err != nil {
			return err
		}
		if !refPointsToCommit(*value.Branch, value.Candidate) {
			return fmt.Errorf("gateway returned a conflict branch that does not preserve the candidate")
		}
	default:
		return fmt.Errorf("gateway returned unsupported Bucket push status %q", value.Status)
	}
	return nil
}

func validateBucketCommit(bucketID string, value BucketCommit) error {
	if value.ID == "" || value.BucketID != bucketID {
		return fmt.Errorf("commit identity does not match the selected Bucket")
	}
	if _, err := cid.Parse(value.Root); err != nil {
		return fmt.Errorf("invalid commit root")
	}
	if value.BaseRoot != "" {
		if _, err := cid.Parse(value.BaseRoot); err != nil {
			return fmt.Errorf("invalid commit base root")
		}
	}
	if value.ChangeSetCID != "" {
		if _, err := cid.Parse(value.ChangeSetCID); err != nil {
			return fmt.Errorf("invalid commit change-set CID")
		}
	}
	seen := make(map[string]struct{}, len(value.Parents))
	for _, parent := range value.Parents {
		if parent == "" || parent == value.ID {
			return fmt.Errorf("invalid commit parent")
		}
		if _, exists := seen[parent]; exists {
			return fmt.Errorf("duplicate commit parent")
		}
		seen[parent] = struct{}{}
	}
	return nil
}

func candidateParentsMatchRequest(candidate BucketCommit, request BucketPushRequest, allowMissing bool) bool {
	if request.BaseCommit == "" {
		return len(candidate.Parents) == 0
	}
	if allowMissing && len(candidate.Parents) == 0 {
		// A history-conflict branch may preserve a candidate whose claimed base
		// could not be resolved, so there is no authenticated parent edge.
		return true
	}
	return len(candidate.Parents) == 1 && candidate.Parents[0] == request.BaseCommit
}

func validateConflictRef(bucketID string, value BucketRef) error {
	nameParts := strings.Split(value.Name, "/")
	if value.BucketID != bucketID || value.Kind != "conflict" || value.State != "open" || len(nameParts) != 3 || nameParts[0] != "conflicts" || nameParts[1] == "" || nameParts[2] == "" {
		return fmt.Errorf("gateway returned an invalid Bucket conflict branch")
	}
	if value.CommitID == "" || value.Root == "" || value.Revision == 0 {
		return fmt.Errorf("gateway returned an empty Bucket conflict branch")
	}
	if _, err := cid.Parse(value.Root); err != nil {
		return fmt.Errorf("gateway returned an invalid Bucket conflict branch root")
	}
	return nil
}

func refPointsToCommit(ref BucketRef, commit BucketCommit) bool {
	return ref.BucketID == commit.BucketID && ref.CommitID == commit.ID && ref.Root == commit.Root
}

func equalBucketCommit(left, right BucketCommit) bool {
	if left.ID != right.ID || left.BucketID != right.BucketID || left.Root != right.Root || left.BaseRoot != right.BaseRoot || left.Author != right.Author || left.Credential != right.Credential || left.ChangeSetCID != right.ChangeSetCID || left.Message != right.Message || !left.CreatedAt.Equal(right.CreatedAt) || len(left.Parents) != len(right.Parents) {
		return false
	}
	for i := range left.Parents {
		if left.Parents[i] != right.Parents[i] {
			return false
		}
	}
	return true
}

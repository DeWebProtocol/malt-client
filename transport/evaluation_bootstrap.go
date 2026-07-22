package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/dewebprotocol/malt/auth/arcset"
	"github.com/dewebprotocol/malt/mutation"
	"github.com/dewebprotocol/malt/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

const (
	EvaluationClientRootBootstrapProfile        = "gateway.evaluation-client-root-bootstrap-object/v1"
	EvaluationBootstrapAuthorizationTokenHeader = "X-Malt-Evaluation-Bootstrap-Authorization"
)

type EvaluationBootstrapEntry struct {
	Path   *string
	Index  *uint64
	Target cid.Cid
}

type EvaluationBootstrapObject struct {
	OperationID  string
	Kind         arcset.Kind
	Backend      maltcid.BackendKind
	ExpectedRoot cid.Cid
	Entries      []EvaluationBootstrapEntry
	Commit       mutation.CommitDescriptor
}

type EvaluationBootstrapResult struct {
	Root            cid.Cid
	ReplayNanos     uint64
	PersistNanos    uint64
	WriteAccounting ClientRootWriteAccounting
}

// BootstrapEvaluationObject creates one first-campaign semantic object on a
// disposable Gateway. The route is intentionally guarded by a secret,
// controller-only capability distinct from the public instance identity;
// subsequent writes use the exact client-root contract.
func (c *Client) BootstrapEvaluationObject(ctx context.Context, bootstrapAuthorizationToken string, value EvaluationBootstrapObject) (EvaluationBootstrapResult, error) {
	if !canonicalLowerSHA256(bootstrapAuthorizationToken) {
		return EvaluationBootstrapResult{}, fmt.Errorf("evaluation bootstrap authorization token must be a canonical SHA-256")
	}
	emptyMeasuredList := value.Kind == arcset.KindList && len(value.Entries) == 0 && value.Commit.FixedList != nil && value.Commit.FixedList.TotalSize == 0 && value.Commit.FixedList.ChunkSize > 0
	if value.OperationID == "" || (value.Kind != arcset.KindMap && value.Kind != arcset.KindList) ||
		(value.Backend != maltcid.BackendKindKZG && value.Backend != maltcid.BackendKindIPA) || !value.ExpectedRoot.Defined() || len(value.Entries) == 0 && !emptyMeasuredList {
		return EvaluationBootstrapResult{}, fmt.Errorf("evaluation bootstrap object is incomplete")
	}
	type wireEntry struct {
		Path   *string `json:"path,omitempty"`
		Index  *uint64 `json:"index,omitempty"`
		Target string  `json:"target"`
	}
	type fixedList struct {
		TotalSize uint64 `json:"total_size"`
		ChunkSize uint64 `json:"chunk_size"`
	}
	request := struct {
		Profile      string      `json:"profile"`
		OperationID  string      `json:"operation_id"`
		Kind         string      `json:"kind"`
		Backend      string      `json:"backend"`
		ExpectedRoot string      `json:"expected_root"`
		Entries      []wireEntry `json:"entries"`
		FixedList    *fixedList  `json:"fixed_list,omitempty"`
	}{
		Profile: EvaluationClientRootBootstrapProfile, OperationID: value.OperationID,
		Kind: string(value.Kind), Backend: string(value.Backend), ExpectedRoot: value.ExpectedRoot.String(), Entries: make([]wireEntry, len(value.Entries)),
	}
	for index, entry := range value.Entries {
		if !entry.Target.Defined() || (value.Kind == arcset.KindMap && (entry.Path == nil || entry.Index != nil)) ||
			(value.Kind == arcset.KindList && (entry.Path != nil || entry.Index == nil)) {
			return EvaluationBootstrapResult{}, fmt.Errorf("evaluation bootstrap entry %d is invalid", index)
		}
		request.Entries[index] = wireEntry{Path: entry.Path, Index: entry.Index, Target: entry.Target.String()}
	}
	if value.Commit.FixedList != nil {
		request.FixedList = &fixedList{TotalSize: value.Commit.FixedList.TotalSize, ChunkSize: value.Commit.FixedList.ChunkSize}
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return EvaluationBootstrapResult{}, err
	}
	u, err := c.endpoint("/v1/evaluation/client-root/bootstrap-object")
	if err != nil {
		return EvaluationBootstrapResult{}, err
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackGatewayHost(u.Hostname())) {
		return EvaluationBootstrapResult{}, fmt.Errorf("evaluation bootstrap authorization token requires HTTPS or a loopback HTTP gateway base URL")
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(encoded))
	if err != nil {
		return EvaluationBootstrapResult{}, err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set(EvaluationBootstrapAuthorizationTokenHeader, bootstrapAuthorizationToken)
	httpClient := *c.http
	httpClient.CheckRedirect = func(next *http.Request, _ []*http.Request) error {
		return fmt.Errorf("refusing evaluation bootstrap redirect to %s", next.URL.Redacted())
	}
	response, err := httpClient.Do(httpRequest)
	if err != nil {
		return EvaluationBootstrapResult{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return EvaluationBootstrapResult{}, c.responseError(response)
	}
	if err := requireClientRootResponseHeaders(response); err != nil {
		return EvaluationBootstrapResult{}, err
	}
	raw, err := readBounded(response.Body, c.maxJSONResponseBytes, "Gateway evaluation bootstrap response")
	if err != nil {
		return EvaluationBootstrapResult{}, err
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return EvaluationBootstrapResult{}, fmt.Errorf("Gateway evaluation bootstrap response: %w", err)
	}
	var wire struct {
		Profile         string                    `json:"profile"`
		Root            string                    `json:"root"`
		ReplayNanos     uint64                    `json:"replay_nanos"`
		PersistNanos    uint64                    `json:"persist_nanos"`
		WriteAccounting ClientRootWriteAccounting `json:"write_accounting"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return EvaluationBootstrapResult{}, fmt.Errorf("decode Gateway evaluation bootstrap response: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return EvaluationBootstrapResult{}, fmt.Errorf("Gateway evaluation bootstrap response has trailing JSON")
	}
	root, err := cid.Parse(wire.Root)
	if err != nil || !root.Equals(value.ExpectedRoot) || wire.Profile != EvaluationClientRootBootstrapProfile || maltcid.BackendKindOf(root) != value.Backend ||
		(value.Kind == arcset.KindMap && maltcid.SemanticKindOf(root) != maltcid.SemanticKindMap) ||
		(value.Kind == arcset.KindList && maltcid.SemanticKindOf(root) != maltcid.SemanticKindList) {
		return EvaluationBootstrapResult{}, fmt.Errorf("Gateway evaluation bootstrap returned a mismatched semantic root")
	}
	if err := wire.WriteAccounting.validate(); err != nil || !wire.WriteAccounting.Available || strings.TrimSpace(wire.WriteAccounting.UnavailableReason) != "" {
		return EvaluationBootstrapResult{}, fmt.Errorf("Gateway evaluation bootstrap returned invalid exact write accounting")
	}
	return EvaluationBootstrapResult{
		Root: root, ReplayNanos: wire.ReplayNanos, PersistNanos: wire.PersistNanos,
		WriteAccounting: wire.WriteAccounting,
	}, nil
}

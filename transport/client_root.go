package transport

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/dewebprotocol/malt/mutation"
	"github.com/dewebprotocol/malt/protocol"
	cid "github.com/ipfs/go-cid"
)

const (
	clientRootOldStateHeader         = "X-Malt-Client-Root-Old-State-Validation-Nanos"
	clientRootReplayHeader           = "X-Malt-Client-Root-Gateway-Replay-Nanos"
	clientRootPersistHeader          = "X-Malt-Client-Root-Persist-Nanos"
	clientRootReceiptHeader          = "X-Malt-Client-Root-Receipt-Nanos"
	clientRootDurableHeader          = "X-Malt-Client-Root-Durable-Boundary"
	clientRootIdempotent             = "X-Malt-Client-Root-Idempotent"
	clientRootWriteAccounting        = "X-Malt-Client-Root-Write-Accounting"
	clientRootWriteAccountingProfile = "gateway.client-root-write-accounting/v1"
	clientRootWriteByteMethod        = "logical-kv-key-plus-value-bytes/v1"
)

var clientRootWriteCategories = []string{"semantic-materialization", "arctable-records", "root-version-metadata"}

// ClientRootPhaseMetrics are Gateway-observed phase durations. They are
// diagnostics, not part of the exact-root receipt or a client trust decision.
type ClientRootPhaseMetrics struct {
	OldStateValidationNS uint64 `json:"old_state_validation_ns"`
	GatewayReplayNS      uint64 `json:"gateway_replay_ns"`
	PersistNS            uint64 `json:"persist_ns"`
	ReceiptNS            uint64 `json:"receipt_ns"`
}

// ClientRootWriteAccounting is untrusted Gateway diagnostic accounting for
// the atomic staging boundary. It excludes payload CAS and physical backend
// bytes, which evaluation workers must account for separately.
type ClientRootWriteAccounting struct {
	Profile            string                              `json:"profile"`
	Available          bool                                `json:"available"`
	UnavailableReason  string                              `json:"unavailable_reason,omitempty"`
	ByteMethod         string                              `json:"byte_method"`
	ObjectLedgerSHA256 string                              `json:"object_ledger_sha256,omitempty"`
	Categories         []ClientRootWriteCategoryAccounting `json:"categories"`
}

type ClientRootWriteCategoryAccounting struct {
	Category                   string `json:"category"`
	AttemptedWrites            uint64 `json:"attempted_writes"`
	AttemptedBytes             uint64 `json:"attempted_bytes"`
	AttemptedNewWrites         uint64 `json:"attempted_new_writes"`
	AttemptedNewBytes          uint64 `json:"attempted_new_bytes"`
	AttemptedReplacementWrites uint64 `json:"attempted_replacement_writes"`
	AttemptedReplacementBytes  uint64 `json:"attempted_replacement_bytes"`
	AttemptedSameValueWrites   uint64 `json:"attempted_same_value_writes"`
	AttemptedSameValueBytes    uint64 `json:"attempted_same_value_bytes"`
	AttemptedDeleteWrites      uint64 `json:"attempted_delete_writes"`
	AttemptedDeleteBytes       uint64 `json:"attempted_delete_bytes"`
	NewlyPersistedWrites       uint64 `json:"newly_persisted_writes"`
	GrossNewBytes              uint64 `json:"gross_new_bytes"`
	NewWrites                  uint64 `json:"new_writes"`
	NewBytes                   uint64 `json:"new_bytes"`
	ReplacedWrites             uint64 `json:"replaced_writes"`
	ReplacementNewBytes        uint64 `json:"replacement_new_bytes"`
	ReplacementReclaimedBytes  uint64 `json:"replacement_reclaimed_bytes"`
	SameValueWrites            uint64 `json:"same_value_writes"`
	DeletedWrites              uint64 `json:"deleted_writes"`
	DeletedReclaimedBytes      uint64 `json:"deleted_reclaimed_bytes"`
	ReclaimedBytes             uint64 `json:"reclaimed_bytes"`
	NetBytes                   int64  `json:"net_bytes"`
}

// UpdateViewResponse keeps the validated core view together with exact wire
// accounting. The Gateway remains untrusted; sdk/writer independently
// recomputes every root before the view can be used.
type UpdateViewResponse struct {
	View      mutation.UpdateView
	WireBytes uint64
}

// ClientRootResponse is an exact receipt plus service-side diagnostic timing.
type ClientRootResponse struct {
	Receipt                  mutation.MaterializationReceipt
	RequestWireBytes         uint64
	ResponseWireBytes        uint64
	RequestEncodingNS        uint64
	ResponseVerifyNS         uint64
	Idempotent               bool
	Gateway                  ClientRootPhaseMetrics
	WriteAccounting          ClientRootWriteAccounting
	WriteAccountingWireBytes uint64
}

// FetchUpdateView requests a complete, bounded state closure for root. Bounds
// are all supplied or all omitted; partial bounds are rejected locally before
// any network request is made.
func (c *Client) FetchUpdateView(ctx context.Context, root cid.Cid, bounds *protocol.UpdateViewBounds) (*UpdateViewResponse, error) {
	if !root.Defined() {
		return nil, fmt.Errorf("update-view root is undefined")
	}
	u, err := c.endpoint("/v1/roots/" + url.PathEscape(root.String()) + "/update-view")
	if err != nil {
		return nil, err
	}
	if bounds != nil {
		if bounds.MaxObjects == 0 || bounds.MaxTotalEntries == 0 || bounds.MaxDepth == 0 {
			return nil, fmt.Errorf("update-view bounds must all be positive or all omitted")
		}
		query := u.Query()
		query.Set("max_objects", strconv.FormatUint(uint64(bounds.MaxObjects), 10))
		query.Set("max_total_entries", strconv.FormatUint(bounds.MaxTotalEntries, 10))
		query.Set("max_depth", strconv.FormatUint(uint64(bounds.MaxDepth), 10))
		u.RawQuery = query.Encode()
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
	if err := requireClientRootResponseHeaders(resp); err != nil {
		return nil, err
	}
	data, err := readBounded(resp.Body, minResponseLimit(c.maxJSONResponseBytes, protocol.MaxClientRootJSONBytes), "Gateway update-view response")
	if err != nil {
		return nil, err
	}
	wire, err := protocol.DecodeUpdateView(data)
	if err != nil {
		return nil, fmt.Errorf("decode Gateway update view: %w", err)
	}
	view, err := wire.Core()
	if err != nil {
		return nil, fmt.Errorf("validate Gateway update view: %w", err)
	}
	if !view.BaseRoot.Equals(root) {
		return nil, fmt.Errorf("Gateway update-view base %s does not match requested root %s", view.BaseRoot, root)
	}
	return &UpdateViewResponse{View: view, WireBytes: uint64(len(data))}, nil
}

// SubmitClientRoot sends one canonical exact-root bundle. The returned
// receipt is strictly decoded and checked against the exact submitted bundle.
// Publication and local root acceptance remain separate operations.
func (c *Client) SubmitClientRoot(ctx context.Context, bundle mutation.ClientRootBundle) (*ClientRootResponse, error) {
	encodingStarted := time.Now()
	wire, err := protocol.NewClientRootBundle(bundle)
	if err != nil {
		return nil, fmt.Errorf("canonicalize client-root bundle: %w", err)
	}
	data, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("encode client-root bundle: %w", err)
	}
	requestEncodingNS := clientRootDurationNS(time.Since(encodingStarted))
	u, err := c.endpoint("/v1/client-roots")
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, c.responseError(resp)
	}
	if err := requireClientRootResponseHeaders(resp); err != nil {
		return nil, err
	}
	metrics, err := parseClientRootPhaseMetrics(resp.Header)
	if err != nil {
		return nil, err
	}
	writeAccounting, accountingBytes, err := parseClientRootWriteAccounting(resp.Header)
	if err != nil {
		return nil, err
	}
	responseData, err := readBounded(resp.Body, minResponseLimit(c.maxJSONResponseBytes, protocol.MaxClientRootJSONBytes), "Gateway materialization receipt")
	if err != nil {
		return nil, err
	}
	verifyStarted := time.Now()
	receiptWire, err := protocol.DecodeMaterializationReceipt(responseData, bundle)
	if err != nil {
		return nil, fmt.Errorf("decode Gateway materialization receipt: %w", err)
	}
	receipt, err := receiptWire.Core(bundle)
	if err != nil {
		return nil, fmt.Errorf("validate Gateway materialization receipt: %w", err)
	}
	durableBoundary := resp.Header.Get(clientRootDurableHeader)
	if durableBoundary == "" || strings.TrimSpace(durableBoundary) != durableBoundary || durableBoundary != receipt.DurableBoundary {
		return nil, fmt.Errorf("Gateway materialization receipt durable boundary header does not match the exact receipt")
	}
	idempotentRaw := resp.Header.Get(clientRootIdempotent)
	if idempotentRaw != "true" && idempotentRaw != "false" {
		return nil, fmt.Errorf("Gateway materialization receipt is missing a canonical idempotency classification")
	}
	idempotent := idempotentRaw == "true"
	return &ClientRootResponse{
		Receipt: receipt, RequestWireBytes: uint64(len(data)), ResponseWireBytes: uint64(len(responseData)),
		RequestEncodingNS: requestEncodingNS, ResponseVerifyNS: clientRootDurationNS(time.Since(verifyStarted)),
		Idempotent: idempotent, Gateway: metrics,
		WriteAccounting: writeAccounting, WriteAccountingWireBytes: accountingBytes,
	}, nil
}

func clientRootDurationNS(value time.Duration) uint64 {
	if value <= 0 {
		return 0
	}
	return uint64(value)
}

func requireClientRootResponseHeaders(resp *http.Response) error {
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return fmt.Errorf("Gateway client-root response has unsupported Content-Type %q", resp.Header.Get("Content-Type"))
	}
	cacheControl := strings.ToLower(resp.Header.Get("Cache-Control"))
	noStore := false
	for _, directive := range strings.Split(cacheControl, ",") {
		if strings.TrimSpace(directive) == "no-store" {
			noStore = true
			break
		}
	}
	if !noStore {
		return fmt.Errorf("Gateway client-root response is missing Cache-Control: no-store")
	}
	return nil
}

func parseClientRootPhaseMetrics(header http.Header) (ClientRootPhaseMetrics, error) {
	values := []*uint64{}
	metrics := ClientRootPhaseMetrics{}
	values = append(values, &metrics.OldStateValidationNS, &metrics.GatewayReplayNS, &metrics.PersistNS, &metrics.ReceiptNS)
	names := []string{clientRootOldStateHeader, clientRootReplayHeader, clientRootPersistHeader, clientRootReceiptHeader}
	for index, name := range names {
		raw := header.Get(name)
		if raw == "" || strings.TrimSpace(raw) != raw {
			return ClientRootPhaseMetrics{}, fmt.Errorf("Gateway client-root response is missing canonical %s", name)
		}
		value, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return ClientRootPhaseMetrics{}, fmt.Errorf("Gateway client-root response has invalid %s: %w", name, err)
		}
		*values[index] = value
	}
	serverTiming := respHeaderTokenSet(header.Values("Server-Timing"))
	for _, name := range []string{"old-state-validation", "gateway-replay", "persist", "receipt"} {
		if _, ok := serverTiming[name]; !ok {
			return ClientRootPhaseMetrics{}, fmt.Errorf("Gateway client-root response Server-Timing omits %q", name)
		}
	}
	return metrics, nil
}

func parseClientRootWriteAccounting(header http.Header) (ClientRootWriteAccounting, uint64, error) {
	encoded := header.Get(clientRootWriteAccounting)
	if encoded == "" || strings.TrimSpace(encoded) != encoded {
		return ClientRootWriteAccounting{}, 0, fmt.Errorf("Gateway client-root response is missing canonical %s", clientRootWriteAccounting)
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw) > 4096 {
		return ClientRootWriteAccounting{}, 0, fmt.Errorf("Gateway client-root write accounting is not bounded raw-URL base64")
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return ClientRootWriteAccounting{}, 0, fmt.Errorf("Gateway client-root write accounting: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var accounting ClientRootWriteAccounting
	if err := decoder.Decode(&accounting); err != nil {
		return ClientRootWriteAccounting{}, 0, fmt.Errorf("decode Gateway client-root write accounting: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ClientRootWriteAccounting{}, 0, fmt.Errorf("Gateway client-root write accounting has trailing JSON")
	}
	if err := accounting.validate(); err != nil {
		return ClientRootWriteAccounting{}, 0, err
	}
	return accounting, uint64(len(raw)), nil
}

func (accounting ClientRootWriteAccounting) validate() error {
	if accounting.Profile != clientRootWriteAccountingProfile || accounting.ByteMethod != clientRootWriteByteMethod {
		return fmt.Errorf("Gateway client-root write accounting has unsupported profile/method")
	}
	if !accounting.Available {
		if accounting.UnavailableReason == "" || accounting.ObjectLedgerSHA256 != "" || len(accounting.Categories) != 0 {
			return fmt.Errorf("unavailable Gateway client-root write accounting carries measurements")
		}
		return nil
	}
	if accounting.UnavailableReason != "" || !canonicalLowerSHA256(accounting.ObjectLedgerSHA256) || len(accounting.Categories) != len(clientRootWriteCategories) {
		return fmt.Errorf("available Gateway client-root write accounting is incomplete")
	}
	for index, category := range accounting.Categories {
		attempts := category.AttemptedNewWrites + category.AttemptedReplacementWrites + category.AttemptedSameValueWrites + category.AttemptedDeleteWrites
		attemptBytes := category.AttemptedNewBytes + category.AttemptedReplacementBytes + category.AttemptedSameValueBytes + category.AttemptedDeleteBytes
		if category.Category != clientRootWriteCategories[index] || category.AttemptedWrites != attempts ||
			category.AttemptedBytes != attemptBytes || category.NetBytes != int64(category.GrossNewBytes)-int64(category.ReclaimedBytes) ||
			category.NewlyPersistedWrites != category.NewWrites+category.ReplacedWrites ||
			category.GrossNewBytes != category.NewBytes+category.ReplacementNewBytes ||
			category.ReclaimedBytes != category.ReplacementReclaimedBytes+category.DeletedReclaimedBytes {
			return fmt.Errorf("Gateway client-root write accounting category %d is inconsistent", index)
		}
	}
	return nil
}

func canonicalLowerSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSONValue(decoder, "$"); err != nil {
		return err
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("trailing token %v", token)
		}
		return err
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder, path string) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("non-string object key at %s", path)
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate object key %q at %s", key, path)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder, path+"."+key); err != nil {
				return err
			}
		}
		_, err := decoder.Token()
		return err
	case '[':
		for index := 0; decoder.More(); index++ {
			if err := scanJSONValue(decoder, fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
		_, err := decoder.Token()
		return err
	default:
		return fmt.Errorf("unexpected JSON delimiter %q at %s", delimiter, path)
	}
}

func respHeaderTokenSet(values []string) map[string]struct{} {
	result := make(map[string]struct{})
	for _, value := range values {
		for _, member := range strings.Split(value, ",") {
			name, _, _ := strings.Cut(strings.TrimSpace(member), ";")
			if name != "" {
				result[strings.ToLower(name)] = struct{}{}
			}
		}
	}
	return result
}

func minResponseLimit(configured int64, protocolLimit int) int64 {
	limit := int64(protocolLimit)
	if configured < limit {
		return configured
	}
	return limit
}

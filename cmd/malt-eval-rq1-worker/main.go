// Command malt-eval-rq1-worker is the stable process boundary used by the
// evaluator for long-lived warm CAR/Direct-CAS clients. Cold runs start a new
// process. Stdout is JSONL only; diagnostics and flag errors go to stderr.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/dewebprotocol/malt-client/merkledag"
	"github.com/dewebprotocol/malt-client/transport"
	cid "github.com/ipfs/go-cid"
)

const (
	workerRecordSchema  = "malt-rq1-worker-record/v1"
	workerRequestSchema = "malt-rq1-worker-request/v1"
	maxWorkerLineBytes  = 1 << 20
	maxWorkerRequests   = 1_000_000
	routeCAR            = "trustless-car"
	routeDirectCAS      = "direct-cas"

	evaluationInstanceTokenHeader = "X-Malt-Evaluation-Instance-Token"
	evaluationOperationHeader     = "X-Malt-Evaluation-RQ1-Operation"
	evaluationRouteHeader         = "X-Malt-Evaluation-RQ1-Route"
	evaluationLeaseHeader         = "X-Malt-Evaluation-RQ1-Lease"
	evaluationCacheProfile        = "gateway.rq1-cache-observation/v1"
)

var operationIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)

type workerRequest struct {
	SchemaVersion string   `json:"schema_version"`
	OperationID   string   `json:"operation_id"`
	Segments      []string `json:"segments"`
}

type workerRecord struct {
	SchemaVersion    string            `json:"schema_version"`
	WorkerID         string            `json:"worker_id"`
	OperationID      string            `json:"operation_id,omitempty"`
	Route            string            `json:"route"`
	Endpoint         string            `json:"endpoint"`
	VerificationRole string            `json:"verification_role"`
	Root             string            `json:"root"`
	Segments         []string          `json:"segments"`
	Success          bool              `json:"success"`
	FailureClass     string            `json:"failure_class,omitempty"`
	Error            string            `json:"error,omitempty"`
	LatencyNS        uint64            `json:"latency_ns"`
	Target           string            `json:"target,omitempty"`
	Kind             string            `json:"kind,omitempty"`
	TotalSize        uint64            `json:"total_size,omitempty"`
	PayloadBytes     uint64            `json:"payload_bytes,omitempty"`
	PayloadSHA256    string            `json:"payload_sha256,omitempty"`
	Metrics          *workerMetrics    `json:"metrics,omitempty"`
	CacheObservation *cacheObservation `json:"cache_observation,omitempty"`
}

type workerMetrics struct {
	NetworkRequests             uint64           `json:"network_requests"`
	CriticalSequentialRounds    uint64           `json:"critical_sequential_rounds"`
	BlockLoadCalls              uint64           `json:"block_load_calls"`
	BlocksVerified              uint64           `json:"blocks_verified"`
	CASGetRequests              uint64           `json:"cas_get_requests"`
	CASBytes                    uint64           `json:"cas_bytes"`
	CARBytes                    uint64           `json:"car_bytes"`
	CARBlocks                   uint64           `json:"car_blocks"`
	ProofBytes                  uint64           `json:"proof_bytes"`
	ProofSteps                  uint64           `json:"proof_steps"`
	NetworkDurationNS           uint64           `json:"network_duration_ns"`
	CIDVerifyDurationNS         uint64           `json:"cid_verify_duration_ns"`
	CARDecodeDurationNS         uint64           `json:"car_decode_duration_ns"`
	PathReplayDurationNS        uint64           `json:"path_replay_duration_ns"`
	ProofDecodeDurationNS       uint64           `json:"proof_decode_duration_ns"`
	ProofVerifyDurationNS       uint64           `json:"proof_verify_duration_ns"`
	PayloadReadDurationNS       uint64           `json:"payload_read_duration_ns"`
	PayloadBindingDurationNS    uint64           `json:"payload_binding_duration_ns"`
	ServerArcTable              serverPhaseTotal `json:"server_arc_table"`
	ServerMaterialization       serverPhaseTotal `json:"server_materialization"`
	ServerOpen                  serverPhaseTotal `json:"server_open"`
	ServerProofSerialization    serverPhaseTotal `json:"server_proof_serialization"`
	ServerResponseSerialization serverPhaseTotal `json:"server_response_serialization"`
	ClientUserCPUNS             uint64           `json:"client_user_cpu_ns"`
	ClientSystemCPUNS           uint64           `json:"client_system_cpu_ns"`
	ProcessPeakRSSBytes         uint64           `json:"process_peak_rss_bytes"`
}

// directCASRawGetter deliberately bypasses transport-level CID hashing so the
// Direct-CAS replay verifier is the sole owner of one hash and its timing.
// The transport method remains bounded; no other worker route uses it.
type directCASRawGetter struct{ client *transport.Client }

func (g directCASRawGetter) Get(ctx context.Context, key cid.Cid) ([]byte, error) {
	return g.client.GetRawForLocalCIDVerification(ctx, key)
}

type serverPhaseTotal struct {
	Operations uint64 `json:"operations"`
	Items      uint64 `json:"items"`
	Bytes      uint64 `json:"bytes"`
	DurationNS uint64 `json:"duration_ns"`
}

type cacheObservation struct {
	Profile                   string        `json:"profile"`
	Action                    string        `json:"action"`
	OperationID               string        `json:"operation_id"`
	Route                     string        `json:"route"`
	Lease                     string        `json:"lease"`
	InstanceToken             string        `json:"instance_token"`
	CompletedOperationsBefore uint64        `json:"completed_operations_before"`
	SuccessfulHTTPRequests    uint64        `json:"successful_http_requests"`
	ProcessState              string        `json:"process_state"`
	ApplicationResultCache    string        `json:"application_result_cache"`
	OSPageCache               string        `json:"os_page_cache"`
	GatewayHealth             gatewayHealth `json:"gateway_health"`
}

type gatewayHealth struct {
	Profile                 string `json:"profile"`
	RawSHA256               string `json:"raw_sha256"`
	RawBytes                uint64 `json:"raw_bytes"`
	InstanceToken           string `json:"instance_token"`
	CacheObservationProfile string `json:"cache_observation_profile"`
	ReadPhasesProfile       string `json:"read_phases_profile"`
	ApplicationResultCache  string `json:"application_result_cache"`
	OSPageCache             string `json:"os_page_cache"`
}

type workerConfig struct {
	baseURL        string
	route          string
	root           cid.Cid
	workerID       string
	instanceToken  string
	requestTimeout time.Duration
	cacheClient    *http.Client
	routeHeaders   *evaluationHeaderTransport
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("malt-eval-rq1-worker", flag.ContinueOnError)
	flags.SetOutput(stderr)
	baseURL := flags.String("base-url", "", "Gateway or direct-CAS base URL")
	route := flags.String("route", "", "trustless-car or direct-cas")
	rootText := flags.String("root", "", "caller-selected Merkle-DAG root CID")
	workerID := flags.String("worker-id", "", "registered process/run identifier")
	instanceToken := flags.String("gateway-instance-token", "", "canonical disposable Gateway evaluation instance token")
	timeout := flags.Duration("request-timeout", 5*time.Minute, "per-read deadline")
	selfTestCorpus := flags.String("self-test-corpus", "", "formal E0 CAR/Direct-CAS correctness corpus")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if *selfTestCorpus != "" {
		if *baseURL != "" || *rootText != "" || *workerID != "" || *instanceToken != "" {
			return fmt.Errorf("formal E0 self-test cannot be combined with runtime Gateway/root/worker flags")
		}
		return runClientRouteSelfTest(strings.TrimSpace(*route), *selfTestCorpus, stdout)
	}
	root, err := cid.Parse(*rootText)
	if err != nil {
		return fmt.Errorf("invalid -root: %w", err)
	}
	config := workerConfig{
		baseURL: strings.TrimSpace(*baseURL), route: strings.TrimSpace(*route), root: root,
		workerID: strings.TrimSpace(*workerID), instanceToken: strings.TrimSpace(*instanceToken), requestTimeout: *timeout,
	}
	if err := config.validate(); err != nil {
		return err
	}
	config.routeHeaders = &evaluationHeaderTransport{base: http.DefaultTransport, instanceToken: config.instanceToken}
	config.cacheClient = &http.Client{Timeout: config.requestTimeout}
	remote, err := transport.New(transport.Options{
		BaseURL:    config.baseURL,
		HTTPClient: &http.Client{Timeout: config.requestTimeout, Transport: config.routeHeaders},
	})
	if err != nil {
		return err
	}
	profile, err := merkledag.New(remote)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	scanner := bufio.NewScanner(stdin)
	scanner.Buffer(make([]byte, 64<<10), maxWorkerLineBytes)
	requests := 0
	var health gatewayHealth
	var healthErr error
	healthObserved := false
	for scanner.Scan() {
		requests++
		if requests > maxWorkerRequests {
			return fmt.Errorf("worker exceeds %d-request process limit", maxWorkerRequests)
		}
		raw := append([]byte(nil), scanner.Bytes()...)
		request, decodeErr := decodeWorkerRequest(raw)
		if decodeErr != nil {
			if request.OperationID == "" {
				request.OperationID = fmt.Sprintf("invalid-input-%06d", requests)
			}
			if request.Segments == nil {
				request.Segments = []string{}
			}
			record := config.baseRecord(request)
			record.FailureClass = "input_invalid"
			record.Error = decodeErr.Error()
			if err := encoder.Encode(record); err != nil {
				return err
			}
			continue
		}
		controlCtx, controlCancel := context.WithTimeout(context.Background(), config.requestTimeout)
		if !healthObserved {
			health, healthErr = config.observeGatewayHealth(controlCtx)
			healthObserved = true
		}
		var cacheBegin cacheObservation
		var cacheErr error
		if healthErr == nil {
			cacheBegin, cacheErr = config.exchangeCacheObservation(controlCtx, "begin", request, "")
		} else {
			cacheErr = healthErr
		}
		controlCancel()
		if cacheErr == nil {
			config.routeHeaders.Set(request.OperationID, config.route, cacheBegin.Lease)
		}
		usageBefore, usageErr := readProcessUsage()
		operationCtx, operationCancel := context.WithTimeout(context.Background(), config.requestTimeout)
		started := time.Now()
		var result *merkledag.VerifiedReadResult
		if cacheErr == nil && usageErr == nil {
			switch config.route {
			case routeCAR:
				result, err = profile.ReadMerkleDAGCARVerified(operationCtx, config.root, request.Segments)
			case routeDirectCAS:
				result, err = merkledag.ReadMerkleDAGDirectCASVerified(operationCtx, directCASRawGetter{client: remote}, config.root, request.Segments, nil, nil)
			}
		}
		config.routeHeaders.Clear()
		operationCancel()
		record := config.baseRecord(request)
		record.LatencyNS = durationNS(time.Since(started))
		if cacheErr != nil {
			record.FailureClass = "cache_observation"
			record.Error = cacheErr.Error()
		} else if usageErr != nil {
			record.FailureClass = "resource_accounting"
			record.Error = usageErr.Error()
		} else if err != nil {
			record.FailureClass = classifyFailure(err)
			record.Error = err.Error()
		} else {
			metrics := newWorkerMetrics(result.Metrics)
			usageAfter, usageErr := readProcessUsage()
			if usageErr != nil {
				record.FailureClass = "resource_accounting"
				record.Error = usageErr.Error()
			} else if usageErr := addResourceMetrics(&metrics, usageBefore, usageAfter); usageErr != nil {
				record.FailureClass = "resource_accounting"
				record.Error = usageErr.Error()
			} else {
				record.Success = true
				record.Target = result.Target.String()
				record.Kind = result.Kind
				record.TotalSize = result.TotalSize
				record.PayloadBytes = uint64(len(result.Data))
				digest := sha256.Sum256(result.Data)
				record.PayloadSHA256 = hex.EncodeToString(digest[:])
				record.Metrics = &metrics
				endCtx, endCancel := context.WithTimeout(context.Background(), config.requestTimeout)
				cacheEnd, cacheErr := config.exchangeCacheObservation(endCtx, "end", request, cacheBegin.Lease)
				endCancel()
				if cacheErr != nil {
					record.Success = false
					record.FailureClass = "cache_observation"
					record.Error = cacheErr.Error()
					record.Target = ""
					record.Kind = ""
					record.TotalSize = 0
					record.PayloadBytes = 0
					record.PayloadSHA256 = ""
					record.Metrics = nil
				} else {
					cacheEnd.GatewayHealth = health
					record.CacheObservation = &cacheEnd
				}
			}
		}
		if err := encoder.Encode(record); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		if strings.Contains(err.Error(), "token too long") {
			return fmt.Errorf("worker request exceeds %d bytes", maxWorkerLineBytes)
		}
		return err
	}
	return nil
}

func newWorkerMetrics(value merkledag.VerifiedReadMetrics) workerMetrics {
	return workerMetrics{
		NetworkRequests: value.NetworkRequests, CriticalSequentialRounds: value.CriticalSequentialRounds,
		BlockLoadCalls: value.BlockLoadCalls, BlocksVerified: value.BlocksVerified,
		CASGetRequests: value.CASGetRequests, CASBytes: value.CASBytes, CARBytes: value.CARBytes, CARBlocks: value.CARBlocks,
		NetworkDurationNS: value.NetworkDurationNS, CIDVerifyDurationNS: value.CIDVerifyDurationNS,
		PayloadBindingDurationNS: value.PayloadBindingDurationNS,
		CARDecodeDurationNS:      value.CARDecodeDurationNS, PathReplayDurationNS: value.PathReplayDurationNS,
		PayloadReadDurationNS: value.PayloadReadDurationNS,
	}
}

func (config workerConfig) validate() error {
	if config.baseURL == "" || config.workerID == "" {
		return fmt.Errorf("-base-url and -worker-id are required")
	}
	if config.route != routeCAR && config.route != routeDirectCAS {
		return fmt.Errorf("-route must be %q or %q", routeCAR, routeDirectCAS)
	}
	if config.requestTimeout <= 0 {
		return fmt.Errorf("-request-timeout must be positive")
	}
	if !canonicalToken(config.instanceToken) {
		return fmt.Errorf("-gateway-instance-token must be 64 lowercase hexadecimal characters")
	}
	return nil
}

func (config workerConfig) baseRecord(request workerRequest) workerRecord {
	verificationRole := "local-car-cid-link-replay"
	if config.route == routeDirectCAS {
		verificationRole = "local-direct-cas-cid-link-replay"
	}
	return workerRecord{
		SchemaVersion: workerRecordSchema, WorkerID: config.workerID, OperationID: request.OperationID,
		Route: config.route, Endpoint: "verified-bytes", VerificationRole: verificationRole,
		Root: config.root.String(), Segments: append([]string(nil), request.Segments...),
	}
}

func decodeWorkerRequest(data []byte) (workerRequest, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return workerRequest{}, fmt.Errorf("worker request is empty")
	}
	var request workerRequest
	if err := decodeStrictJSON(data, &request); err != nil {
		return workerRequest{}, fmt.Errorf("decode worker request: %w", err)
	}
	if request.SchemaVersion != workerRequestSchema {
		return request, fmt.Errorf("schema_version must be %q", workerRequestSchema)
	}
	if !operationIDPattern.MatchString(request.OperationID) {
		return request, fmt.Errorf("operation_id does not match the RQ1 worker contract")
	}
	if request.Segments == nil || len(request.Segments) > 256 {
		return request, fmt.Errorf("segments must be an explicit array with at most 256 values")
	}
	for index, segment := range request.Segments {
		if segment == "" || len(segment) > 1024 || strings.Contains(segment, "/") {
			return request, fmt.Errorf("invalid segment %d", index)
		}
	}
	return request, nil
}

func classifyFailure(err error) string {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "deadline"
	}
	var transportErr *transport.Error
	if errors.As(err, &transportErr) {
		return "remote_rejection"
	}
	var networkErr net.Error
	if errors.As(err, &networkErr) {
		return "network"
	}
	return "local_verification"
}

func durationNS(value time.Duration) uint64 {
	if value <= 0 {
		return 0
	}
	return uint64(value)
}

type cacheObservationRequest struct {
	Profile     string `json:"profile"`
	Action      string `json:"action"`
	OperationID string `json:"operation_id"`
	Route       string `json:"route"`
	Lease       string `json:"lease,omitempty"`
}

func (config workerConfig) exchangeCacheObservation(ctx context.Context, action string, operation workerRequest, lease string) (cacheObservation, error) {
	body, err := json.Marshal(cacheObservationRequest{
		Profile: evaluationCacheProfile, Action: action, OperationID: operation.OperationID, Route: config.route, Lease: lease,
	})
	if err != nil {
		return cacheObservation{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(config.baseURL, "/")+"/v1/evaluation/rq1/cache-observation", bytes.NewReader(body))
	if err != nil {
		return cacheObservation{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(evaluationInstanceTokenHeader, config.instanceToken)
	response, err := config.cacheClient.Do(request)
	if err != nil {
		return cacheObservation{}, err
	}
	defer response.Body.Close()
	encoded, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if err != nil {
		return cacheObservation{}, err
	}
	if len(encoded) > 64<<10 {
		return cacheObservation{}, fmt.Errorf("RQ1 cache observation exceeds 65536 bytes")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return cacheObservation{}, fmt.Errorf("RQ1 cache observation HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(encoded)))
	}
	var observation cacheObservation
	if err := decodeStrictJSON(encoded, &observation); err != nil {
		return cacheObservation{}, fmt.Errorf("decode RQ1 cache observation: %w", err)
	}
	if observation.Profile != evaluationCacheProfile || observation.Action != action || observation.OperationID != operation.OperationID ||
		observation.Route != config.route || !canonicalToken(observation.Lease) || observation.InstanceToken != config.instanceToken ||
		observation.ApplicationResultCache != "none" || observation.OSPageCache != "uncontrolled" ||
		observation.ProcessState != "fresh-process-first-operation" && observation.ProcessState != "same-process-retained" {
		return cacheObservation{}, fmt.Errorf("RQ1 cache observation does not bind the exact operation/instance/cache boundary")
	}
	if action == "begin" {
		if lease != "" || observation.SuccessfulHTTPRequests != 0 {
			return cacheObservation{}, fmt.Errorf("RQ1 cache begin has invalid lease/request state")
		}
	} else if action == "end" {
		if observation.Lease != lease || observation.SuccessfulHTTPRequests == 0 {
			return cacheObservation{}, fmt.Errorf("RQ1 cache end did not observe a successful concrete route request")
		}
	} else {
		return cacheObservation{}, fmt.Errorf("unsupported RQ1 cache action %q", action)
	}
	return observation, nil
}

func (config workerConfig) observeGatewayHealth(ctx context.Context) (gatewayHealth, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(config.baseURL, "/")+"/healthz", nil)
	if err != nil {
		return gatewayHealth{}, err
	}
	response, err := config.cacheClient.Do(request)
	if err != nil {
		return gatewayHealth{}, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil {
		return gatewayHealth{}, err
	}
	if len(raw) > 1<<20 {
		return gatewayHealth{}, fmt.Errorf("Gateway health exceeds 1048576 bytes")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return gatewayHealth{}, fmt.Errorf("Gateway health HTTP %d", response.StatusCode)
	}
	var values map[string]json.RawMessage
	if err := decodeStrictJSON(raw, &values); err != nil {
		return gatewayHealth{}, fmt.Errorf("decode Gateway health: %w", err)
	}
	require := func(key, want string) error {
		encoded, ok := values[key]
		if !ok {
			return fmt.Errorf("Gateway health omitted %q", key)
		}
		var got string
		if err := json.Unmarshal(encoded, &got); err != nil || got != want {
			return fmt.Errorf("Gateway health %q does not equal %q", key, want)
		}
		return nil
	}
	for key, want := range map[string]string{
		"status":                                  "ok",
		"evaluation_instance_token":               config.instanceToken,
		"evaluation_rq1_cache_observation":        evaluationCacheProfile,
		"evaluation_rq1_read_phases":              "gateway.rq1-read-phases/v1",
		"evaluation_rq1_application_result_cache": "none",
		"evaluation_rq1_os_page_cache":            "uncontrolled",
	} {
		if err := require(key, want); err != nil {
			return gatewayHealth{}, err
		}
	}
	digest := sha256.Sum256(raw)
	return gatewayHealth{
		Profile: "malt-rq1-gateway-health-observation/v1", RawSHA256: hex.EncodeToString(digest[:]), RawBytes: uint64(len(raw)),
		InstanceToken: config.instanceToken, CacheObservationProfile: evaluationCacheProfile,
		ReadPhasesProfile: "gateway.rq1-read-phases/v1", ApplicationResultCache: "none", OSPageCache: "uncontrolled",
	}, nil
}

type evaluationHeaderTransport struct {
	base          http.RoundTripper
	instanceToken string

	mu          sync.RWMutex
	operationID string
	route       string
	lease       string
}

func (transport *evaluationHeaderTransport) Set(operationID, route, lease string) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.operationID = operationID
	transport.route = route
	transport.lease = lease
}

func (transport *evaluationHeaderTransport) Clear() {
	transport.Set("", "", "")
}

func (transport *evaluationHeaderTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.mu.RLock()
	operationID, route, lease := transport.operationID, transport.route, transport.lease
	transport.mu.RUnlock()
	if operationID == "" || route == "" || lease == "" {
		return transport.base.RoundTrip(request)
	}
	copy := request.Clone(request.Context())
	copy.Header = request.Header.Clone()
	copy.Header.Set(evaluationInstanceTokenHeader, transport.instanceToken)
	copy.Header.Set(evaluationOperationHeader, operationID)
	copy.Header.Set(evaluationRouteHeader, route)
	copy.Header.Set(evaluationLeaseHeader, lease)
	return transport.base.RoundTrip(copy)
}

func decodeStrictJSON(data []byte, target any) error {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("expected exactly one JSON object")
	}
	return nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSONValue(decoder, "$"); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("unexpected trailing JSON")
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
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON object key %q at %s", key, path)
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
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
}

func canonicalToken(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func addResourceMetrics(metrics *workerMetrics, before, after processUsage) error {
	if metrics == nil || after.userCPUNS < before.userCPUNS || after.systemCPUNS < before.systemCPUNS || after.peakRSSBytes == 0 {
		return fmt.Errorf("invalid process resource counter transition")
	}
	metrics.ClientUserCPUNS = after.userCPUNS - before.userCPUNS
	metrics.ClientSystemCPUNS = after.systemCPUNS - before.systemCPUNS
	metrics.ProcessPeakRSSBytes = after.peakRSSBytes
	return nil
}

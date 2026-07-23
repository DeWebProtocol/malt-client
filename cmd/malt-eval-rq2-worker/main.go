// Command malt-eval-rq2-worker is the native client-root process boundary for
// the paper RQ2 evaluator. Stdout is JSONL only. One process owns one complete
// long-lived session and exits after a verified session-end audit.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/dewebprotocol/malt-client/internal/evaluation/machine"
	"github.com/dewebprotocol/malt-client/internal/evaluation/rq2fixture"
	"github.com/dewebprotocol/malt-client/transport"
)

const (
	maxWorkerLineBytes = 1 << 20
	maxFixtureBytes    = 64 << 20
	maxRequests        = 2048
)

var identityPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)

type workerConfig struct {
	gatewayBaseURL string
	fixturePath    string
	workerID       string
	platformID     string
	clientKind     string
	backend        string
	lifecycle      string
	requestTimeout time.Duration
	lowPowerARM    bool
	gatewayToken   string
	machinePath    string
	machineSHA256  string
	machineBytes   int64
	machine        *machine.Evidence
}

type worker struct {
	config       workerConfig
	fixture      *rq2fixture.Fixture
	remote       *transport.Client
	native       *nativeSession
	sessionID    string
	fixtureID    string
	state        string
	receiptCount uint64
}

func main() {
	var err error
	if len(os.Args) > 1 && os.Args[1] == "--e0-self-test" {
		err = runNativeE0SelfTest(os.Args[2:], os.Stdout, os.Stderr)
	} else {
		err = run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	config, err := parseFlags(args, stderr)
	if err != nil {
		return err
	}
	fixture, err := readFixture(config.fixturePath)
	if err != nil {
		return err
	}
	remote, err := transport.New(transport.Options{BaseURL: config.gatewayBaseURL, HTTPClient: &http.Client{Timeout: config.requestTimeout}})
	if err != nil {
		return err
	}
	healthContext, cancelHealth := context.WithTimeout(context.Background(), config.requestTimeout)
	health, err := remote.Health(healthContext)
	cancelHealth()
	if err != nil {
		return fmt.Errorf("verify disposable Gateway instance health: %w", err)
	}
	if health.Status != "ok" || health.EvaluationInstanceToken != config.gatewayToken {
		return fmt.Errorf("Gateway health did not echo the exact registered disposable instance token")
	}
	machineEvidence, err := machine.LoadPinned(config.machinePath, config.machineSHA256, config.machineBytes)
	if err != nil {
		return fmt.Errorf("verify paper machine descriptor: %w", err)
	}
	if machineEvidence.Descriptor.LowPowerARM() != config.lowPowerARM {
		return fmt.Errorf("-low-power-arm does not match the verified machine descriptor classification")
	}
	config.machine = machineEvidence
	sourceFixture, err := rq2fixture.Decode(fixture)
	if err != nil {
		return err
	}
	w := &worker{config: config, fixture: sourceFixture, remote: remote, state: recordPreflight}
	defer func() {
		if w.native != nil {
			_ = w.native.close()
		}
	}()
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	scanner := bufio.NewScanner(stdin)
	scanner.Buffer(make([]byte, 64<<10), maxWorkerLineBytes)
	requests := 0
	for scanner.Scan() {
		requests++
		if requests > maxRequests {
			return fmt.Errorf("RQ2 worker exceeds %d-request session limit", maxRequests)
		}
		request, err := decodeWorkerRequest(scanner.Bytes())
		if err != nil {
			return err
		}
		if err := w.bindRequest(request); err != nil {
			return err
		}
		record := w.exchange(request)
		if err := encoder.Encode(record); err != nil {
			return err
		}
		if request.RecordKind == recordSessionEnd {
			if scanner.Scan() {
				return fmt.Errorf("RQ2 worker received input after session-end")
			}
			if err := scanner.Err(); err != nil {
				return err
			}
			return nil
		}
	}
	if err := scanner.Err(); err != nil {
		if strings.Contains(err.Error(), "token too long") {
			return fmt.Errorf("RQ2 worker request exceeds %d bytes", maxWorkerLineBytes)
		}
		return err
	}
	return fmt.Errorf("RQ2 worker input closed before session-end")
}

func parseFlags(args []string, stderr io.Writer) (workerConfig, error) {
	flags := flag.NewFlagSet("malt-eval-rq2-worker", flag.ContinueOnError)
	flags.SetOutput(stderr)
	baseURL := flags.String("gateway-base-url", "", "Gateway base URL")
	fixture := flags.String("fixture", "", "pinned logical fixture file")
	workerID := flags.String("worker-id", "", "registered worker identifier")
	platformID := flags.String("platform-id", "", "registered platform identifier")
	clientKind := flags.String("client-kind", "", "native or browser-wasm")
	backend := flags.String("backend", "", "kzg or ipa")
	lifecycle := flags.String("lifecycle", "", "registered lifecycle")
	lowPowerARM := flags.String("low-power-arm", "", "registered low-power ARM classification (true or false)")
	gatewayToken := flags.String("gateway-instance-token", "", "campaign-pinned disposable Gateway instance token")
	machinePath := flags.String("machine-descriptor", "", "pinned machine descriptor artifact")
	machineSHA256 := flags.String("machine-descriptor-sha256", "", "registered machine descriptor SHA-256")
	machineBytes := flags.Int64("machine-descriptor-bytes", 0, "registered machine descriptor byte length")
	timeout := flags.Duration("request-timeout", 5*time.Minute, "per-request timeout")
	if err := flags.Parse(args); err != nil {
		return workerConfig{}, err
	}
	if flags.NArg() != 0 {
		return workerConfig{}, fmt.Errorf("unexpected positional arguments")
	}
	config := workerConfig{
		gatewayBaseURL: strings.TrimSpace(*baseURL), fixturePath: strings.TrimSpace(*fixture),
		workerID: strings.TrimSpace(*workerID), platformID: strings.TrimSpace(*platformID),
		clientKind: strings.TrimSpace(*clientKind), backend: strings.TrimSpace(*backend),
		lifecycle: strings.TrimSpace(*lifecycle), requestTimeout: *timeout,
		gatewayToken: strings.TrimSpace(*gatewayToken),
		machinePath:  strings.TrimSpace(*machinePath), machineSHA256: strings.TrimSpace(*machineSHA256), machineBytes: *machineBytes,
	}
	if *lowPowerARM != "true" && *lowPowerARM != "false" {
		return workerConfig{}, fmt.Errorf("-low-power-arm must be explicitly true or false")
	}
	config.lowPowerARM, _ = strconv.ParseBool(*lowPowerARM)
	if !canonicalLowerSHA256(config.gatewayToken) {
		return workerConfig{}, fmt.Errorf("-gateway-instance-token must be one canonical lowercase SHA-256 value")
	}
	if config.machinePath == "" || !canonicalLowerSHA256(config.machineSHA256) || config.machineBytes <= 0 || config.machineBytes > machine.MaxDescriptorBytes {
		return workerConfig{}, fmt.Errorf("machine descriptor path/SHA-256/bytes pin is required")
	}
	if config.gatewayBaseURL == "" || config.fixturePath == "" || !identityPattern.MatchString(config.workerID) || !identityPattern.MatchString(config.platformID) {
		return workerConfig{}, fmt.Errorf("gateway, fixture, worker, and platform flags are required")
	}
	if config.backend != "kzg" && config.backend != "ipa" {
		return workerConfig{}, fmt.Errorf("-backend must be kzg or ipa")
	}
	if config.clientKind == clientNative && config.lifecycle != lifecycleNativeLong ||
		config.clientKind == clientBrowserWASM && config.lifecycle != lifecycleBrowserCold && config.lifecycle != lifecycleBrowserSteady {
		return workerConfig{}, fmt.Errorf("client kind and lifecycle do not match")
	}
	if config.clientKind != clientNative && config.clientKind != clientBrowserWASM {
		return workerConfig{}, fmt.Errorf("unsupported -client-kind %q", config.clientKind)
	}
	if config.requestTimeout <= 0 || config.requestTimeout > 24*time.Hour {
		return workerConfig{}, fmt.Errorf("-request-timeout must be in (0,24h]")
	}
	return config, nil
}

func canonicalLowerSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			if char < 'a' || char > 'f' {
				return false
			}
		}
	}
	return true
}

func readFixture(path string) ([]byte, error) {
	lstat, err := os.Lstat(path)
	if err != nil || lstat.Mode()&os.ModeSymlink != 0 || !lstat.Mode().IsRegular() {
		return nil, fmt.Errorf("RQ2 fixture is not a regular non-symlink file: %v", err)
	}
	if lstat.Size() <= 0 || lstat.Size() > maxFixtureBytes {
		return nil, fmt.Errorf("RQ2 fixture size must be in 1..%d bytes", maxFixtureBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(lstat, opened) {
		return nil, fmt.Errorf("RQ2 fixture changed before it was opened")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxFixtureBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != lstat.Size() {
		return nil, fmt.Errorf("RQ2 fixture changed while being read")
	}
	post, err := os.Lstat(path)
	if err != nil || !os.SameFile(lstat, post) || post.Mode()&os.ModeSymlink != 0 || post.Size() != lstat.Size() {
		return nil, fmt.Errorf("RQ2 fixture changed after it was read")
	}
	return data, nil
}

func decodeWorkerRequest(raw []byte) (workerRequest, error) {
	if err := rejectDuplicateRequestKeys(raw); err != nil {
		return workerRequest{}, fmt.Errorf("decode RQ2 request: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var request workerRequest
	if err := decoder.Decode(&request); err != nil {
		return workerRequest{}, fmt.Errorf("decode RQ2 request: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return workerRequest{}, fmt.Errorf("RQ2 request must contain exactly one JSON object")
	}
	if err := request.validate(); err != nil {
		return workerRequest{}, err
	}
	return request, nil
}

func rejectDuplicateRequestKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanRequestJSONValue(decoder, "$"); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("JSON contains trailing data")
		}
		return err
	}
	return nil
}

func scanRequestJSONValue(decoder *json.Decoder, path string) error {
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
			if err := scanRequestJSONValue(decoder, path+"."+key); err != nil {
				return err
			}
		}
		_, err := decoder.Token()
		return err
	case '[':
		for index := 0; decoder.More(); index++ {
			if err := scanRequestJSONValue(decoder, fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
		_, err := decoder.Token()
		return err
	default:
		return fmt.Errorf("unexpected JSON delimiter %q at %s", delimiter, path)
	}
}

func (r workerRequest) validate() error {
	if r.SchemaVersion != workerRequestSchema || !identityPattern.MatchString(r.WorkerID) || !identityPattern.MatchString(r.RequestID) ||
		!identityPattern.MatchString(r.SessionID) || !identityPattern.MatchString(r.PlatformID) || !identityPattern.MatchString(r.FixtureID) {
		return fmt.Errorf("invalid RQ2 request identity")
	}
	switch r.RecordKind {
	case recordPreflight:
		if r.Operation != "" || r.Measured || r.ExpectedAcceptedRoot != "" {
			return fmt.Errorf("preflight request contains mutation state")
		}
	case recordSessionStart, recordSessionEnd:
		if r.Operation != "" || r.Measured || r.ExpectedAcceptedRoot == "" {
			return fmt.Errorf("session request is incomplete")
		}
	case recordMutation:
		if !identityPattern.MatchString(r.Operation) || r.ExpectedAcceptedRoot == "" {
			return fmt.Errorf("mutation request is incomplete")
		}
	default:
		return fmt.Errorf("unsupported RQ2 record kind %q", r.RecordKind)
	}
	return nil
}

func (w *worker) bindRequest(request workerRequest) error {
	if request.WorkerID != w.config.workerID || request.PlatformID != w.config.platformID || request.ClientKind != w.config.clientKind ||
		request.Backend != w.config.backend || request.Lifecycle != w.config.lifecycle {
		return fmt.Errorf("RQ2 request does not bind configured worker coordinate")
	}
	if w.sessionID == "" {
		w.sessionID, w.fixtureID = request.SessionID, request.FixtureID
	}
	if request.SessionID != w.sessionID || request.FixtureID != w.fixtureID {
		return fmt.Errorf("RQ2 request changed session or fixture identity")
	}
	if w.fixture == nil || request.FixtureID != w.fixture.FixtureID {
		return fmt.Errorf("RQ2 request fixture identity does not match the pinned source fixture")
	}
	if request.RecordKind != w.state && !(w.state == recordMutation && request.RecordKind == recordSessionEnd) {
		return fmt.Errorf("RQ2 request kind %q is out of order; want %q", request.RecordKind, w.state)
	}
	return nil
}

func (w *worker) exchange(request workerRequest) workerRecord {
	switch request.RecordKind {
	case recordPreflight:
		return w.preflight(request)
	case recordSessionStart:
		return w.startSession(request)
	case recordMutation:
		return w.mutate(request)
	case recordSessionEnd:
		return w.endSession(request)
	default:
		return failedRecord(request, "input_invalid", fmt.Errorf("unsupported request kind"))
	}
}

func (w *worker) preflight(request workerRequest) workerRecord {
	if w.config.clientKind == clientBrowserWASM {
		w.state = recordSessionStart
		return failedRecord(request, "capability_unavailable", fmt.Errorf("real browser/WASM execution is not provided by the native worker; use a pinned browser worker"))
	}
	if w.config.lowPowerARM && runtime.GOARCH != "arm" && runtime.GOARCH != "arm64" {
		w.state = recordSessionStart
		return failedRecord(request, "platform_mismatch", fmt.Errorf("low-power ARM registration cannot run on %s", runtime.GOARCH))
	}
	native, err := newNativeSession(w.config, w.remote, w.fixture)
	if err != nil {
		w.state = recordSessionStart
		return failedRecord(request, "capability_unavailable", err)
	}
	w.native = native
	record := baseRecord(request)
	record.Success = true
	record.Capabilities = requiredCapabilities(w.config.clientKind, w.config.backend)
	record.Runtime = &runtimeEvidence{
		OS: runtime.GOOS, Architecture: runtime.GOARCH, LowPowerARM: w.config.lowPowerARM,
		MachineDescriptorID: w.config.machine.Descriptor.ID, MachineDescriptorSHA256: w.config.machine.SHA256,
	}
	w.state = recordSessionStart
	return record
}

func requiredCapabilities(clientKind, backend string) []string {
	values := []string{"client-root-bundle-v1", "exact-root-receipt-v1", "phase-metrics-v1", "update-view-v1"}
	if clientKind == clientNative {
		values = append(values, "long-lived-session-v1", "native-writer-v1")
	} else {
		values = append(values, "wasm-cold-start-v1", "wasm-steady-session-v1", "wasm-writer-v1")
	}
	values = append(values, "commitment-"+backend+"-v1")
	slices.Sort(values)
	return values
}

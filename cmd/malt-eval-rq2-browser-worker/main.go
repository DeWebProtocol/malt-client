// Command malt-eval-rq2-browser-worker is the real-browser process boundary
// for paper RQ2. It launches a pinned Chromium-family executable, serves the
// pinned Go/WASM writer through a non-cacheable loopback origin, and relays the
// evaluator's strict JSONL protocol through DevTools. Stdout contains JSONL
// records only; browser diagnostics are bounded on stderr.
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
	"net/url"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/dewebprotocol/malt-client/internal/evaluation/machine"
	"github.com/dewebprotocol/malt-client/internal/evaluation/rq2wire"
)

const (
	maxWorkerLineBytes      = 1 << 20
	maxWorkerRequests       = 2048
	maxBrowserLauncherBytes = 512 << 20
)

var browserEnginePattern = regexp.MustCompile(`^(chromium|chrome)-[0-9]+(?:\.[0-9]+){1,3}$`)

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(value string) error {
	if value == "" || strings.HasPrefix(value, "-") || strings.IndexByte(value, 0) >= 0 || len(value) > 4096 || len(*s) >= 16 {
		return fmt.Errorf("invalid or excessive browser launch argument")
	}
	*s = append(*s, value)
	return nil
}

type hostConfig struct {
	gatewayBaseURL       string
	gatewayToken         string
	fixturePath          string
	workerID             string
	platformID           string
	clientKind           string
	backend              string
	lifecycle            string
	steadyWarmup         string
	sessionMutationCount int
	requestTimeout       time.Duration
	lowPowerARM          bool
	browserPath          string
	browserEngine        string
	browserArgs          []string
	browserPin           artifactPin
	wasmPin              artifactPin
	wasmExecPin          artifactPin
	machinePin           artifactPin
}

type browserWorker struct {
	config                hostConfig
	fixture               []byte
	fixtureSHA256         string
	wasm                  []byte
	wasmExec              []byte
	browserArtifact       artifactSnapshot
	wasmArtifact          artifactSnapshot
	wasmExecArtifact      artifactSnapshot
	capabilityError       error
	browser               *browserSession
	sessionID             string
	fixtureID             string
	state                 string
	preflightComplete     bool
	mutationCount         uint64
	measuredMutationCount uint64
	machine               *machine.Evidence
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--e0-self-test" {
		if err := runBrowserE0SelfTest(os.Args[2:], os.Stdout, os.Stderr); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) (returnErr error) {
	config, err := parseFlags(args, stderr)
	if err != nil {
		return err
	}
	worker, err := newBrowserWorker(config)
	if err != nil {
		return err
	}
	defer func() {
		if worker.browser != nil {
			returnErr = errors.Join(returnErr, worker.browser.close())
		}
	}()
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	scanner := bufio.NewScanner(stdin)
	scanner.Buffer(make([]byte, 64<<10), maxWorkerLineBytes)
	requests := 0
	for scanner.Scan() {
		requests++
		if requests > maxWorkerRequests {
			return fmt.Errorf("RQ2 browser worker exceeds %d-request limit", maxWorkerRequests)
		}
		request, err := decodeWorkerRequest(scanner.Bytes())
		if err != nil {
			return err
		}
		if err := worker.bindRequest(request); err != nil {
			return err
		}
		requestContext, cancel := context.WithTimeout(context.Background(), config.requestTimeout)
		record := worker.exchange(requestContext, request)
		cancel()
		if err := rq2wire.Bind(record, request); err != nil {
			return err
		}
		if err := record.Validate(); err != nil {
			return fmt.Errorf("browser worker constructed invalid record: %w", err)
		}
		if err := encoder.Encode(record); err != nil {
			return err
		}
		if request.RecordKind == rq2wire.RecordSessionEnd {
			if scanner.Scan() {
				return fmt.Errorf("RQ2 browser worker received input after session-end")
			}
			if err := scanner.Err(); err != nil {
				return err
			}
			if record.Success {
				return worker.verifyArtifacts()
			}
			return nil
		}
	}
	if err := scanner.Err(); err != nil {
		if strings.Contains(err.Error(), "token too long") {
			return fmt.Errorf("RQ2 browser worker request exceeds %d bytes", maxWorkerLineBytes)
		}
		return err
	}
	return fmt.Errorf("RQ2 browser worker input closed before session-end")
}

func parseFlags(args []string, stderr io.Writer) (hostConfig, error) {
	flags := flag.NewFlagSet("malt-eval-rq2-browser-worker", flag.ContinueOnError)
	flags.SetOutput(stderr)
	baseURL := flags.String("gateway-base-url", "", "Gateway base URL")
	gatewayToken := flags.String("gateway-instance-token", "", "disposable Gateway token")
	fixture := flags.String("fixture", "", "pinned logical fixture")
	workerID := flags.String("worker-id", "", "registered worker identifier")
	platformID := flags.String("platform-id", "", "registered platform identifier")
	clientKind := flags.String("client-kind", "", "must be browser-wasm")
	backend := flags.String("backend", "", "kzg or ipa")
	lifecycle := flags.String("lifecycle", "", "browser-cold or browser-steady")
	steadyWarmup := flags.String("steady-warmup-operation", "", "exact unmeasured steady-session warmup operation")
	sessionMutationCount := flags.Int("session-mutation-count", 0, "exact measured mutation count for a short-session pair")
	lowPower := flags.String("low-power-arm", "", "registered low-power ARM classification")
	timeout := flags.Duration("request-timeout", 5*time.Minute, "per-request timeout")
	browserPath := flags.String("browser-path", "", "pinned Chromium-family launcher")
	browserEngine := flags.String("browser-engine", "", "exact detected browser engine/version")
	browserSHA := flags.String("browser-launcher-sha256", "", "launcher SHA-256")
	browserBytes := flags.Int64("browser-launcher-bytes", 0, "launcher bytes")
	wasmPath := flags.String("wasm", "", "Go/WASM writer artifact")
	wasmSHA := flags.String("wasm-sha256", "", "Go/WASM writer SHA-256")
	wasmBytes := flags.Int64("wasm-bytes", 0, "Go/WASM writer bytes")
	wasmExecPath := flags.String("wasm-exec", "", "Go wasm_exec.js artifact")
	wasmExecSHA := flags.String("wasm-exec-sha256", "", "wasm_exec.js SHA-256")
	wasmExecBytes := flags.Int64("wasm-exec-bytes", 0, "wasm_exec.js bytes")
	machinePath := flags.String("machine-descriptor", "", "pinned machine descriptor artifact")
	machineSHA := flags.String("machine-descriptor-sha256", "", "machine descriptor SHA-256")
	machineBytes := flags.Int64("machine-descriptor-bytes", 0, "machine descriptor bytes")
	var browserArgs stringList
	flags.Var(&browserArgs, "browser-launch-arg", "argument before Chromium flags (repeatable)")
	if err := flags.Parse(args); err != nil {
		return hostConfig{}, err
	}
	if flags.NArg() != 0 {
		return hostConfig{}, fmt.Errorf("unexpected positional arguments")
	}
	if *lowPower != "true" && *lowPower != "false" {
		return hostConfig{}, fmt.Errorf("-low-power-arm must be explicitly true or false")
	}
	lowPowerARM, _ := strconv.ParseBool(*lowPower)
	config := hostConfig{
		gatewayBaseURL: strings.TrimRight(strings.TrimSpace(*baseURL), "/"), gatewayToken: strings.TrimSpace(*gatewayToken),
		fixturePath: strings.TrimSpace(*fixture), workerID: strings.TrimSpace(*workerID), platformID: strings.TrimSpace(*platformID),
		clientKind: strings.TrimSpace(*clientKind), backend: strings.TrimSpace(*backend), lifecycle: strings.TrimSpace(*lifecycle),
		steadyWarmup:         strings.TrimSpace(*steadyWarmup),
		sessionMutationCount: *sessionMutationCount,
		requestTimeout:       *timeout, lowPowerARM: lowPowerARM, browserPath: strings.TrimSpace(*browserPath),
		browserEngine: strings.TrimSpace(*browserEngine), browserArgs: slices.Clone(browserArgs),
	}
	config.browserPin = artifactPin{path: config.browserPath, sha256: strings.TrimSpace(*browserSHA), bytes: *browserBytes, executable: true, allowSymlink: true, maxBytes: maxBrowserLauncherBytes}
	config.wasmPin = artifactPin{path: strings.TrimSpace(*wasmPath), sha256: strings.TrimSpace(*wasmSHA), bytes: *wasmBytes, maxBytes: maxWASMBytes}
	config.wasmExecPin = artifactPin{path: strings.TrimSpace(*wasmExecPath), sha256: strings.TrimSpace(*wasmExecSHA), bytes: *wasmExecBytes, maxBytes: maxSupportBytes}
	config.machinePin = artifactPin{path: strings.TrimSpace(*machinePath), sha256: strings.TrimSpace(*machineSHA), bytes: *machineBytes, maxBytes: machine.MaxDescriptorBytes}
	parsedURL, err := url.Parse(config.gatewayBaseURL)
	if err != nil || parsedURL.Scheme != "http" && parsedURL.Scheme != "https" || parsedURL.Host == "" || parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		return hostConfig{}, fmt.Errorf("invalid -gateway-base-url")
	}
	if !rq2wire.IDPattern.MatchString(config.workerID) || !rq2wire.IDPattern.MatchString(config.platformID) || !canonicalSHA256(config.gatewayToken) || config.fixturePath == "" {
		return hostConfig{}, fmt.Errorf("worker/platform/fixture/Gateway token flags are incomplete")
	}
	if config.clientKind != rq2wire.ClientBrowserWASM || config.backend != "kzg" && config.backend != "ipa" ||
		config.lifecycle != rq2wire.LifecycleBrowserCold && config.lifecycle != rq2wire.LifecycleBrowserSteady && config.lifecycle != rq2wire.LifecycleBrowserShort {
		return hostConfig{}, fmt.Errorf("browser worker coordinate is invalid")
	}
	if config.sessionMutationCount < 0 || config.sessionMutationCount > 1024 ||
		(config.sessionMutationCount > 0 && !slices.Contains([]int{1, 2, 4, 16, 64}, config.sessionMutationCount)) ||
		(config.lifecycle == rq2wire.LifecycleBrowserShort && config.sessionMutationCount == 0) ||
		(config.lifecycle == rq2wire.LifecycleBrowserCold && config.sessionMutationCount != 0) {
		return hostConfig{}, fmt.Errorf("browser worker session mutation count is invalid")
	}
	if !browserEnginePattern.MatchString(config.browserEngine) || !rq2wire.IDPattern.MatchString(config.steadyWarmup) ||
		config.requestTimeout <= 0 || config.requestTimeout > 24*time.Hour {
		return hostConfig{}, fmt.Errorf("browser engine or request timeout is invalid")
	}
	if config.lowPowerARM && runtime.GOARCH != "arm" && runtime.GOARCH != "arm64" {
		return hostConfig{}, fmt.Errorf("low-power ARM cannot be claimed by %s", runtime.GOARCH)
	}
	for _, pin := range []artifactPin{config.browserPin, config.wasmPin, config.wasmExecPin} {
		if pin.path == "" || !canonicalSHA256(pin.sha256) || pin.bytes <= 0 {
			return hostConfig{}, fmt.Errorf("browser/WASM artifact pins are required")
		}
	}
	if config.machinePin.path == "" || !canonicalSHA256(config.machinePin.sha256) || config.machinePin.bytes <= 0 || config.machinePin.bytes > machine.MaxDescriptorBytes {
		return hostConfig{}, fmt.Errorf("machine descriptor path/SHA-256/bytes pin is required")
	}
	return config, nil
}

func newBrowserWorker(config hostConfig) (*browserWorker, error) {
	fixture, err := readFixture(config.fixturePath)
	if err != nil {
		return nil, err
	}
	machineEvidence, err := machine.LoadPinned(config.machinePin.path, config.machinePin.sha256, config.machinePin.bytes)
	if err != nil {
		return nil, fmt.Errorf("verify paper machine descriptor: %w", err)
	}
	if machineEvidence.Descriptor.LowPowerARM() != config.lowPowerARM {
		return nil, fmt.Errorf("-low-power-arm does not match the verified machine descriptor classification")
	}
	wasmArtifact, wasm, err := loadPinnedArtifact(config.wasmPin, true)
	if err != nil {
		return nil, fmt.Errorf("verify Go/WASM writer: %w", err)
	}
	wasmExecArtifact, wasmExec, err := loadPinnedArtifact(config.wasmExecPin, true)
	if err != nil {
		return nil, fmt.Errorf("verify wasm_exec.js: %w", err)
	}
	worker := &browserWorker{
		config: config, fixture: fixture, wasm: wasm, wasmExec: wasmExec,
		wasmArtifact: wasmArtifact, wasmExecArtifact: wasmExecArtifact, state: rq2wire.RecordPreflight, machine: machineEvidence,
	}
	digest := sha256.Sum256(fixture)
	worker.fixtureSHA256 = hex.EncodeToString(digest[:])
	browserArtifact, _, err := loadPinnedArtifact(config.browserPin, false)
	if err != nil {
		worker.capabilityError = fmt.Errorf("pinned browser launcher unavailable: %w", err)
	} else if runtime.GOOS != "linux" {
		worker.capabilityError = fmt.Errorf("real browser peak-RSS measurement requires Linux /proc")
	} else {
		worker.browserArtifact = browserArtifact
	}
	return worker, nil
}

func (w *browserWorker) bindRequest(request rq2wire.WorkerRequest) error {
	if request.ClientKind != w.config.clientKind || request.Backend != w.config.backend || request.Lifecycle != w.config.lifecycle ||
		request.WorkerID != w.config.workerID || request.PlatformID != w.config.platformID {
		return fmt.Errorf("RQ2 browser request does not bind configured worker coordinate")
	}
	if w.sessionID == "" {
		w.sessionID, w.fixtureID = request.SessionID, request.FixtureID
	}
	if request.SessionID != w.sessionID || request.FixtureID != w.fixtureID {
		return fmt.Errorf("RQ2 browser request changed session or fixture identity")
	}
	switch w.state {
	case rq2wire.RecordPreflight, rq2wire.RecordSessionStart:
		if request.RecordKind != w.state {
			return fmt.Errorf("RQ2 browser request kind %q is out of order; want %q", request.RecordKind, w.state)
		}
	case "active":
		if request.RecordKind != rq2wire.RecordMutation && request.RecordKind != rq2wire.RecordSessionEnd {
			return fmt.Errorf("RQ2 browser active session rejects %q", request.RecordKind)
		}
	default:
		return fmt.Errorf("RQ2 browser worker is closed")
	}
	return nil
}

func (w *browserWorker) exchange(ctx context.Context, request rq2wire.WorkerRequest) rq2wire.WorkerRecord {
	if request.RecordKind == rq2wire.RecordPreflight {
		return w.preflight(ctx, request)
	}
	if w.browser == nil {
		return rq2wire.FailedRecord(request, "capability_unavailable", fmt.Errorf("real browser session is unavailable"))
	}
	if request.RecordKind == rq2wire.RecordMutation {
		if w.config.lifecycle == rq2wire.LifecycleBrowserCold && (w.mutationCount != 0 || !request.Measured) {
			return rq2wire.FailedRecord(request, "lifecycle_invalid", fmt.Errorf("cold browser lifecycle requires exactly one measured first mutation"))
		}
		if w.config.lifecycle == rq2wire.LifecycleBrowserShort && (!request.Measured || w.mutationCount >= uint64(w.config.sessionMutationCount)) {
			return rq2wire.FailedRecord(request, "lifecycle_invalid", fmt.Errorf("short browser lifecycle requires exactly %d measured mutations", w.config.sessionMutationCount))
		}
		if w.config.lifecycle == rq2wire.LifecycleBrowserSteady {
			if w.mutationCount == 0 && (request.Measured || request.Operation != w.config.steadyWarmup) {
				return rq2wire.FailedRecord(request, "lifecycle_invalid", fmt.Errorf("steady browser lifecycle must begin with exact unmeasured warmup %q", w.config.steadyWarmup))
			}
			if w.mutationCount != 0 && !request.Measured {
				return rq2wire.FailedRecord(request, "lifecycle_invalid", fmt.Errorf("steady browser lifecycle permits only one unmeasured warmup"))
			}
			if w.config.sessionMutationCount > 0 && w.mutationCount > uint64(w.config.sessionMutationCount) {
				return rq2wire.FailedRecord(request, "lifecycle_invalid", fmt.Errorf("paired steady baseline permits exactly %d measured mutations", w.config.sessionMutationCount))
			}
		}
	}
	if request.RecordKind == rq2wire.RecordSessionEnd {
		if (w.config.lifecycle == rq2wire.LifecycleBrowserCold && w.mutationCount != 1) ||
			(w.config.lifecycle == rq2wire.LifecycleBrowserShort && (w.mutationCount != uint64(w.config.sessionMutationCount) || w.measuredMutationCount != uint64(w.config.sessionMutationCount))) ||
			(w.config.lifecycle == rq2wire.LifecycleBrowserSteady && w.config.sessionMutationCount == 0 && w.mutationCount < 2) ||
			(w.config.lifecycle == rq2wire.LifecycleBrowserSteady && w.config.sessionMutationCount > 0 && (w.mutationCount != uint64(w.config.sessionMutationCount+1) || w.measuredMutationCount != uint64(w.config.sessionMutationCount))) {
			return rq2wire.FailedRecord(request, "lifecycle_invalid", fmt.Errorf("browser session ended before its cold/steady mutation contract completed"))
		}
	}
	record, call, cpuNS, peakBytes, samples, err := w.browser.exchange(ctx, request)
	if err != nil {
		return rq2wire.FailedRecord(request, "browser_execution", w.poisonBrowser(err))
	}
	if err := rq2wire.Bind(record, request); err != nil {
		return rq2wire.FailedRecord(request, "browser_protocol", w.poisonBrowser(err))
	}
	if record.Success && record.RecordKind == rq2wire.RecordMutation {
		metrics := &record.Mutation.Metrics
		metrics.CPUTotal = measuredPhase(cpuNS, 0, 1)
		metrics.PeakMemory = measuredPhase(call.CallNS, peakBytes, samples)
		requestJSON, _ := json.Marshal(request)
		metrics.JSWASMBoundary = measuredPhase(call.BoundaryNS, uint64(len(requestJSON)+len(call.RecordJSON)), 1)
		if w.config.lifecycle == rq2wire.LifecycleBrowserCold || w.config.lifecycle == rq2wire.LifecycleBrowserShort && w.mutationCount == 0 {
			metrics.WASMDownload = measuredPhase(w.browser.cold.WASMDownloadNS, w.browser.cold.WASMDownloadBytes, 1)
			metrics.WASMInstantiate = measuredPhase(w.browser.cold.WASMInstantiateNS, 0, 1)
			metrics.ParameterLoad = measuredPhase(w.browser.cold.ParameterLoadNS, w.browser.cold.ParameterBytes, 1)
			metrics.FirstMutation = measuredPhase(call.CallNS, 0, 1)
		}
	}
	if record.Success {
		switch request.RecordKind {
		case rq2wire.RecordSessionStart:
			w.state = "active"
		case rq2wire.RecordMutation:
			w.mutationCount++
			if request.Measured {
				w.measuredMutationCount++
			}
		case rq2wire.RecordSessionEnd:
			if err := w.verifyArtifacts(); err != nil {
				return rq2wire.FailedRecord(request, "artifact_changed", err)
			}
			w.state = "closed"
		}
	}
	return record
}

// poisonBrowser closes the process boundary after an exchange timeout or an
// unbindable result. The Go/WASM request uses browser-owned fetches which may
// outlive the CDP wait context; terminating Chromium is the only fail-closed
// guarantee that no late request can mutate the disposable Gateway or overlap
// a later sample.
func (w *browserWorker) poisonBrowser(cause error) error {
	if cause == nil {
		cause = errors.New("browser session entered an unknown terminal state")
	}
	browser := w.browser
	w.browser = nil
	w.state = "poisoned"
	if browser == nil {
		return cause
	}
	return errors.Join(cause, browser.forceTerminate())
}

func (w *browserWorker) preflight(_ context.Context, request rq2wire.WorkerRequest) rq2wire.WorkerRecord {
	if w.preflightComplete {
		return rq2wire.FailedRecord(request, "session_state", fmt.Errorf("browser preflight was already attempted"))
	}
	w.preflightComplete = true
	if w.capabilityError != nil {
		return rq2wire.FailedRecord(request, "capability_unavailable", w.capabilityError)
	}
	if err := w.verifyArtifacts(); err != nil {
		return rq2wire.FailedRecord(request, "artifact_changed", err)
	}
	// The outer JSONL loop cancels each request context after emitting its
	// record. Chromium is a session-lifetime process, so bind startup to its
	// own bounded context inside startBrowser and close it explicitly when the
	// worker session ends instead of killing it after preflight.
	browser, err := startBrowser(context.Background(), browserLaunchConfig{
		path: w.config.browserPath, arguments: w.config.browserArgs, engine: w.config.browserEngine,
		timeout: w.config.requestTimeout, gatewayURL: w.config.gatewayBaseURL, token: w.config.gatewayToken,
		backend: w.config.backend, wasmSHA256: w.config.wasmPin.sha256,
	}, w.fixture, w.wasm, w.wasmExec)
	if err != nil {
		return rq2wire.FailedRecord(request, "capability_unavailable", err)
	}
	w.browser = browser
	record := rq2wire.BaseRecord(request)
	record.Success = true
	record.Capabilities = exactCapabilities(w.config.backend)
	record.Runtime = browserRuntime(browser.engine, w.config.wasmPin.sha256, w.machine, browser.cold)
	w.state = rq2wire.RecordSessionStart
	return record
}

func (w *browserWorker) verifyArtifacts() error {
	if w.capabilityError == nil {
		if err := w.browserArtifact.verify(); err != nil {
			return fmt.Errorf("browser launcher: %w", err)
		}
	}
	if err := w.wasmArtifact.verify(); err != nil {
		return fmt.Errorf("Go/WASM writer: %w", err)
	}
	if err := w.wasmExecArtifact.verify(); err != nil {
		return fmt.Errorf("wasm_exec.js: %w", err)
	}
	machineEvidence, err := machine.LoadPinned(w.config.machinePin.path, w.config.machinePin.sha256, w.config.machinePin.bytes)
	if err != nil || w.machine == nil || machineEvidence.Descriptor.ID != w.machine.Descriptor.ID || machineEvidence.SHA256 != w.machine.SHA256 {
		if err == nil {
			err = fmt.Errorf("machine descriptor identity changed")
		}
		return fmt.Errorf("machine descriptor: %w", err)
	}
	fixture, err := readFixture(w.config.fixturePath)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(fixture)
	if len(fixture) != len(w.fixture) || hex.EncodeToString(digest[:]) != w.fixtureSHA256 {
		return fmt.Errorf("browser fixture changed after startup")
	}
	return nil
}

func measuredPhase(duration, bytes, count uint64) rq2wire.PhaseMeasurement {
	return rq2wire.ObservedPhase(duration, bytes, max(uint64(1), count))
}

func decodeWorkerRequest(raw []byte) (rq2wire.WorkerRequest, error) {
	var request rq2wire.WorkerRequest
	if err := strictJSON(raw, &request); err != nil {
		return rq2wire.WorkerRequest{}, fmt.Errorf("decode RQ2 browser request: %w", err)
	}
	if err := request.Validate(); err != nil {
		return rq2wire.WorkerRequest{}, err
	}
	return request, nil
}

func strictJSON(raw []byte, target any) error {
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("JSON must contain exactly one value")
	}
	return nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanJSONValue(decoder, "$"); err != nil {
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

func canonicalSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

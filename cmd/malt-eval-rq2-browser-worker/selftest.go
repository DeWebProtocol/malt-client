package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dewebprotocol/malt-client/internal/evaluation/e0selftest"
	"github.com/dewebprotocol/malt-client/internal/evaluation/machine"
	"github.com/dewebprotocol/malt-client/internal/evaluation/rq2e0"
	"github.com/dewebprotocol/malt-client/internal/evaluation/rq2fixture"
	"github.com/dewebprotocol/malt-client/internal/evaluation/rq2wire"
	cid "github.com/ipfs/go-cid"
)

const (
	browserE0CapabilityID = "rq2.wasm-writer"
	browserE0ProfileID    = "rq2-wasm-writer-positive-hostile-v1"
	// Updated only when the ordered compiled case contract intentionally
	// changes together with the evaluator-owned registry.
	browserE0ExpectedProfileSHA256 = "8a46f8c36ac11d89f1453645faccfaf9d04802307ef16df10840d2db58448c52"
)

var browserE0Profile = e0selftest.Profile{
	ProfileID: browserE0ProfileID,
	PositiveCases: []string{
		"execute-browser-kzg-cold-document-flow",
		"execute-browser-kzg-steady-operation-matrix",
		"execute-browser-ipa-cold-map-replace",
		"execute-browser-kzg-short-session-continuity",
	},
	HostileCases: []string{
		"reject-malformed-request",
		"reject-wasm-pin-substitution",
		"reject-steady-without-warmup",
		"reject-backend-root-substitution",
		"reject-browser-engine-pin-substitution",
		"reject-hung-gateway-timeout-and-late-commit",
	},
}

var browserE0RequiredOperations = []string{
	"document-edit-cid-binding-submit", "list-append", "list-replace", "map-insert", "map-replace",
}

type browserE0Config struct {
	fixturePath  string
	machinePath  string
	browserPath  string
	wasmPath     string
	wasmExecPath string
	timeout      time.Duration

	fixture       *rq2fixture.Fixture
	machine       *machine.Evidence
	browserEngine string
	browserPin    artifactPin
	wasmPin       artifactPin
	wasmExecPin   artifactPin
	machinePin    artifactPin
}

type browserE0Operation struct {
	name     string
	measured bool
}

type browserE0Case struct {
	backend              string
	lifecycle            string
	sessionMutationCount int
	operations           []browserE0Operation
}

func runBrowserE0SelfTest(arguments []string, output, stderr io.Writer) error {
	config, err := parseBrowserE0Flags(arguments, stderr)
	if err != nil {
		return err
	}
	config, err = prepareBrowserE0(config)
	if err != nil {
		return err
	}
	contract, err := browserE0Profile.Contract()
	if err != nil {
		return err
	}
	if contract.ProfileSHA256 != browserE0ExpectedProfileSHA256 {
		return fmt.Errorf("compiled wasm-writer E0 profile digest drifted: got %s", contract.ProfileSHA256)
	}
	results := make([]e0selftest.CaseResult, 0, len(browserE0Profile.PositiveCases)+len(browserE0Profile.HostileCases))
	for _, caseID := range browserE0Profile.PositiveCases {
		if err := executeBrowserE0Positive(config, caseID); err != nil {
			return fmt.Errorf("browser E0 positive case %q: %w", caseID, err)
		}
		results = append(results, e0selftest.CaseResult{ID: caseID, Passed: true})
	}
	for _, caseID := range browserE0Profile.HostileCases {
		if err := executeBrowserE0Hostile(config, caseID); err != nil {
			return fmt.Errorf("browser E0 hostile case %q: %w", caseID, err)
		}
		results = append(results, e0selftest.CaseResult{ID: caseID, Passed: true})
	}
	receipt, err := e0selftest.Issue(browserE0CapabilityID, browserE0Profile, results)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(receipt)
}

func parseBrowserE0Flags(arguments []string, stderr io.Writer) (browserE0Config, error) {
	flags := flag.NewFlagSet("malt-eval-rq2-browser-worker --e0-self-test", flag.ContinueOnError)
	flags.SetOutput(stderr)
	fixture := flags.String("fixture", "", "pinned RQ2 source fixture corpus")
	machinePath := flags.String("machine-descriptor", "", "pinned platform machine descriptor")
	browserPath := flags.String("browser-launcher", "", "pinned Chromium-family executable")
	wasmPath := flags.String("wasm", "", "pinned Go/WASM writer")
	wasmExecPath := flags.String("wasm-exec", "", "pinned matching wasm_exec.js")
	timeout := flags.Duration("request-timeout", 3*time.Minute, "bounded per-request timeout")
	if err := flags.Parse(arguments); err != nil {
		return browserE0Config{}, err
	}
	if flags.NArg() != 0 || *fixture == "" || *machinePath == "" || *browserPath == "" || *wasmPath == "" || *wasmExecPath == "" || *timeout <= 0 || *timeout > 10*time.Minute {
		return browserE0Config{}, errors.New("browser formal E0 requires fixture, machine descriptor, browser launcher, WASM, wasm_exec.js, and a bounded timeout")
	}
	config := browserE0Config{
		fixturePath: filepath.Clean(*fixture), machinePath: filepath.Clean(*machinePath), browserPath: filepath.Clean(*browserPath),
		wasmPath: filepath.Clean(*wasmPath), wasmExecPath: filepath.Clean(*wasmExecPath), timeout: *timeout,
	}
	for _, path := range config.inputPaths() {
		if !filepath.IsAbs(path) {
			return browserE0Config{}, errors.New("browser formal E0 file paths must be absolute")
		}
	}
	return config, nil
}

func (c browserE0Config) inputPaths() []string {
	return []string{c.fixturePath, c.machinePath, c.browserPath, c.wasmPath, c.wasmExecPath}
}

func prepareBrowserE0(config browserE0Config) (browserE0Config, error) {
	if err := validateBrowserE0InvocationPaths(config.inputPaths()); err != nil {
		return browserE0Config{}, err
	}
	fixtureRaw, err := readFixture(config.fixturePath)
	if err != nil {
		return browserE0Config{}, err
	}
	config.fixture, err = rq2fixture.Decode(fixtureRaw)
	if err != nil {
		return browserE0Config{}, err
	}
	if err := config.fixture.RequireOperations(browserE0RequiredOperations); err != nil {
		return browserE0Config{}, err
	}
	for _, backend := range []string{"kzg", "ipa"} {
		if _, err := config.fixture.Root(backend); err != nil {
			return browserE0Config{}, fmt.Errorf("browser formal E0 fixture %s root: %w", backend, err)
		}
	}
	config.machinePin, err = describeBrowserE0Artifact(config.machinePath, machine.MaxDescriptorBytes, false)
	if err != nil {
		return browserE0Config{}, fmt.Errorf("machine descriptor: %w", err)
	}
	config.machine, err = machine.LoadPinned(config.machinePath, config.machinePin.sha256, config.machinePin.bytes)
	if err != nil {
		return browserE0Config{}, fmt.Errorf("machine descriptor: %w", err)
	}
	config.browserPin, err = describeBrowserE0Artifact(config.browserPath, maxBrowserLauncherBytes, true)
	if err != nil {
		return browserE0Config{}, fmt.Errorf("browser launcher: %w", err)
	}
	config.wasmPin, err = describeBrowserE0Artifact(config.wasmPath, maxWASMBytes, false)
	if err != nil {
		return browserE0Config{}, fmt.Errorf("Go/WASM writer: %w", err)
	}
	config.wasmExecPin, err = describeBrowserE0Artifact(config.wasmExecPath, maxSupportBytes, false)
	if err != nil {
		return browserE0Config{}, fmt.Errorf("wasm_exec.js: %w", err)
	}
	probeContext, cancel := context.WithTimeout(context.Background(), min(config.timeout, 30*time.Second))
	defer cancel()
	config.browserEngine, err = probeBrowserE0Engine(probeContext, config.browserPath)
	if err != nil {
		return browserE0Config{}, err
	}
	return config, nil
}

func validateBrowserE0InvocationPaths(consumed []string) error {
	want, err := e0selftest.InputPaths()
	if err != nil {
		return err
	}
	consumed = slices.Clone(consumed)
	slices.Sort(consumed)
	if !slices.Equal(consumed, want) {
		return fmt.Errorf("browser typed self-test flags consume %v, E0 invocation pins %v", consumed, want)
	}
	return nil
}

func describeBrowserE0Artifact(path string, maximum int64, executable bool) (artifactPin, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || maximum <= 0 {
		return artifactPin{}, errors.New("artifact path must be canonical and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return artifactPin{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return artifactPin{}, errors.New("artifact must be a bounded regular non-symlink file")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return artifactPin{}, errors.New("artifact path or one of its parents must not be symlinked")
	}
	file, err := os.Open(path)
	if err != nil {
		return artifactPin{}, err
	}
	hash := sha256.New()
	written, readErr := io.Copy(hash, io.LimitReader(file, maximum+1))
	closeErr := file.Close()
	if readErr != nil {
		return artifactPin{}, readErr
	}
	if closeErr != nil {
		return artifactPin{}, closeErr
	}
	post, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, post) || post.Mode()&os.ModeSymlink != 0 || written != info.Size() {
		return artifactPin{}, errors.New("artifact changed while it was hashed")
	}
	pin := artifactPin{path: path, sha256: hex.EncodeToString(hash.Sum(nil)), bytes: written, executable: executable, maxBytes: maximum}
	if _, _, err := loadPinnedArtifact(pin, false); err != nil {
		return artifactPin{}, err
	}
	return pin, nil
}

func probeBrowserE0Engine(ctx context.Context, browserPath string) (string, error) {
	output, err := exec.CommandContext(ctx, browserPath, "--version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("run pinned browser version probe: %w: %s", err, boundedText(output, 1024))
	}
	engine, err := parseBrowserEngineOutput(string(output))
	if err != nil {
		return "", err
	}
	return engine, nil
}

func executeBrowserE0Positive(config browserE0Config, caseID string) error {
	testCase, err := browserE0PositiveCase(caseID)
	if err != nil {
		return err
	}
	harness, gateway, root, err := startBrowserE0Worker(config, testCase, caseID, browserE0Overrides{})
	if err != nil {
		return err
	}
	defer gateway.Close()
	if err := runBrowserE0Session(harness, config, testCase, caseID, root); err != nil {
		harness.Abort()
		return err
	}
	if err := harness.Close(); err != nil {
		return err
	}
	if got, want := gateway.Operations(), uint64(len(testCase.operations)); got != want {
		return fmt.Errorf("conformance Gateway accepted %d operations, want %d", got, want)
	}
	return nil
}

func browserE0PositiveCase(caseID string) (browserE0Case, error) {
	switch caseID {
	case "execute-browser-kzg-cold-document-flow":
		return browserE0Case{backend: "kzg", lifecycle: rq2wire.LifecycleBrowserCold, operations: []browserE0Operation{{name: "document-edit-cid-binding-submit", measured: true}}}, nil
	case "execute-browser-kzg-steady-operation-matrix":
		return browserE0Case{backend: "kzg", lifecycle: rq2wire.LifecycleBrowserSteady, operations: []browserE0Operation{
			{name: "map-replace", measured: false},
			{name: "document-edit-cid-binding-submit", measured: true},
			{name: "list-append", measured: true},
			{name: "list-replace", measured: true},
			{name: "map-insert", measured: true},
			{name: "map-replace", measured: true},
		}}, nil
	case "execute-browser-ipa-cold-map-replace":
		return browserE0Case{backend: "ipa", lifecycle: rq2wire.LifecycleBrowserCold, operations: []browserE0Operation{{name: "map-replace", measured: true}}}, nil
	case "execute-browser-kzg-short-session-continuity":
		return browserE0Case{backend: "kzg", lifecycle: rq2wire.LifecycleBrowserShort, sessionMutationCount: 2, operations: []browserE0Operation{
			{name: "document-edit-cid-binding-submit", measured: true},
			{name: "document-edit-cid-binding-submit", measured: true},
		}}, nil
	default:
		return browserE0Case{}, errors.New("unknown browser E0 positive case")
	}
}

type browserE0Overrides struct {
	browserSHA string
	wasmSHA    string
	engine     string
}

func startBrowserE0Worker(config browserE0Config, testCase browserE0Case, caseID string, overrides browserE0Overrides) (*rq2e0.Harness, *rq2e0.ConformanceGateway, cid.Cid, error) {
	tokenDigest := sha256.Sum256([]byte("malt-rq2-browser-e0\x00" + caseID))
	token := hex.EncodeToString(tokenDigest[:])
	gateway, root, err := rq2e0.NewConformanceGateway(config.fixture, testCase.backend, token)
	if err != nil {
		return nil, nil, cid.Undef, err
	}
	args := browserE0WorkerArguments(config, testCase, caseID, gateway.URL(), token, overrides)
	harness, err := rq2e0.StartHarness(config.timeout, func(input io.Reader, output io.Writer) error {
		return run(args, input, output, io.Discard)
	})
	if err != nil {
		gateway.Close()
		return nil, nil, cid.Undef, err
	}
	return harness, gateway, root, nil
}

func browserE0WorkerArguments(config browserE0Config, testCase browserE0Case, caseID, gatewayURL, token string, overrides browserE0Overrides) []string {
	browserSHA := config.browserPin.sha256
	if overrides.browserSHA != "" {
		browserSHA = overrides.browserSHA
	}
	wasmSHA := config.wasmPin.sha256
	if overrides.wasmSHA != "" {
		wasmSHA = overrides.wasmSHA
	}
	engine := config.browserEngine
	if overrides.engine != "" {
		engine = overrides.engine
	}
	return []string{
		"-gateway-base-url", gatewayURL, "-gateway-instance-token", token,
		"-fixture", config.fixturePath, "-worker-id", "e0-browser-" + shortBrowserE0ID(caseID), "-platform-id", "e0-browser",
		"-client-kind", rq2wire.ClientBrowserWASM, "-backend", testCase.backend, "-lifecycle", testCase.lifecycle,
		"-steady-warmup-operation", "map-replace", "-session-mutation-count", strconv.Itoa(testCase.sessionMutationCount),
		"-low-power-arm=" + strconv.FormatBool(config.machine.Descriptor.LowPowerARM()), "-request-timeout", config.timeout.String(),
		"-browser-path", config.browserPath, "-browser-engine", engine,
		"-browser-launcher-sha256", browserSHA, "-browser-launcher-bytes", strconv.FormatInt(config.browserPin.bytes, 10),
		"-wasm", config.wasmPath, "-wasm-sha256", wasmSHA, "-wasm-bytes", strconv.FormatInt(config.wasmPin.bytes, 10),
		"-wasm-exec", config.wasmExecPath, "-wasm-exec-sha256", config.wasmExecPin.sha256, "-wasm-exec-bytes", strconv.FormatInt(config.wasmExecPin.bytes, 10),
		"-machine-descriptor", config.machinePath, "-machine-descriptor-sha256", config.machinePin.sha256, "-machine-descriptor-bytes", strconv.FormatInt(config.machinePin.bytes, 10),
	}
}

func runBrowserE0Session(harness *rq2e0.Harness, config browserE0Config, testCase browserE0Case, caseID string, root cid.Cid) error {
	preflight := browserE0Request(config.fixture.FixtureID, testCase, caseID, "preflight", rq2wire.RecordPreflight, "", false, "")
	preflightRecord, err := browserE0Exchange(harness, preflight, true)
	if err != nil {
		return err
	}
	if preflightRecord.Runtime == nil || preflightRecord.Runtime.BrowserEngine != config.browserEngine || preflightRecord.Runtime.WASMSHA256 != config.wasmPin.sha256 {
		return fmt.Errorf("browser preflight did not bind pinned engine/WASM provenance: %+v", preflightRecord.Runtime)
	}
	start := browserE0Request(config.fixture.FixtureID, testCase, caseID, "session-start", rq2wire.RecordSessionStart, "", false, root.String())
	if _, err := browserE0Exchange(harness, start, true); err != nil {
		return err
	}
	accepted := root.String()
	for index, operation := range testCase.operations {
		request := browserE0Request(config.fixture.FixtureID, testCase, caseID, fmt.Sprintf("mutation-%02d", index), rq2wire.RecordMutation, operation.name, operation.measured, accepted)
		record, err := browserE0Exchange(harness, request, true)
		if err != nil {
			return err
		}
		if record.Mutation == nil || record.Mutation.PriorRoot != accepted || !record.Mutation.ReceiptAccepted || record.Mutation.ReceiptRoot != record.Mutation.CandidateRoot {
			return fmt.Errorf("browser mutation continuity/receipt evidence is incomplete: %+v", record.Mutation)
		}
		if err := validateBrowserE0LifecycleMetrics(config, testCase, index, record.Mutation.Metrics); err != nil {
			return fmt.Errorf("browser mutation %d lifecycle metrics: %w", index, err)
		}
		accepted = record.Mutation.ReceiptRoot
	}
	end := browserE0Request(config.fixture.FixtureID, testCase, caseID, "session-end", rq2wire.RecordSessionEnd, "", false, accepted)
	endRecord, err := browserE0Exchange(harness, end, true)
	if err != nil {
		return err
	}
	if endRecord.Session == nil || endRecord.Session.AcceptedRoot != accepted || !endRecord.Session.AuditPassed || endRecord.Session.ReceiptCount != uint64(len(testCase.operations)) {
		return fmt.Errorf("browser session-end audit is incomplete: %+v", endRecord.Session)
	}
	return nil
}

func validateBrowserE0LifecycleMetrics(config browserE0Config, testCase browserE0Case, index int, metrics rq2wire.MutationMetrics) error {
	if !metrics.MutationTotal.Applicable || metrics.MutationTotal.DurationNS == 0 {
		return errors.New("inclusive browser mutation total is absent")
	}
	if !metrics.JSWASMBoundary.Applicable || metrics.JSWASMBoundary.Count == 0 || metrics.JSWASMBoundary.Bytes == 0 {
		return errors.New("real JS/WASM boundary evidence is absent")
	}
	cold := testCase.lifecycle == rq2wire.LifecycleBrowserCold || testCase.lifecycle == rq2wire.LifecycleBrowserShort && index == 0
	phases := []rq2wire.PhaseMeasurement{metrics.WASMDownload, metrics.WASMInstantiate, metrics.ParameterLoad, metrics.FirstMutation}
	for _, phase := range phases {
		if phase.Applicable != cold {
			return fmt.Errorf("cold phase applicability=%t, want %t", phase.Applicable, cold)
		}
		if cold && (phase.Status != rq2wire.PhaseObserved || phase.Count == 0) {
			return errors.New("cold phase lacks a real observation")
		}
		if !cold && (phase.Status != rq2wire.PhaseNotApplicable || phase.DurationNS != 0 || phase.Bytes != 0 || phase.Count != 0) {
			return errors.New("steady/later short-session mutation contains cold-start evidence")
		}
	}
	if !cold {
		return nil
	}
	_, _, parameterBytes, ok := rq2wire.ParameterEvidence(testCase.backend)
	if !ok || metrics.WASMDownload.Bytes != uint64(config.wasmPin.bytes) || metrics.ParameterLoad.Bytes != parameterBytes || metrics.WASMInstantiate.DurationNS == 0 || metrics.FirstMutation.DurationNS == 0 {
		return fmt.Errorf("cold evidence does not bind exact WASM/parameter bytes and nonzero instantiate/first-mutation time: %+v", metrics)
	}
	return nil
}

func browserE0Exchange(harness *rq2e0.Harness, request rq2wire.WorkerRequest, requireSuccess bool) (rq2wire.WorkerRecord, error) {
	var record rq2wire.WorkerRecord
	if err := harness.Exchange(request, &record); err != nil {
		return rq2wire.WorkerRecord{}, err
	}
	if err := rq2wire.Bind(record, request); err != nil {
		return rq2wire.WorkerRecord{}, err
	}
	if err := record.Validate(); err != nil {
		return rq2wire.WorkerRecord{}, err
	}
	if requireSuccess && !record.Success {
		return rq2wire.WorkerRecord{}, fmt.Errorf("browser worker failed: %s: %s", record.FailureClass, record.Error)
	}
	return record, nil
}

func browserE0Request(fixtureID string, testCase browserE0Case, caseID, requestID, kind, operation string, measured bool, root string) rq2wire.WorkerRequest {
	return rq2wire.WorkerRequest{
		SchemaVersion: rq2wire.WorkerRequestSchema, WorkerID: "e0-browser-" + shortBrowserE0ID(caseID), RequestID: requestID,
		RecordKind: kind, SessionID: "session-" + shortBrowserE0ID(caseID), ClientKind: rq2wire.ClientBrowserWASM,
		PlatformID: "e0-browser", Backend: testCase.backend, Lifecycle: testCase.lifecycle, FixtureID: fixtureID,
		Operation: operation, Measured: measured, ExpectedAcceptedRoot: root,
	}
}

func executeBrowserE0Hostile(config browserE0Config, caseID string) error {
	switch caseID {
	case "reject-malformed-request":
		return browserE0MalformedRequest(config, caseID)
	case "reject-wasm-pin-substitution":
		return browserE0StartupFailure(config, caseID, browserE0Overrides{wasmSHA: substitutedBrowserE0Digest(config.wasmPin.sha256)})
	case "reject-steady-without-warmup":
		return browserE0SteadyWithoutWarmup(config, caseID)
	case "reject-backend-root-substitution":
		return browserE0BackendRootSubstitution(config, caseID)
	case "reject-browser-engine-pin-substitution":
		if err := browserE0EngineSubstitution(config, caseID); err != nil {
			return err
		}
		return browserE0BrowserPinSubstitution(config, caseID+"-launcher")
	case "reject-hung-gateway-timeout-and-late-commit":
		return browserE0HungGatewayTimeout(config, caseID)
	default:
		return errors.New("unknown browser E0 hostile case")
	}
}

func browserE0MalformedRequest(config browserE0Config, caseID string) error {
	testCase := browserE0Case{backend: "kzg", lifecycle: rq2wire.LifecycleBrowserCold}
	harness, gateway, _, err := startBrowserE0Worker(config, testCase, caseID, browserE0Overrides{})
	if err != nil {
		return err
	}
	defer gateway.Close()
	defer harness.Abort()
	if err := harness.WriteRaw([]byte(`{"schema_version":"malt-rq2-worker-request/v1","unknown":true}`)); err != nil {
		return err
	}
	if err := harness.WaitError(); err != nil {
		return err
	}
	if gateway.Operations() != 0 {
		return errors.New("malformed browser request reached the Gateway writer capability")
	}
	return nil
}

func browserE0StartupFailure(config browserE0Config, caseID string, overrides browserE0Overrides) error {
	testCase := browserE0Case{backend: "kzg", lifecycle: rq2wire.LifecycleBrowserCold}
	harness, gateway, _, err := startBrowserE0Worker(config, testCase, caseID, overrides)
	if err != nil {
		return err
	}
	defer gateway.Close()
	defer harness.Abort()
	request := browserE0Request(config.fixture.FixtureID, testCase, caseID, "preflight", rq2wire.RecordPreflight, "", false, "")
	var record rq2wire.WorkerRecord
	if err := harness.Exchange(request, &record); err == nil {
		return fmt.Errorf("artifact-pin substitution unexpectedly emitted a worker record: %+v", record)
	}
	if err := harness.WaitError(); err != nil {
		return err
	}
	if gateway.Operations() != 0 {
		return errors.New("artifact-pin substitution reached the Gateway writer capability")
	}
	return nil
}

func browserE0BrowserPinSubstitution(config browserE0Config, caseID string) error {
	testCase := browserE0Case{backend: "kzg", lifecycle: rq2wire.LifecycleBrowserCold}
	overrides := browserE0Overrides{browserSHA: substitutedBrowserE0Digest(config.browserPin.sha256)}
	harness, gateway, _, err := startBrowserE0Worker(config, testCase, caseID, overrides)
	if err != nil {
		return err
	}
	defer gateway.Close()
	defer harness.Abort()
	record, err := browserE0Exchange(harness, browserE0Request(config.fixture.FixtureID, testCase, caseID, "preflight", rq2wire.RecordPreflight, "", false, ""), false)
	if err != nil {
		return err
	}
	if record.Success || record.FailureClass != "capability_unavailable" || !strings.Contains(record.Error, "launcher unavailable") {
		return fmt.Errorf("browser-launcher pin substitution was not rejected: %+v", record)
	}
	if gateway.Operations() != 0 {
		return errors.New("browser-launcher pin substitution reached the Gateway writer capability")
	}
	return nil
}

func browserE0SteadyWithoutWarmup(config browserE0Config, caseID string) error {
	testCase := browserE0Case{backend: "kzg", lifecycle: rq2wire.LifecycleBrowserSteady, operations: []browserE0Operation{{name: "document-edit-cid-binding-submit", measured: true}}}
	harness, gateway, root, err := startBrowserE0Worker(config, testCase, caseID, browserE0Overrides{})
	if err != nil {
		return err
	}
	defer gateway.Close()
	defer harness.Abort()
	if _, err := browserE0Exchange(harness, browserE0Request(config.fixture.FixtureID, testCase, caseID, "preflight", rq2wire.RecordPreflight, "", false, ""), true); err != nil {
		return err
	}
	if _, err := browserE0Exchange(harness, browserE0Request(config.fixture.FixtureID, testCase, caseID, "session-start", rq2wire.RecordSessionStart, "", false, root.String()), true); err != nil {
		return err
	}
	record, err := browserE0Exchange(harness, browserE0Request(config.fixture.FixtureID, testCase, caseID, "measured-without-warmup", rq2wire.RecordMutation, "document-edit-cid-binding-submit", true, root.String()), false)
	if err != nil {
		return err
	}
	if record.Success || record.FailureClass != "lifecycle_invalid" {
		return fmt.Errorf("steady browser accepted a measured mutation without warmup: %+v", record)
	}
	if gateway.Operations() != 0 {
		return errors.New("steady-without-warmup reached the Gateway writer capability")
	}
	return nil
}

func browserE0BackendRootSubstitution(config browserE0Config, caseID string) error {
	testCase := browserE0Case{backend: "kzg", lifecycle: rq2wire.LifecycleBrowserCold}
	harness, gateway, _, err := startBrowserE0Worker(config, testCase, caseID, browserE0Overrides{})
	if err != nil {
		return err
	}
	defer gateway.Close()
	defer harness.Abort()
	if _, err := browserE0Exchange(harness, browserE0Request(config.fixture.FixtureID, testCase, caseID, "preflight", rq2wire.RecordPreflight, "", false, ""), true); err != nil {
		return err
	}
	wrongRoot, err := config.fixture.Root("ipa")
	if err != nil {
		return err
	}
	request := browserE0Request(config.fixture.FixtureID, testCase, caseID, "session-start-substituted-root", rq2wire.RecordSessionStart, "", false, wrongRoot.String())
	var record rq2wire.WorkerRecord
	if err := harness.Exchange(request, &record); err == nil {
		return fmt.Errorf("backend-root substitution unexpectedly emitted a record: %+v", record)
	}
	if err := harness.WaitError(); err != nil {
		return err
	}
	if gateway.Operations() != 0 {
		return errors.New("backend-root substitution reached the Gateway writer capability")
	}
	return nil
}

func browserE0EngineSubstitution(config browserE0Config, caseID string) error {
	testCase := browserE0Case{backend: "kzg", lifecycle: rq2wire.LifecycleBrowserCold}
	wrongEngine := "chromium-0.0"
	if config.browserEngine == wrongEngine {
		wrongEngine = "chrome-0.0"
	}
	harness, gateway, _, err := startBrowserE0Worker(config, testCase, caseID, browserE0Overrides{engine: wrongEngine})
	if err != nil {
		return err
	}
	defer gateway.Close()
	defer harness.Abort()
	record, err := browserE0Exchange(harness, browserE0Request(config.fixture.FixtureID, testCase, caseID, "preflight", rq2wire.RecordPreflight, "", false, ""), false)
	if err != nil {
		return err
	}
	if record.Success || record.FailureClass != "capability_unavailable" || !strings.Contains(record.Error, "registered") {
		return fmt.Errorf("browser engine substitution was not rejected: %+v", record)
	}
	if gateway.Operations() != 0 {
		return errors.New("browser-engine substitution reached the Gateway writer capability")
	}
	return nil
}

const (
	// The delay exceeds the force-termination bound. After the proxy reports
	// that the production request arrived, the test explicitly cancels the CDP
	// wait and then waits past this delay plus a grace interval. Forwarding is
	// therefore possible only if killing Chromium failed to cancel real work.
	browserE0HungGatewayDelay = 7 * time.Second
	browserE0RouteReachBound  = 5 * time.Second
	browserE0LateCommitGrace  = 500 * time.Millisecond
)

// browserE0DelayedGatewayProxy forwards the complete production HTTP surface
// until armed. Once armed, exactly the client-root route is held beyond the
// browser exchange deadline. Cancellation must come from terminating the real
// Chromium process; a delayed request is never forwarded after cancellation.
type browserE0DelayedGatewayProxy struct {
	server  *httptest.Server
	proxy   *httputil.ReverseProxy
	delay   time.Duration
	started chan time.Time

	mu       sync.Mutex
	armed    bool
	requests uint64
}

func newBrowserE0DelayedGatewayProxy(target string, delay time.Duration) (*browserE0DelayedGatewayProxy, error) {
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || delay <= 0 {
		return nil, errors.New("invalid browser E0 delayed Gateway proxy")
	}
	value := &browserE0DelayedGatewayProxy{
		proxy: httputil.NewSingleHostReverseProxy(parsed), delay: delay, started: make(chan time.Time, 1),
	}
	value.server = httptest.NewServer(value)
	return value, nil
}

func (p *browserE0DelayedGatewayProxy) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	p.mu.Lock()
	armed := p.armed && request.Method == http.MethodPost && request.URL.Path == "/v1/client-roots"
	if armed {
		p.requests++
	}
	p.mu.Unlock()
	if !armed {
		p.proxy.ServeHTTP(response, request)
		return
	}
	started := time.Now()
	select {
	case p.started <- started:
	default:
	}
	timer := time.NewTimer(p.delay)
	defer timer.Stop()
	select {
	case <-request.Context().Done():
		return
	case <-timer.C:
		if request.Context().Err() != nil {
			return
		}
		p.proxy.ServeHTTP(response, request)
	}
}

func (p *browserE0DelayedGatewayProxy) URL() string { return p.server.URL }

func (p *browserE0DelayedGatewayProxy) Arm() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.armed || p.requests != 0 {
		return errors.New("browser E0 delayed Gateway proxy was reused")
	}
	p.armed = true
	return nil
}

func (p *browserE0DelayedGatewayProxy) Requests() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.requests
}

func (p *browserE0DelayedGatewayProxy) Close() {
	if p != nil && p.server != nil {
		p.server.Close()
		p.server = nil
	}
}

func browserE0HungGatewayTimeout(config browserE0Config, caseID string) error {
	testCase := browserE0Case{backend: "kzg", lifecycle: rq2wire.LifecycleBrowserSteady}
	tokenDigest := sha256.Sum256([]byte("malt-rq2-browser-e0\x00" + caseID))
	token := hex.EncodeToString(tokenDigest[:])
	gateway, root, err := rq2e0.NewConformanceGateway(config.fixture, testCase.backend, token)
	if err != nil {
		return err
	}
	defer gateway.Close()
	proxy, err := newBrowserE0DelayedGatewayProxy(gateway.URL(), browserE0HungGatewayDelay)
	if err != nil {
		return err
	}
	defer proxy.Close()
	arguments := browserE0WorkerArguments(config, testCase, caseID, proxy.URL(), token, browserE0Overrides{})
	workerConfig, err := parseFlags(arguments, io.Discard)
	if err != nil {
		return err
	}
	worker, err := newBrowserWorker(workerConfig)
	if err != nil {
		return err
	}
	defer func() {
		if worker.browser != nil {
			_ = worker.browser.close()
		}
	}()

	exchange := func(ctx context.Context, request rq2wire.WorkerRequest) (rq2wire.WorkerRecord, error) {
		if err := worker.bindRequest(request); err != nil {
			return rq2wire.WorkerRecord{}, err
		}
		record := worker.exchange(ctx, request)
		if err := rq2wire.Bind(record, request); err != nil {
			return rq2wire.WorkerRecord{}, err
		}
		if err := record.Validate(); err != nil {
			return rq2wire.WorkerRecord{}, err
		}
		return record, nil
	}
	boundedExchange := func(request rq2wire.WorkerRequest) (rq2wire.WorkerRecord, error) {
		requestContext, cancel := context.WithTimeout(context.Background(), config.timeout)
		defer cancel()
		return exchange(requestContext, request)
	}
	preflight := browserE0Request(config.fixture.FixtureID, testCase, caseID, "preflight", rq2wire.RecordPreflight, "", false, "")
	preflightRecord, err := boundedExchange(preflight)
	if err != nil || !preflightRecord.Success {
		return fmt.Errorf("hung-Gateway preflight: record=%+v err=%w", preflightRecord, err)
	}
	start := browserE0Request(config.fixture.FixtureID, testCase, caseID, "session-start", rq2wire.RecordSessionStart, "", false, root.String())
	startRecord, err := boundedExchange(start)
	if err != nil || !startRecord.Success {
		return fmt.Errorf("hung-Gateway session start: record=%+v err=%w", startRecord, err)
	}
	warmup := browserE0Request(config.fixture.FixtureID, testCase, caseID, "warmup", rq2wire.RecordMutation, "map-replace", false, root.String())
	warmupRecord, err := boundedExchange(warmup)
	if err != nil || !warmupRecord.Success || warmupRecord.Mutation == nil {
		return fmt.Errorf("hung-Gateway steady warmup: record=%+v err=%w", warmupRecord, err)
	}
	baselineOperations := gateway.Operations()
	if baselineOperations != 1 {
		return fmt.Errorf("hung-Gateway warmup accepted %d operations, want 1", baselineOperations)
	}
	if err := proxy.Arm(); err != nil {
		return err
	}
	originalBrowser := worker.browser
	if originalBrowser == nil || originalBrowser.process == nil {
		return errors.New("hung-Gateway case has no live Chromium process")
	}
	request := browserE0Request(
		config.fixture.FixtureID, testCase, caseID, "hung-mutation", rq2wire.RecordMutation,
		"document-edit-cid-binding-submit", true, warmupRecord.Mutation.ReceiptRoot,
	)
	type exchangeResult struct {
		record rq2wire.WorkerRecord
		err    error
	}
	requestContext, cancel := context.WithTimeout(context.Background(), config.timeout)
	result := make(chan exchangeResult, 1)
	go func() {
		record, err := exchange(requestContext, request)
		result <- exchangeResult{record: record, err: err}
	}()
	var started time.Time
	select {
	case started = <-proxy.started:
		// The request is now held inside the delayed production-route proxy.
		// Trigger the same context-failure path as the per-request deadline,
		// without racing route arrival against a preselected wall deadline.
		cancel()
	case premature := <-result:
		cancel()
		return fmt.Errorf("hung-Gateway exchange completed before the production route was reached: record=%+v err=%w", premature.record, premature.err)
	case <-time.After(browserE0RouteReachBound):
		cancel()
		return errors.New("hung-Gateway mutation did not reach the production client-root route within the safety bound")
	}
	terminationStarted := time.Now()
	var completed exchangeResult
	select {
	case completed = <-result:
	case <-time.After(browserForceTerminationBound + browserE0LateCommitGrace):
		return errors.New("hung-Gateway exchange did not complete within the force-termination bound")
	}
	record, exchangeErr := completed.record, completed.err
	if exchangeErr != nil {
		return exchangeErr
	}
	if time.Since(terminationStarted) > browserForceTerminationBound+browserE0LateCommitGrace {
		return errors.New("hung-Gateway exchange exceeded the force-termination bound")
	}
	timeoutText := strings.ToLower(record.Error)
	if record.Success || record.FailureClass != "browser_execution" ||
		!strings.Contains(timeoutText, "deadline") && !strings.Contains(timeoutText, "timeout") && !strings.Contains(timeoutText, "canceled") {
		return fmt.Errorf("hung Gateway did not produce a browser deadline failure: %+v", record)
	}
	if strings.Contains(timeoutText, "force terminate chromium exceeded") {
		return fmt.Errorf("hung Gateway exceeded the strict force-termination bound: %+v", record)
	}
	if worker.browser != nil || worker.state != "poisoned" {
		return errors.New("timed-out browser worker retained a reusable Chromium/WASM session")
	}
	select {
	case <-originalBrowser.process.done:
	default:
		return errors.New("timed-out browser worker returned before Chromium terminated")
	}
	remaining := browserE0HungGatewayDelay + browserE0LateCommitGrace - time.Since(started)
	if remaining > 0 {
		timer := time.NewTimer(remaining)
		defer timer.Stop()
		<-timer.C
	}
	if proxy.Requests() != 1 || gateway.Operations() != baselineOperations {
		return fmt.Errorf("late browser work escaped termination: delayed requests=%d Gateway operations=%d, want 1/%d", proxy.Requests(), gateway.Operations(), baselineOperations)
	}
	return nil
}

func substitutedBrowserE0Digest(live string) string {
	value := strings.Repeat("0", 64)
	if live == value {
		return strings.Repeat("1", 64)
	}
	return value
}

func shortBrowserE0ID(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:6])
}

func browserE0ProfileDigest() string {
	contract, err := browserE0Profile.Contract()
	if err != nil {
		return ""
	}
	return contract.ProfileSHA256
}

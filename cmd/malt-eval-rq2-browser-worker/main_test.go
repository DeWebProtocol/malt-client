package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	clientcas "github.com/dewebprotocol/malt-client/internal/cas"
	"github.com/dewebprotocol/malt-client/internal/evaluation/machine"
	"github.com/dewebprotocol/malt-client/internal/evaluation/rq2fixture"
	"github.com/dewebprotocol/malt-client/internal/evaluation/rq2wire"
	clienttransport "github.com/dewebprotocol/malt-client/transport"
	"github.com/dewebprotocol/malt/auth/arcset"
	materializermemory "github.com/dewebprotocol/malt/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt/auth/commitment"
	"github.com/dewebprotocol/malt/auth/commitment/ipa"
	"github.com/dewebprotocol/malt/auth/commitment/kzg"
	listtree "github.com/dewebprotocol/malt/auth/semantic/list/tree"
	"github.com/dewebprotocol/malt/auth/semantic/mapping"
	mappingradix "github.com/dewebprotocol/malt/auth/semantic/mapping/radix"
	"github.com/dewebprotocol/malt/mutation"
	"github.com/dewebprotocol/malt/protocol"
	clientwriter "github.com/dewebprotocol/malt/sdk/writer"
	"github.com/dewebprotocol/malt/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

func TestParseBrowserEngineOutputUsesExactVersion(t *testing.T) {
	for input, expected := range map[string]string{
		"Chromium 150.0.7871.114 snap\n":        "chromium-150.0.7871.114",
		"Google Chrome 149.0.7654.2":            "chrome-149.0.7654.2",
		"Google Chrome for Testing 148.0.1.2\n": "chrome-148.0.1.2",
	} {
		actual, err := parseBrowserEngineOutput(input)
		if err != nil || actual != expected {
			t.Fatalf("parseBrowserEngineOutput(%q) = %q, %v; want %q", input, actual, err, expected)
		}
	}
	for _, invalid := range []string{"Chromium", "Firefox 150.0", "Chromium 150", "Chromium latest"} {
		if _, err := parseBrowserEngineOutput(invalid); err == nil {
			t.Fatalf("invalid version output %q was accepted", invalid)
		}
	}
}

func TestPoisonBrowserMakesSessionTerminal(t *testing.T) {
	worker := &browserWorker{browser: &browserSession{}, state: "active"}
	cause := fmt.Errorf("exchange timeout")
	if err := worker.poisonBrowser(cause); !strings.Contains(err.Error(), cause.Error()) {
		t.Fatalf("poison error = %v", err)
	}
	if worker.browser != nil || worker.state != "poisoned" {
		t.Fatalf("poisoned worker retained browser/state: %#v", worker)
	}
	request := rq2wire.WorkerRequest{RecordKind: rq2wire.RecordMutation}
	if err := worker.bindRequest(request); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("poisoned worker accepted another request: %v", err)
	}
}

func TestPoisonBrowserImmediatelyForceTerminatesProcess(t *testing.T) {
	command := exec.Command(os.Args[0], "-test.run=TestBrowserForceTerminationHelper")
	command.Env = append(os.Environ(), "MALT_BROWSER_FORCE_TERMINATION_HELPER=1")
	configureBrowserProcess(command)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	completion := &processCompletion{done: make(chan struct{})}
	go func() {
		completion.err = command.Wait()
		close(completion.done)
	}()
	worker := &browserWorker{browser: &browserSession{command: command, process: completion}, state: "active"}
	started := time.Now()
	err := worker.poisonBrowser(errors.New("forced test failure"))
	if elapsed := time.Since(started); elapsed > browserForceTerminationBound+time.Second {
		t.Fatalf("force termination took %s, bound %s", elapsed, browserForceTerminationBound)
	}
	if err == nil || !strings.Contains(err.Error(), "forced test failure") || strings.Contains(err.Error(), "exceeded") {
		t.Fatalf("force termination error = %v", err)
	}
	select {
	case <-completion.done:
	default:
		t.Fatal("force termination returned before the browser process was reaped")
	}
}

func TestBrowserForceTerminationHelper(t *testing.T) {
	if os.Getenv("MALT_BROWSER_FORCE_TERMINATION_HELPER") != "1" {
		return
	}
	for {
		time.Sleep(time.Hour)
	}
}

func TestParseFlagsRequiresPinnedBrowserAndWASMArtifacts(t *testing.T) {
	digest := strings.Repeat("a", 64)
	base := []string{
		"-gateway-base-url", "http://127.0.0.1:8080", "-gateway-instance-token", digest,
		"-fixture", "/tmp/fixture", "-worker-id", "worker", "-platform-id", "browser",
		"-client-kind", "browser-wasm", "-backend", "kzg", "-lifecycle", "browser-cold",
		"-steady-warmup-operation", "map-replace",
		"-low-power-arm=false", "-browser-path", "/usr/bin/chromium", "-browser-engine", "chromium-150.0.7871.114",
		"-browser-launcher-sha256", digest, "-browser-launcher-bytes", "1",
		"-wasm", "/tmp/writer.wasm", "-wasm-sha256", digest, "-wasm-bytes", "1",
		"-wasm-exec", "/tmp/wasm_exec.js", "-wasm-exec-sha256", digest, "-wasm-exec-bytes", "1",
		"-machine-descriptor", "/tmp/machine.json", "-machine-descriptor-sha256", digest, "-machine-descriptor-bytes", "1",
	}
	config, err := parseFlags(base, &bytes.Buffer{})
	if err != nil || config.clientKind != rq2wire.ClientBrowserWASM {
		t.Fatalf("parseFlags() = %#v, %v", config, err)
	}
	for index, value := range base {
		if value == "-wasm-sha256" {
			hostile := append([]string(nil), base...)
			hostile[index+1] = "latest"
			if _, err := parseFlags(hostile, &bytes.Buffer{}); err == nil {
				t.Fatal("non-pinned WASM artifact was accepted")
			}
			break
		}
	}
	short := append([]string(nil), base...)
	for index := range short {
		if short[index] == "browser-cold" {
			short[index] = "browser-short-session"
			break
		}
	}
	if _, err := parseFlags(short, &bytes.Buffer{}); err == nil {
		t.Fatal("short-session lifecycle without an exact mutation count was accepted")
	}
	short = append(short, "-session-mutation-count", "2")
	if config, err := parseFlags(short, &bytes.Buffer{}); err != nil || config.sessionMutationCount != 2 {
		t.Fatalf("typed short-session flags = %#v, %v", config, err)
	}
}

func TestMissingBrowserCapabilityFailsClosedAtPreflight(t *testing.T) {
	directory := t.TempDir()
	fixturePath := filepath.Join(directory, "fixture.bin")
	wasmPath := filepath.Join(directory, "writer.wasm")
	wasmExecPath := filepath.Join(directory, "wasm_exec.js")
	for path, value := range map[string][]byte{fixturePath: []byte("fixture"), wasmPath: []byte("wasm"), wasmExecPath: []byte("exec")} {
		if err := os.WriteFile(path, value, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	config := hostConfig{
		gatewayBaseURL: "http://127.0.0.1:1", gatewayToken: strings.Repeat("a", 64), fixturePath: fixturePath,
		workerID: "worker", platformID: "browser", clientKind: rq2wire.ClientBrowserWASM, backend: "kzg",
		lifecycle: rq2wire.LifecycleBrowserCold, requestTimeout: time.Second,
		steadyWarmup: "map-replace",
		browserPath:  "/definitely/missing/chromium", browserEngine: "chromium-150.0.7871.114",
		browserPin: artifactPin{path: "/definitely/missing/chromium", sha256: strings.Repeat("b", 64), bytes: 1, executable: true, allowSymlink: true, maxBytes: maxBrowserLauncherBytes},
		wasmPin:    testArtifactPin(t, wasmPath, maxWASMBytes), wasmExecPin: testArtifactPin(t, wasmExecPath, maxSupportBytes),
		machinePin: testMachinePin(t, false),
	}
	worker, err := newBrowserWorker(config)
	if err != nil {
		t.Fatal(err)
	}
	request := preflightRequest(config)
	record := worker.preflight(context.Background(), request)
	if record.Success || record.FailureClass != "capability_unavailable" || !strings.Contains(record.Error, "browser launcher unavailable") {
		t.Fatalf("missing browser preflight = %#v", record)
	}
	if err := record.Validate(); err != nil {
		t.Fatalf("failed preflight is not protocol-valid: %v", err)
	}
}

func TestDecodeWorkerRequestRejectsUnknownAndTrailingData(t *testing.T) {
	raw := `{"schema_version":"malt-rq2-worker-request/v1","worker_id":"worker","request_id":"preflight","record_kind":"preflight","session_id":"session","client_kind":"browser-wasm","platform_id":"browser","backend":"kzg","lifecycle":"browser-cold","fixture_id":"fixture","measured":false}`
	if _, err := decodeWorkerRequest([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	for _, hostile := range []string{
		strings.TrimSuffix(raw, "}") + `,"extra":true}`,
		strings.Replace(raw, `"worker_id":"worker"`, `"worker_id":"worker","worker_id":"other"`, 1),
		raw + `{}`,
	} {
		if _, err := decodeWorkerRequest([]byte(hostile)); err == nil {
			t.Fatalf("hostile JSON was accepted: %s", hostile)
		}
	}
}

func TestRunMissingBrowserEmitsOneStrictFailedPreflightLine(t *testing.T) {
	directory := t.TempDir()
	fixturePath := filepath.Join(directory, "fixture.bin")
	wasmPath := filepath.Join(directory, "writer.wasm")
	wasmExecPath := filepath.Join(directory, "wasm_exec.js")
	for path, value := range map[string][]byte{fixturePath: []byte("fixture"), wasmPath: []byte("wasm"), wasmExecPath: []byte("exec")} {
		if err := os.WriteFile(path, value, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	wasmPin := testArtifactPin(t, wasmPath, maxWASMBytes)
	wasmExecPin := testArtifactPin(t, wasmExecPath, maxSupportBytes)
	machinePin := testMachinePin(t, false)
	token := strings.Repeat("a", 64)
	args := []string{
		"-gateway-base-url", "http://127.0.0.1:1", "-gateway-instance-token", token,
		"-fixture", fixturePath, "-worker-id", "worker", "-platform-id", "browser",
		"-client-kind", "browser-wasm", "-backend", "kzg", "-lifecycle", "browser-cold", "-low-power-arm=false",
		"-steady-warmup-operation", "map-replace", "-browser-path", "/definitely/missing/chromium",
		"-browser-engine", "chromium-150.0.7871.114", "-browser-launcher-sha256", strings.Repeat("b", 64), "-browser-launcher-bytes", "1",
		"-wasm", wasmPath, "-wasm-sha256", wasmPin.sha256, "-wasm-bytes", strconv.FormatInt(wasmPin.bytes, 10),
		"-wasm-exec", wasmExecPath, "-wasm-exec-sha256", wasmExecPin.sha256, "-wasm-exec-bytes", strconv.FormatInt(wasmExecPin.bytes, 10),
		"-machine-descriptor", machinePin.path, "-machine-descriptor-sha256", machinePin.sha256, "-machine-descriptor-bytes", strconv.FormatInt(machinePin.bytes, 10),
	}
	config, err := parseFlags(args, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	requestJSON, _ := json.Marshal(preflightRequest(config))
	var stdout bytes.Buffer
	err = run(args, bytes.NewReader(append(requestJSON, '\n')), &stdout, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "closed before session-end") {
		t.Fatalf("run error = %v", err)
	}
	if bytes.Count(stdout.Bytes(), []byte{'\n'}) != 1 {
		t.Fatalf("stdout is not one strict JSONL record: %q", stdout.String())
	}
	var record rq2wire.WorkerRecord
	if err := strictJSON(bytes.TrimSpace(stdout.Bytes()), &record); err != nil {
		t.Fatal(err)
	}
	if record.Success || record.FailureClass != "capability_unavailable" {
		t.Fatalf("missing-browser stdout = %#v", record)
	}
}

func TestRealChromiumExecutesColdAndSteadyBrowserOperations(t *testing.T) {
	if testing.Short() || runtime.GOOS != "linux" {
		t.Skip("real Chromium/WASM integration requires a non-short Linux test")
	}
	browserPath, err := exec.LookPath("chromium")
	if err != nil {
		browserPath, err = exec.LookPath("google-chrome")
	}
	if err != nil {
		t.Skip("Chromium-family browser is not installed")
	}
	versionCommand := exec.Command(browserPath, "--version")
	versionOutput, err := versionCommand.CombinedOutput()
	if err != nil {
		t.Skipf("browser version probe unavailable: %v", err)
	}
	engine, err := parseBrowserEngineOutput(string(versionOutput))
	if err != nil {
		t.Skipf("unsupported installed browser: %v", err)
	}
	directory := t.TempDir()
	wasmPath := filepath.Join(directory, "writer.wasm")
	moduleRoot := filepath.Clean(filepath.Join("..", ".."))
	build := exec.Command("go", "build", "-buildvcs=false", "-o", wasmPath, "./cmd/malt-eval-rq2-browser-wasm")
	build.Dir = moduleRoot
	build.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm", "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build real Go/WASM writer: %v\n%s", err, output)
	}
	wasmExecPath := filepath.Join(runtime.GOROOT(), "lib", "wasm", "wasm_exec.js")
	if _, err := os.Stat(wasmExecPath); err != nil {
		t.Skipf("matching wasm_exec.js is unavailable: %v", err)
	}
	browserPin := testArtifactPinAllowSymlink(t, browserPath, maxBrowserLauncherBytes, true)
	wasmPin := testArtifactPin(t, wasmPath, maxWASMBytes)
	wasmExecPin := testArtifactPin(t, wasmExecPath, maxSupportBytes)
	testCases := []struct {
		name                 string
		backend              string
		lifecycle            string
		sessionMutationCount int
		operations           []testBrowserOperation
	}{
		{name: "kzg-cold", backend: "kzg", lifecycle: rq2wire.LifecycleBrowserCold, operations: []testBrowserOperation{{name: "document-edit-cid-binding-submit", measured: true}}},
		{name: "kzg-steady", backend: "kzg", lifecycle: rq2wire.LifecycleBrowserSteady, operations: []testBrowserOperation{
			{name: "map-replace", measured: false},
			{name: "document-edit-cid-binding-submit", measured: true}, {name: "list-append", measured: true},
			{name: "list-replace", measured: true}, {name: "map-insert", measured: true}, {name: "map-replace", measured: true},
		}},
		{name: "ipa-cold", backend: "ipa", lifecycle: rq2wire.LifecycleBrowserCold, operations: []testBrowserOperation{{name: "map-replace", measured: true}}},
		{name: "kzg-short-n2", backend: "kzg", lifecycle: rq2wire.LifecycleBrowserShort, sessionMutationCount: 2, operations: []testBrowserOperation{
			{name: "document-edit-cid-binding-submit", measured: true}, {name: "document-edit-cid-binding-submit", measured: true},
		}},
		{name: "kzg-short-baseline-n2", backend: "kzg", lifecycle: rq2wire.LifecycleBrowserSteady, sessionMutationCount: 2, operations: []testBrowserOperation{
			{name: "map-replace", measured: false},
			{name: "document-edit-cid-binding-submit", measured: true}, {name: "document-edit-cid-binding-submit", measured: true},
		}},
	}
	for caseIndex, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			token := strings.Repeat(string(rune('a'+caseIndex)), 64)
			gatewayFixture, initialRoot, fixtureBytes := newTestBrowserGateway(t, token, testCase.backend)
			fixturePath := filepath.Join(t.TempDir(), "fixture.bin")
			if err := os.WriteFile(fixturePath, fixtureBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			gateway := httptest.NewServer(gatewayFixture)
			defer gateway.Close()
			config := hostConfig{
				gatewayBaseURL: gateway.URL, gatewayToken: token, fixturePath: fixturePath,
				workerID: "worker-" + testCase.name, platformID: "browser", clientKind: rq2wire.ClientBrowserWASM, backend: testCase.backend,
				lifecycle: testCase.lifecycle, sessionMutationCount: testCase.sessionMutationCount, requestTimeout: 2 * time.Minute,
				steadyWarmup: "map-replace",
				browserPath:  browserPath, browserEngine: engine, browserPin: browserPin,
				wasmPin: wasmPin, wasmExecPin: wasmExecPin,
				machinePin: testMachinePin(t, false),
			}
			worker, err := newBrowserWorker(config)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			exchange := func(request rq2wire.WorkerRequest) rq2wire.WorkerRecord {
				t.Helper()
				if err := worker.bindRequest(request); err != nil {
					t.Fatal(err)
				}
				record := worker.exchange(ctx, request)
				if err := rq2wire.Bind(record, request); err != nil {
					t.Fatal(err)
				}
				if err := record.Validate(); err != nil {
					t.Fatalf("invalid real-browser record: %v\n%#v", err, record)
				}
				if !record.Success {
					t.Fatalf("real browser request %s failed: %s: %s", request.RequestID, record.FailureClass, record.Error)
				}
				return record
			}
			preflight := exchange(preflightRequest(config))
			if preflight.Runtime == nil || preflight.Runtime.BrowserEngine != engine || preflight.Runtime.WASMSHA256 != wasmPin.sha256 {
				t.Fatalf("real browser runtime provenance = %#v", preflight.Runtime)
			}
			start := requestFor(config, rq2wire.RecordSessionStart, "session-start", "", false, initialRoot.String())
			exchange(start)
			acceptedRoot := initialRoot.String()
			for index, operation := range testCase.operations {
				request := requestFor(config, rq2wire.RecordMutation, fmt.Sprintf("mutation-%03d", index), operation.name, operation.measured, acceptedRoot)
				record := exchange(request)
				acceptedRoot = record.Mutation.ReceiptRoot
				metrics := record.Mutation.Metrics
				if !metrics.CPUTotal.Applicable || !metrics.PeakMemory.Applicable || metrics.PeakMemory.Bytes == 0 ||
					!metrics.JSWASMBoundary.Applicable || metrics.JSWASMBoundary.Bytes == 0 {
					t.Fatalf("real browser resource/boundary metrics are incomplete: %#v", metrics)
				}
				cold := testCase.lifecycle == rq2wire.LifecycleBrowserCold || testCase.lifecycle == rq2wire.LifecycleBrowserShort && index == 0
				if metrics.WASMDownload.Applicable != cold || metrics.WASMInstantiate.Applicable != cold || metrics.ParameterLoad.Applicable != cold || metrics.FirstMutation.Applicable != cold {
					t.Fatalf("cold/steady phase classification is wrong: %#v", metrics)
				}
			}
			exchange(requestFor(config, rq2wire.RecordSessionEnd, "session-end", "", false, acceptedRoot))
			if err := worker.browser.close(); err != nil {
				t.Fatalf("close real browser: %v", err)
			}
		})
	}
}

type testBrowserOperation struct {
	name     string
	measured bool
}

func requestFor(config hostConfig, kind, requestID, operation string, measured bool, root string) rq2wire.WorkerRequest {
	return rq2wire.WorkerRequest{
		SchemaVersion: rq2wire.WorkerRequestSchema, WorkerID: config.workerID, RequestID: requestID,
		RecordKind: kind, SessionID: "session", ClientKind: rq2wire.ClientBrowserWASM, PlatformID: config.platformID,
		Backend: config.backend, Lifecycle: config.lifecycle, FixtureID: "fixture", Operation: operation,
		Measured: measured, ExpectedAcceptedRoot: root,
	}
}

type testBrowserGateway struct {
	mu      sync.Mutex
	token   string
	views   map[string]mutation.UpdateView
	runtime *clientwriter.Runtime
}

func newTestBrowserGateway(t *testing.T, token, backend string) (*testBrowserGateway, cid.Cid, []byte) {
	t.Helper()
	var scheme commitment.IndexCommitment
	var err error
	if backend == "kzg" {
		scheme, err = kzg.NewScheme()
	} else {
		scheme, err = ipa.NewScheme()
	}
	if err != nil {
		t.Fatal(err)
	}
	view := testBrowserUpdateView(t, scheme)
	writerRuntime, err := clientwriter.NewRuntime(
		materializermemory.New(true),
		map[maltcid.BackendKind]commitment.IndexCommitment{maltcid.BackendKind(backend): scheme},
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture := testBrowserSourceFixture(t, backend, view.BaseRoot)
	return &testBrowserGateway{token: token, views: map[string]mutation.UpdateView{view.BaseRoot.String(): view}, runtime: writerRuntime}, view.BaseRoot, fixture
}

func (g *testBrowserGateway) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "private, no-store")
	switch {
	case request.URL.Path == "/healthz" && request.Method == http.MethodGet:
		_ = json.NewEncoder(response).Encode(map[string]any{"status": "ok", "evaluation_instance_token": g.token})
	case strings.HasPrefix(request.URL.Path, "/v1/roots/") && strings.HasSuffix(request.URL.Path, "/update-view") && request.Method == http.MethodGet:
		root := strings.TrimSuffix(strings.TrimPrefix(request.URL.Path, "/v1/roots/"), "/update-view")
		g.mu.Lock()
		view, exists := g.views[root]
		g.mu.Unlock()
		if !exists {
			http.Error(response, "unknown root", http.StatusNotFound)
			return
		}
		wire, err := protocol.NewUpdateView(view)
		if err != nil {
			http.Error(response, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(response).Encode(wire)
	case request.URL.Path == "/v1/cas/batch" && request.Method == http.MethodPost:
		g.handleCASBatch(response, request)
	case request.URL.Path == "/v1/client-roots" && request.Method == http.MethodPost:
		g.handleClientRoot(response, request)
	default:
		http.NotFound(response, request)
	}
}

func (g *testBrowserGateway) handleCASBatch(response http.ResponseWriter, request *http.Request) {
	var submitted struct {
		Profile string `json:"profile"`
		Blocks  []struct {
			Codec uint64 `json:"codec"`
			Data  []byte `json:"data"`
		} `json:"blocks"`
	}
	if err := json.NewDecoder(request.Body).Decode(&submitted); err != nil || submitted.Profile != clienttransport.CASPutBatchProfile || len(submitted.Blocks) != 1 {
		http.Error(response, "invalid CAS batch", http.StatusBadRequest)
		return
	}
	results := make([]map[string]string, len(submitted.Blocks))
	for index, block := range submitted.Blocks {
		key, err := clientcas.CIDForBlock(clientcas.Block{Codec: block.Codec, Data: block.Data})
		if err != nil {
			http.Error(response, err.Error(), http.StatusBadRequest)
			return
		}
		results[index] = map[string]string{"cid": key.String(), "status": "stored"}
	}
	response.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(response).Encode(map[string]any{"profile": clienttransport.CASPutBatchProfile, "results": results})
}

func (g *testBrowserGateway) handleClientRoot(response http.ResponseWriter, request *http.Request) {
	var submitted protocol.ClientRootBundle
	if err := json.NewDecoder(request.Body).Decode(&submitted); err != nil {
		http.Error(response, err.Error(), http.StatusBadRequest)
		return
	}
	bundle, err := submitted.Core()
	if err != nil {
		http.Error(response, err.Error(), http.StatusBadRequest)
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	view, exists := g.views[bundle.View.BaseRoot.String()]
	if !exists || !view.BaseRoot.Equals(bundle.View.BaseRoot) {
		http.Error(response, "stale root", http.StatusConflict)
		return
	}
	verified, err := g.runtime.VerifyUpdateView(request.Context(), bundle.View)
	if err != nil {
		http.Error(response, err.Error(), http.StatusBadRequest)
		return
	}
	recomputed, err := g.runtime.ComputeBundle(request.Context(), bundle.OperationID, verified, bundle.Intent)
	if err != nil || !recomputed.Bundle.Candidate.Equals(bundle.Candidate) {
		http.Error(response, "client-root recomputation mismatch", http.StatusBadRequest)
		return
	}
	recomputedDigest, err := recomputed.Bundle.Digest()
	if err != nil {
		http.Error(response, err.Error(), http.StatusInternalServerError)
		return
	}
	bundleDigest, err := bundle.Digest()
	if err != nil || recomputedDigest != bundleDigest {
		http.Error(response, "client-root bundle digest mismatch", http.StatusBadRequest)
		return
	}
	g.views[bundle.Candidate.String()] = recomputed.NextView
	receipt := mutation.MaterializationReceipt{
		Profile: mutation.MaterializationReceiptProfile, OperationID: bundle.OperationID,
		BaseRoot: bundle.View.BaseRoot, Candidate: bundle.Candidate, BundleDigest: bundleDigest,
		DurableBoundary: "gateway-client-root-atomic-v1",
	}
	wireReceipt, err := protocol.NewMaterializationReceipt(receipt, bundle)
	if err != nil {
		http.Error(response, err.Error(), http.StatusInternalServerError)
		return
	}
	for name, value := range map[string]string{
		"X-Malt-Client-Root-Old-State-Validation-Nanos": "1",
		"X-Malt-Client-Root-Gateway-Replay-Nanos":       "1",
		"X-Malt-Client-Root-Persist-Nanos":              "1",
		"X-Malt-Client-Root-Receipt-Nanos":              "1",
		"X-Malt-Client-Root-Durable-Boundary":           receipt.DurableBoundary,
		"X-Malt-Client-Root-Idempotent":                 "false",
		"Server-Timing":                                 "old-state-validation;dur=0.000001, gateway-replay;dur=0.000001, persist;dur=0.000001, receipt;dur=0.000001",
	} {
		response.Header().Set(name, value)
	}
	accounting, _ := json.Marshal(map[string]any{
		"profile": "gateway.client-root-write-accounting/v1", "available": false,
		"unavailable_reason": "integration-test", "byte_method": "logical-kv-key-plus-value-bytes/v1",
		"categories": []any{},
	})
	response.Header().Set("X-Malt-Client-Root-Write-Accounting", base64.RawURLEncoding.EncodeToString(accounting))
	_ = json.NewEncoder(response).Encode(wireReceipt)
}

func testBrowserUpdateView(t *testing.T, scheme commitment.IndexCommitment) mutation.UpdateView {
	t.Helper()
	ctx := context.Background()
	document := testRawCID(t, []byte("document"))
	chunkABytes := make([]byte, 32)
	chunkBBytes := make([]byte, 32)
	copy(chunkABytes, "chunk-a")
	copy(chunkBBytes, "chunk-b")
	chunkA := testRawCID(t, chunkABytes)
	chunkB := testRawCID(t, chunkBBytes)
	store := materializermemory.New(true)
	lister, err := listtree.NewList(scheme, store)
	if err != nil {
		t.Fatal(err)
	}
	listRoot, err := lister.CommitFixed(ctx, "list", []cid.Cid{chunkA, chunkB}, 32, 64)
	if err != nil {
		t.Fatal(err)
	}
	mapper, err := mappingradix.NewMap(scheme, store)
	if err != nil {
		t.Fatal(err)
	}
	root, err := mapper.Commit(ctx, "root", mapping.NewViewFrom(map[string]cid.Cid{"document.txt": document, "list.bin": listRoot}))
	if err != nil {
		t.Fatal(err)
	}
	documentCoordinate, _ := arcset.NewMapCoordinate("document.txt")
	listCoordinate, _ := arcset.NewMapCoordinate("list.bin")
	rootEntries, err := arcset.NewCanonicalArcSet(arcset.KindMap, []arcset.ArcEntry{
		{Coordinate: documentCoordinate, Target: arcset.NewCASTarget(document)},
		{Coordinate: listCoordinate, Target: arcset.NewListTarget(listRoot)},
	})
	if err != nil {
		t.Fatal(err)
	}
	listEntries, err := arcset.NewCanonicalArcSet(arcset.KindList, []arcset.ArcEntry{
		{Coordinate: arcset.NewListCoordinateUint64(0), Target: arcset.NewCASTarget(chunkA)},
		{Coordinate: arcset.NewListCoordinateUint64(1), Target: arcset.NewCASTarget(chunkB)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return mutation.UpdateView{
		Profile: mutation.UpdateViewProfile, StateProfile: mutation.StatefulCompleteVectorsProfile,
		BaseRoot: root, Bounds: mutation.UpdateViewBounds{MaxObjects: 8, MaxTotalEntries: 64, MaxDepth: 8},
		Objects: []mutation.UpdateObject{
			{ObjectID: "list", Root: listRoot, Kind: arcset.KindList, Entries: listEntries, Commit: mutation.CommitDescriptor{FixedList: &mutation.FixedListCommit{ChunkSize: 32, TotalSize: 64}}},
			{ObjectID: "root", Root: root, Kind: arcset.KindMap, Entries: rootEntries},
		},
	}
}

func testBrowserSourceFixture(t *testing.T, backend string, root cid.Cid) []byte {
	t.Helper()
	document := []byte("document")
	chunkA := make([]byte, 32)
	chunkB := make([]byte, 32)
	copy(chunkA, "chunk-a")
	copy(chunkB, "chunk-b")
	index := uint64(0)
	seed := sha256.Sum256([]byte("browser source fixture seed"))
	value := rq2fixture.Fixture{
		SchemaVersion: rq2fixture.SchemaVersion, FixtureID: "fixture", MutationSeedSHA256: hex.EncodeToString(seed[:]),
		InitialRoots: []rq2fixture.RootBinding{{Backend: backend, CID: root.String()}},
		DirectFiles:  []rq2fixture.DirectFile{{Path: "document.txt", Coordinate: "document.txt", Bytes: document, CID: testRawCID(t, document).String()}},
		ListFiles: []rq2fixture.ListFile{{
			Path: "list.bin", Coordinate: "list.bin", ChunkSize: 32, TotalSize: 64,
			Chunks: []rq2fixture.ListChunk{{Index: 0, Bytes: chunkA, CID: testRawCID(t, chunkA).String()}, {Index: 1, Bytes: chunkB, CID: testRawCID(t, chunkB).String()}},
		}},
		Operations: []rq2fixture.Operation{
			{Name: "document-edit-cid-binding-submit", Kind: rq2fixture.KindDocumentEdit, SourcePath: "document.txt", SourceCoordinate: "document.txt", PayloadBytes: 32},
			{Name: "map-replace", Kind: rq2fixture.KindDirectReplace, SourcePath: "document.txt", SourceCoordinate: "document.txt", PayloadBytes: 16},
			{Name: "map-insert", Kind: rq2fixture.KindDirectInsert, DestinationPath: "inserted.txt", DestinationCoordinate: "inserted.txt", PayloadBytes: 16},
			{Name: "list-append", Kind: rq2fixture.KindListAppend, SourcePath: "list.bin", SourceCoordinate: "list.bin", PayloadBytes: 32},
			{Name: "list-replace", Kind: rq2fixture.KindListReplace, SourcePath: "list.bin", SourceCoordinate: "list.bin", PayloadBytes: 32, ListIndex: &index},
		},
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rq2fixture.Decode(raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

func testRawCID(t *testing.T, value []byte) cid.Cid {
	t.Helper()
	key, err := clientcas.CIDForBlock(clientcas.Block{Codec: cid.Raw, Data: value})
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func preflightRequest(config hostConfig) rq2wire.WorkerRequest {
	return rq2wire.WorkerRequest{
		SchemaVersion: rq2wire.WorkerRequestSchema, WorkerID: config.workerID, RequestID: "preflight",
		RecordKind: rq2wire.RecordPreflight, SessionID: "session", ClientKind: rq2wire.ClientBrowserWASM,
		PlatformID: config.platformID, Backend: config.backend, Lifecycle: config.lifecycle, FixtureID: "fixture",
	}
}

func testArtifactPin(t *testing.T, path string, maximum int64) artifactPin {
	t.Helper()
	return testArtifactPinAllowSymlink(t, path, maximum, false)
}

func testMachinePin(t *testing.T, lowPower bool) artifactPin {
	t.Helper()
	identity, err := machine.Probe()
	if err != nil {
		t.Fatal(err)
	}
	classification := machine.ClassGeneral
	if lowPower {
		classification = machine.ClassLowPower
	}
	descriptor, err := machine.NewDescriptor("test-machine", classification, "test-suite:registered-platform-evidence", identity)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "machine.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	return artifactPin{path: path, sha256: hex.EncodeToString(digest[:]), bytes: int64(len(raw)), maxBytes: machine.MaxDescriptorBytes}
}

func testArtifactPinAllowSymlink(t *testing.T, path string, maximum int64, executable bool) artifactPin {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	return artifactPin{
		path: path, sha256: hex.EncodeToString(digest[:]), bytes: int64(len(data)), executable: executable,
		allowSymlink: executable, maxBytes: maximum,
	}
}

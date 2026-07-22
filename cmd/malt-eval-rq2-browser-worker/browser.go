package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/dewebprotocol/malt-client/internal/evaluation/machine"
	"github.com/dewebprotocol/malt-client/internal/evaluation/rq2wire"
)

const (
	maxBrowserLogBytes           = 64 << 10
	browserForceTerminationBound = 2 * time.Second
)

var (
	devtoolsPattern = regexp.MustCompile(`DevTools listening on (ws://[^[:space:]]+)`)
	versionPattern  = regexp.MustCompile(`^(Chromium|Google Chrome(?: for Testing)?) ([0-9]+(?:\.[0-9]+){1,3})(?:[[:space:]].*)?$`)
)

type browserLaunchConfig struct {
	path       string
	arguments  []string
	engine     string
	timeout    time.Duration
	gatewayURL string
	token      string
	backend    string
	wasmSHA256 string
}

type coldStartMetrics struct {
	WASMDownloadNS    uint64
	WASMDownloadBytes uint64
	WASMInstantiateNS uint64
	ParameterLoadNS   uint64
	ParameterBytes    uint64
	ParameterProfile  string
	ParameterSHA256   string
}

type browserCall struct {
	RecordJSON string `json:"record_json"`
	CallNS     uint64 `json:"call_ns"`
	BoundaryNS uint64 `json:"boundary_ns"`
	HeapBytes  uint64 `json:"heap_bytes"`
	WASMMemory uint64 `json:"wasm_memory_bytes"`
}

type browserStatus struct {
	Phase        string `json:"phase"`
	Error        string `json:"error,omitempty"`
	WASMSHA256   string `json:"wasm_sha256,omitempty"`
	DownloadNS   uint64 `json:"download_ns,omitempty"`
	DownloadByte uint64 `json:"download_bytes,omitempty"`
	Instantiate  uint64 `json:"instantiate_ns,omitempty"`
	Initialize   *struct {
		ParameterLoadNS    uint64 `json:"parameter_load_ns"`
		ParameterLoadBytes uint64 `json:"parameter_load_bytes"`
		ParameterProfile   string `json:"parameter_profile"`
		ParameterSHA256    string `json:"parameter_sha256"`
		FixtureBytes       uint64 `json:"fixture_bytes"`
		FixtureSHA256      string `json:"fixture_sha256"`
	} `json:"initialize,omitempty"`
}

type browserSession struct {
	command   *exec.Cmd
	process   *processCompletion
	stderr    *boundedLog
	cdp       *cdpClient
	server    *http.Server
	listener  net.Listener
	profile   string
	engine    string
	cold      coldStartMetrics
	processID int
	closeOnce sync.Once
	closeErr  error
}

type processCompletion struct {
	done chan struct{}
	err  error
}

func detectBrowserEngine(ctx context.Context, config browserLaunchConfig) (string, error) {
	arguments := append([]string(nil), config.arguments...)
	arguments = append(arguments, "--version")
	command := exec.CommandContext(ctx, config.path, arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("run browser version probe: %w: %s", err, boundedText(output, 1024))
	}
	engine, err := parseBrowserEngineOutput(string(output))
	if err != nil {
		return "", err
	}
	if config.engine != engine {
		return "", fmt.Errorf("browser engine/version is %q, registered %q", engine, config.engine)
	}
	return engine, nil
}

func parseBrowserEngineOutput(output string) (string, error) {
	line := strings.TrimSpace(output)
	matches := versionPattern.FindStringSubmatch(line)
	if len(matches) != 3 {
		return "", fmt.Errorf("unsupported browser version output %q", boundedText([]byte(output), 1024))
	}
	prefix := "chromium-"
	if strings.HasPrefix(matches[1], "Google Chrome") {
		prefix = "chrome-"
	}
	return prefix + matches[2], nil
}

func startBrowser(ctx context.Context, config browserLaunchConfig, fixture, wasm, wasmExec []byte) (*browserSession, error) {
	// The version subprocess is part of browser startup and must obey the same
	// bound as DevTools discovery and WASM initialization. The Chromium session
	// itself remains explicitly owned and closed by browserSession.
	startupContext, cancel := context.WithTimeout(ctx, config.timeout)
	defer cancel()
	engine, err := detectBrowserEngine(startupContext, config)
	if err != nil {
		return nil, err
	}
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, err
	}
	prefix := "/rq2-" + hex.EncodeToString(tokenBytes)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	failed := true
	defer func() {
		if failed {
			_ = listener.Close()
		}
	}()
	baseURL := "http://" + listener.Addr().String() + prefix
	page, err := browserPage(browserPageConfig{
		GatewayURL: baseURL + "/gateway", FixtureURL: baseURL + "/fixture", WASMURL: baseURL + "/writer.wasm",
		WASMSHA256: config.wasmSHA256, GatewayToken: config.token, Backend: config.backend,
	})
	if err != nil {
		return nil, err
	}
	target, err := url.Parse(config.gatewayURL)
	if err != nil {
		return nil, err
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorLog = log.New(io.Discard, "", 0)
	proxy.ErrorHandler = func(response http.ResponseWriter, _ *http.Request, cause error) {
		response.Header().Set("Cache-Control", "no-store")
		http.Error(response, "Gateway proxy failed: "+cause.Error(), http.StatusBadGateway)
	}
	mux := http.NewServeMux()
	serveBytes := func(contentType string, data []byte) http.HandlerFunc {
		return func(response http.ResponseWriter, request *http.Request) {
			if request.Method != http.MethodGet {
				response.Header().Set("Allow", http.MethodGet)
				http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			response.Header().Set("Cache-Control", "no-store, max-age=0")
			response.Header().Set("Content-Type", contentType)
			response.Header().Set("X-Content-Type-Options", "nosniff")
			_, _ = response.Write(data)
		}
	}
	mux.HandleFunc(prefix+"/", serveBytes("text/html; charset=utf-8", page))
	mux.HandleFunc(prefix+"/wasm_exec.js", serveBytes("text/javascript; charset=utf-8", wasmExec))
	mux.HandleFunc(prefix+"/writer.wasm", serveBytes("application/wasm", wasm))
	mux.HandleFunc(prefix+"/fixture", serveBytes("application/octet-stream", fixture))
	mux.Handle(prefix+"/gateway/", http.StripPrefix(prefix+"/gateway", proxy))
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.Serve(listener)
	}()

	profile, err := os.MkdirTemp("", "malt-rq2-browser-profile-")
	if err != nil {
		_ = server.Close()
		return nil, err
	}
	arguments := append([]string(nil), config.arguments...)
	arguments = append(arguments,
		"--headless=new", "--no-sandbox", "--disable-gpu", "--disable-background-networking",
		"--disable-component-update", "--disable-default-apps", "--disable-extensions", "--disable-sync",
		"--enable-precise-memory-info", "--metrics-recording-only", "--no-first-run", "--password-store=basic",
		"--remote-allow-origins=*", "--remote-debugging-port=0", "--user-data-dir="+profile,
		baseURL+"/",
	)
	command := exec.CommandContext(ctx, config.path, arguments...)
	configureBrowserProcess(command)
	command.Stdout = io.Discard
	stderr := &boundedLog{limit: maxBrowserLogBytes}
	stderrPipe, err := command.StderrPipe()
	if err != nil {
		_ = server.Close()
		_ = os.RemoveAll(profile)
		return nil, err
	}
	if err := command.Start(); err != nil {
		_ = server.Close()
		_ = os.RemoveAll(profile)
		return nil, err
	}
	process := &processCompletion{done: make(chan struct{})}
	go func() {
		process.err = command.Wait()
		close(process.done)
	}()
	devtoolsURL := make(chan string, 1)
	go scanBrowserLog(stderrPipe, stderr, devtoolsURL)
	session := &browserSession{
		command: command, process: process, stderr: stderr, server: server, listener: listener, profile: profile,
		engine: engine, processID: command.Process.Pid,
	}
	var browserWebsocket string
	select {
	case browserWebsocket = <-devtoolsURL:
	case <-process.done:
		_ = session.close()
		return nil, fmt.Errorf("browser exited before DevTools became ready: %v%s", process.err, formatBrowserLog(stderr))
	case err := <-serveErr:
		_ = session.close()
		return nil, fmt.Errorf("browser host HTTP server failed: %w", err)
	case <-startupContext.Done():
		_ = session.close()
		return nil, fmt.Errorf("browser DevTools startup: %w%s", startupContext.Err(), formatBrowserLog(stderr))
	}
	pageWebsocket, err := findPageWebsocket(startupContext, browserWebsocket, baseURL+"/")
	if err != nil {
		_ = session.close()
		return nil, fmt.Errorf("find browser page: %w%s", err, formatBrowserLog(stderr))
	}
	client, err := newCDPClient(startupContext, pageWebsocket)
	if err != nil {
		_ = session.close()
		return nil, fmt.Errorf("connect browser DevTools: %w", err)
	}
	session.cdp = client
	if err := client.call(startupContext, "Performance.enable", map[string]any{}, nil); err != nil {
		_ = session.close()
		return nil, err
	}
	status, err := waitBrowserReady(startupContext, client)
	if err != nil {
		_ = session.close()
		return nil, fmt.Errorf("initialize real browser/WASM writer: %w%s", err, formatBrowserLog(stderr))
	}
	fixtureDigest := sha256.Sum256(fixture)
	parameterProfile, parameterSHA256, parameterBytes, parameterOK := rq2wire.ParameterEvidence(config.backend)
	if status.WASMSHA256 != config.wasmSHA256 || status.DownloadByte != uint64(len(wasm)) || status.DownloadNS == 0 || status.Instantiate == 0 ||
		status.Initialize == nil || status.Initialize.ParameterLoadNS == 0 || !parameterOK ||
		status.Initialize.ParameterLoadBytes != parameterBytes || status.Initialize.ParameterProfile != parameterProfile || status.Initialize.ParameterSHA256 != parameterSHA256 ||
		status.Initialize.FixtureBytes != uint64(len(fixture)) || status.Initialize.FixtureSHA256 != hex.EncodeToString(fixtureDigest[:]) {
		_ = session.close()
		return nil, fmt.Errorf("browser cold-start provenance/timing evidence is incomplete")
	}
	session.cold = coldStartMetrics{
		WASMDownloadNS: status.DownloadNS, WASMDownloadBytes: status.DownloadByte,
		WASMInstantiateNS: status.Instantiate, ParameterLoadNS: status.Initialize.ParameterLoadNS,
		ParameterBytes:   status.Initialize.ParameterLoadBytes,
		ParameterProfile: status.Initialize.ParameterProfile, ParameterSHA256: status.Initialize.ParameterSHA256,
	}
	failed = false
	return session, nil
}

func (b *browserSession) exchange(ctx context.Context, request rq2wire.WorkerRequest) (rq2wire.WorkerRecord, browserCall, uint64, uint64, uint64, error) {
	rawRequest, err := json.Marshal(request)
	if err != nil {
		return rq2wire.WorkerRecord{}, browserCall{}, 0, 0, 0, err
	}
	beforeCPU, err := b.cdp.taskDuration(ctx)
	if err != nil {
		return rq2wire.WorkerRecord{}, browserCall{}, 0, 0, 0, err
	}
	sampler, err := startResidentSampler(b.processID)
	if err != nil {
		return rq2wire.WorkerRecord{}, browserCall{}, 0, 0, 0, err
	}
	quoted, _ := json.Marshal(string(rawRequest))
	returned, callErr := b.cdp.evaluateString(ctx, "window.maltHostExchange("+string(quoted)+")", true)
	peak, samples, sampleErr := sampler.stop()
	if callErr != nil {
		return rq2wire.WorkerRecord{}, browserCall{}, 0, 0, 0, callErr
	}
	if sampleErr != nil {
		return rq2wire.WorkerRecord{}, browserCall{}, 0, 0, 0, sampleErr
	}
	afterCPU, err := b.cdp.taskDuration(ctx)
	if err != nil || afterCPU < beforeCPU {
		return rq2wire.WorkerRecord{}, browserCall{}, 0, 0, 0, fmt.Errorf("invalid Chromium TaskDuration delta")
	}
	var call browserCall
	if err := strictJSON([]byte(returned), &call); err != nil {
		return rq2wire.WorkerRecord{}, browserCall{}, 0, 0, 0, err
	}
	if call.RecordJSON == "" || call.CallNS == 0 {
		return rq2wire.WorkerRecord{}, browserCall{}, 0, 0, 0, fmt.Errorf("browser/WASM boundary omitted call evidence")
	}
	var record rq2wire.WorkerRecord
	if err := strictJSON([]byte(call.RecordJSON), &record); err != nil {
		return rq2wire.WorkerRecord{}, browserCall{}, 0, 0, 0, err
	}
	if call.HeapBytes > peak {
		peak = call.HeapBytes
	}
	if call.WASMMemory > peak {
		peak = call.WASMMemory
	}
	cpuNS := secondsToNS(afterCPU - beforeCPU)
	return record, call, cpuNS, peak, max(uint64(1), samples), nil
}

func (b *browserSession) close() error {
	b.closeOnce.Do(func() {
		if b.cdp != nil {
			closeContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = b.cdp.call(closeContext, "Browser.close", map[string]any{}, nil)
			cancel()
			_ = b.cdp.Close()
		}
		if b.server != nil {
			shutdownContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			if err := b.server.Shutdown(shutdownContext); err != nil && !errors.Is(err, http.ErrServerClosed) {
				b.closeErr = errors.Join(b.closeErr, err)
			}
			cancel()
		}
		if b.command != nil && b.command.Process != nil && b.process != nil {
			select {
			case <-b.process.done:
				if b.process.err != nil && !strings.Contains(b.process.err.Error(), "signal: killed") {
					b.closeErr = errors.Join(b.closeErr, b.process.err)
				}
			case <-time.After(3 * time.Second):
				_ = forceKillBrowserProcess(b.command)
				<-b.process.done
			}
		}
		if b.profile != "" {
			b.closeErr = errors.Join(b.closeErr, os.RemoveAll(b.profile))
		}
	})
	return b.closeErr
}

// forceTerminate is the failure-only process boundary. It sends an immediate
// non-graceful kill before attempting CDP or HTTP cleanup, then requires both
// process reaping and connection teardown to complete within one fixed bound.
// Normal successful sessions continue to use close's graceful path.
func (b *browserSession) forceTerminate() error {
	if b == nil {
		return nil
	}
	b.closeOnce.Do(func() {
		started := time.Now()
		exceeded := false
		deadline := time.NewTimer(browserForceTerminationBound)
		defer deadline.Stop()

		if b.command != nil && b.command.Process != nil {
			b.closeErr = errors.Join(b.closeErr, forceKillBrowserProcess(b.command))
		}
		if b.cdp != nil {
			b.closeErr = errors.Join(b.closeErr, b.cdp.forceClose())
		}
		if b.server != nil {
			if err := b.server.Close(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				b.closeErr = errors.Join(b.closeErr, err)
			}
		}
		if b.listener != nil {
			if err := b.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				b.closeErr = errors.Join(b.closeErr, err)
			}
		}
		if b.process != nil {
			select {
			case <-b.process.done:
				if b.process.err != nil && !browserWasForceKilled(b.process.err) {
					b.closeErr = errors.Join(b.closeErr, b.process.err)
				}
			case <-deadline.C:
				exceeded = true
				b.closeErr = errors.Join(b.closeErr, fmt.Errorf("force terminate Chromium exceeded %s", browserForceTerminationBound))
			}
		}
		if b.profile != "" {
			profile := b.profile
			b.profile = ""
			b.closeErr = errors.Join(b.closeErr, os.RemoveAll(profile))
		}
		if time.Since(started) > browserForceTerminationBound && !exceeded {
			b.closeErr = errors.Join(b.closeErr, fmt.Errorf("force terminate Chromium exceeded %s", browserForceTerminationBound))
		}
	})
	return b.closeErr
}

func browserWasForceKilled(err error) bool {
	if err == nil {
		return true
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "signal: killed") || strings.Contains(text, "signal: terminated") || strings.Contains(text, "exit status 137")
}

func findPageWebsocket(ctx context.Context, browserWebsocket, pageURL string) (string, error) {
	parsed, err := url.Parse(browserWebsocket)
	if err != nil {
		return "", err
	}
	endpoint := "http://" + parsed.Host + "/json/list"
	client := &http.Client{Timeout: 2 * time.Second}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		response, err := client.Do(request)
		if err == nil {
			var targets []struct {
				Type                 string `json:"type"`
				URL                  string `json:"url"`
				WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
			}
			decodeErr := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&targets)
			_ = response.Body.Close()
			if decodeErr == nil {
				for _, target := range targets {
					if target.Type == "page" && target.URL == pageURL && strings.HasPrefix(target.WebSocketDebuggerURL, "ws://") {
						return target.WebSocketDebuggerURL, nil
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ticker.C:
		}
	}
}

func waitBrowserReady(ctx context.Context, client *cdpClient) (browserStatus, error) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		raw, err := client.evaluateString(ctx, `typeof window.maltHostStatus === "function" ? window.maltHostStatus() : JSON.stringify({phase:"loading"})`, false)
		if err == nil {
			var status browserStatus
			if err := strictJSON([]byte(raw), &status); err != nil {
				return browserStatus{}, err
			}
			switch status.Phase {
			case "ready":
				return status, nil
			case "failed":
				return browserStatus{}, errors.New(status.Error)
			}
		}
		select {
		case <-ctx.Done():
			return browserStatus{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

func scanBrowserLog(reader io.Reader, output *boundedLog, devtools chan<- string) {
	buffer := make([]byte, 4096)
	pending := ""
	found := false
	for {
		count, err := reader.Read(buffer)
		if count > 0 {
			chunk := buffer[:count]
			_, _ = output.Write(chunk)
			if !found {
				pending += string(chunk)
				if matches := devtoolsPattern.FindStringSubmatch(pending); len(matches) == 2 {
					devtools <- matches[1]
					found = true
				}
				if len(pending) > 8192 {
					pending = pending[len(pending)-4096:]
				}
			}
		}
		if err != nil {
			return
		}
	}
}

type browserPageConfig struct {
	GatewayURL   string `json:"gateway_url"`
	FixtureURL   string `json:"fixture_url"`
	WASMURL      string `json:"wasm_url"`
	WASMSHA256   string `json:"wasm_sha256"`
	GatewayToken string `json:"gateway_instance_token"`
	Backend      string `json:"backend"`
}

func browserPage(config browserPageConfig) ([]byte, error) {
	configuration, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	quotedConfiguration, err := json.Marshal(string(configuration))
	if err != nil {
		return nil, err
	}
	page := `<!doctype html><meta charset="utf-8"><title>MALT RQ2 browser writer</title>
<script src="wasm_exec.js"></script><script>
"use strict";
const maltConfig = JSON.parse(` + string(quotedConfiguration) + `);
const maltState = {phase:"loading"};
let maltInstance = null;
window.maltHostStatus = () => JSON.stringify(maltState);
const ns = milliseconds => Math.max(1, Math.round(milliseconds * 1000000));
const heapBytes = () => performance.memory ? performance.memory.usedJSHeapSize : 0;
const sha256 = async bytes => Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))).map(value => value.toString(16).padStart(2,"0")).join("");
const waitForWriter = async () => {
  const deadline = performance.now() + 86400000;
  while (!globalThis.maltRQ2WASMReady) {
    if (performance.now() > deadline) throw new Error("WASM writer readiness timeout");
    await new Promise(resolve => setTimeout(resolve, 1));
  }
};
window.maltHostExchange = async raw => {
  const beforeHeap = heapBytes();
  const started = performance.now();
  const recordJSON = await globalThis.maltRQ2Exchange(raw);
  const callNS = ns(performance.now() - started);
  const internalNS = Number(globalThis.maltRQ2LastExecutionNS || 0);
  const afterHeap = heapBytes();
  const wasmBytes = maltInstance && maltInstance.exports.mem ? maltInstance.exports.mem.buffer.byteLength : 0;
  return JSON.stringify({record_json:recordJSON, call_ns:callNS, boundary_ns:Math.max(0,callNS-internalNS), heap_bytes:Math.max(beforeHeap,afterHeap), wasm_memory_bytes:wasmBytes});
};
(async () => {
  try {
    const downloadStarted = performance.now();
    const response = await fetch(maltConfig.wasm_url, {cache:"no-store"});
    if (!response.ok || !(response.headers.get("cache-control") || "").includes("no-store")) throw new Error("WASM fetch was not a non-cacheable success");
    const wasmBytes = await response.arrayBuffer();
    const downloadNS = ns(performance.now() - downloadStarted);
    const actualSHA256 = await sha256(wasmBytes);
    if (actualSHA256 !== maltConfig.wasm_sha256) throw new Error("downloaded WASM digest mismatch");
    const go = new Go();
    const instantiateStarted = performance.now();
    const instantiated = await WebAssembly.instantiate(wasmBytes, go.importObject);
    const instantiateNS = ns(performance.now() - instantiateStarted);
    maltInstance = instantiated.instance;
    go.run(maltInstance).catch(error => { maltState.phase="failed"; maltState.error=String(error); });
    await waitForWriter();
    const initializeJSON = await globalThis.maltRQ2Initialize(JSON.stringify({
      gateway_base_url:maltConfig.gateway_url,
      gateway_instance_token:maltConfig.gateway_instance_token,
      fixture_url:maltConfig.fixture_url,
      backend:maltConfig.backend
    }));
    maltState.phase = "ready";
    maltState.wasm_sha256 = actualSHA256;
    maltState.download_ns = downloadNS;
    maltState.download_bytes = wasmBytes.byteLength;
    maltState.instantiate_ns = instantiateNS;
    maltState.initialize = JSON.parse(initializeJSON);
  } catch (error) {
    maltState.phase = "failed";
    maltState.error = String(error && error.stack ? error.stack : error);
  }
})();
</script>`
	return []byte(page), nil
}

type boundedLog struct {
	mu        sync.Mutex
	limit     int
	buffer    bytes.Buffer
	truncated bool
}

func (b *boundedLog) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	original := len(value)
	remaining := b.limit - b.buffer.Len()
	if remaining > 0 {
		_, _ = b.buffer.Write(value[:min(len(value), remaining)])
	}
	if original > remaining {
		b.truncated = true
	}
	return original, nil
}

func (b *boundedLog) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func formatBrowserLog(log *boundedLog) string {
	if log == nil || strings.TrimSpace(log.String()) == "" {
		return ""
	}
	return "; Chromium stderr: " + strings.TrimSpace(log.String())
}

func boundedText(value []byte, limit int) string {
	value = bytes.TrimSpace(value)
	if len(value) > limit {
		value = value[:limit]
	}
	return string(value)
}

func secondsToNS(value float64) uint64 {
	if value <= 0 {
		return 0
	}
	return uint64(value * float64(time.Second))
}

func browserRuntime(engine, wasmSHA string, machineEvidence *machine.Evidence, cold coldStartMetrics) *rq2wire.RuntimeEvidence {
	return &rq2wire.RuntimeEvidence{
		OS: runtime.GOOS, Architecture: runtime.GOARCH, LowPowerARM: machineEvidence.Descriptor.LowPowerARM(),
		MachineDescriptorID: machineEvidence.Descriptor.ID, MachineDescriptorSHA256: machineEvidence.SHA256,
		BrowserEngine: engine, WASMSHA256: wasmSHA,
		ParameterProfile: cold.ParameterProfile, ParameterSHA256: cold.ParameterSHA256, ParameterInputBytes: cold.ParameterBytes,
	}
}

func exactCapabilities(backend string) []string {
	values := rq2wire.RequiredCapabilities(rq2wire.ClientBrowserWASM, backend)
	slices.Sort(values)
	return values
}

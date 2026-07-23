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
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/dewebprotocol/malt-client/internal/evaluation/e0selftest"
)

const (
	maltAdapterSelfTestCorpusSchema = "malt-eval-rq3-malt-adapter-self-test/v1"
	controllerRequestSchema         = "malt-rq3-gateway-controller-request/v2"
	controllerResponseSchema        = "malt-rq3-gateway-controller-response/v2"
	controllerCapabilityID          = "rq3.gateway-lifecycle-controller.v1"
	directoryIdentityProfile        = "physical-directory-posix-device-inode/v1"
)

var maltAdapterSelfTestProfile = e0selftest.Profile{
	ProfileID: "rq3-malt-adapter-positive-hostile-v1",
	PositiveCases: []string{
		"execute-controlled-malt-kzg",
		"execute-git-first-parent-malt-kzg",
	},
	HostileCases: []string{
		"reject-malformed-request",
		"reject-tampered-payload",
		"reject-stale-before-value",
	},
}

type maltSelfTestConfig struct {
	corpusPath     string
	controllerPath string
	cleanPath      string
	optionsPath    string
	requestTimeout time.Duration
	boundWorkloads []string
	gitExecutables []string
}

type repeatedPathFlag []string

func (f *repeatedPathFlag) String() string { return strings.Join(*f, ",") }
func (f *repeatedPathFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

type maltAdapterSelfTestCorpus struct {
	SchemaVersion string                            `json:"schema_version"`
	PositiveCases []maltAdapterSelfTestPositiveCase `json:"positive_cases"`
	HostileCases  []maltAdapterSelfTestHostileCase  `json:"hostile_cases"`
}

type maltAdapterSelfTestPositiveCase struct {
	ID         string  `json:"id"`
	SourceKind string  `json:"source_kind"`
	Run        runSpec `json:"run"`
}

type maltAdapterSelfTestHostileCase struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

type controllerArtifactPin struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type controllerEngineConfiguration struct {
	Engine                string `json:"engine"`
	Version               string `json:"version"`
	OptionsArtifactSHA256 string `json:"options_artifact_sha256"`
	SyncWrites            bool   `json:"sync_writes"`
	WALPolicy             string `json:"wal_policy"`
	LSMPolicy             string `json:"lsm_policy"`
	CompactionPolicy      string `json:"compaction_policy"`
	GCPolicy              string `json:"gc_policy"`
}

type controllerStartBinding struct {
	System                      string                        `json:"system"`
	WorkloadID                  string                        `json:"workload_id"`
	PassMode                    string                        `json:"pass_mode"`
	RunPhase                    string                        `json:"run_phase"`
	ClusterID                   string                        `json:"cluster_id"`
	RunIndex                    int                           `json:"run_index"`
	Directory                   string                        `json:"directory"`
	DirectoryID                 string                        `json:"directory_id"`
	DirectoryIdentity           directoryIdentity             `json:"directory_identity"`
	BaseURL                     string                        `json:"base_url"`
	InstanceToken               string                        `json:"instance_token"`
	BootstrapAuthorizationToken string                        `json:"bootstrap_authorization_token"`
	InitialRoot                 string                        `json:"initial_root"`
	CleanSnapshot               controllerArtifactPin         `json:"clean_snapshot"`
	OptionsArtifact             controllerArtifactPin         `json:"options_artifact"`
	EngineConfiguration         controllerEngineConfiguration `json:"engine_configuration"`
	Disposable                  bool                          `json:"disposable"`
	RequireInitiallyEmpty       bool                          `json:"require_initially_empty"`
	EmptyOperationLog           bool                          `json:"empty_operation_log"`
}

type controllerStopBinding struct {
	BindingSHA256 string `json:"binding_sha256"`
}

type controllerRequest struct {
	SchemaVersion string                  `json:"schema_version"`
	RequestID     string                  `json:"request_id"`
	Operation     string                  `json:"operation"`
	Start         *controllerStartBinding `json:"start,omitempty"`
	Stop          *controllerStopBinding  `json:"stop,omitempty"`
}

type controllerResponse struct {
	SchemaVersion     string                   `json:"schema_version"`
	RequestID         string                   `json:"request_id"`
	OK                bool                     `json:"ok"`
	CapabilityID      string                   `json:"capability_id"`
	State             string                   `json:"state"`
	BindingSHA256     string                   `json:"binding_sha256"`
	DirectoryIdentity directoryIdentity        `json:"directory_identity"`
	Quiesced          bool                     `json:"quiesced"`
	Error             *controllerResponseError `json:"error,omitempty"`
}

type directoryIdentity struct {
	Profile string `json:"profile"`
	Device  uint64 `json:"device"`
	Inode   uint64 `json:"inode"`
}

func (identity directoryIdentity) validate() error {
	if identity.Profile != directoryIdentityProfile || identity.Device == 0 || identity.Inode == 0 {
		return errors.New("physical directory identity must bind a nonzero POSIX device/inode")
	}
	return nil
}

type controllerResponseError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type badgerOptionsIdentity struct {
	SchemaVersion        string `json:"schema_version"`
	Engine               string `json:"engine"`
	Module               string `json:"module"`
	Version              string `json:"version"`
	OptionsSource        string `json:"options_source"`
	DirectoryPolicy      string `json:"directory_policy"`
	ValueDirectoryPolicy string `json:"value_directory_policy"`
	SyncWrites           bool   `json:"sync_writes"`
	Logger               string `json:"logger"`
	WALPolicy            string `json:"wal_policy"`
	LSMPolicy            string `json:"lsm_policy"`
	CompactionPolicy     string `json:"compaction_policy"`
	GCPolicy             string `json:"gc_policy"`
}

type selfTestGatewayController struct {
	command       *exec.Cmd
	stdin         io.WriteCloser
	output        *bufio.Scanner
	stderr        bytes.Buffer
	bindingSHA256 string
	directoryID   directoryIdentity
}

func hasMALTSelfTestFlag(arguments []string) bool {
	for _, argument := range arguments {
		if argument == "-self-test-corpus" || argument == "--self-test-corpus" || strings.HasPrefix(argument, "-self-test-corpus=") || strings.HasPrefix(argument, "--self-test-corpus=") {
			return true
		}
	}
	return false
}

func parseMALTSelfTestFlags(arguments []string) (maltSelfTestConfig, error) {
	flags := flag.NewFlagSet("malt-eval-rq3-malt-worker-self-test", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	corpus := flags.String("self-test-corpus", "", "formal E0 MALT adapter corpus")
	controller := flags.String("gateway-controller", "", "pinned disposable Gateway controller")
	clean := flags.String("clean-snapshot", "", "pinned empty Gateway snapshot descriptor")
	options := flags.String("badger-options", "", "pinned synchronous Badger options descriptor")
	timeout := flags.Duration("request-timeout", 2*time.Minute, "per-request self-test timeout")
	var boundWorkloads, gitExecutables repeatedPathFlag
	flags.Var(&boundWorkloads, "bound-workload", "production RQ3 workload artifact bound by formal E0 (repeatable)")
	flags.Var(&gitExecutables, "git-executable", "production Git executable bound by formal E0 (repeatable)")
	if err := flags.Parse(arguments); err != nil {
		return maltSelfTestConfig{}, err
	}
	if flags.NArg() != 0 || *corpus == "" || *controller == "" || *clean == "" || *options == "" || *timeout <= 0 || *timeout > 10*time.Minute {
		return maltSelfTestConfig{}, errors.New("formal E0 self-test requires -self-test-corpus, -gateway-controller, -clean-snapshot, -badger-options, and a bounded positive -request-timeout")
	}
	for _, path := range []string{*corpus, *controller, *clean, *options} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return maltSelfTestConfig{}, errors.New("formal E0 self-test file paths must be absolute and clean")
		}
	}
	return maltSelfTestConfig{
		corpusPath: *corpus, controllerPath: *controller, cleanPath: *clean, optionsPath: *options, requestTimeout: *timeout,
		boundWorkloads: append([]string(nil), boundWorkloads...), gitExecutables: append([]string(nil), gitExecutables...),
	}, nil
}

func runMALTAdapterSelfTest(ctx context.Context, config maltSelfTestConfig, output io.Writer) error {
	if err := validateMALTSelfTestInputs(config); err != nil {
		return err
	}
	var corpus maltAdapterSelfTestCorpus
	if err := decodeMALTSelfTestFile(config.corpusPath, maxWorkerLineBytes, &corpus); err != nil {
		return fmt.Errorf("MALT adapter self-test corpus: %w", err)
	}
	if err := corpus.validate(); err != nil {
		return err
	}
	cleanPin, err := describeControllerArtifact(config.cleanPath)
	if err != nil {
		return fmt.Errorf("clean snapshot input: %w", err)
	}
	optionsPin, err := describeControllerArtifact(config.optionsPath)
	if err != nil {
		return fmt.Errorf("Badger options input: %w", err)
	}
	var options badgerOptionsIdentity
	if err := decodeMALTSelfTestFile(config.optionsPath, 1<<20, &options); err != nil {
		return fmt.Errorf("Badger options identity: %w", err)
	}
	if options.SchemaVersion != "gateway-badger-options/v1" || options.Engine != "badger" || options.Module != "github.com/dgraph-io/badger/v4" || strings.TrimSpace(options.Version) == "" ||
		options.OptionsSource != "badger.DefaultOptions" || options.DirectoryPolicy != "campaign-empty-directory" || options.ValueDirectoryPolicy != "same-as-directory" || !options.SyncWrites || options.Logger != "disabled" ||
		options.WALPolicy != "value-log-default-fixed" || options.LSMPolicy != "default-options-fixed" || options.CompactionPolicy != "close-before-scan-no-extra-compaction" || options.GCPolicy != "disabled" {
		return errors.New("Badger options input has an invalid identity")
	}

	results := make([]e0selftest.CaseResult, 0, len(corpus.PositiveCases)+len(corpus.HostileCases))
	for _, testCase := range corpus.PositiveCases {
		if err := executeMALTPositiveCase(ctx, config, cleanPin, optionsPin, options.Version, testCase); err != nil {
			return fmt.Errorf("MALT adapter self-test positive case %q: %w", testCase.ID, err)
		}
		results = append(results, e0selftest.CaseResult{ID: testCase.ID, Passed: true})
	}
	for _, testCase := range corpus.HostileCases {
		if err := executeMALTHostileCase(ctx, config, cleanPin, optionsPin, options.Version, testCase, corpus.PositiveCases); err != nil {
			return fmt.Errorf("MALT adapter self-test hostile case %q: %w", testCase.ID, err)
		}
		results = append(results, e0selftest.CaseResult{ID: testCase.ID, Passed: true})
	}
	receipt, err := e0selftest.Issue("rq3.malt-system-adapter", maltAdapterSelfTestProfile, results)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(receipt)
}

func (c maltAdapterSelfTestCorpus) validate() error {
	if c.SchemaVersion != maltAdapterSelfTestCorpusSchema || len(c.PositiveCases) != len(maltAdapterSelfTestProfile.PositiveCases) || len(c.HostileCases) != len(maltAdapterSelfTestProfile.HostileCases) {
		return errors.New("MALT adapter self-test corpus has an invalid schema or case count")
	}
	for index, testCase := range c.PositiveCases {
		if testCase.ID != maltAdapterSelfTestProfile.PositiveCases[index] || testCase.Run.Workload.Kind != testCase.SourceKind || testCase.Run.PassMode != "accounting" || testCase.Run.RunPhase != "accounting" || testCase.Run.RunIndex != 0 || testCase.Run.InitialRoot != "" {
			return fmt.Errorf("MALT adapter positive case %d does not match the compiled source/run contract", index)
		}
		if index == 0 && testCase.SourceKind != "controlled" || index == 1 && testCase.SourceKind != "git-first-parent" {
			return fmt.Errorf("MALT adapter positive case %q has a mismatched source kind", testCase.ID)
		}
		if err := validateWorkloadIdentity(testCase.Run.Workload); err != nil {
			return fmt.Errorf("MALT adapter positive case %q identity: %w", testCase.ID, err)
		}
		if err := validateFrozenCommitListBinding(testCase.Run); err != nil {
			return fmt.Errorf("MALT adapter positive case %q commit-list binding: %w", testCase.ID, err)
		}
	}
	wantKinds := []string{"malformed-request", "tampered-payload", "stale-before-value"}
	for index, testCase := range c.HostileCases {
		if testCase.ID != maltAdapterSelfTestProfile.HostileCases[index] || testCase.Kind != wantKinds[index] {
			return fmt.Errorf("MALT adapter hostile case %d does not match the compiled contract", index)
		}
	}
	return nil
}

func executeMALTPositiveCase(ctx context.Context, config maltSelfTestConfig, cleanPin, optionsPin controllerArtifactPin, version string, testCase maltAdapterSelfTestPositiveCase) error {
	return withDisposableSelfTestGateway(ctx, config, cleanPin, optionsPin, version, testCase.ID, testCase.Run, func(worker *campaignWorker) error {
		result, err := worker.run(ctx, testCase.Run)
		if err != nil {
			return err
		}
		if result.CapabilityID != capabilityID || result.System != systemMALTKZG || result.Workload != testCase.Run.Workload || len(result.Commits) != len(testCase.Run.Commits)+1 || len(result.WriteEvents) == 0 {
			return errors.New("production MALT worker returned an incomplete exact-ledger result")
		}
		for index, record := range result.Commits {
			want := testCase.Run.Snapshot.CommitID
			if index > 0 {
				want = testCase.Run.Commits[index-1].CommitID
			}
			if record.CommitID != want || record.Root == "" || record.HistoryRootsRetained != uint32(index+1) ||
				record.NonWorkloadSetupRootsRetained != 1 {
				return fmt.Errorf("MALT commit record %d does not bind the retained history", index)
			}
		}
		return nil
	})
}

func executeMALTHostileCase(ctx context.Context, config maltSelfTestConfig, cleanPin, optionsPin controllerArtifactPin, version string, testCase maltAdapterSelfTestHostileCase, positives []maltAdapterSelfTestPositiveCase) error {
	switch testCase.Kind {
	case "malformed-request":
		if _, err := decodeWorkerRequest([]byte(`{"schema_version":"malt-rq3-malt-worker-request/v1","request_id":"malformed","operation":"run","unknown":true}`)); err == nil {
			return errors.New("production MALT request decoder accepted an unknown field")
		}
		return nil
	case "tampered-payload":
		run, err := cloneMALTSelfTestRun(positives[0].Run)
		if err != nil {
			return err
		}
		run.Snapshot.Files[0].PayloadBase64 = "dGFtcGVyZWQ="
		return withDisposableSelfTestGateway(ctx, config, cleanPin, optionsPin, version, testCase.ID, run, func(worker *campaignWorker) error {
			if _, err := worker.run(ctx, run); err == nil || !strings.Contains(strings.ToLower(err.Error()), "payload sha-256 mismatch") {
				return fmt.Errorf("production MALT worker did not reject a tampered payload binding: %v", err)
			}
			return nil
		})
	case "stale-before-value":
		run, err := cloneMALTSelfTestRun(positives[0].Run)
		if err != nil {
			return err
		}
		run.Commits[0].Mutations[0].ExpectedOldSHA256 = strings.Repeat("0", 64)
		return withDisposableSelfTestGateway(ctx, config, cleanPin, optionsPin, version, testCase.ID, run, func(worker *campaignWorker) error {
			if _, err := worker.run(ctx, run); err == nil || !strings.Contains(strings.ToLower(err.Error()), "old payload digest mismatch") {
				return fmt.Errorf("production MALT worker did not reject a stale expected-old value: %v", err)
			}
			return nil
		})
	default:
		return fmt.Errorf("unsupported hostile kind %q", testCase.Kind)
	}
}

func validateMALTSelfTestInputs(config maltSelfTestConfig) error {
	consumed := []string{config.corpusPath, config.controllerPath, config.cleanPath, config.optionsPath}
	for _, path := range config.boundWorkloads {
		if err := validateMALTBoundWorkload(path); err != nil {
			return fmt.Errorf("bound workload %q: %w", path, err)
		}
		consumed = append(consumed, path)
	}
	for _, path := range config.gitExecutables {
		if err := validateMALTBoundExecutable(path); err != nil {
			return fmt.Errorf("Git executable %q: %w", path, err)
		}
		consumed = append(consumed, path)
	}
	for index, path := range consumed {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("consumed self-test path %d is not absolute and clean", index)
		}
	}
	want, err := e0selftest.InputPaths()
	if err != nil {
		return err
	}
	slices.Sort(consumed)
	if !slices.Equal(consumed, want) {
		return fmt.Errorf("typed self-test flags consume %v, E0 invocation pins %v", consumed, want)
	}
	return nil
}

func validateMALTBoundWorkload(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > maxWorkerLineBytes {
		return errors.New("workload is empty or exceeds the bounded size")
	}
	var identity struct {
		SchemaVersion string `json:"schema_version"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&identity); err != nil {
		return err
	}
	if identity.SchemaVersion != "malt-rq3-controlled-workload/v1" && identity.SchemaVersion != "malt-eval-git-trace/v1" {
		return fmt.Errorf("unsupported production workload schema %q", identity.SchemaVersion)
	}
	return nil
}

func validateMALTBoundExecutable(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return errors.New("file must be a non-symlink executable")
	}
	return nil
}

func withDisposableSelfTestGateway(ctx context.Context, config maltSelfTestConfig, cleanPin, optionsPin controllerArtifactPin, version, caseID string, run runSpec, execute func(*campaignWorker) error) (resultErr error) {
	tempRoot, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		return fmt.Errorf("resolve temporary directory: %w", err)
	}
	stateDirectory, err := os.MkdirTemp(tempRoot, "malt-rq3-e0-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stateDirectory)
	directoryLease, err := openSelfTestDirectoryLease(stateDirectory)
	if err != nil {
		return err
	}
	defer directoryLease.Close()
	if err := directoryLease.Verify("before Gateway controller start"); err != nil {
		return err
	}
	baseURL, err := reserveSelfTestBaseURL()
	if err != nil {
		return err
	}
	instanceToken := selfTestToken("instance", caseID)
	bootstrapToken := selfTestToken("bootstrap", caseID)
	binding := controllerStartBinding{
		System: systemMALTKZG, WorkloadID: run.Workload.ID, PassMode: run.PassMode, RunPhase: run.RunPhase,
		ClusterID: run.ClusterID, RunIndex: run.RunIndex, Directory: stateDirectory, DirectoryID: "e0-" + caseID,
		DirectoryIdentity: directoryLease.Identity(),
		BaseURL:           baseURL, InstanceToken: instanceToken, BootstrapAuthorizationToken: bootstrapToken,
		InitialRoot: "", CleanSnapshot: cleanPin, OptionsArtifact: optionsPin,
		EngineConfiguration: controllerEngineConfiguration{
			Engine: "badger", Version: version, OptionsArtifactSHA256: optionsPin.SHA256, SyncWrites: true,
			WALPolicy: "value-log-default-fixed", LSMPolicy: "default-options-fixed",
			CompactionPolicy: "close-before-scan-no-extra-compaction", GCPolicy: "disabled",
		},
		Disposable: true, RequireInitiallyEmpty: true, EmptyOperationLog: true,
	}
	controller, err := startSelfTestGatewayController(ctx, config.controllerPath, binding, directoryLease.Identity())
	if err != nil {
		return err
	}
	defer func() {
		if controller != nil {
			if stopErr := controller.stop(); stopErr != nil && resultErr == nil {
				resultErr = stopErr
			}
		}
	}()
	if err := directoryLease.Verify("after Gateway controller ready"); err != nil {
		return err
	}
	worker, err := newCampaignWorker(workerConfig{
		gatewayBaseURL: baseURL, instanceToken: instanceToken, bootstrapAuthorizationToken: bootstrapToken,
		requestTimeout: config.requestTimeout,
	})
	if err != nil {
		return err
	}
	executeErr := execute(worker)
	afterWorkloadErr := directoryLease.Verify("after RQ3 workload")
	stopErr := controller.stop()
	controller = nil
	afterStopErr := directoryLease.Verify("after Gateway controller stop")
	return errors.Join(executeErr, afterWorkloadErr, stopErr, afterStopErr)
}

func startSelfTestGatewayController(ctx context.Context, executable string, binding controllerStartBinding, leasedIdentity directoryIdentity) (*selfTestGatewayController, error) {
	if err := validateRegisteredDirectoryIdentity(binding.DirectoryIdentity, leasedIdentity); err != nil {
		return nil, err
	}
	command := exec.CommandContext(ctx, executable)
	command.Env = []string{"LANG=C", "LC_ALL=C", "TZ=UTC"}
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, err
	}
	controller := &selfTestGatewayController{command: command, stdin: stdin}
	controller.output = bufio.NewScanner(stdout)
	controller.output.Buffer(make([]byte, 64<<10), maxWorkerLineBytes)
	command.Stderr = &controller.stderr
	if err := command.Start(); err != nil {
		_ = stdin.Close()
		return nil, err
	}
	fail := func(cause error) (*selfTestGatewayController, error) {
		_ = stdin.Close()
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		_ = command.Wait()
		return nil, cause
	}
	bindingSHA256, err := canonicalSelfTestDigest(binding)
	if err != nil {
		return fail(err)
	}
	controller.bindingSHA256 = bindingSHA256
	controller.directoryID = leasedIdentity
	request := controllerRequest{SchemaVersion: controllerRequestSchema, RequestID: "start", Operation: "start", Start: &binding}
	if err := writeControllerRequest(stdin, request); err != nil {
		return fail(err)
	}
	response, err := controller.readResponse()
	if err != nil {
		return fail(err)
	}
	if err := validateSelfTestGatewayControllerResponse(response, "start", "ready", bindingSHA256, leasedIdentity, false); err != nil {
		return fail(err)
	}
	return controller, nil
}

func (c *selfTestGatewayController) stop() error {
	if c == nil || c.command == nil {
		return errors.New("Gateway controller is not running")
	}
	request := controllerRequest{
		SchemaVersion: controllerRequestSchema, RequestID: "stop", Operation: "stop",
		Stop: &controllerStopBinding{BindingSHA256: c.bindingSHA256},
	}
	if err := writeControllerRequest(c.stdin, request); err != nil {
		return c.abort(err)
	}
	response, err := c.readResponse()
	if err != nil {
		return c.abort(err)
	}
	if err := validateSelfTestGatewayControllerResponse(response, "stop", "stopped", c.bindingSHA256, c.directoryID, true); err != nil {
		return c.abort(err)
	}
	if err := c.stdin.Close(); err != nil {
		return c.abort(err)
	}
	if c.output.Scan() {
		return c.abort(errors.New("Gateway controller emitted a trailing response"))
	}
	if err := c.output.Err(); err != nil {
		return c.abort(err)
	}
	waitErr := c.command.Wait()
	c.command = nil
	if waitErr != nil {
		return fmt.Errorf("Gateway controller exited unsuccessfully: %w; stderr=%q", waitErr, strings.TrimSpace(c.stderr.String()))
	}
	if stderr := strings.TrimSpace(c.stderr.String()); stderr != "" {
		return fmt.Errorf("Gateway controller emitted unsolicited stderr: %q", stderr)
	}
	return nil
}

func validateRegisteredDirectoryIdentity(registered, leased directoryIdentity) error {
	if err := leased.validate(); err != nil {
		return fmt.Errorf("leased physical directory identity: %w", err)
	}
	if err := registered.validate(); err != nil {
		return fmt.Errorf("registered physical directory identity: %w", err)
	}
	if registered != leased {
		return errors.New("registered physical directory identity does not match the opened directory lease")
	}
	return nil
}

func validateSelfTestGatewayControllerResponse(response controllerResponse, requestID, state, bindingSHA256 string, identity directoryIdentity, quiesced bool) error {
	if response.SchemaVersion != controllerResponseSchema || response.RequestID != requestID || !response.OK ||
		response.CapabilityID != controllerCapabilityID || response.State != state || response.BindingSHA256 != bindingSHA256 ||
		response.DirectoryIdentity != identity || response.Quiesced != quiesced || response.Error != nil {
		return fmt.Errorf("Gateway controller returned an invalid %s response or directory identity: %#v", state, response)
	}
	return nil
}

func (c *selfTestGatewayController) abort(cause error) error {
	_ = c.stdin.Close()
	if c.command != nil && c.command.Process != nil {
		_ = c.command.Process.Kill()
	}
	if c.command != nil {
		_ = c.command.Wait()
	}
	c.command = nil
	return cause
}

func (c *selfTestGatewayController) readResponse() (controllerResponse, error) {
	if !c.output.Scan() {
		if err := c.output.Err(); err != nil {
			return controllerResponse{}, err
		}
		return controllerResponse{}, fmt.Errorf("Gateway controller closed before its response; stderr=%q", strings.TrimSpace(c.stderr.String()))
	}
	var response controllerResponse
	if err := decodeStrictMALTSelfTestJSON(c.output.Bytes(), &response); err != nil {
		return controllerResponse{}, err
	}
	return response, nil
}

func writeControllerRequest(output io.Writer, request controllerRequest) error {
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(request)
}

func reserveSelfTestBaseURL() (string, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		return "", err
	}
	return "http://" + address, nil
}

func selfTestToken(purpose, caseID string) string {
	digest := sha256.Sum256([]byte("malt-rq3-e0/" + purpose + "/" + caseID))
	return hex.EncodeToString(digest[:])
}

func describeControllerArtifact(path string) (controllerArtifactPin, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return controllerArtifactPin{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 1<<20 {
		return controllerArtifactPin{}, errors.New("controller artifact must be a bounded non-symlink regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return controllerArtifactPin{}, err
	}
	digest := sha256.Sum256(data)
	return controllerArtifactPin{Path: path, SHA256: hex.EncodeToString(digest[:]), Bytes: info.Size()}, nil
}

func cloneMALTSelfTestRun(run runSpec) (runSpec, error) {
	encoded, err := json.Marshal(run)
	if err != nil {
		return runSpec{}, err
	}
	var clone runSpec
	if err := json.Unmarshal(encoded, &clone); err != nil {
		return runSpec{}, err
	}
	return clone, nil
}

func decodeMALTSelfTestFile(path string, maximum int, target any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > maximum {
		return errors.New("file is empty or exceeds the bounded size")
	}
	return decodeStrictMALTSelfTestJSON(data, target)
}

func decodeStrictMALTSelfTestJSON(data []byte, target any) error {
	if err := rejectDuplicateKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func canonicalSelfTestDigest(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	var normalized any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := decoder.Decode(&normalized); err != nil {
		return "", err
	}
	encoded, err = json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

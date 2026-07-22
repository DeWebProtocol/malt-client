package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/dewebprotocol/malt-client/internal/evaluation/e0selftest"
	"github.com/dewebprotocol/malt-client/internal/evaluation/machine"
	"github.com/dewebprotocol/malt-client/internal/evaluation/rq2e0"
	"github.com/dewebprotocol/malt-client/internal/evaluation/rq2fixture"
	"github.com/dewebprotocol/malt-client/internal/evaluation/rq2wire"
)

const (
	nativeE0CapabilityID = "rq2.native-writer"
	nativeE0ProfileID    = "rq2-native-writer-positive-hostile-v1"
	// Updated only when the ordered compiled case contract intentionally
	// changes together with the evaluator-owned registry.
	nativeE0ExpectedProfileSHA256 = "4496552d3c18ebddf9dfc4736f37bdea346074f6e790f613725ec07b6d8437fe"
)

var nativeE0Profile = e0selftest.Profile{
	ProfileID: nativeE0ProfileID,
	PositiveCases: []string{
		"execute-native-kzg-operation-matrix",
		"execute-native-ipa-operation-matrix",
	},
	HostileCases: []string{
		"reject-malformed-request",
		"reject-backend-root-substitution",
		"reject-stale-session-root",
		"reject-tampered-fixture",
		"reject-machine-descriptor-pin-substitution",
	},
}

var nativeE0Operations = []string{
	"append", "batch-sync", "create-small-file", "delete-directory-entry", "insert-directory-entry",
	"modify-small-file", "move", "rename", "replace-large-file-chunk",
}

type nativeE0Config struct {
	fixturePath string
	machinePath string
	timeout     time.Duration
	fixture     *rq2fixture.Fixture
	machine     *machine.Evidence
	machinePin  rq2e0.FilePin
}

type nativeE0Execution struct {
	gateway *rq2e0.ConformanceGateway
	harness *rq2e0.Harness
	root    string
}

func (e *nativeE0Execution) abort() {
	if e == nil {
		return
	}
	if e.harness != nil {
		e.harness.Abort()
	}
	if e.gateway != nil {
		e.gateway.Close()
	}
}

func runNativeE0SelfTest(arguments []string, output, stderr io.Writer) error {
	config, err := parseNativeE0Flags(arguments, stderr)
	if err != nil {
		return err
	}
	config, err = prepareNativeE0Inputs(config)
	if err != nil {
		return err
	}
	contract, err := nativeE0Profile.Contract()
	if err != nil {
		return err
	}
	if contract.ProfileSHA256 != nativeE0ExpectedProfileSHA256 {
		return fmt.Errorf("compiled native-writer E0 profile digest drifted: got %s", contract.ProfileSHA256)
	}
	results := make([]e0selftest.CaseResult, 0, len(nativeE0Profile.PositiveCases)+len(nativeE0Profile.HostileCases))
	for _, testCase := range nativeE0Profile.PositiveCases {
		backend := "kzg"
		if strings.Contains(testCase, "ipa") {
			backend = "ipa"
		}
		if err := executeNativeE0Matrix(config, backend, testCase); err != nil {
			return fmt.Errorf("native E0 positive case %q: %w", testCase, err)
		}
		results = append(results, e0selftest.CaseResult{ID: testCase, Passed: true})
	}
	for _, testCase := range nativeE0Profile.HostileCases {
		if err := executeNativeE0Hostile(config, testCase); err != nil {
			return fmt.Errorf("native E0 hostile case %q: %w", testCase, err)
		}
		results = append(results, e0selftest.CaseResult{ID: testCase, Passed: true})
	}
	receipt, err := e0selftest.Issue(nativeE0CapabilityID, nativeE0Profile, results)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(receipt)
}

func parseNativeE0Flags(arguments []string, stderr io.Writer) (nativeE0Config, error) {
	flags := flag.NewFlagSet("malt-eval-rq2-worker --e0-self-test", flag.ContinueOnError)
	flags.SetOutput(stderr)
	fixture := flags.String("fixture", "", "pinned RQ2 source fixture corpus")
	machinePath := flags.String("machine-descriptor", "", "pinned platform machine descriptor")
	timeout := flags.Duration("request-timeout", 3*time.Minute, "bounded per-case timeout")
	if err := flags.Parse(arguments); err != nil {
		return nativeE0Config{}, err
	}
	if flags.NArg() != 0 || *fixture == "" || *machinePath == "" || *timeout <= 0 || *timeout > 10*time.Minute {
		return nativeE0Config{}, errors.New("native formal E0 requires only fixture, machine descriptor, and a bounded timeout")
	}
	config := nativeE0Config{fixturePath: filepath.Clean(*fixture), machinePath: filepath.Clean(*machinePath), timeout: *timeout}
	for _, path := range []string{config.fixturePath, config.machinePath} {
		if !filepath.IsAbs(path) {
			return nativeE0Config{}, errors.New("native formal E0 file paths must be canonical and absolute")
		}
	}
	return config, nil
}

func prepareNativeE0Inputs(config nativeE0Config) (nativeE0Config, error) {
	want, err := e0selftest.InputPaths()
	if err != nil {
		return nativeE0Config{}, err
	}
	consumed := []string{config.fixturePath, config.machinePath}
	slices.Sort(consumed)
	if !slices.Equal(consumed, want) {
		return nativeE0Config{}, fmt.Errorf("native typed self-test flags consume %v, E0 invocation pins %v", consumed, want)
	}
	fixtureRaw, err := readFixture(config.fixturePath)
	if err != nil {
		return nativeE0Config{}, err
	}
	config.fixture, err = rq2fixture.Decode(fixtureRaw)
	if err != nil {
		return nativeE0Config{}, err
	}
	if err := config.fixture.RequireOperations(nativeE0Operations); err != nil {
		return nativeE0Config{}, err
	}
	for _, backend := range []string{"kzg", "ipa"} {
		if _, err := config.fixture.Root(backend); err != nil {
			return nativeE0Config{}, err
		}
	}
	config.machinePin, err = rq2e0.DescribeRegularFile("rq2-native-machine-descriptor", config.machinePath)
	if err != nil {
		return nativeE0Config{}, err
	}
	config.machine, err = machine.LoadPinned(config.machinePath, config.machinePin.SHA256, config.machinePin.Bytes)
	if err != nil {
		return nativeE0Config{}, err
	}
	return config, nil
}

func executeNativeE0Matrix(config nativeE0Config, backend, caseID string) error {
	execution, err := startNativeE0Execution(config, backend, caseID, config.fixturePath, "")
	if err != nil {
		return err
	}
	defer execution.abort()
	if err := runNativeE0Session(execution.harness, config.fixture, backend, execution.root, nativeE0Operations, caseID); err != nil {
		return err
	}
	if err := execution.harness.Close(); err != nil {
		return err
	}
	if operations := execution.gateway.Operations(); operations != uint64(len(nativeE0Operations)) {
		return fmt.Errorf("conformance Gateway observed %d exact-root submissions, want %d", operations, len(nativeE0Operations))
	}
	return nil
}

func executeNativeE0Hostile(config nativeE0Config, caseID string) error {
	switch caseID {
	case "reject-malformed-request":
		valid, err := json.Marshal(nativeE0Request(config.fixture.FixtureID, "kzg", caseID, "preflight", recordPreflight, "", false, ""))
		if err != nil {
			return err
		}
		duplicate := bytes.Replace(valid, []byte(`"worker_id":`), []byte(`"worker_id":"duplicate","worker_id":`), 1)
		for _, hostile := range []struct {
			id  string
			raw []byte
		}{
			{id: "unknown-field", raw: []byte(`{"schema_version":"malt-rq2-worker-request/v1","unknown":true}`)},
			{id: "duplicate-field", raw: duplicate},
		} {
			execution, err := startNativeE0Execution(config, "kzg", caseID+"-"+hostile.id, config.fixturePath, "")
			if err != nil {
				return err
			}
			if err := execution.harness.WriteRaw(hostile.raw); err != nil {
				execution.abort()
				return err
			}
			if err := execution.harness.WaitError(); err != nil {
				execution.abort()
				return err
			}
			if err := requireNoNativeE0Submissions(execution); err != nil {
				execution.abort()
				return err
			}
			execution.abort()
		}
		return nil
	case "reject-backend-root-substitution":
		return withNativeHostileHarness(config, caseID, func(execution *nativeE0Execution) error {
			ipaRoot, err := config.fixture.Root("ipa")
			if err != nil {
				return err
			}
			if err := nativeE0Preflight(execution.harness, config.fixture.FixtureID, "kzg", caseID); err != nil {
				return err
			}
			request := nativeE0Request(config.fixture.FixtureID, "kzg", caseID, "session-start", recordSessionStart, "", false, ipaRoot.String())
			record, err := nativeE0Exchange(execution.harness, request, false, false)
			if err != nil {
				return err
			}
			if record.Success || record.FailureClass != "input_invalid" {
				return fmt.Errorf("backend/root substitution was not rejected: %+v", record)
			}
			return requireNoNativeE0Submissions(execution)
		})
	case "reject-stale-session-root":
		return withNativeHostileHarness(config, caseID, func(execution *nativeE0Execution) error {
			if err := nativeE0Preflight(execution.harness, config.fixture.FixtureID, "kzg", caseID); err != nil {
				return err
			}
			if err := nativeE0StartSession(execution.harness, config.fixture.FixtureID, "kzg", caseID, execution.root); err != nil {
				return err
			}
			initialRoot := execution.root
			first := nativeE0Request(config.fixture.FixtureID, "kzg", caseID, "mutation-current", recordMutation, nativeE0Operations[0], true, initialRoot)
			firstRecord, err := nativeE0Exchange(execution.harness, first, true, true)
			if err != nil {
				return err
			}
			if firstRecord.Mutation == nil {
				return errors.New("stale-root setup mutation omitted mutation evidence")
			}
			request := nativeE0Request(config.fixture.FixtureID, "kzg", caseID, "mutation-stale", recordMutation, nativeE0Operations[1], true, initialRoot)
			record, err := nativeE0Exchange(execution.harness, request, true, false)
			if err != nil {
				return err
			}
			if record.Success || record.FailureClass != "root_continuity" {
				return fmt.Errorf("stale accepted root was not rejected: %+v", record)
			}
			if operations := execution.gateway.Operations(); operations != 1 {
				return fmt.Errorf("stale-root hostile case submitted %d client roots, want 1 setup mutation", operations)
			}
			return nil
		})
	case "reject-tampered-fixture":
		tampered, err := tamperedNativeE0Fixture(config)
		if err != nil {
			return err
		}
		defer os.Remove(tampered)
		return expectNativeWorkerStartupFailure(config, caseID, tampered, "")
	case "reject-machine-descriptor-pin-substitution":
		return expectNativeWorkerStartupFailure(config, caseID, config.fixturePath, strings.Repeat("0", 64))
	default:
		return fmt.Errorf("unknown native E0 hostile case %q", caseID)
	}
}

func withNativeHostileHarness(config nativeE0Config, caseID string, execute func(*nativeE0Execution) error) error {
	execution, err := startNativeE0Execution(config, "kzg", caseID, config.fixturePath, "")
	if err != nil {
		return err
	}
	defer execution.abort()
	return execute(execution)
}

func expectNativeWorkerStartupFailure(config nativeE0Config, caseID, fixturePath, overrideMachineSHA string) error {
	execution, err := startNativeE0Execution(config, "kzg", caseID, fixturePath, overrideMachineSHA)
	if err != nil {
		return err
	}
	defer execution.abort()
	request := nativeE0Request(config.fixture.FixtureID, "kzg", caseID, "preflight", recordPreflight, "", false, "")
	var record rq2wire.WorkerRecord
	if err := execution.harness.Exchange(request, &record); err == nil {
		return fmt.Errorf("hostile native startup unexpectedly emitted a record: %+v", record)
	}
	if err := execution.harness.WaitError(); err != nil {
		return err
	}
	return requireNoNativeE0Submissions(execution)
}

func startNativeE0Execution(config nativeE0Config, backend, caseID, fixturePath, overrideMachineSHA string) (*nativeE0Execution, error) {
	tokenDigest := sha256.Sum256([]byte(nativeE0CapabilityID + "\x00" + backend + "\x00" + caseID))
	token := hex.EncodeToString(tokenDigest[:])
	gateway, root, err := rq2e0.NewConformanceGateway(config.fixture, backend, token)
	if err != nil {
		return nil, err
	}
	machineSHA := config.machinePin.SHA256
	if overrideMachineSHA != "" {
		machineSHA = overrideMachineSHA
	}
	args := []string{
		"-gateway-base-url", gateway.URL(), "-fixture", fixturePath, "-worker-id", "e0-worker-" + shortNativeE0ID(caseID),
		"-platform-id", "e0-native", "-client-kind", clientNative, "-backend", backend, "-lifecycle", lifecycleNativeLong,
		"-low-power-arm=" + strconv.FormatBool(config.machine.Descriptor.LowPowerARM()), "-gateway-instance-token", token,
		"-machine-descriptor", config.machinePath, "-machine-descriptor-sha256", machineSHA,
		"-machine-descriptor-bytes", strconv.FormatInt(config.machinePin.Bytes, 10), "-request-timeout", config.timeout.String(),
	}
	harness, err := rq2e0.StartHarness(config.timeout, func(input io.Reader, output io.Writer) error {
		return run(args, input, output, io.Discard)
	})
	if err != nil {
		gateway.Close()
		return nil, err
	}
	return &nativeE0Execution{gateway: gateway, harness: harness, root: root.String()}, nil
}

func requireNoNativeE0Submissions(execution *nativeE0Execution) error {
	if operations := execution.gateway.Operations(); operations != 0 {
		return fmt.Errorf("hostile case submitted %d client roots", operations)
	}
	return nil
}

func runNativeE0Session(harness *rq2e0.Harness, fixture *rq2fixture.Fixture, backend, root string, operations []string, caseID string) error {
	if err := nativeE0Preflight(harness, fixture.FixtureID, backend, caseID); err != nil {
		return err
	}
	if err := nativeE0StartSession(harness, fixture.FixtureID, backend, caseID, root); err != nil {
		return err
	}
	accepted := root
	for index, operation := range operations {
		request := nativeE0Request(fixture.FixtureID, backend, caseID, fmt.Sprintf("mutation-%02d", index), recordMutation, operation, true, accepted)
		record, err := nativeE0Exchange(harness, request, true, true)
		if err != nil {
			return err
		}
		if !record.Success || record.Mutation == nil || !record.Mutation.ReceiptAccepted || record.Mutation.Operation != operation || record.Mutation.PriorRoot != accepted || record.Mutation.ReceiptRoot == accepted ||
			!record.Mutation.Metrics.MutationTotal.Applicable || record.Mutation.Metrics.MutationTotal.DurationNS == 0 ||
			!record.Mutation.Metrics.ClientRootGeneration.Applicable || !record.Mutation.Metrics.GatewayPersist.Applicable || !record.Mutation.Metrics.ReceiptCheck.Applicable {
			return fmt.Errorf("native production mutation %q returned incomplete evidence: %+v", operation, record)
		}
		accepted = record.Mutation.ReceiptRoot
	}
	request := nativeE0Request(fixture.FixtureID, backend, caseID, "session-end", recordSessionEnd, "", false, accepted)
	ended, err := nativeE0Exchange(harness, request, true, true)
	if err != nil {
		return err
	}
	if !ended.Success || ended.Session == nil || ended.Session.AcceptedRoot != accepted || ended.Session.ReceiptCount != uint64(len(operations)) || !ended.Session.AuditPassed {
		return fmt.Errorf("native production session-end audit failed: %+v", ended)
	}
	return nil
}

func nativeE0Preflight(harness *rq2e0.Harness, fixtureID, backend, caseID string) error {
	request := nativeE0Request(fixtureID, backend, caseID, "preflight", recordPreflight, "", false, "")
	record, err := nativeE0Exchange(harness, request, true, true)
	if err != nil {
		return err
	}
	if !record.Success || record.Runtime == nil || !slices.Contains(record.Capabilities, "native-writer-v1") || !slices.Contains(record.Capabilities, "long-lived-session-v1") {
		return fmt.Errorf("native production preflight failed: %+v", record)
	}
	return nil
}

func nativeE0StartSession(harness *rq2e0.Harness, fixtureID, backend, caseID, root string) error {
	request := nativeE0Request(fixtureID, backend, caseID, "session-start", recordSessionStart, "", false, root)
	record, err := nativeE0Exchange(harness, request, true, true)
	if err != nil {
		return err
	}
	if !record.Success || record.Session == nil || record.Session.AcceptedRoot != root {
		return fmt.Errorf("native production session did not start from exact root: %+v", record)
	}
	return nil
}

func nativeE0Exchange(harness *rq2e0.Harness, request rq2wire.WorkerRequest, requireValidRequest, requireSuccess bool) (rq2wire.WorkerRecord, error) {
	requestErr := request.Validate()
	if requireValidRequest && requestErr != nil {
		return rq2wire.WorkerRecord{}, requestErr
	}
	if !requireValidRequest && requestErr == nil {
		return rq2wire.WorkerRecord{}, errors.New("native E0 hostile request unexpectedly satisfies the shared wire contract")
	}
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
		return rq2wire.WorkerRecord{}, fmt.Errorf("native worker failed: %s: %s", record.FailureClass, record.Error)
	}
	return record, nil
}

func nativeE0Request(fixtureID, backend, caseID, requestID, kind, operation string, measured bool, root string) rq2wire.WorkerRequest {
	return rq2wire.WorkerRequest{
		SchemaVersion: rq2wire.WorkerRequestSchema, WorkerID: "e0-worker-" + shortNativeE0ID(caseID), RequestID: requestID,
		RecordKind: kind, SessionID: "e0-session-" + shortNativeE0ID(caseID), ClientKind: clientNative,
		PlatformID: "e0-native", Backend: backend, Lifecycle: lifecycleNativeLong, FixtureID: fixtureID,
		Operation: operation, Measured: measured, ExpectedAcceptedRoot: root,
	}
}

func tamperedNativeE0Fixture(config nativeE0Config) (string, error) {
	raw, err := json.Marshal(config.fixture)
	if err != nil {
		return "", err
	}
	fixture, err := rq2fixture.Decode(raw)
	if err != nil {
		return "", err
	}
	switch {
	case len(fixture.DirectFiles) > 0 && len(fixture.DirectFiles[0].Bytes) > 0:
		fixture.DirectFiles[0].Bytes[0] ^= 0xff
	case len(fixture.ListFiles) > 0 && len(fixture.ListFiles[0].Chunks) > 0 && len(fixture.ListFiles[0].Chunks[0].Bytes) > 0:
		fixture.ListFiles[0].Chunks[0].Bytes[0] ^= 0xff
	default:
		return "", errors.New("native E0 fixture has no payload byte to tamper")
	}
	tampered, err := json.Marshal(fixture)
	if err != nil {
		return "", err
	}
	file, err := os.CreateTemp(filepath.Dir(config.fixturePath), "rq2-native-e0-tampered-*.json")
	if err != nil {
		return "", err
	}
	name := file.Name()
	if _, err := file.Write(tampered); err != nil {
		_ = file.Close()
		_ = os.Remove(name)
		return "", err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(name)
		return "", err
	}
	return name, nil
}

func shortNativeE0ID(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:6])
}

func nativeE0ProfileDigest() string {
	contract, err := nativeE0Profile.Contract()
	if err != nil {
		return ""
	}
	return contract.ProfileSHA256
}

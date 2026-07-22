package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/dewebprotocol/malt-client/internal/evaluation/e0selftest"
	"github.com/dewebprotocol/malt-client/merkledag/rq3baseline"
)

const hashAdapterSelfTestCorpusSchema = "malt-eval-rq3-hash-adapter-self-test/v1"

var hashAdapterSelfTestProfile = e0selftest.Profile{
	ProfileID: "rq3-hash-adapters-positive-hostile-v1",
	PositiveCases: []string{
		"execute-controlled-merkledag",
		"execute-controlled-hamt",
		"execute-git-first-parent-merkledag",
		"execute-git-first-parent-hamt",
	},
	HostileCases: []string{
		"reject-malformed-request",
		"reject-tampered-payload",
		"reject-stale-before-value",
	},
}

type hashAdapterSelfTestCorpus struct {
	SchemaVersion string                            `json:"schema_version"`
	PositiveCases []hashAdapterSelfTestPositiveCase `json:"positive_cases"`
	HostileCases  []hashAdapterSelfTestHostileCase  `json:"hostile_cases"`
}

type hashAdapterSelfTestPositiveCase struct {
	ID           string              `json:"id"`
	SourceKind   string              `json:"source_kind"`
	Run          rq3baseline.RunSpec `json:"run"`
	TraceBinding *hashTraceBinding   `json:"trace_binding,omitempty"`
}

type hashTraceBinding struct {
	TraceID          string   `json:"trace_id"`
	CommitIDs        []string `json:"commit_ids"`
	CommitListSHA256 string   `json:"commit_list_sha256"`
}

type hashAdapterSelfTestHostileCase struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

type repeatedPathFlag []string

func (f *repeatedPathFlag) String() string { return strings.Join(*f, ",") }
func (f *repeatedPathFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func runHashAdapterSelfTest(ctx context.Context, corpusPath string, boundWorkloads, gitExecutables []string, output io.Writer) error {
	if err := validateHashSelfTestInputs(corpusPath, boundWorkloads, gitExecutables); err != nil {
		return err
	}
	var corpus hashAdapterSelfTestCorpus
	if err := decodeHashSelfTestCorpus(corpusPath, &corpus); err != nil {
		return err
	}
	if err := corpus.validate(); err != nil {
		return err
	}
	results := make([]e0selftest.CaseResult, 0, len(corpus.PositiveCases)+len(corpus.HostileCases))
	for _, testCase := range corpus.PositiveCases {
		if err := executeHashPositiveCase(ctx, testCase); err != nil {
			return fmt.Errorf("hash adapter self-test positive case %q: %w", testCase.ID, err)
		}
		results = append(results, e0selftest.CaseResult{ID: testCase.ID, Passed: true})
	}
	for _, testCase := range corpus.HostileCases {
		if err := executeHashHostileCase(ctx, testCase, corpus.PositiveCases); err != nil {
			return fmt.Errorf("hash adapter self-test hostile case %q: %w", testCase.ID, err)
		}
		results = append(results, e0selftest.CaseResult{ID: testCase.ID, Passed: true})
	}
	receipt, err := e0selftest.Issue("rq3.hash-system-adapters", hashAdapterSelfTestProfile, results)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(receipt)
}

func (c hashAdapterSelfTestCorpus) validate() error {
	if c.SchemaVersion != hashAdapterSelfTestCorpusSchema || len(c.PositiveCases) != len(hashAdapterSelfTestProfile.PositiveCases) || len(c.HostileCases) != len(hashAdapterSelfTestProfile.HostileCases) {
		return errors.New("hash adapter self-test corpus has an invalid schema or case count")
	}
	for index, testCase := range c.PositiveCases {
		if testCase.ID != hashAdapterSelfTestProfile.PositiveCases[index] {
			return fmt.Errorf("hash adapter positive case %d has id %q", index, testCase.ID)
		}
		wantSystem := rq3baseline.SystemMerkleDAGUnixFS
		wantSource := "controlled"
		if testCase.ID == "execute-controlled-hamt" {
			wantSystem = rq3baseline.SystemHAMTUnixFS
		}
		if testCase.ID == "execute-git-first-parent-merkledag" || testCase.ID == "execute-git-first-parent-hamt" {
			wantSource = "git-first-parent"
		}
		if testCase.ID == "execute-git-first-parent-hamt" {
			wantSystem = rq3baseline.SystemHAMTUnixFS
		}
		if testCase.SourceKind != wantSource || testCase.Run.System != wantSystem {
			return fmt.Errorf("hash adapter positive case %q has a mismatched source/system", testCase.ID)
		}
		if testCase.SourceKind == "git-first-parent" {
			if testCase.TraceBinding == nil || validateHashTraceBinding(testCase.Run, *testCase.TraceBinding) != nil {
				return fmt.Errorf("hash adapter positive case %q has an invalid trace binding", testCase.ID)
			}
		} else if testCase.TraceBinding != nil {
			return fmt.Errorf("controlled hash adapter case %q carries a trace binding", testCase.ID)
		}
	}
	wantKinds := []string{"malformed-request", "tampered-payload", "stale-before-value"}
	for index, testCase := range c.HostileCases {
		if testCase.ID != hashAdapterSelfTestProfile.HostileCases[index] || testCase.Kind != wantKinds[index] {
			return fmt.Errorf("hash adapter hostile case %d does not match the compiled contract", index)
		}
	}
	return nil
}

func executeHashPositiveCase(ctx context.Context, testCase hashAdapterSelfTestPositiveCase) error {
	request := rq3baseline.WorkerRequest{
		SchemaVersion: rq3baseline.WorkerRequestSchema,
		RequestID:     testCase.ID,
		Operation:     rq3baseline.OperationRun,
		Run:           &testCase.Run,
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return err
	}
	response := handleLine(ctx, encoded)
	if !response.OK || response.Result == nil || response.Error != nil || response.Result.System != testCase.Run.System || len(response.Result.Records) != len(testCase.Run.Commits)+1 {
		return fmt.Errorf("production hash worker did not execute the exact frozen run: %#v", response)
	}
	for index, record := range response.Result.Records {
		want := testCase.Run.Snapshot.CommitID
		if index > 0 {
			want = testCase.Run.Commits[index-1].CommitID
		}
		if record.CommitID != want || record.Root == "" {
			return fmt.Errorf("hash result record %d does not bind commit %q", index, want)
		}
	}
	return nil
}

func executeHashHostileCase(ctx context.Context, testCase hashAdapterSelfTestHostileCase, positives []hashAdapterSelfTestPositiveCase) error {
	switch testCase.Kind {
	case "malformed-request":
		response := handleLine(ctx, []byte(`{"schema_version":"malt-rq3-hash-worker-request/v1","request_id":"malformed","operation":"run","unknown":true}`))
		if response.OK || response.Error == nil || response.Error.Code != "invalid_request" {
			return errors.New("production hash request decoder accepted an unknown field")
		}
		return nil
	case "tampered-payload":
		run, err := cloneHashRun(positives[0].Run)
		if err != nil {
			return err
		}
		run.Snapshot.Files[0].PayloadBase64 = "dGFtcGVyZWQ="
		request := rq3baseline.WorkerRequest{SchemaVersion: rq3baseline.WorkerRequestSchema, RequestID: "tampered", Operation: rq3baseline.OperationRun, Run: &run}
		encoded, err := json.Marshal(request)
		if err != nil {
			return err
		}
		response := handleLine(ctx, encoded)
		if response.OK || response.Error == nil || response.Error.Code != "invalid_or_failed_run" {
			return errors.New("production hash adapter accepted a payload whose bytes do not match its SHA-256 binding")
		}
		return nil
	case "stale-before-value":
		run, err := cloneHashRun(positives[0].Run)
		if err != nil {
			return err
		}
		run.Commits[0].Mutations[0].ExpectedOldSHA256 = strings.Repeat("0", 64)
		request := rq3baseline.WorkerRequest{SchemaVersion: rq3baseline.WorkerRequestSchema, RequestID: "stale-before", Operation: rq3baseline.OperationRun, Run: &run}
		encoded, err := json.Marshal(request)
		if err != nil {
			return err
		}
		response := handleLine(ctx, encoded)
		if response.OK || response.Error == nil || response.Error.Code != "invalid_or_failed_run" {
			return errors.New("production hash adapter accepted a stale expected-old value")
		}
		return nil
	default:
		return fmt.Errorf("unsupported hostile kind %q", testCase.Kind)
	}
}

func validateHashSelfTestInputs(corpusPath string, boundWorkloads, gitExecutables []string) error {
	consumed := []string{corpusPath}
	for _, path := range boundWorkloads {
		if err := validateBoundWorkload(path); err != nil {
			return fmt.Errorf("bound workload %q: %w", path, err)
		}
		consumed = append(consumed, path)
	}
	for _, path := range gitExecutables {
		if err := validateBoundExecutable(path); err != nil {
			return fmt.Errorf("Git executable %q: %w", path, err)
		}
		consumed = append(consumed, path)
	}
	return requireExactInvocationPaths(consumed)
}

func validateBoundWorkload(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > maxJSONLRecordBytes {
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

func validateBoundExecutable(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return errors.New("file must be a non-symlink executable")
	}
	return nil
}

func requireExactInvocationPaths(consumed []string) error {
	for index, path := range consumed {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("consumed path %d is not absolute and clean", index)
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

func validateHashTraceBinding(run rq3baseline.RunSpec, binding hashTraceBinding) error {
	commitIDs := make([]string, 0, len(run.Commits)+1)
	commitIDs = append(commitIDs, run.Snapshot.CommitID)
	for _, commit := range run.Commits {
		commitIDs = append(commitIDs, commit.CommitID)
	}
	if binding.TraceID == "" || !slices.Equal(commitIDs, binding.CommitIDs) {
		return errors.New("frozen run commit IDs do not equal the registered first-parent trace")
	}
	digest, err := hashCommitListDigest(commitIDs)
	if err != nil {
		return err
	}
	if digest != binding.CommitListSHA256 {
		return errors.New("registered first-parent trace commit-list digest mismatch")
	}
	return nil
}

func hashCommitListDigest(commitIDs []string) (string, error) {
	encoded, err := json.Marshal(struct {
		Commits []string `json:"commits"`
	}{Commits: commitIDs})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func cloneHashRun(run rq3baseline.RunSpec) (rq3baseline.RunSpec, error) {
	encoded, err := json.Marshal(run)
	if err != nil {
		return rq3baseline.RunSpec{}, err
	}
	var clone rq3baseline.RunSpec
	if err := json.Unmarshal(encoded, &clone); err != nil {
		return rq3baseline.RunSpec{}, err
	}
	return clone, nil
}

func decodeHashSelfTestCorpus(path string, target *hashAdapterSelfTestCorpus) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read hash adapter self-test corpus: %w", err)
	}
	if len(data) == 0 || len(data) > maxJSONLRecordBytes {
		return errors.New("hash adapter self-test corpus is empty or exceeds the bounded size")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode strict hash adapter self-test corpus: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("hash adapter self-test corpus contains a trailing JSON value")
		}
		return fmt.Errorf("decode hash adapter self-test corpus trailer: %w", err)
	}
	return nil
}

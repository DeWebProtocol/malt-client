package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dewebprotocol/malt-client/merkledag/rq3baseline"
)

func TestWorkerServesCapabilitiesAndRunAsStrictJSONL(t *testing.T) {
	capRequest := rq3baseline.WorkerRequest{
		SchemaVersion: rq3baseline.WorkerRequestSchema, RequestID: "cap-1", Operation: rq3baseline.OperationCapabilities,
	}
	runRequest := rq3baseline.WorkerRequest{
		SchemaVersion: rq3baseline.WorkerRequestSchema, RequestID: "run-1", Operation: rq3baseline.OperationRun, Run: testRunSpec(true),
	}
	var input bytes.Buffer
	for _, request := range []rq3baseline.WorkerRequest{capRequest, runRequest} {
		encoded, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		input.Write(encoded)
		input.WriteByte('\n')
	}
	var output bytes.Buffer
	if err := runWorker(t.Context(), &input, &output); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&output)
	var capResponse, runResponse rq3baseline.WorkerResponse
	if err := decoder.Decode(&capResponse); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&runResponse); err != nil {
		t.Fatal(err)
	}
	if !capResponse.OK || capResponse.Capability == nil || capResponse.Result != nil || capResponse.Capability.CapabilityID == "" {
		t.Fatalf("capability response = %#v", capResponse)
	}
	if !runResponse.OK || runResponse.Result == nil || runResponse.Capability != nil || len(runResponse.Result.Records) != 1 {
		t.Fatalf("run response = %#v", runResponse)
	}
}

func TestWorkerRejectsUnknownAndTrailingJSONButContinues(t *testing.T) {
	input := strings.Join([]string{
		`{"schema_version":"malt-rq3-hash-worker-request/v1","request_id":"bad-1","operation":"capabilities","unknown":true}`,
		`{"schema_version":"malt-rq3-hash-worker-request/v1","request_id":"bad-2","operation":"capabilities"} {}`,
		`{"schema_version":"malt-rq3-hash-worker-request/v1","request_id":"bad-3","operation":"capabilities","run":{"system":"a","system":"b"}}`,
		`{"schema_version":"malt-rq3-hash-worker-request/v1","request_id":"good","operation":"capabilities"}`,
	}, "\n") + "\n"
	var output bytes.Buffer
	if err := runWorker(t.Context(), strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&output)
	responses := make([]rq3baseline.WorkerResponse, 0, 4)
	for range 4 {
		var response rq3baseline.WorkerResponse
		if err := decoder.Decode(&response); err != nil {
			t.Fatal(err)
		}
		responses = append(responses, response)
	}
	if len(responses) != 4 {
		t.Fatalf("responses = %d, output = %s", len(responses), output.String())
	}
	if responses[0].OK || responses[0].Error == nil || !strings.Contains(responses[0].Error.Message, "unknown field") {
		t.Fatalf("unknown-field response = %#v", responses[0])
	}
	if responses[1].OK || responses[1].Error == nil || !strings.Contains(responses[1].Error.Message, "trailing JSON") {
		t.Fatalf("trailing response = %#v", responses[1])
	}
	if responses[2].OK || responses[2].Error == nil || !strings.Contains(responses[2].Error.Message, "duplicate JSON key") {
		t.Fatalf("duplicate-key response = %#v", responses[2])
	}
	if !responses[3].OK || responses[3].RequestID != "good" {
		t.Fatalf("worker did not continue: %#v", responses[3])
	}
}

func TestWorkerReportsFailClosedCapabilityGap(t *testing.T) {
	request := rq3baseline.WorkerRequest{
		SchemaVersion: rq3baseline.WorkerRequestSchema, RequestID: "unsupported", Operation: rq3baseline.OperationRun, Run: testRunSpec(true),
	}
	request.Run.Snapshot.Files[0].FileKind = "symlink"
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	response := handleLine(t.Context(), encoded)
	if response.OK || response.Error == nil || response.Error.Code != "unsupported_capability" || response.Error.CapabilityGap != "symlink_and_special_file_mutation" {
		t.Fatalf("response = %#v", response)
	}
}

func TestWorkerRejectsSemanticallyInvalidEnvelope(t *testing.T) {
	request := rq3baseline.WorkerRequest{
		SchemaVersion: rq3baseline.WorkerRequestSchema, RequestID: "bad-envelope", Operation: rq3baseline.OperationCapabilities, Run: testRunSpec(true),
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	response := handleLine(t.Context(), encoded)
	if response.OK || response.RequestID != request.RequestID || response.Error == nil || response.Error.Code != "invalid_request" {
		t.Fatalf("response = %#v", response)
	}
}

func testRunSpec(rawLeaves bool) *rq3baseline.RunSpec {
	payload := []byte("payload")
	digest := sha256.Sum256(payload)
	mode := uint32(0o644)
	return &rq3baseline.RunSpec{
		System: rq3baseline.SystemMerkleDAGUnixFS,
		Layout: rq3baseline.LayoutSpec{
			Model: "unixfs", FileLayout: "balanced", DirectoryLayout: "basic",
			Chunking:   rq3baseline.ChunkingSpec{Algorithm: "fixed", SizeBytes: 4},
			HAMTFanout: 0, RawFileLeaf: &rawLeaves,
		},
		Snapshot: rq3baseline.Snapshot{
			CommitID: "c1",
			Files: []rq3baseline.FrozenFile{{
				Path: "file.txt", FileKind: rq3baseline.FileKindRegular, PayloadBase64: base64.StdEncoding.EncodeToString(payload), PayloadSHA256: hex.EncodeToString(digest[:]), Mode: &mode,
			}},
		},
		Commits: []rq3baseline.Commit{},
	}
}

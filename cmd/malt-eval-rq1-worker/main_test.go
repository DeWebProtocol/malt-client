package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cid "github.com/ipfs/go-cid"
	mh "github.com/multiformats/go-multihash"
)

func TestDirectCASWorkerEmitsAtomicVerifiedRecordAndSurvivesBadInput(t *testing.T) {
	payload := []byte("locally verified direct CAS payload")
	root, err := cid.Prefix{Version: 1, Codec: cid.Raw, MhType: mh.SHA2_256, MhLength: -1}.Sum(payload)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/healthz" {
			_ = json.NewEncoder(writer).Encode(map[string]string{
				"status": "ok", "evaluation_instance_token": clientTestInstanceToken,
				"evaluation_rq1_cache_observation":        evaluationCacheProfile,
				"evaluation_rq1_read_phases":              "gateway.rq1-read-phases/v1",
				"evaluation_rq1_application_result_cache": "none",
				"evaluation_rq1_os_page_cache":            "uncontrolled",
			})
			return
		}
		if request.URL.Path == "/v1/evaluation/rq1/cache-observation" {
			serveClientCacheObservation(t, writer, request)
			return
		}
		if request.Method != http.MethodGet || request.URL.Path != "/v1/cas/"+root.String() {
			http.NotFound(writer, request)
			return
		}
		if request.Header.Get(evaluationInstanceTokenHeader) != clientTestInstanceToken || request.Header.Get(evaluationOperationHeader) != "read-1" ||
			request.Header.Get(evaluationRouteHeader) != routeDirectCAS || request.Header.Get(evaluationLeaseHeader) != clientTestLease {
			t.Fatalf("route headers = %#v", request.Header)
		}
		writer.Header().Set("Content-Type", "application/octet-stream")
		_, _ = writer.Write(payload)
	}))
	defer server.Close()

	stdin := strings.NewReader("{\"schema_version\":\"malt-rq1-worker-request/v1\",\"operation_id\":\"read-1\",\"segments\":[]}\n{\"schema_version\":\"malt-rq1-worker-request/v1\",\"operation_id\":\"bad\",\"segments\":[],\"unknown\":true}\n")
	var stdout, stderr bytes.Buffer
	err = run([]string{
		"-base-url", server.URL, "-route", routeDirectCAS, "-root", root.String(), "-worker-id", "process-1",
		"-gateway-instance-token", clientTestInstanceToken,
	}, stdin, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
	scanner := bufio.NewScanner(&stdout)
	var records []workerRecord
	for scanner.Scan() {
		var record workerRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatalf("decode output line: %v", err)
		}
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("records = %d, want 2; output=%q", len(records), stdout.String())
	}
	verified := records[0]
	if !verified.Success || verified.OperationID != "read-1" || verified.Route != routeDirectCAS || verified.Endpoint != "verified-bytes" || verified.VerificationRole != "local-direct-cas-cid-link-replay" || verified.Root != root.String() ||
		verified.Target != root.String() || verified.PayloadBytes != uint64(len(payload)) || verified.PayloadSHA256 == "" || verified.Metrics == nil {
		t.Fatalf("verified record = %#v", verified)
	}
	if verified.Metrics.CASGetRequests != 1 || verified.Metrics.CriticalSequentialRounds != 1 || verified.Metrics.BlocksVerified != 1 {
		t.Fatalf("verified metrics = %#v", verified.Metrics)
	}
	if verified.Metrics.CIDVerifyDurationNS == 0 || verified.Metrics.PayloadBindingDurationNS == 0 ||
		verified.Metrics.PayloadBindingDurationNS > verified.Metrics.CIDVerifyDurationNS {
		t.Fatalf("verification phase metrics = %#v", verified.Metrics)
	}
	if verified.Metrics.ProcessPeakRSSBytes == 0 || verified.Metrics.ServerArcTable != (serverPhaseTotal{}) ||
		verified.Metrics.ServerResponseSerialization != (serverPhaseTotal{}) {
		t.Fatalf("resource/server metrics = %#v", verified.Metrics)
	}
	if verified.CacheObservation == nil || verified.CacheObservation.CompletedOperationsBefore != 0 ||
		verified.CacheObservation.ProcessState != "fresh-process-first-operation" || verified.CacheObservation.SuccessfulHTTPRequests != 1 ||
		verified.CacheObservation.GatewayHealth.RawBytes == 0 || verified.CacheObservation.GatewayHealth.OSPageCache != "uncontrolled" {
		t.Fatalf("cache observation = %#v", verified.CacheObservation)
	}
	invalid := records[1]
	if invalid.Success || invalid.FailureClass != "input_invalid" || invalid.Error == "" || invalid.Metrics != nil || invalid.CacheObservation != nil {
		t.Fatalf("invalid record = %#v", invalid)
	}
}

func TestWorkerRejectsInvalidConfigurationAndOversizedLine(t *testing.T) {
	root, err := cid.Prefix{Version: 1, Codec: cid.Raw, MhType: mh.SHA2_256, MhLength: -1}.Sum([]byte("root"))
	if err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-base-url", "http://127.0.0.1", "-route", "trusted", "-root", root.String(), "-worker-id", "p", "-gateway-instance-token", clientTestInstanceToken}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("unsupported worker route was accepted")
	}
	line := strings.Repeat("x", maxWorkerLineBytes+1) + "\n"
	if err := run([]string{"-base-url", "http://127.0.0.1", "-route", routeDirectCAS, "-root", root.String(), "-worker-id", "p", "-gateway-instance-token", clientTestInstanceToken}, strings.NewReader(line), &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("oversized worker request was accepted")
	}
}

func serveClientCacheObservation(t *testing.T, writer http.ResponseWriter, request *http.Request) {
	t.Helper()
	if request.Method != http.MethodPost || request.Header.Get(evaluationInstanceTokenHeader) != clientTestInstanceToken {
		http.Error(writer, "invalid instance token", http.StatusForbidden)
		return
	}
	var wire cacheObservationRequest
	if err := json.NewDecoder(request.Body).Decode(&wire); err != nil {
		http.Error(writer, err.Error(), http.StatusBadRequest)
		return
	}
	requests := uint64(0)
	if wire.Action == "end" {
		if wire.Lease != clientTestLease {
			http.Error(writer, "invalid lease", http.StatusConflict)
			return
		}
		requests = 1
	}
	_ = json.NewEncoder(writer).Encode(cacheObservation{
		Profile: evaluationCacheProfile, Action: wire.Action, OperationID: wire.OperationID, Route: wire.Route,
		Lease: clientTestLease, InstanceToken: clientTestInstanceToken, CompletedOperationsBefore: 0,
		SuccessfulHTTPRequests: requests, ProcessState: "fresh-process-first-operation",
		ApplicationResultCache: "none", OSPageCache: "uncontrolled",
	})
}

const clientTestInstanceToken = "8888888888888888888888888888888888888888888888888888888888888888"
const clientTestLease = "6666666666666666666666666666666666666666666666666666666666666666"

func TestDecodeWorkerRequestRejectsTrailingValueAndMissingSegments(t *testing.T) {
	if _, err := decodeWorkerRequest([]byte(`{"schema_version":"malt-rq1-worker-request/v1","operation_id":"x","segments":[]} {}`)); err == nil {
		t.Fatal("trailing JSON was accepted")
	}
	if _, err := decodeWorkerRequest([]byte(`{"schema_version":"malt-rq1-worker-request/v1","operation_id":"x"}`)); err == nil {
		t.Fatal("omitted segments were accepted")
	}
	if _, err := decodeWorkerRequest([]byte(`{"schema_version":"malt-rq1-worker-request/v1","operation_id":"bad/id","segments":[]}`)); err == nil {
		t.Fatal("path-like operation ID was accepted")
	}
	if _, err := decodeWorkerRequest([]byte(`{"schema_version":"malt-rq1-worker-request/v1","operation_id":"x","segments":["a/b"]}`)); err == nil {
		t.Fatal("slash-encoded segment was accepted")
	}
	if _, err := decodeWorkerRequest([]byte(`{"schema_version":"malt-rq1-worker-request/v1","operation_id":"one","operation_id":"two","segments":[]}`)); err == nil {
		t.Fatal("duplicate worker request key was accepted")
	}
}

func TestStrictEvaluationJSONRejectsDuplicateKeys(t *testing.T) {
	var value cacheObservation
	if err := decodeStrictJSON([]byte(`{"profile":"one","profile":"two"}`), &value); err == nil {
		t.Fatal("duplicate cache-observation key was accepted")
	}
}

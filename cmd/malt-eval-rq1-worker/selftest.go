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
	"slices"
	"strings"
	"sync/atomic"
	"time"

	casmemory "github.com/dewebprotocol/malt-client/internal/cas/memory"
	"github.com/dewebprotocol/malt-client/internal/evaluation/e0selftest"
	"github.com/dewebprotocol/malt-client/merkledag"
	merkledagimport "github.com/dewebprotocol/malt-client/merkledag/importer"
	cid "github.com/ipfs/go-cid"
	car "github.com/ipld/go-car/v2"
	carstorage "github.com/ipld/go-car/v2/storage"
)

const (
	clientRouteSelfTestCorpusSchema = "malt-rq1-client-route-correctness-corpus/v1"
	clientRouteSelfTestToken        = "9999999999999999999999999999999999999999999999999999999999999999"
	clientRouteSelfTestLease        = "7777777777777777777777777777777777777777777777777777777777777777"
)

var clientRouteSelfTestProfiles = map[string]e0selftest.Profile{
	routeCAR: {
		ProfileID:     "rq1-trustless-car-positive-hostile-v1",
		PositiveCases: []string{"car-positive"},
		HostileCases:  []string{"malformed-request", "car-cid-mismatch", "wrong-path"},
	},
	routeDirectCAS: {
		ProfileID:     "rq1-direct-cas-positive-hostile-v1",
		PositiveCases: []string{"direct-cas-positive"},
		HostileCases:  []string{"malformed-request", "cid-content-mismatch", "wrong-path"},
	},
}

var clientRouteSelfTestCapabilities = map[string]string{
	routeCAR:       "rq1.trustless-car",
	routeDirectCAS: "rq1.direct-cas",
}

type clientRouteSelfTestCorpus struct {
	SchemaVersion          string   `json:"schema_version"`
	TrustlessCARPayloadB64 string   `json:"trustless_car_payload_base64"`
	DirectCASPayloadB64    string   `json:"direct_cas_payload_base64"`
	Segments               []string `json:"segments"`
	ChunkBytes             int      `json:"chunk_bytes"`
}

type clientRouteFixture struct {
	store    *casmemory.Store
	root     cid.Cid
	segments []string
	payload  []byte
	evidence []merkledag.MerkleDAGBlock
}

type recordingBlockGetter struct {
	store    *casmemory.Store
	evidence []merkledag.MerkleDAGBlock
}

func (g *recordingBlockGetter) Get(ctx context.Context, key cid.Cid) ([]byte, error) {
	data, err := g.store.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	g.evidence = append(g.evidence, merkledag.MerkleDAGBlock{
		CID: key.String(), Codec: key.Type(), Data: append([]byte(nil), data...),
	})
	return data, nil
}

type selfTestWorkerRunner func(context.Context, string, string, cid.Cid, []string, bool) (workerRecord, error)

func runClientRouteSelfTest(route, corpusPath string, output io.Writer) error {
	return runClientRouteSelfTestWithRunner(route, corpusPath, output, runSelfTestWorkerProcess)
}

func runClientRouteSelfTestWithRunner(route, corpusPath string, output io.Writer, runner selfTestWorkerRunner) error {
	profile, ok := clientRouteSelfTestProfiles[route]
	if !ok || runner == nil {
		return fmt.Errorf("formal E0 self-test route must be %q or %q", routeCAR, routeDirectCAS)
	}
	corpus, err := loadClientRouteSelfTestCorpus(corpusPath)
	if err != nil {
		return err
	}
	carPayload, directPayload, err := corpus.validate()
	if err != nil {
		return err
	}
	payload := carPayload
	if route == routeDirectCAS {
		payload = directPayload
	}
	fixture, err := newClientRouteFixture(payload, corpus.Segments, corpus.ChunkBytes)
	if err != nil {
		return fmt.Errorf("build RQ1 client-route self-test fixture: %w", err)
	}
	results := make([]e0selftest.CaseResult, 0, len(profile.PositiveCases)+len(profile.HostileCases))
	for _, caseID := range append(append([]string(nil), profile.PositiveCases...), profile.HostileCases...) {
		passed, err := runClientRouteSelfTestCase(route, caseID, fixture, runner)
		if err != nil {
			return fmt.Errorf("RQ1 %s self-test %s: %w", route, caseID, err)
		}
		if !passed {
			return fmt.Errorf("RQ1 %s self-test %s did not observe its required accept/reject behavior", route, caseID)
		}
		results = append(results, e0selftest.CaseResult{ID: caseID, Passed: true})
	}
	receipt, err := e0selftest.Issue(clientRouteSelfTestCapabilities[route], profile, results)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(receipt)
}

func loadClientRouteSelfTestCorpus(path string) (clientRouteSelfTestCorpus, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return clientRouteSelfTestCorpus{}, errors.New("RQ1 client-route self-test corpus path must be canonical and absolute")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return clientRouteSelfTestCorpus{}, fmt.Errorf("inspect RQ1 client-route self-test corpus: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxWorkerLineBytes {
		return clientRouteSelfTestCorpus{}, errors.New("RQ1 client-route self-test corpus must be a bounded regular non-symlink file")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return clientRouteSelfTestCorpus{}, errors.New("RQ1 client-route self-test corpus path or parent is symlinked")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return clientRouteSelfTestCorpus{}, err
	}
	var corpus clientRouteSelfTestCorpus
	if err := decodeStrictJSON(data, &corpus); err != nil {
		return clientRouteSelfTestCorpus{}, fmt.Errorf("decode RQ1 client-route self-test corpus: %w", err)
	}
	return corpus, nil
}

func (c clientRouteSelfTestCorpus) validate() ([]byte, []byte, error) {
	if c.SchemaVersion != clientRouteSelfTestCorpusSchema ||
		!slices.Equal(c.Segments, []string{"docs", "payload.bin"}) || c.ChunkBytes != 5 {
		return nil, nil, errors.New("RQ1 client-route self-test corpus has an invalid schema, exact path, or chunk profile")
	}
	carPayload, err := base64.StdEncoding.Strict().DecodeString(c.TrustlessCARPayloadB64)
	if err != nil || len(carPayload) < c.ChunkBytes*2 {
		return nil, nil, errors.New("RQ1 client-route self-test corpus has invalid Trustless-CAR payload bytes")
	}
	directPayload, err := base64.StdEncoding.Strict().DecodeString(c.DirectCASPayloadB64)
	if err != nil || len(directPayload) < c.ChunkBytes*2 {
		return nil, nil, errors.New("RQ1 client-route self-test corpus has invalid Direct-CAS payload bytes")
	}
	if bytes.Equal(carPayload, directPayload) {
		return nil, nil, errors.New("RQ1 client-route self-test payloads must be distinct")
	}
	return carPayload, directPayload, nil
}

func newClientRouteFixture(payload []byte, segments []string, chunkBytes int) (clientRouteFixture, error) {
	store := casmemory.New()
	result, err := merkledagimport.ImportFiles(context.Background(), store, []merkledagimport.File{{
		Path: strings.Join(segments, "/"), Data: append([]byte(nil), payload...), Mode: 0o644,
	}}, merkledagimport.Options{
		Model: merkledagimport.ModelUnixFS, FileLayout: merkledagimport.FileLayoutBalanced,
		DirLayout: merkledagimport.DirLayoutBasic, ChunkSize: chunkBytes,
	})
	if err != nil {
		return clientRouteFixture{}, err
	}
	root, err := cid.Parse(result.Root)
	if err != nil {
		return clientRouteFixture{}, err
	}
	recorder := &recordingBlockGetter{store: store}
	verified, err := merkledag.ReadMerkleDAGDirectCASVerified(context.Background(), recorder, root, segments, nil, nil)
	if err != nil {
		return clientRouteFixture{}, err
	}
	if !bytes.Equal(verified.Data, payload) || !verified.Root.Equals(root) || len(recorder.evidence) == 0 {
		return clientRouteFixture{}, errors.New("generated RQ1 client-route fixture failed local replay")
	}
	return clientRouteFixture{
		store: store, root: root, segments: append([]string(nil), segments...), payload: append([]byte(nil), payload...),
		evidence: append([]merkledag.MerkleDAGBlock(nil), recorder.evidence...),
	}, nil
}

func runClientRouteSelfTestCase(route, caseID string, fixture clientRouteFixture, runner selfTestWorkerRunner) (bool, error) {
	carBytes, err := encodeSelfTestCAR(fixture.root, fixture.evidence, caseID == "car-cid-mismatch")
	if err != nil {
		return false, err
	}
	var routeRequests atomic.Uint64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if serveClientRouteSelfTestControl(writer, request, route, &routeRequests) {
			return
		}
		if !validClientRouteSelfTestHeaders(request, route) {
			http.Error(writer, "invalid RQ1 route binding", http.StatusForbidden)
			return
		}
		switch route {
		case routeCAR:
			if request.Method != http.MethodPost || request.URL.Path != "/v1/compat/merkledag/car/read" || request.Header.Get("Content-Type") != "application/json" {
				http.NotFound(writer, request)
				return
			}
			body, readErr := io.ReadAll(io.LimitReader(request.Body, maxWorkerLineBytes+1))
			var wire merkledag.MerkleDAGReadRequest
			if readErr != nil || len(body) > maxWorkerLineBytes || decodeStrictJSON(body, &wire) != nil || wire.Root != fixture.root.String() {
				http.Error(writer, "invalid CAR read request", http.StatusBadRequest)
				return
			}
			routeRequests.Add(1)
			writer.Header().Set("Content-Type", merkledag.MerkleDAGCARReadMediaType)
			_, _ = writer.Write(carBytes)
		case routeDirectCAS:
			if request.Method != http.MethodGet || !strings.HasPrefix(request.URL.Path, "/v1/cas/") {
				http.NotFound(writer, request)
				return
			}
			key, parseErr := cid.Parse(strings.TrimPrefix(request.URL.Path, "/v1/cas/"))
			if parseErr != nil {
				http.Error(writer, "invalid CID", http.StatusBadRequest)
				return
			}
			data, getErr := fixture.store.Get(request.Context(), key)
			if getErr != nil {
				http.NotFound(writer, request)
				return
			}
			if caseID == "cid-content-mismatch" && key.Equals(fixture.root) {
				data[0] ^= 0xff
			}
			routeRequests.Add(1)
			writer.Header().Set("Content-Type", "application/octet-stream")
			_, _ = writer.Write(data)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	segments := append([]string(nil), fixture.segments...)
	if caseID == "wrong-path" {
		segments = []string{"docs", "missing.bin"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	record, err := runner(ctx, server.URL, route, fixture.root, segments, caseID == "malformed-request")
	if err != nil {
		return false, err
	}
	requests := routeRequests.Load()
	if record.Route != route || record.Root != fixture.root.String() || record.Endpoint != "verified-bytes" {
		return false, nil
	}
	switch caseID {
	case "car-positive", "direct-cas-positive":
		digest := sha256.Sum256(fixture.payload)
		role := "local-car-cid-link-replay"
		if route == routeDirectCAS {
			role = "local-direct-cas-cid-link-replay"
		}
		if !record.Success || record.VerificationRole != role || record.PayloadBytes != uint64(len(fixture.payload)) ||
			record.PayloadSHA256 != hex.EncodeToString(digest[:]) || record.Metrics == nil || requests == 0 {
			return false, nil
		}
		if record.Metrics.CIDVerifyDurationNS == 0 || record.Metrics.PayloadBindingDurationNS == 0 ||
			record.Metrics.PayloadBindingDurationNS > record.Metrics.CIDVerifyDurationNS {
			return false, nil
		}
		if route == routeCAR {
			return record.Metrics.NetworkRequests == 1 && record.Metrics.CARBlocks > 0 && record.Metrics.BlocksVerified > 0, nil
		}
		return record.Metrics.CASGetRequests > 0 && record.Metrics.CASGetRequests == record.Metrics.BlocksVerified, nil
	case "malformed-request":
		return !record.Success && record.FailureClass == "input_invalid" && requests == 0, nil
	case "car-cid-mismatch", "cid-content-mismatch", "wrong-path":
		return !record.Success && record.FailureClass == "local_verification" && record.Error != "" && requests > 0, nil
	default:
		return false, fmt.Errorf("unknown RQ1 client-route self-test case %q", caseID)
	}
}

func encodeSelfTestCAR(root cid.Cid, evidence []merkledag.MerkleDAGBlock, corrupt bool) ([]byte, error) {
	var output bytes.Buffer
	writable, err := carstorage.NewWritable(&output, []cid.Cid{root}, car.WriteAsCarV1(true))
	if err != nil {
		return nil, err
	}
	for index, item := range evidence {
		key, err := cid.Parse(item.CID)
		if err != nil {
			return nil, err
		}
		data := append([]byte(nil), item.Data...)
		if corrupt && index == 0 {
			data[0] ^= 0xff
		}
		if err := writable.Put(context.Background(), key.KeyString(), data); err != nil {
			return nil, err
		}
	}
	if err := writable.Finalize(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func serveClientRouteSelfTestControl(writer http.ResponseWriter, request *http.Request, route string, routeRequests *atomic.Uint64) bool {
	switch request.URL.Path {
	case "/healthz":
		_ = json.NewEncoder(writer).Encode(map[string]string{
			"status": "ok", "evaluation_instance_token": clientRouteSelfTestToken,
			"evaluation_rq1_cache_observation":        evaluationCacheProfile,
			"evaluation_rq1_read_phases":              "gateway.rq1-read-phases/v1",
			"evaluation_rq1_application_result_cache": "none",
			"evaluation_rq1_os_page_cache":            "uncontrolled",
		})
		return true
	case "/v1/evaluation/rq1/cache-observation":
		if request.Method != http.MethodPost || request.Header.Get(evaluationInstanceTokenHeader) != clientRouteSelfTestToken {
			http.Error(writer, "invalid RQ1 cache observation request", http.StatusForbidden)
			return true
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, (64<<10)+1))
		var wire cacheObservationRequest
		if err != nil || len(body) > 64<<10 || decodeStrictJSON(body, &wire) != nil || wire.Profile != evaluationCacheProfile || wire.Route != route || wire.OperationID != "read-1" {
			http.Error(writer, "invalid RQ1 cache observation binding", http.StatusBadRequest)
			return true
		}
		requests := uint64(0)
		if wire.Action == "end" {
			if wire.Lease != clientRouteSelfTestLease {
				http.Error(writer, "invalid RQ1 cache lease", http.StatusConflict)
				return true
			}
			requests = routeRequests.Load()
		} else if wire.Action != "begin" || wire.Lease != "" || routeRequests.Load() != 0 {
			http.Error(writer, "invalid RQ1 cache action", http.StatusConflict)
			return true
		}
		_ = json.NewEncoder(writer).Encode(cacheObservation{
			Profile: evaluationCacheProfile, Action: wire.Action, OperationID: wire.OperationID, Route: wire.Route,
			Lease: clientRouteSelfTestLease, InstanceToken: clientRouteSelfTestToken, CompletedOperationsBefore: 0,
			SuccessfulHTTPRequests: requests, ProcessState: "fresh-process-first-operation",
			ApplicationResultCache: "none", OSPageCache: "uncontrolled",
		})
		return true
	default:
		return false
	}
}

func validClientRouteSelfTestHeaders(request *http.Request, route string) bool {
	return request.Header.Get(evaluationInstanceTokenHeader) == clientRouteSelfTestToken &&
		request.Header.Get(evaluationOperationHeader) == "read-1" && request.Header.Get(evaluationRouteHeader) == route &&
		request.Header.Get(evaluationLeaseHeader) == clientRouteSelfTestLease
}

func runSelfTestWorkerProcess(ctx context.Context, baseURL, route string, root cid.Cid, segments []string, malformed bool) (workerRecord, error) {
	executable, err := os.Executable()
	if err != nil {
		return workerRecord{}, err
	}
	input, args, err := selfTestWorkerInvocation(baseURL, route, root, segments, malformed)
	if err != nil {
		return workerRecord{}, err
	}
	command := exec.CommandContext(ctx, executable, args...)
	command.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		return workerRecord{}, fmt.Errorf("run RQ1 production worker process: %w (stderr=%q)", err, strings.TrimSpace(stderr.String()))
	}
	if stderr.Len() != 0 {
		return workerRecord{}, fmt.Errorf("RQ1 production worker emitted stderr %q", strings.TrimSpace(stderr.String()))
	}
	return decodeSelfTestWorkerRecord(stdout.Bytes())
}

func runSelfTestWorkerInProcess(ctx context.Context, baseURL, route string, root cid.Cid, segments []string, malformed bool) (workerRecord, error) {
	if err := ctx.Err(); err != nil {
		return workerRecord{}, err
	}
	input, args, err := selfTestWorkerInvocation(baseURL, route, root, segments, malformed)
	if err != nil {
		return workerRecord{}, err
	}
	var stdout, stderr bytes.Buffer
	if err := run(args, bytes.NewReader(input), &stdout, &stderr); err != nil {
		return workerRecord{}, fmt.Errorf("run nested RQ1 worker: %w (stderr=%q)", err, strings.TrimSpace(stderr.String()))
	}
	if stderr.Len() != 0 {
		return workerRecord{}, fmt.Errorf("nested RQ1 worker emitted stderr %q", strings.TrimSpace(stderr.String()))
	}
	return decodeSelfTestWorkerRecord(stdout.Bytes())
}

func selfTestWorkerInvocation(baseURL, route string, root cid.Cid, segments []string, malformed bool) ([]byte, []string, error) {
	request := workerRequest{SchemaVersion: workerRequestSchema, OperationID: "read-1", Segments: append([]string(nil), segments...)}
	input, err := json.Marshal(request)
	if err != nil {
		return nil, nil, err
	}
	if malformed {
		input = []byte(`{"schema_version":"malt-rq1-worker-request/v1","operation_id":"read-1","segments":[],"unknown":true}`)
	}
	input = append(input, '\n')
	args := []string{
		"-base-url", baseURL, "-route", route, "-root", root.String(), "-worker-id", "e0-process",
		"-gateway-instance-token", clientRouteSelfTestToken, "-request-timeout", "20s",
	}
	return input, args, nil
}

func decodeSelfTestWorkerRecord(data []byte) (workerRecord, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var record workerRecord
	if err := decoder.Decode(&record); err != nil {
		return workerRecord{}, err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return workerRecord{}, errors.New("RQ1 worker process emitted trailing output")
	}
	return record, nil
}

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dewebprotocol/malt-client/internal/evaluation/e0selftest"
)

func TestClientRouteFormalE0SelfTestsIssueBoundReceipts(t *testing.T) {
	corpus := writeClientRouteSelfTestCorpus(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{routeCAR, routeDirectCAS} {
		t.Run(route, func(t *testing.T) {
			profile := clientRouteSelfTestProfiles[route]
			environment, err := e0selftest.BuildInvocationEnvironment(
				clientRouteSelfTestCapabilities[route], profile,
				e0selftest.InputFile{FileID: "rq1-client-route-worker", Path: executable},
				[]e0selftest.InputFile{{FileID: "rq1-client-route-corpus", Path: corpus}},
				[]string{"rq1-client-route-corpus"},
			)
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv(e0selftest.InvocationEnvironment, environment)
			var output bytes.Buffer
			if err := runClientRouteSelfTestWithRunner(route, corpus, &output, runSelfTestWorkerInProcess); err != nil {
				t.Fatal(err)
			}
			var receipt e0selftest.Receipt
			if err := json.Unmarshal(output.Bytes(), &receipt); err != nil {
				t.Fatal(err)
			}
			if err := receipt.Validate(); err != nil {
				t.Fatal(err)
			}
			if receipt.CapabilityID != clientRouteSelfTestCapabilities[route] || receipt.Positive.Executed != 1 || receipt.Hostile.Executed != 3 ||
				receipt.TestedExecutable.FileID != "rq1-client-route-worker" || len(receipt.TestedInputs) != 1 || receipt.TestedInputs[0].FileID != "rq1-client-route-corpus" {
				t.Fatalf("receipt = %+v", receipt)
			}
		})
	}
}

func TestClientRouteFormalE0RejectsCapabilityRelabelAndRuntimeFlags(t *testing.T) {
	corpus := writeClientRouteSelfTestCorpus(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	profile := clientRouteSelfTestProfiles[routeCAR]
	environment, err := e0selftest.BuildInvocationEnvironment(
		clientRouteSelfTestCapabilities[routeDirectCAS], profile,
		e0selftest.InputFile{FileID: "rq1-client-route-worker", Path: executable},
		[]e0selftest.InputFile{{FileID: "rq1-client-route-corpus", Path: corpus}},
		[]string{"rq1-client-route-corpus"},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(e0selftest.InvocationEnvironment, environment)
	var output bytes.Buffer
	if err := runClientRouteSelfTestWithRunner(routeCAR, corpus, &output, runSelfTestWorkerInProcess); err == nil || !strings.Contains(err.Error(), "does not match E0 invocation") {
		t.Fatalf("route/capability relabel error = %v", err)
	}
	if output.Len() != 0 {
		t.Fatalf("relabel emitted receipt %q", output.String())
	}
	if err := run([]string{"-route", routeCAR, "-self-test-corpus", corpus, "-base-url", "http://127.0.0.1"}, bytes.NewReader(nil), &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("formal self-test accepted runtime Gateway flags")
	}
}

func TestClientRouteSelfTestProfileDigestsAreStable(t *testing.T) {
	want := map[string]string{
		routeCAR:       "89fbb5b13a51fe0b1a2fdc867f0aa27cb5f9be86aaaa0ef9eaf3239769e799f2",
		routeDirectCAS: "04cd42d5dfeef2607600e0594ab11fbc1edf05ca563e752006d0cfc42f5d4d1a",
	}
	for route, profile := range clientRouteSelfTestProfiles {
		contract, err := profile.Contract()
		if err != nil {
			t.Fatal(err)
		}
		if contract.ProfileSHA256 != want[route] {
			t.Fatalf("%s profile digest = %s", route, contract.ProfileSHA256)
		}
	}
}

func TestClientRouteSelfTestCorpusRejectsDrift(t *testing.T) {
	path := writeClientRouteSelfTestCorpus(t)
	corpus, err := loadClientRouteSelfTestCorpus(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := corpus.validate(); err != nil {
		t.Fatal(err)
	}
	corpus.Segments = []string{"payload.bin"}
	if _, _, err := corpus.validate(); err == nil {
		t.Fatal("client-route corpus accepted a changed semantic path")
	}
	corpus, err = loadClientRouteSelfTestCorpus(path)
	if err != nil {
		t.Fatal(err)
	}
	corpus.DirectCASPayloadB64 = corpus.TrustlessCARPayloadB64
	if _, _, err := corpus.validate(); err == nil {
		t.Fatal("client-route corpus accepted route-aliased payloads")
	}
}

func writeClientRouteSelfTestCorpus(t *testing.T) string {
	t.Helper()
	value := clientRouteSelfTestCorpus{
		SchemaVersion:          clientRouteSelfTestCorpusSchema,
		TrustlessCARPayloadB64: base64.StdEncoding.EncodeToString([]byte("unit fixture for CAR verification")),
		DirectCASPayloadB64:    base64.StdEncoding.EncodeToString([]byte("unit fixture for direct CAS replay")),
		Segments:               []string{"docs", "payload.bin"}, ChunkBytes: 5,
	}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "rq1-client-route-corpus.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

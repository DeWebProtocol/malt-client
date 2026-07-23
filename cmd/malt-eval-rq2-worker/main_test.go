package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestParseFlagsRequiresExplicitLowPowerClassification(t *testing.T) {
	base := []string{
		"-gateway-base-url", "http://127.0.0.1:8080", "-fixture", "/tmp/fixture",
		"-worker-id", "worker", "-platform-id", "host", "-client-kind", "native",
		"-backend", "kzg", "-lifecycle", "native-long-lived",
		"-gateway-instance-token", strings.Repeat("a", 64),
		"-machine-descriptor", "/tmp/machine.json", "-machine-descriptor-sha256", strings.Repeat("c", 64), "-machine-descriptor-bytes", "1",
	}
	if _, err := parseFlags(base, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "low-power-arm") {
		t.Fatalf("missing low-power classification error = %v", err)
	}
	config, err := parseFlags(append(base, "-low-power-arm=false"), &bytes.Buffer{})
	if err != nil || config.lowPowerARM {
		t.Fatalf("explicit host classification = %#v, %v", config, err)
	}
}

func TestRunFailsClosedOnGatewayInstanceTokenMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/healthz" {
			http.NotFound(response, request)
			return
		}
		_, _ = io.WriteString(response, `{"status":"ok","evaluation_instance_token":"`+strings.Repeat("b", 64)+`"}`)
	}))
	defer server.Close()
	fixture := filepath.Join(t.TempDir(), "fixture.bin")
	if err := os.WriteFile(fixture, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{
		"-gateway-base-url", server.URL, "-fixture", fixture, "-worker-id", "worker", "-platform-id", "host",
		"-client-kind", "native", "-backend", "kzg", "-lifecycle", "native-long-lived",
		"-low-power-arm=false", "-gateway-instance-token", strings.Repeat("a", 64), "-request-timeout", "5s",
		"-machine-descriptor", "/tmp/machine.json", "-machine-descriptor-sha256", strings.Repeat("c", 64), "-machine-descriptor-bytes", "1",
	}
	err := run(args, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "exact registered disposable instance token") {
		t.Fatalf("token mismatch error = %v", err)
	}
}

func TestReadFixtureRejectsSymlinkAndDetectsContent(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "fixture.bin")
	if err := os.WriteFile(target, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := readFixture(target)
	if err != nil || string(data) != "fixture" {
		t.Fatalf("read fixture = %q, %v", data, err)
	}
	link := filepath.Join(directory, "fixture-link")
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if _, err := readFixture(link); err == nil {
		t.Fatal("fixture symlink was accepted")
	}
}

func TestDecodeWorkerRequestRejectsUnknownAndTrailingJSON(t *testing.T) {
	valid := `{"schema_version":"malt-rq2-worker-request/v1","worker_id":"worker","request_id":"preflight","record_kind":"preflight","session_id":"session","client_kind":"native","platform_id":"host","backend":"kzg","lifecycle":"native-long-lived","fixture_id":"fixture","measured":false}`
	if _, err := decodeWorkerRequest([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for _, hostile := range []string{
		strings.TrimSuffix(valid, "}") + `,"unknown":true}`,
		strings.Replace(valid, `"worker_id":"worker"`, `"worker_id":"worker","worker_id":"other"`, 1),
		valid + `{}`,
	} {
		if _, err := decodeWorkerRequest([]byte(hostile)); err == nil {
			t.Fatalf("hostile request was accepted: %s", hostile)
		}
	}
}

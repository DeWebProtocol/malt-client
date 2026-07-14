package daemon

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dewebprotocol/malt-client/internal/truststore"
)

func TestLifecycleIdentityIsAuthenticatedAndNotExposedByHealth(t *testing.T) {
	store, err := truststore.Open(filepath.Join(t.TempDir(), "roots.json"))
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewWithInstance(store, "managed-instance")
	if err != nil {
		t.Fatal(err)
	}

	healthReq := httptest.NewRequest(http.MethodGet, "/health", nil)
	healthRec := httptest.NewRecorder()
	server.Handler().ServeHTTP(healthRec, healthReq)
	var health map[string]any
	if err := json.Unmarshal(healthRec.Body.Bytes(), &health); err != nil {
		t.Fatal(err)
	}
	if _, ok := health["instance"]; ok {
		t.Fatalf("health exposed lifecycle instance: %#v", health)
	}

	for _, test := range []struct {
		name   string
		token  string
		status int
	}{
		{name: "missing", status: http.StatusUnauthorized},
		{name: "wrong", token: "other-instance", status: http.StatusUnauthorized},
		{name: "matching", token: "managed-instance", status: http.StatusOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/_lifecycle/identity", nil)
			if test.token != "" {
				req.Header.Set(lifecycleInstanceHeader, test.token)
			}
			rec := httptest.NewRecorder()
			server.Handler().ServeHTTP(rec, req)
			if rec.Code != test.status {
				t.Fatalf("status = %d, want %d", rec.Code, test.status)
			}
		})
	}
}

func TestLocalAPIKeepsCandidateSeparate(t *testing.T) {
	store, err := truststore.Open(filepath.Join(t.TempDir(), "roots.json"))
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	root := "bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku"
	req := httptest.NewRequest(http.MethodPut, "/v1/roots/docs", strings.NewReader(`{"root":"`+root+`","profile":"unixfs"}`))
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("trust status=%d body=%s", rec.Code, rec.Body.String())
	}
	record, err := store.Get("docs")
	if err != nil || record.AcceptedRoot != root {
		t.Fatalf("record=%#v err=%v", record, err)
	}
}

func TestListenCreatesPrivateUnixSocket(t *testing.T) {
	store, err := truststore.Open(filepath.Join(t.TempDir(), "roots.json"))
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(t.TempDir(), "client.sock")
	listener, err := server.Listen(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	info, err := os.Stat(socket)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %#o, want 0600", info.Mode().Perm())
	}
}

func TestListenRefusesToReplaceRegularFile(t *testing.T) {
	store, err := truststore.Open(filepath.Join(t.TempDir(), "roots.json"))
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(t.TempDir(), "client.sock")
	if err := os.WriteFile(socket, []byte("do not replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Listen(socket); err == nil {
		t.Fatal("Listen replaced a non-socket path")
	}
}

func TestListenRefusesToReplaceLiveUnixSocket(t *testing.T) {
	store, err := truststore.Open(filepath.Join(t.TempDir(), "roots.json"))
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(t.TempDir(), "client.sock")
	live, err := net.Listen("unix", socket)
	if err != nil {
		t.Skipf("unix sockets are unavailable: %v", err)
	}
	defer live.Close()
	if _, err := server.Listen(socket); err == nil || !strings.Contains(err.Error(), "live socket") {
		t.Fatalf("Listen error = %v, want live-socket refusal", err)
	}
}

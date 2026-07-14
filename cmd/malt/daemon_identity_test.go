package main

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestStopDaemonSignalsOnlyMatchingLiveInstance(t *testing.T) {
	var stopped atomic.Bool
	socketPath := serveLifecycleTestDaemon(t, "live-instance", &stopped)
	state := daemonState{PID: 4242, Instance: "live-instance"}
	if err := writeDaemonState(pidPath(socketPath), state); err != nil {
		t.Fatal(err)
	}
	signals := 0
	err := stopDaemonWithSignal(socketPath, func(pid int) error {
		signals++
		if pid != state.PID {
			t.Fatalf("signal pid = %d, want %d", pid, state.PID)
		}
		stopped.Store(true)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if signals != 1 {
		t.Fatalf("signals = %d, want 1", signals)
	}
	if _, err := os.Stat(pidPath(socketPath)); !os.IsNotExist(err) {
		t.Fatalf("daemon state was not removed: %v", err)
	}
}

func TestStopDaemonRejectsMismatchedLiveInstanceWithoutSignaling(t *testing.T) {
	var stopped atomic.Bool
	socketPath := serveLifecycleTestDaemon(t, "live-instance", &stopped)
	if err := writeDaemonState(pidPath(socketPath), daemonState{PID: 4242, Instance: "stale-instance"}); err != nil {
		t.Fatal(err)
	}
	signals := 0
	err := stopDaemonWithSignal(socketPath, func(int) error {
		signals++
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "cannot be verified") {
		t.Fatalf("stopDaemonWithSignal error = %v, want identity rejection", err)
	}
	if signals != 0 {
		t.Fatalf("signals = %d, want 0", signals)
	}
	if got, err := readDaemonState(pidPath(socketPath)); err != nil || got.Instance != "stale-instance" {
		t.Fatalf("unverified daemon state should be preserved: got %#v, err %v", got, err)
	}
}

func TestStopDaemonRejectsUnavailableHealthWithoutSignaling(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "missing.sock")
	if err := writeDaemonState(pidPath(socketPath), daemonState{PID: 4242, Instance: "stale-instance"}); err != nil {
		t.Fatal(err)
	}
	signals := 0
	err := stopDaemonWithSignal(socketPath, func(int) error {
		signals++
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "cannot be verified") {
		t.Fatalf("stopDaemonWithSignal error = %v, want unverifiable identity", err)
	}
	if signals != 0 {
		t.Fatalf("signals = %d, want 0", signals)
	}
	if got, err := readDaemonState(pidPath(socketPath)); err != nil || got.Instance != "stale-instance" {
		t.Fatalf("unavailable daemon state should be preserved: got %#v, err %v", got, err)
	}
}

func TestStopDaemonRejectsLegacyPIDFileWithoutSignaling(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "missing.sock")
	if err := os.WriteFile(pidPath(socketPath), []byte("4242\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	signals := 0
	err := stopDaemonWithSignal(socketPath, func(int) error {
		signals++
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "decode daemon state") {
		t.Fatalf("stopDaemonWithSignal error = %v, want legacy-state rejection", err)
	}
	if signals != 0 {
		t.Fatalf("signals = %d, want 0", signals)
	}
	if data, err := os.ReadFile(pidPath(socketPath)); err != nil || string(data) != "4242\n" {
		t.Fatalf("legacy daemon state should be preserved for manual recovery: data %q, err %v", data, err)
	}
}

func TestDaemonStateIsPrivateJSONAndEnvironmentIsReplaced(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "daemon.pid")
	want := daemonState{PID: 4242, Instance: "managed-instance"}
	if err := os.WriteFile(statePath, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeDaemonState(statePath, want); err != nil {
		t.Fatal(err)
	}
	got, err := readDaemonState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("state = %#v, want %#v", got, want)
	}
	info, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %#o, want 0600", info.Mode().Perm())
	}
	env := withDaemonInstanceEnv([]string{"PATH=/bin", daemonInstanceEnv + "=old"}, "new")
	joined := strings.Join(env, "\n")
	if strings.Contains(joined, daemonInstanceEnv+"=old") || strings.Count(joined, daemonInstanceEnv+"=new") != 1 {
		t.Fatalf("environment = %v", env)
	}
}

func TestRemoveSocketIfMatchDoesNotRemoveReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.sock")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldFile, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer oldFile.Close()
	oldInfo, err := oldFile.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := removeSocketIfMatch(path, oldInfo); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("replacement was removed: %v", err)
	}
	if string(data) != "replacement" {
		t.Fatalf("replacement content = %q", data)
	}
}

func TestDaemonLifecycleLockRejectsConcurrentOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.lifecycle.lock")
	unlock, err := acquireDaemonLifecycleLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acquireDaemonLifecycleLock(path); err == nil || !strings.Contains(err.Error(), "in progress") {
		t.Fatalf("second lock error = %v, want lifecycle contention", err)
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
	unlock, err = acquireDaemonLifecycleLock(path)
	if err != nil {
		t.Fatalf("lock was not reusable after release: %v", err)
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
}

func serveLifecycleTestDaemon(t *testing.T, instance string, stopped *atomic.Bool) string {
	t.Helper()
	socketPath := filepath.Join(t.TempDir(), "daemon.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Skipf("unix sockets are unavailable: %v", err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/_lifecycle/identity" || stopped.Load() {
			http.Error(w, "not running", http.StatusServiceUnavailable)
			return
		}
		if r.Header.Get(daemonInstanceHeader) != instance {
			http.Error(w, "identity mismatch", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})}
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
	})
	go func() { _ = server.Serve(listener) }()
	return socketPath
}

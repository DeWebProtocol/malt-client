//go:build linux

package daemon

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateSocketPathUsesLinuxSunPathLimit(t *testing.T) {
	if err := validateSocketPath(strings.Repeat("x", 107)); err != nil {
		t.Fatalf("107-byte Linux socket path rejected: %v", err)
	}
	if err := validateSocketPath(strings.Repeat("x", 108)); err == nil {
		t.Fatal("108-byte Linux socket path unexpectedly accepted")
	}
}

func TestListenRejectsOverlongAliasWithoutRemovingLiveSocket(t *testing.T) {
	socketPath := shortSocketPath(t)
	live, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Skipf("unix sockets are unavailable: %v", err)
	}
	defer live.Close()

	longAlias := filepath.Dir(socketPath) + "/" + strings.Repeat("./", 64) + filepath.Base(socketPath)
	if len([]byte(longAlias)) <= 107 {
		t.Fatalf("test alias is only %d bytes", len([]byte(longAlias)))
	}
	if _, err := os.Lstat(longAlias); err != nil {
		t.Fatalf("overlong alias must resolve to the live socket for this regression test: %v", err)
	}

	if _, err := new(Server).Listen(longAlias); err == nil || !strings.Contains(err.Error(), "at most 107") {
		t.Fatalf("Listen error = %v, want Linux socket path length rejection", err)
	}
	if _, err := os.Lstat(socketPath); err != nil {
		t.Fatalf("live socket was removed after rejecting overlong alias: %v", err)
	}
	conn, err := net.DialTimeout("unix", socketPath, time.Second)
	if err != nil {
		t.Fatalf("live socket no longer accepts connections: %v", err)
	}
	_ = conn.Close()
}

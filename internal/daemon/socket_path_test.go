package daemon

import (
	"strings"
	"testing"
)

func TestValidateSocketPathLength(t *testing.T) {
	if err := validateSocketPathLength("/tmp/client.sock", 16); err != nil {
		t.Fatalf("short socket path rejected: %v", err)
	}
	err := validateSocketPathLength(strings.Repeat("x", 17), 16)
	if err == nil || !strings.Contains(err.Error(), "configure a shorter daemon.socket_path") {
		t.Fatalf("long socket path error = %v", err)
	}
}

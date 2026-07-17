//go:build darwin

package daemon

import (
	"strings"
	"testing"
)

func TestValidateSocketPathUsesDarwinSunPathLimit(t *testing.T) {
	if err := validateSocketPath(strings.Repeat("x", 103)); err != nil {
		t.Fatalf("103-byte Darwin socket path rejected: %v", err)
	}
	if err := validateSocketPath(strings.Repeat("x", 104)); err == nil {
		t.Fatal("104-byte Darwin socket path unexpectedly accepted")
	}
}

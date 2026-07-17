//go:build dragonfly || freebsd || netbsd || openbsd

package daemon

import (
	"strings"
	"testing"
)

func TestValidateSocketPathUsesBSDSunPathLimit(t *testing.T) {
	if err := validateSocketPath(strings.Repeat("x", 103)); err != nil {
		t.Fatalf("103-byte BSD socket path rejected: %v", err)
	}
	if err := validateSocketPath(strings.Repeat("x", 104)); err == nil {
		t.Fatal("104-byte BSD socket path unexpectedly accepted")
	}
}

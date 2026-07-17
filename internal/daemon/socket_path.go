package daemon

import (
	"fmt"
	"strings"
)

// ValidateSocketPath checks the configured local daemon endpoint before any
// lifecycle code creates directories, locks, logs, or child processes.
func ValidateSocketPath(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("daemon socket path is empty")
	}
	if strings.IndexByte(path, 0) >= 0 {
		return fmt.Errorf("daemon socket path contains a NUL byte: configure daemon.socket_path without NUL bytes")
	}
	return validateSocketPath(path)
}

func validateSocketPathLength(path string, maxBytes int) error {
	if len([]byte(path)) <= maxBytes {
		return nil
	}
	return fmt.Errorf("daemon socket path is %d bytes; this platform allows at most %d: configure a shorter daemon.socket_path", len([]byte(path)), maxBytes)
}

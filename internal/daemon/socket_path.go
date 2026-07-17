package daemon

import "fmt"

func validateSocketPathLength(path string, maxBytes int) error {
	if len([]byte(path)) <= maxBytes {
		return nil
	}
	return fmt.Errorf("daemon socket path is %d bytes; this platform allows at most %d: configure a shorter daemon.socket_path", len([]byte(path)), maxBytes)
}

//go:build !windows

package daemon

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func (s *Server) Listen(socketPath string) (net.Listener, error) {
	if strings.TrimSpace(socketPath) == "" {
		return nil, fmt.Errorf("daemon socket path is empty")
	}
	if err := validateSocketPath(socketPath); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		return nil, err
	}
	if err := removeStaleSocket(socketPath); err != nil {
		return nil, err
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = listener.Close()
		return nil, err
	}
	return listener, nil
}

func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to replace non-socket path %s", path)
	}
	conn, dialErr := net.DialTimeout("unix", path, 250*time.Millisecond)
	if dialErr == nil {
		_ = conn.Close()
		return fmt.Errorf("refusing to replace live socket %s", path)
	}
	return os.Remove(path)
}

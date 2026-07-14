//go:build windows

package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/Microsoft/go-winio"
)

// PipeName maps the configured daemon endpoint path to a stable local named
// pipe. The configured value remains portable across client config files.
func PipeName(endpoint string) string {
	digest := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(endpoint))))
	return `\\.\pipe\malt-client-` + hex.EncodeToString(digest[:16])
}

func (s *Server) Listen(endpoint string) (net.Listener, error) {
	if strings.TrimSpace(endpoint) == "" {
		return nil, fmt.Errorf("daemon endpoint is empty")
	}
	return winio.ListenPipe(PipeName(endpoint), &winio.PipeConfig{
		SecurityDescriptor: "D:P(A;;GA;;;SY)(A;;GA;;;OW)",
		MessageMode:        false,
		InputBufferSize:    64 << 10,
		OutputBufferSize:   64 << 10,
	})
}

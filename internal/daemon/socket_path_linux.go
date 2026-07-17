//go:build linux

package daemon

// Linux sockaddr_un.sun_path is 108 bytes including the trailing NUL for a
// filesystem pathname.
func validateSocketPath(path string) error {
	return validateSocketPathLength(path, 107)
}

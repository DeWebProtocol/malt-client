//go:build darwin

package daemon

// Darwin's sockaddr_un.sun_path is 104 bytes including the trailing NUL.
func validateSocketPath(path string) error {
	return validateSocketPathLength(path, 103)
}

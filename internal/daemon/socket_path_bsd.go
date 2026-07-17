//go:build dragonfly || freebsd || netbsd || openbsd

package daemon

// These BSD sockaddr_un.sun_path fields are 104 bytes including the trailing
// NUL for a filesystem pathname.
func validateSocketPath(path string) error {
	return validateSocketPathLength(path, 103)
}

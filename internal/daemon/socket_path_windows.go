//go:build windows

package daemon

// Windows maps the configured endpoint to a bounded hashed named-pipe name, so
// only the common non-empty validation applies.
func validateSocketPath(string) error { return nil }

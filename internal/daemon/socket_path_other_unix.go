//go:build !darwin && !windows && !linux && !dragonfly && !freebsd && !netbsd && !openbsd

package daemon

func validateSocketPath(string) error { return nil }

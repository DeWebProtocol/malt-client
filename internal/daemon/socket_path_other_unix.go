//go:build !darwin && !windows

package daemon

func validateSocketPath(string) error { return nil }

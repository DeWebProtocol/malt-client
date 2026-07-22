//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package bucketsync

func syncParentDirectory(string) error { return nil }

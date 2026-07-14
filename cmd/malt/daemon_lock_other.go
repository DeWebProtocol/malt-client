//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly && !windows

package main

import (
	"fmt"
	"os"
)

func acquireDaemonLifecycleLock(path string) (func() error, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return nil, fmt.Errorf("another daemon lifecycle operation is in progress: %w", err)
		}
		return nil, err
	}
	return func() error {
		closeErr := file.Close()
		removeErr := os.Remove(path)
		if closeErr != nil {
			return closeErr
		}
		return removeErr
	}, nil
}

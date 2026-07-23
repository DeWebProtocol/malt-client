//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly && !windows

package bucketsync

import (
	"fmt"
	"os"
	"time"
)

func acquireLock(path string) (func() error, error) {
	deadline := time.Now().Add(10 * time.Second)
	for {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err == nil {
			return func() error {
				closeErr := file.Close()
				removeErr := os.Remove(path)
				if closeErr != nil {
					return closeErr
				}
				return removeErr
			}, nil
		}
		if !os.IsExist(err) {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for Bucket workspace lock %s; remove a stale lock file if no client process is active", path)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

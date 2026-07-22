//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly && !windows

package bucketsync

import (
	"os"
	"time"
)

func acquireLock(path string) (func() error, error) {
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
		time.Sleep(10 * time.Millisecond)
	}
}

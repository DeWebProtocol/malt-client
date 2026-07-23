//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package bucketsync

import "os"

func syncParentDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	maxFixtureBytes = 32 << 20
	maxWASMBytes    = 256 << 20
	maxSupportBytes = 8 << 20
)

type artifactPin struct {
	path         string
	sha256       string
	bytes        int64
	executable   bool
	allowSymlink bool
	maxBytes     int64
}

type artifactSnapshot struct {
	pin          artifactPin
	resolvedPath string
	symlink      string
}

func loadPinnedArtifact(pin artifactPin, retain bool) (artifactSnapshot, []byte, error) {
	if !filepath.IsAbs(pin.path) || !canonicalSHA256(pin.sha256) || pin.bytes <= 0 || pin.maxBytes <= 0 || pin.bytes > pin.maxBytes {
		return artifactSnapshot{}, nil, fmt.Errorf("invalid artifact pin for %q", pin.path)
	}
	lstat, err := os.Lstat(pin.path)
	if err != nil {
		return artifactSnapshot{}, nil, err
	}
	symlink := ""
	resolved := pin.path
	if lstat.Mode()&os.ModeSymlink != 0 {
		if !pin.allowSymlink {
			return artifactSnapshot{}, nil, fmt.Errorf("artifact %q must not be a symlink", pin.path)
		}
		symlink, err = os.Readlink(pin.path)
		if err != nil {
			return artifactSnapshot{}, nil, err
		}
		resolved, err = filepath.EvalSymlinks(pin.path)
		if err != nil {
			return artifactSnapshot{}, nil, err
		}
	} else if !lstat.Mode().IsRegular() {
		return artifactSnapshot{}, nil, fmt.Errorf("artifact %q is not a regular file", pin.path)
	}
	file, err := os.Open(resolved)
	if err != nil {
		return artifactSnapshot{}, nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() {
		return artifactSnapshot{}, nil, fmt.Errorf("artifact %q did not open as a regular file", pin.path)
	}
	if pin.executable && opened.Mode()&0o111 == 0 {
		return artifactSnapshot{}, nil, fmt.Errorf("artifact %q is not executable", pin.path)
	}
	hash := sha256.New()
	var data []byte
	var writer io.Writer = hash
	if retain {
		data = make([]byte, 0, pin.bytes)
		writer = io.MultiWriter(hash, byteAppender{target: &data})
	}
	written, err := io.Copy(writer, io.LimitReader(file, pin.maxBytes+1))
	if err != nil {
		return artifactSnapshot{}, nil, err
	}
	if written != pin.bytes || written != opened.Size() || hex.EncodeToString(hash.Sum(nil)) != pin.sha256 {
		return artifactSnapshot{}, nil, fmt.Errorf("artifact %q does not match its SHA-256/size pin", pin.path)
	}
	return artifactSnapshot{pin: pin, resolvedPath: resolved, symlink: symlink}, data, nil
}

func (s artifactSnapshot) verify() error {
	current, _, err := loadPinnedArtifact(s.pin, false)
	if err != nil {
		return err
	}
	if current.resolvedPath != s.resolvedPath || current.symlink != s.symlink {
		return fmt.Errorf("artifact %q changed its resolved identity", s.pin.path)
	}
	return nil
}

type byteAppender struct{ target *[]byte }

func (w byteAppender) Write(value []byte) (int, error) {
	*w.target = append(*w.target, value...)
	return len(value), nil
}

func readFixture(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("fixture path must be absolute")
	}
	lstat, err := os.Lstat(path)
	if err != nil || lstat.Mode()&os.ModeSymlink != 0 || !lstat.Mode().IsRegular() {
		return nil, fmt.Errorf("RQ2 browser fixture is not a regular non-symlink file: %v", err)
	}
	if lstat.Size() <= 0 || lstat.Size() > maxFixtureBytes {
		return nil, fmt.Errorf("RQ2 browser fixture size must be in 1..%d bytes", maxFixtureBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(lstat, opened) {
		return nil, fmt.Errorf("RQ2 browser fixture changed before it was opened")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxFixtureBytes+1))
	if err != nil {
		return nil, err
	}
	post, err := os.Lstat(path)
	if err != nil || !os.SameFile(lstat, post) || post.Mode()&os.ModeSymlink != 0 || post.Size() != lstat.Size() || int64(len(data)) != lstat.Size() {
		return nil, fmt.Errorf("RQ2 browser fixture changed while it was read")
	}
	return data, nil
}

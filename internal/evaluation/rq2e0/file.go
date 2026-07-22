package rq2e0

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

var fileIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

// FilePin is a live descriptor for one formal-E0 regular-file input.
type FilePin struct {
	FileID string `json:"e0_file_id"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// DescribeRegularFile rejects symlinks and replacement races while deriving
// the exact digest and size consumed by a production worker.
func DescribeRegularFile(fileID, path string) (FilePin, error) {
	if !fileIDPattern.MatchString(fileID) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return FilePin{}, errors.New("invalid RQ2 E0 regular-file identity or path")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 {
		return FilePin{}, fmt.Errorf("RQ2 E0 input is not a nonempty regular non-symlink file: %v", err)
	}
	file, err := os.Open(path)
	if err != nil {
		return FilePin{}, err
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		_ = file.Close()
		return FilePin{}, errors.New("RQ2 E0 input changed before it was opened")
	}
	hash := sha256.New()
	written, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil {
		return FilePin{}, copyErr
	}
	if closeErr != nil {
		return FilePin{}, closeErr
	}
	post, err := os.Lstat(path)
	if err != nil || post.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, post) || written != info.Size() {
		return FilePin{}, errors.New("RQ2 E0 input changed while it was read")
	}
	return FilePin{FileID: fileID, Path: path, SHA256: hex.EncodeToString(hash.Sum(nil)), Bytes: written}, nil
}

// ValidateFilePin verifies that a declared pin still identifies the same
// regular file at the point where it is consumed.
func ValidateFilePin(pin FilePin) error {
	live, err := DescribeRegularFile(pin.FileID, pin.Path)
	if err != nil {
		return err
	}
	if live.SHA256 != pin.SHA256 || live.Bytes != pin.Bytes {
		return errors.New("RQ2 E0 input does not match its SHA-256/size pin")
	}
	return nil
}

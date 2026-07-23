//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// selfTestDirectoryLease keeps the exact temporary directory inode open for
// the complete controller-ready/workload/controller-stop lifecycle. The
// controller owns a separate descriptor; matching identities bind both
// processes to the same physical directory rather than merely the same path.
type selfTestDirectoryLease struct {
	path      string
	directory *os.File
	identity  directoryIdentity
}

func openSelfTestDirectoryLease(path string) (*selfTestDirectoryLease, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.IsDir() {
		return nil, fmt.Errorf("self-test state path is not a real directory: %v", err)
	}
	directory, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open self-test state directory: %w", err)
	}
	openedInfo, err := directory.Stat()
	if err != nil || !openedInfo.IsDir() || !os.SameFile(pathInfo, openedInfo) {
		_ = directory.Close()
		return nil, fmt.Errorf("self-test state directory changed while opening: %v", err)
	}
	identity, err := identityFromOpenedDirectory(openedInfo)
	if err != nil {
		_ = directory.Close()
		return nil, err
	}
	return &selfTestDirectoryLease{path: path, directory: directory, identity: identity}, nil
}

func identityFromOpenedDirectory(info os.FileInfo) (directoryIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return directoryIdentity{}, errors.New("self-test directory stat does not expose Linux device/inode identity")
	}
	identity := directoryIdentity{Profile: directoryIdentityProfile, Device: uint64(stat.Dev), Inode: stat.Ino}
	if err := identity.validate(); err != nil {
		return directoryIdentity{}, err
	}
	return identity, nil
}

func (lease *selfTestDirectoryLease) Identity() directoryIdentity {
	if lease == nil {
		return directoryIdentity{}
	}
	return lease.identity
}

func (lease *selfTestDirectoryLease) Verify(boundary string) error {
	if lease == nil || lease.directory == nil {
		return errors.New("self-test directory lease is not open")
	}
	openedInfo, err := lease.directory.Stat()
	if err != nil {
		return fmt.Errorf("%s: stat opened self-test directory: %w", boundary, err)
	}
	openedIdentity, err := identityFromOpenedDirectory(openedInfo)
	if err != nil {
		return err
	}
	pathInfo, err := os.Lstat(lease.path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.IsDir() || !os.SameFile(openedInfo, pathInfo) {
		return fmt.Errorf("%s: self-test directory path no longer names the leased inode: %v", boundary, err)
	}
	pathIdentity, err := identityFromOpenedDirectory(pathInfo)
	if err != nil {
		return err
	}
	if openedIdentity != lease.identity || pathIdentity != lease.identity {
		return fmt.Errorf("%s: self-test directory device/inode changed", boundary)
	}
	return nil
}

func (lease *selfTestDirectoryLease) Close() error {
	if lease == nil || lease.directory == nil {
		return nil
	}
	directory := lease.directory
	lease.directory = nil
	return directory.Close()
}

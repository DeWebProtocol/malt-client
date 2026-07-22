//go:build !linux

package main

import "errors"

type selfTestDirectoryLease struct{}

func openSelfTestDirectoryLease(string) (*selfTestDirectoryLease, error) {
	return nil, errors.New("RQ3 physical directory identity requires Linux device/inode support")
}

func (lease *selfTestDirectoryLease) Identity() directoryIdentity { return directoryIdentity{} }

func (lease *selfTestDirectoryLease) Verify(string) error {
	return errors.New("RQ3 physical directory identity requires Linux device/inode support")
}

func (lease *selfTestDirectoryLease) Close() error { return nil }

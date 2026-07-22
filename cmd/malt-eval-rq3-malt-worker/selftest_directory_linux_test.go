//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSelfTestDirectoryLeaseBindsOpenedInodeAcrossPathChecks(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "state")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	lease, err := openSelfTestDirectoryLease(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if err := lease.Identity().validate(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Verify("initial"); err != nil {
		t.Fatal(err)
	}
	displaced := filepath.Join(parent, "displaced")
	if err := os.Rename(path, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := lease.Verify("rebound"); err == nil {
		t.Fatal("path rebinding to a different directory inode was accepted")
	}
}

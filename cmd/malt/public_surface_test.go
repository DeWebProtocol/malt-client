package main

import (
	"slices"
	"testing"

	"github.com/spf13/cobra"
)

func TestRootCommandExposesClientApplicationsOnly(t *testing.T) {
	want := []string{"add", "bucket", "cat", "daemon", "init", "merkledag", "resolve", "rm", "root", "stat", "verify"}
	var got []string
	for _, command := range rootCmd.Commands() {
		if !command.Hidden {
			got = append(got, command.Name())
		}
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("public commands = %v, want %v", got, want)
	}
}

func TestDaemonLifecycleCommandsSuppressCobraNoise(t *testing.T) {
	for _, command := range []*cobra.Command{daemonStartCmd, daemonStatusCmd, daemonStopCmd, daemonRestartCmd} {
		if !command.SilenceUsage || !command.SilenceErrors {
			t.Fatalf("%s must suppress usage and duplicate runtime errors", command.Name())
		}
	}
}

func TestAddExposesBothAuthenticationTargets(t *testing.T) {
	if addCmd.Flag("target") == nil || addCmd.Flag("file-layout") == nil || addCmd.Flag("dir-layout") == nil {
		t.Fatal("add command does not expose Merkle DAG target/layout flags")
	}
}

func TestContentCommandsExposeStableRangeAndCandidateContracts(t *testing.T) {
	if statCmd.Use != "stat <trusted-root|alias> [path]" {
		t.Fatalf("stat use = %q", statCmd.Use)
	}
	if catCmd.Flag("offset") == nil || catCmd.Flag("length") == nil {
		t.Fatal("cat command does not expose paired range flags")
	}
	if rmCmd.Use != "rm <trusted-root|alias> <path>" {
		t.Fatalf("rm use = %q", rmCmd.Use)
	}
	if merkleDAGResolveCmd.Use != "resolve <trusted-root-cid> [path]" || merkleDAGCatCmd.Flag("offset") == nil || merkleDAGCatCmd.Flag("length") == nil {
		t.Fatal("Merkle DAG compatibility command contract is incomplete")
	}
}

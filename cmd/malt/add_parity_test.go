package main

import (
	"strings"
	"testing"

	clientadd "github.com/dewebprotocol/malt-client/application/add"
)

func TestMerkleDAGSummaryDoesNotClaimMALTObjects(t *testing.T) {
	got := formatAddSummary(addSummary{Target: clientadd.TargetMerkleDAG, Files: 2, Bytes: 5, NewRoot: "bafy-root"})
	if !strings.Contains(got, "Merkle DAG UnixFS") || strings.Contains(got, "MALT objects") {
		t.Fatalf("summary = %q", got)
	}
}

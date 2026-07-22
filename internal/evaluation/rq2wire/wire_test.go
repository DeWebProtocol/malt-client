package rq2wire

import "testing"

func TestPipelineApplicabilityMatchesExecutedPayloadWork(t *testing.T) {
	tests := []struct {
		name, client, operation string
		scanChunk, hash         bool
	}{
		{"browser document edit", ClientBrowserWASM, "document-edit-cid-binding-submit", true, true},
		{"browser map replace", ClientBrowserWASM, "map-replace", false, true},
		{"browser list append", ClientBrowserWASM, "list-append", false, true},
		{"native payload", ClientNative, "modify-small-file", true, true},
		{"native rename", ClientNative, "rename", false, false},
		{"native move", ClientNative, "move", false, false},
		{"native delete", ClientNative, "delete-directory-entry", false, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scanChunk, hash := pipelineApplicability(test.client, test.operation)
			if scanChunk != test.scanChunk || hash != test.hash {
				t.Fatalf("pipelineApplicability(%q, %q) = %t/%t, want %t/%t", test.client, test.operation, scanChunk, hash, test.scanChunk, test.hash)
			}
		})
	}
}

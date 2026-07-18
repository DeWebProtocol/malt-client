package unixfs_test

import (
	"bytes"
	"testing"

	unixfs "github.com/dewebprotocol/malt-client/unixfs"
)

func TestMaterializeStagedFilePayloadRejectsDeclaredSizeMismatchBeforePublication(t *testing.T) {
	const chunkSize = 4
	tests := []struct {
		name         string
		data         []byte
		declaredSize int64
		wantNoPut    bool
	}{
		{name: "small short", data: []byte("abc"), declaredSize: 4, wantNoPut: true},
		{name: "small long", data: []byte("abcde"), declaredSize: 4, wantNoPut: true},
		{name: "list short same chunk count", data: []byte("123456789"), declaredSize: 10},
		{name: "list long same chunk count", data: []byte("1234567890"), declaredSize: 9},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			remote := &countingWriterRemote{inner: newRealRemote(t)}
			if _, _, err := unixfs.MaterializeStagedFilePayload(
				t.Context(), remote, remote, bytes.NewReader(test.data), test.declaredSize, chunkSize,
			); err == nil {
				t.Fatal("MaterializeStagedFilePayload accepted a declared-size mismatch")
			}
			if remote.mutationCalls != 0 {
				t.Fatalf("declared-size mismatch performed %d fixed-list root mutations", remote.mutationCalls)
			}
			if test.wantNoPut && remote.blockCalls != 0 {
				t.Fatalf("small declared-size mismatch uploaded %d blocks", remote.blockCalls)
			}
		})
	}
}

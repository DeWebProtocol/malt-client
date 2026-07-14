package main

import (
	"testing"

	cid "github.com/ipfs/go-cid"
)

func mustParseCID(t *testing.T, raw string) cid.Cid {
	t.Helper()
	key, err := cid.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

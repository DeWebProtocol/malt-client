package main

import (
	"context"
	"fmt"

	"github.com/dewebprotocol/malt-client/internal/merkledagimport"
)

func addInputsWithMerkleDAGUnixFS(ctx context.Context, casClient addCASClient, rawInputs []string, opts addBuildOptions) (*addUnixFSResult, error) {
	if opts.Prefix != "" || opts.Wrap || opts.WrapName != "" {
		return nil, fmt.Errorf("merkle-dag target does not support --prefix, --wrap, or --wrap-name yet")
	}
	if len(rawInputs) != 1 {
		return nil, fmt.Errorf("merkle-dag target expects exactly one local path")
	}
	ignoreFilter, err := newAddIgnoreFilter(rawInputs[0], opts.Ignore)
	if err != nil {
		return nil, err
	}
	result, err := merkledagimport.ImportPath(ctx, casClient, rawInputs[0], merkledagimport.Options{
		Model:      opts.Model,
		FileLayout: opts.FileLayout,
		DirLayout:  opts.DirLayout,
		ChunkSize:  addFixedChunkSize,
		Ignore:     ignoreFilter,
	})
	if err != nil {
		return nil, err
	}
	return &addUnixFSResult{Files: result.Files, Bytes: result.Bytes, NewRoot: result.Root}, nil
}

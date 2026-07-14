package main

import (
	"fmt"
	"strings"

	unixfs "github.com/dewebprotocol/malt-client/unixfs/model"
)

const addFixedChunkSize = unixfs.DefaultChunkSize

const (
	addModelUnixFS = "unixfs"

	addLayoutFlat         = "flat"
	addLayoutHierarchical = "hierarchical"
)

type addBuildOptions struct {
	Prefix   string
	Wrap     bool
	WrapName string
	Model    string
	Layout   string
	Ignore   addIgnoreOptions
}

func normalizeAddBuildOptions(opts addBuildOptions) (addBuildOptions, error) {
	opts.Model = normalizeAddToken(opts.Model)
	opts.Layout = normalizeAddToken(opts.Layout)
	if opts.Model == "" {
		opts.Model = addModelUnixFS
	}
	if opts.Model != addModelUnixFS {
		return opts, fmt.Errorf("unsupported add model %q", opts.Model)
	}
	if opts.Layout == "" {
		opts.Layout = addLayoutFlat
	}
	if opts.Layout != addLayoutFlat && opts.Layout != addLayoutHierarchical {
		return opts, fmt.Errorf("unsupported malt unixfs layout %q", opts.Layout)
	}
	return opts, nil
}

func normalizeAddToken(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

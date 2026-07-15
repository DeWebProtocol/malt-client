package application

import (
	"context"
	"fmt"
	"io"

	"github.com/dewebprotocol/malt-client/unixfs"
)

// UnixFS composes locally verified UnixFS operations with accepted/candidate
// root policy. It never promotes writer results automatically.
type UnixFS struct {
	reader unixfs.Reader
	writer unixfs.Writer
	roots  *Roots
}

func NewUnixFS(reader unixfs.Reader, writer unixfs.Writer, roots *Roots) (*UnixFS, error) {
	if reader == nil {
		return nil, fmt.Errorf("unixfs reader is nil")
	}
	if roots == nil {
		return nil, fmt.Errorf("trusted-root application is nil")
	}
	return &UnixFS{reader: reader, writer: writer, roots: roots}, nil
}

func (a *UnixFS) Stat(ctx context.Context, selector, path string) (*unixfs.Stat, error) {
	selected, err := a.roots.Select(selector)
	if err != nil {
		return nil, err
	}
	return a.reader.Stat(ctx, selected.Root, path)
}

func (a *UnixFS) ReadFile(ctx context.Context, selector, path string) (*unixfs.ReadResult, error) {
	selected, err := a.roots.Select(selector)
	if err != nil {
		return nil, err
	}
	return a.reader.ReadFile(ctx, selected.Root, path)
}

func (a *UnixFS) ReadFileRange(ctx context.Context, selector, path string, offset, length uint64) (*unixfs.ReadResult, error) {
	selected, err := a.roots.Select(selector)
	if err != nil {
		return nil, err
	}
	return a.reader.ReadFileRange(ctx, selected.Root, path, offset, length)
}

func (a *UnixFS) EmptyDirectory(ctx context.Context) (*unixfs.WriteResult, error) {
	if a.writer == nil {
		return nil, fmt.Errorf("unixfs writer is nil")
	}
	return requireUnacceptedWrite(a.writer.EmptyDirectory(ctx))
}

func (a *UnixFS) AddDirectory(ctx context.Context, selector, path string) (*unixfs.WriteResult, error) {
	selected, err := a.writeSelection(selector)
	if err != nil {
		return nil, err
	}
	result, err := requireUnacceptedWrite(a.writer.AddDirectory(ctx, selected.Root, path))
	if err != nil {
		return nil, err
	}
	if !result.BaseRoot.Equals(selected.Root) {
		return nil, fmt.Errorf("unixfs write result does not match caller-selected root")
	}
	return result, a.recordWriteCandidate(selected, result, "unixfs add directory")
}

func (a *UnixFS) AddFile(ctx context.Context, selector, path string, body []byte) (*unixfs.WriteResult, error) {
	selected, err := a.writeSelection(selector)
	if err != nil {
		return nil, err
	}
	result, err := requireUnacceptedWrite(a.writer.AddFile(ctx, selected.Root, path, body))
	if err != nil {
		return nil, err
	}
	if !result.BaseRoot.Equals(selected.Root) {
		return nil, fmt.Errorf("unixfs write result does not match caller-selected root")
	}
	return result, a.recordWriteCandidate(selected, result, "unixfs add file")
}

func (a *UnixFS) AddFileStream(ctx context.Context, selector, path string, body io.Reader) (*unixfs.WriteResult, error) {
	selected, err := a.writeSelection(selector)
	if err != nil {
		return nil, err
	}
	result, err := requireUnacceptedWrite(a.writer.AddFileStream(ctx, selected.Root, path, body))
	if err != nil {
		return nil, err
	}
	if !result.BaseRoot.Equals(selected.Root) {
		return nil, fmt.Errorf("unixfs write result does not match caller-selected root")
	}
	return result, a.recordWriteCandidate(selected, result, "unixfs add file")
}

func (a *UnixFS) AddFileSized(ctx context.Context, selector, path string, body io.Reader, size int64) (*unixfs.WriteResult, error) {
	selected, err := a.writeSelection(selector)
	if err != nil {
		return nil, err
	}
	result, err := requireUnacceptedWrite(a.writer.AddFileSized(ctx, selected.Root, path, body, size))
	if err != nil {
		return nil, err
	}
	if !result.BaseRoot.Equals(selected.Root) {
		return nil, fmt.Errorf("unixfs write result does not match caller-selected root")
	}
	return result, a.recordWriteCandidate(selected, result, "unixfs add file")
}

func (a *UnixFS) RemovePath(ctx context.Context, selector, path string) (*unixfs.RemoveResult, error) {
	if a.writer == nil {
		return nil, fmt.Errorf("unixfs writer is nil")
	}
	selected, err := a.roots.Select(selector)
	if err != nil {
		return nil, err
	}
	result, err := a.writer.RemovePath(ctx, selected.Root, path)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, fmt.Errorf("unixfs writer returned a nil removal result")
	}
	if result.Accepted {
		return nil, fmt.Errorf("unixfs writer marked a candidate root as accepted")
	}
	if !result.BaseRoot.Equals(selected.Root) || !result.CandidateRoot.Defined() {
		return nil, fmt.Errorf("unixfs removal result does not match caller-selected root")
	}
	if selected.Alias != "" {
		if _, err := a.roots.RecordCandidate(selected.Alias, result.CandidateRoot, selected.Root, "unixfs remove"); err != nil {
			return nil, fmt.Errorf("record removal candidate: %w", err)
		}
	}
	return result, nil
}

func (a *UnixFS) writeSelection(selector string) (RootSelection, error) {
	if a.writer == nil {
		return RootSelection{}, fmt.Errorf("unixfs writer is nil")
	}
	return a.roots.Select(selector)
}

func (a *UnixFS) recordWriteCandidate(selected RootSelection, result *unixfs.WriteResult, source string) error {
	if selected.Alias == "" {
		return nil
	}
	if _, err := a.roots.RecordCandidate(selected.Alias, result.CandidateRoot, selected.Root, source); err != nil {
		return fmt.Errorf("record write candidate: %w", err)
	}
	return nil
}

func requireUnacceptedWrite(result *unixfs.WriteResult, err error) (*unixfs.WriteResult, error) {
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, fmt.Errorf("unixfs writer returned a nil write result")
	}
	if result.Accepted {
		return nil, fmt.Errorf("unixfs writer marked a candidate root as accepted")
	}
	if !result.CandidateRoot.Defined() {
		return nil, fmt.Errorf("unixfs writer returned an undefined candidate root")
	}
	if result.BaseRoot.Defined() && result.BaseRoot.Equals(result.CandidateRoot) {
		return nil, fmt.Errorf("unixfs writer returned its base root as a candidate")
	}
	return result, nil
}

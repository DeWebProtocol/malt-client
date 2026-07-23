package rq2e0

import (
	"context"
	"fmt"

	clientcas "github.com/dewebprotocol/malt-client/internal/cas"
	"github.com/dewebprotocol/malt-client/internal/evaluation/rq2fixture"
	materializermemory "github.com/dewebprotocol/malt/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt/auth/commitment"
	"github.com/dewebprotocol/malt/auth/commitment/ipa"
	"github.com/dewebprotocol/malt/auth/commitment/kzg"
	listtree "github.com/dewebprotocol/malt/auth/semantic/list/tree"
	"github.com/dewebprotocol/malt/auth/semantic/mapping"
	mappingradix "github.com/dewebprotocol/malt/auth/semantic/mapping/radix"
	cid "github.com/ipfs/go-cid"
)

// BuildFixture computes the exact KZG and IPA initial roots for a source
// definition using the production fixture object IDs and layout. It then
// reconstructs both complete update views, so tests cannot publish a fixture
// whose roots are merely well-typed but do not bind the declared source.
func BuildFixture(ctx context.Context, source *rq2fixture.SourceDefinition) (*rq2fixture.Fixture, error) {
	if ctx == nil || source == nil {
		return nil, fmt.Errorf("RQ2 E0 fixture source or context is nil")
	}
	if err := source.Validate(); err != nil {
		return nil, err
	}
	roots := make([]rq2fixture.RootBinding, 0, 2)
	for _, backend := range []string{"kzg", "ipa"} {
		root, err := buildSourceRoot(ctx, source, backend)
		if err != nil {
			return nil, fmt.Errorf("build %s RQ2 E0 fixture root: %w", backend, err)
		}
		roots = append(roots, rq2fixture.RootBinding{Backend: backend, CID: root.String()})
	}
	fixture, err := source.Fixture(roots)
	if err != nil {
		return nil, err
	}
	for _, backend := range []string{"kzg", "ipa"} {
		if _, _, err := buildFixtureView(ctx, fixture, backend); err != nil {
			return nil, fmt.Errorf("verify %s RQ2 E0 fixture view: %w", backend, err)
		}
	}
	return fixture, nil
}

func buildSourceRoot(ctx context.Context, source *rq2fixture.SourceDefinition, backend string) (cid.Cid, error) {
	var scheme commitment.IndexCommitment
	var err error
	switch backend {
	case "kzg":
		scheme, err = kzg.NewScheme()
	case "ipa":
		scheme, err = ipa.NewScheme()
	default:
		return cid.Undef, fmt.Errorf("unsupported RQ2 E0 backend %q", backend)
	}
	if err != nil {
		return cid.Undef, err
	}
	store := materializermemory.New(true)
	lister, err := listtree.NewList(scheme, store)
	if err != nil {
		return cid.Undef, err
	}
	mapper, err := mappingradix.NewMap(scheme, store)
	if err != nil {
		return cid.Undef, err
	}
	bindings := make(map[string]cid.Cid, len(source.DirectFiles)+len(source.ListFiles))
	for _, file := range source.DirectFiles {
		key, err := clientcas.CIDForBlock(clientcas.Block{Codec: cid.Raw, Data: file.Bytes})
		if err != nil {
			return cid.Undef, err
		}
		bindings[file.Path] = key
	}
	for index, file := range source.ListFiles {
		chunks := make([]cid.Cid, len(file.Chunks))
		for chunkIndex, chunk := range file.Chunks {
			key, err := clientcas.CIDForBlock(clientcas.Block{Codec: cid.Raw, Data: chunk.Bytes})
			if err != nil {
				return cid.Undef, err
			}
			chunks[chunkIndex] = key
		}
		root, err := lister.CommitFixed(ctx, fmt.Sprintf("rq2-list-%03d", index), chunks, file.ChunkSize, file.TotalSize)
		if err != nil {
			return cid.Undef, err
		}
		bindings[file.Path] = root
	}
	return mapper.Commit(ctx, "rq2-root", mapping.NewViewFrom(bindings))
}

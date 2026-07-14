package main

import (
	"context"
	"fmt"

	malt "github.com/dewebprotocol/malt"
	gatewayclient "github.com/dewebprotocol/malt-client/internal/gateway"
	unixfsmodel "github.com/dewebprotocol/malt-client/unixfs/model"
	unixfs "github.com/dewebprotocol/malt-client/unixfs/sdk"
	"github.com/dewebprotocol/malt/protocol"
	clientverifier "github.com/dewebprotocol/malt/sdk/verifier"
	"github.com/dewebprotocol/malt/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

type addMaterializeResult = unixfs.StagedMaterializeResult

type addStagedRootCreator struct {
	gateway *gatewayclient.Client
}

type addStagedPathStatter struct {
	gateway  *gatewayclient.Client
	verifier *clientverifier.Verifier
}

func (c addStagedRootCreator) CreateStagedRoot(ctx context.Context, bindings map[string]string) (cid.Cid, error) {
	resp, err := c.gateway.CreateRootStructure(ctx, bindings)
	if err != nil {
		return cid.Undef, err
	}
	rootCID, err := cid.Decode(resp.Root)
	if err != nil {
		return cid.Undef, fmt.Errorf("decode created map root: %w", err)
	}
	return rootCID, nil
}

func (s addStagedPathStatter) StatStagedPath(ctx context.Context, root string, p string) (unixfs.StagedPathStat, error) {
	rootCID, err := cid.Parse(root)
	if err != nil {
		return unixfs.StagedPathStat{}, err
	}
	segments, err := unixfsmodel.ParsePath(p)
	if err != nil {
		return unixfs.StagedPathStat{}, err
	}
	target, err := s.resolveAndVerify(ctx, rootCID, segments)
	if err != nil {
		return unixfs.StagedPathStat{}, err
	}
	storageKind := unixfsmodel.StorageKindFromCID(target)
	kind := unixfs.StagedKindFile
	payload := ""
	if maltcid.SemanticKindOf(target) == maltcid.SemanticKindMap {
		kind = unixfs.StagedKindDirectory
		payloadTarget, err := s.resolveAndVerify(ctx, rootCID, append(append([]string(nil), segments...), "@payload"))
		if err != nil {
			return unixfs.StagedPathStat{}, fmt.Errorf("resolve directory payload for %q: %w", p, err)
		}
		payload = payloadTarget.String()
	}
	return unixfs.StagedPathStat{
		Kind:        kind,
		StorageKind: storageKind,
		Key:         target.String(),
		Payload:     payload,
	}, nil
}

func (s addStagedPathStatter) resolveAndVerify(ctx context.Context, root cid.Cid, segments []string) (cid.Cid, error) {
	request, err := protocol.NewResolveRequest(malt.ResolveRequest{Root: root, Segments: segments})
	if err != nil {
		return cid.Undef, err
	}
	result, err := s.gateway.Resolve(ctx, request)
	if err != nil {
		return cid.Undef, err
	}
	if err := s.verifier.VerifyResolve(ctx, protocol.ResolveVerification{Request: request, Result: *result}); err != nil {
		return cid.Undef, fmt.Errorf("verify gateway resolve locally: %w", err)
	}
	target, err := cid.Parse(result.Target)
	if err != nil {
		return cid.Undef, fmt.Errorf("decode resolved target: %w", err)
	}
	return target, nil
}

func loadExistingCurrentTree(ctx context.Context, gateway *gatewayclient.Client, casClient addCASClient, rootCID string) (*unixfs.StagedNode, error) {
	verifier, err := clientverifier.NewDefault()
	if err != nil {
		return nil, fmt.Errorf("initialize local verifier: %w", err)
	}
	statter := addStagedPathStatter{gateway: gateway, verifier: verifier}
	return unixfs.LoadStagedCurrentTree(ctx, statter, casClient, rootCID)
}

func materializeDirectory(ctx context.Context, gateway *gatewayclient.Client, casClient addCASClient, node *unixfs.StagedNode) (*addMaterializeResult, error) {
	return unixfs.MaterializeStagedDirectory(ctx, addStagedRootCreator{gateway: gateway}, asAddCASBatcher(casClient), node)
}

func addMaterializeStats(dst *addMaterializeResult, src *addMaterializeResult) {
	unixfs.AddStagedMaterializeStats(dst, src)
}

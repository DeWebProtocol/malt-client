package add

import (
	"context"
	"fmt"

	malt "github.com/dewebprotocol/malt"
	unixfs "github.com/dewebprotocol/malt-client/unixfs"
	unixfsmodel "github.com/dewebprotocol/malt-client/unixfs/model"
	"github.com/dewebprotocol/malt/protocol"
	clientverifier "github.com/dewebprotocol/malt/sdk/verifier"
	cid "github.com/ipfs/go-cid"
)

type addMaterializeResult = unixfs.StagedMaterializeResult

type addStagedPathStatter struct {
	gateway  unixfs.Remote
	verifier *clientverifier.Verifier
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
	kind, storageKind, err := classifyStagedTarget(target)
	if err != nil {
		return unixfs.StagedPathStat{}, err
	}
	payload := ""
	if kind == unixfs.StagedKindDirectory {
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

func classifyStagedTarget(target cid.Cid) (kind, storageKind string, err error) {
	storageKind = unixfsmodel.StorageKindFromCID(target)
	switch storageKind {
	case "map":
		return unixfs.StagedKindDirectory, storageKind, nil
	case "list", "raw":
		return unixfs.StagedKindFile, storageKind, nil
	default:
		return "", "", fmt.Errorf("unsupported UnixFS target CID %s", target)
	}
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

func loadExistingCurrentTree(ctx context.Context, gateway unixfs.Remote, casClient addCASClient, rootCID string) (*unixfs.StagedNode, error) {
	verifier, err := clientverifier.NewDefault()
	if err != nil {
		return nil, fmt.Errorf("initialize local verifier: %w", err)
	}
	statter := addStagedPathStatter{gateway: gateway, verifier: verifier}
	return unixfs.LoadStagedCurrentTree(ctx, statter, casClient, rootCID)
}

func materializeDirectory(ctx context.Context, gateway unixfs.StagedRootCreator, casClient addCASClient, node *unixfs.StagedNode) (*addMaterializeResult, error) {
	return unixfs.MaterializeStagedDirectory(ctx, gateway, asAddCASBatcher(casClient), node)
}

func addMaterializeStats(dst *addMaterializeResult, src *addMaterializeResult) {
	unixfs.AddStagedMaterializeStats(dst, src)
}

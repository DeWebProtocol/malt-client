// Package add owns reusable local-input staging and UnixFS materialization for
// both native MALT and IPFS-compatible Merkle DAG targets.
package add

import (
	"context"
	"fmt"
	"strings"

	"github.com/dewebprotocol/malt-client/application"
	"github.com/dewebprotocol/malt-client/unixfs"
	"github.com/dewebprotocol/malt/mutation"
	cid "github.com/ipfs/go-cid"
)

const (
	TargetMALT      = addTargetMALT
	TargetMerkleDAG = addTargetMerkleDAG
	ModelUnixFS     = addModelUnixFS
	LayoutHybrid    = addLayoutHybrid

	FileLayoutBalanced = addFileLayoutBalanced
	FileLayoutTrickle  = addFileLayoutTrickle
	DirLayoutBasic     = addDirLayoutBasic
	DirLayoutHAMT      = addDirLayoutHAMT
	DirLayoutAdaptive  = addDirLayoutAdaptive
)

type Options = addBuildOptions
type IgnoreOptions = addIgnoreOptions
type Result = addUnixFSResult

// GraphGateway is the narrow native graph capability used by the add
// materializer.
type GraphGateway interface {
	unixfs.Remote
	unixfs.StagedRootCreator
}

// Gateway combines graph operations with the UnixFS-owned fixed-list writer.
// It has no concrete HTTP response types.
type Gateway interface {
	GraphGateway
	unixfs.FixedListPayloadWriter
}

type gateway struct {
	GraphGateway
	lists unixfs.FixedListPayloadWriter
}

// NewGateway composes a native graph port with the UnixFS fixed-list adapter.
func NewGateway(graph GraphGateway, lists unixfs.FixedListPayloadWriter) (Gateway, error) {
	if graph == nil {
		return nil, fmt.Errorf("add graph gateway is nil")
	}
	if lists == nil {
		return nil, fmt.Errorf("add fixed-list writer is nil")
	}
	return &gateway{GraphGateway: graph, lists: lists}, nil
}

func (g *gateway) CreateFixedListBaseRoot(ctx context.Context) (cid.Cid, error) {
	return g.lists.CreateFixedListBaseRoot(ctx)
}

func (g *gateway) ApplyFixedListPayloadMutation(ctx context.Context, mut mutation.SemanticMutation) (cid.Cid, error) {
	return g.lists.ApplyFixedListPayloadMutation(ctx, mut)
}

// CAS is the immutable byte capability shared by MALT and Merkle DAG targets.
type CAS interface {
	Put(context.Context, []byte) (cid.Cid, error)
	PutWithCodec(context.Context, []byte, uint64) (cid.Cid, error)
	Get(context.Context, cid.Cid) ([]byte, error)
}

// Request is the application-level bulk add input. Root and Alias are mutually
// exclusive; Alias selects only a locally accepted root.
type Request struct {
	Inputs  []string
	Root    string
	Alias   string
	Options Options
}

// Execution includes normalized options and the exact accepted base used for
// candidate recording.
type Execution struct {
	Result   *Result
	Options  Options
	BaseRoot string
	Alias    string
}

// NormalizeOptions applies the stable application policy for target, model,
// layout, and compatibility aliases.
func NormalizeOptions(opts Options) (Options, error) {
	return normalizeAddBuildOptions(opts)
}

// Run stages local inputs, materializes the selected target, and records a
// native MALT result as an unaccepted candidate when Alias is supplied. It
// never promotes that candidate.
func Run(ctx context.Context, roots *application.Roots, gateway Gateway, cas CAS, request Request) (*Execution, error) {
	return run(ctx, roots, gateway, cas, request, addInputsWithUnixFS)
}

type materializeFunc func(context.Context, Gateway, addCASClient, []string, string, addBuildOptions) (*addUnixFSResult, error)

func run(ctx context.Context, roots *application.Roots, gateway Gateway, cas CAS, request Request, materialize materializeFunc) (*Execution, error) {
	normalized, err := normalizeAddBuildOptions(request.Options)
	if err != nil {
		return nil, err
	}
	if cas == nil {
		return nil, fmt.Errorf("add CAS is nil")
	}
	if materialize == nil {
		return nil, fmt.Errorf("add materializer is nil")
	}
	baseRoot := strings.TrimSpace(request.Root)
	alias := strings.TrimSpace(request.Alias)
	if normalized.Target == addTargetMerkleDAG {
		if baseRoot != "" || alias != "" {
			return nil, fmt.Errorf("root and alias are only supported with the MALT target")
		}
	} else {
		if baseRoot != "" && alias != "" {
			return nil, fmt.Errorf("alias and root cannot be used together")
		}
		if alias != "" {
			if roots == nil {
				return nil, fmt.Errorf("trusted-root application is required for an alias")
			}
			selected, err := roots.Select(alias)
			if err != nil {
				return nil, err
			}
			baseRoot = selected.Root.String()
			alias = selected.Alias
		} else if baseRoot != "" {
			parsed, err := cid.Parse(baseRoot)
			if err != nil {
				return nil, fmt.Errorf("invalid add base root: %w", err)
			}
			baseRoot = parsed.String()
		}
	}

	result, err := materialize(ctx, gateway, cas, request.Inputs, baseRoot, normalized)
	if err != nil {
		return nil, err
	}
	if result == nil || strings.TrimSpace(result.NewRoot) == "" {
		return nil, fmt.Errorf("failed to materialize a new root")
	}
	if alias != "" {
		candidate, err := cid.Parse(result.NewRoot)
		if err != nil {
			return nil, fmt.Errorf("decode add candidate root: %w", err)
		}
		base, _ := cid.Parse(baseRoot)
		if _, err := roots.RecordCandidate(alias, candidate, base, "malt add"); err != nil {
			return nil, fmt.Errorf("record candidate root: %w", err)
		}
	}
	return &Execution{Result: result, Options: normalized, BaseRoot: baseRoot, Alias: alias}, nil
}

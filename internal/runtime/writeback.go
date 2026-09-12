package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"

	"github.com/dewebprotocol/malt-client/application"
	clientrootapp "github.com/dewebprotocol/malt-client/application/clientroot"
	writebackapp "github.com/dewebprotocol/malt-client/application/writeback"
	filesystemmount "github.com/dewebprotocol/malt-client/filesystem/mount"
	filesystemservice "github.com/dewebprotocol/malt-client/filesystem/service"
	"github.com/dewebprotocol/malt-client/filesystem/staging"
	gatewayclient "github.com/dewebprotocol/malt-client/transport"
	truststore "github.com/dewebprotocol/malt-client/trust"
	"github.com/dewebprotocol/malt-client/unixfs"
	unixfsclientroot "github.com/dewebprotocol/malt-client/unixfs/clientroot"
	materializermemory "github.com/dewebprotocol/malt-core/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt-core/auth/commitment"
	"github.com/dewebprotocol/malt-core/auth/commitment/ipa"
	"github.com/dewebprotocol/malt-core/auth/commitment/kzg"
	"github.com/dewebprotocol/malt-core/protocol"
	clientwriter "github.com/dewebprotocol/malt-core/sdk/writer"
	"github.com/dewebprotocol/malt-core/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

const gatewayWritebackSource = "filesystem verified write-back"

type gatewayWritableRemote interface {
	Get(context.Context, cid.Cid) ([]byte, error)
	Put(context.Context, []byte) (cid.Cid, error)
	PutWithCodec(context.Context, []byte, uint64) (cid.Cid, error)
	FetchUpdateView(context.Context, cid.Cid, *protocol.UpdateViewBounds) (*gatewayclient.UpdateViewResponse, error)
	SubmitClientRootResult(context.Context, clientwriter.ComputeResult) (*gatewayclient.ClientRootResponse, error)
}

type gatewayWritableBlocks interface {
	Get(context.Context, cid.Cid) ([]byte, error)
	Put(context.Context, []byte) (cid.Cid, error)
	PutWithCodec(context.Context, []byte, uint64) (cid.Cid, error)
}

type writerFactory interface {
	New() (*clientwriter.Runtime, error)
}

type clientRootWriterFactory struct {
	once    sync.Once
	schemes map[maltcid.BackendKind]commitment.IndexCommitment
	err     error
}

// New returns an isolated speculative materializer over shared immutable
// commitment parameters. The compact IPA profile changes only local execution
// memory and performance; it does not change roots, proofs, or transcripts.
func (f *clientRootWriterFactory) New() (*clientwriter.Runtime, error) {
	if f == nil {
		return nil, fmt.Errorf("client-root writer factory is nil")
	}
	f.once.Do(func() {
		kzgScheme, err := kzg.NewScheme()
		if err != nil {
			f.err = fmt.Errorf("initialize KZG writer: %w", err)
			return
		}
		ipaScheme, err := ipa.NewCommitterScheme(ipa.ProfileCompact)
		if err != nil {
			f.err = fmt.Errorf("initialize IPA writer: %w", err)
			return
		}
		f.schemes = map[maltcid.BackendKind]commitment.IndexCommitment{
			maltcid.BackendKindKZG: kzgScheme,
			maltcid.BackendKindIPA: ipaScheme,
		}
	})
	if f.err != nil {
		return nil, f.err
	}
	schemes := make(map[maltcid.BackendKind]commitment.IndexCommitment, len(f.schemes))
	for backend, scheme := range f.schemes {
		schemes[backend] = scheme
	}
	return clientwriter.NewRuntime(materializermemory.New(true), schemes)
}

type gatewayWritableBindingOptions struct {
	Spec               filesystemmount.Spec
	View               filesystemservice.View
	Base               staging.Base
	Remote             gatewayWritableRemote
	Blocks             gatewayWritableBlocks
	Roots              truststore.Policy
	WriterFactory      writerFactory
	StateDirectory     string
	MaxStagedFileBytes uint64
	Source             string
	Release            func() error
}

func newGatewayWritableBinding(ctx context.Context, opts gatewayWritableBindingOptions) (filesystemmount.WritableBinding, error) {
	if ctx == nil {
		return nil, fmt.Errorf("Gateway writable binding context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	spec, err := filesystemmount.NormalizeSpec(opts.Spec)
	if err != nil {
		return nil, err
	}
	if spec.WritePolicy != filesystemmount.WriteBack || spec.DatasetID != opts.View.DatasetID || spec.Branch != opts.View.Branch || !opts.View.Root.Defined() {
		return nil, fmt.Errorf("Gateway writable binding Spec and View do not match")
	}
	backend := maltcid.BackendKindOf(opts.View.Root)
	if maltcid.SemanticKindOf(opts.View.Root) != maltcid.SemanticKindMap ||
		(backend != maltcid.BackendKindKZG && backend != maltcid.BackendKindIPA) {
		return nil, fmt.Errorf("Gateway writable binding accepted root is not a supported typed MALT Map")
	}
	if nilInterface(opts.Base) || nilInterface(opts.Remote) || nilInterface(opts.Roots) || nilInterface(opts.WriterFactory) {
		return nil, fmt.Errorf("Gateway writable binding requires base, remote, roots, and writer factory")
	}
	blocks := opts.Blocks
	if nilInterface(blocks) {
		blocks = opts.Remote
	}
	layout, err := unixfs.ParseLayoutKind(string(spec.LayoutPolicy))
	if err != nil {
		return nil, err
	}
	cacheDirectory, journalPath, err := writableStatePaths(opts.StateDirectory, spec.DatasetID, spec.Branch)
	if err != nil {
		return nil, err
	}
	staged, err := staging.New(staging.Options{
		Base: opts.Base, CacheDirectory: cacheDirectory, JournalPath: journalPath,
		MaxStagedFileBytes: opts.MaxStagedFileBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("open filesystem write-back staging: %w", err)
	}
	binding := &runtimeWritableBinding{view: opts.View, staged: staged, closing: true, release: opts.Release}
	if err := ensureWritableLayoutState(filepath.Join(filepath.Dir(journalPath), "layout.json"), spec); err != nil {
		return binding, fmt.Errorf("bind filesystem write-back layout: %w", err)
	}
	planner, err := unixfsclientroot.New(layout, blocks)
	if err != nil {
		return binding, err
	}
	writer, err := opts.WriterFactory.New()
	if err != nil {
		return binding, err
	}
	roots, err := application.NewRoots(opts.Roots)
	if err != nil {
		return binding, err
	}
	source := strings.TrimSpace(opts.Source)
	if source == "" {
		source = gatewayWritebackSource
	}
	replay, err := writebackapp.New(writebackapp.Options{
		Queue: staged, Payloads: blocks, Remote: gatewayClientRootRemote{client: opts.Remote},
		Writer: writer, Planner: planner, Roots: roots, TrustAlias: spec.TrustAlias, Source: source,
	})
	if err != nil {
		return binding, err
	}
	binding.replay = replay
	binding.closing = false
	return binding, nil
}

func writableStatePaths(root, datasetID, branch string) (string, string, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return "", "", fmt.Errorf("filesystem writable state directory is empty")
	}
	if strings.TrimSpace(datasetID) != datasetID || strings.TrimSpace(branch) != branch || datasetID == "" || branch == "" ||
		strings.ContainsRune(datasetID, '\x00') || strings.ContainsRune(branch, '\x00') {
		return "", "", fmt.Errorf("filesystem writable dataset and branch identities are invalid")
	}
	digest := sha256.Sum256([]byte("malt-filesystem-writeback/v1\x00" + datasetID + "\x00" + branch))
	directory := filepath.Join(filepath.Clean(root), hex.EncodeToString(digest[:]))
	return filepath.Join(directory, "cache"), filepath.Join(directory, "journal.json"), nil
}

type viewFilesystemBase struct {
	filesystem filesystemmount.ViewFilesystem
}

func (b viewFilesystemBase) Stat(ctx context.Context, view filesystemservice.View, path string) (filesystemservice.Info, error) {
	if nilInterface(b.filesystem) {
		return filesystemservice.Info{}, fmt.Errorf("verified filesystem base is nil")
	}
	return b.filesystem.Stat(ctx, view, path)
}

func (b viewFilesystemBase) ReadDir(ctx context.Context, view filesystemservice.View, path string) ([]filesystemservice.DirEntry, error) {
	if nilInterface(b.filesystem) {
		return nil, fmt.Errorf("verified filesystem base is nil")
	}
	return b.filesystem.ReadDir(ctx, view, path)
}

func (b viewFilesystemBase) ReadFileRange(ctx context.Context, view filesystemservice.View, path string, offset, length uint64) ([]byte, filesystemservice.Info, error) {
	if nilInterface(b.filesystem) {
		return nil, filesystemservice.Info{}, fmt.Errorf("verified filesystem base is nil")
	}
	handle, err := b.filesystem.Open(ctx, view, path)
	if err != nil {
		return nil, filesystemservice.Info{}, err
	}
	if handle == nil {
		return nil, filesystemservice.Info{}, fmt.Errorf("verified filesystem returned a nil handle")
	}
	info := handle.Info()
	body, readErr := handle.Read(ctx, offset, length)
	closeErr := handle.Close()
	if readErr != nil || closeErr != nil {
		return nil, filesystemservice.Info{}, errors.Join(readErr, closeErr)
	}
	return body, info, nil
}

type writebackReplayer interface {
	Replay(context.Context, filesystemservice.View) (writebackapp.Result, error)
}

type runtimeWritableBinding struct {
	lifecycle sync.RWMutex
	mutations sync.Mutex
	view      filesystemservice.View
	staged    *staging.Service
	replay    writebackReplayer
	closing   bool
	closed    bool
	release   func() error
}

func (b *runtimeWritableBinding) enter() (func(), error) {
	if b == nil {
		return nil, filesystemservice.ErrClosed
	}
	b.lifecycle.RLock()
	if b.closing || b.closed || b.staged == nil {
		b.lifecycle.RUnlock()
		return nil, filesystemservice.ErrClosed
	}
	return b.lifecycle.RUnlock, nil
}

func (b *runtimeWritableBinding) Stat(ctx context.Context, path string) (filesystemservice.Info, error) {
	leave, err := b.enter()
	if err != nil {
		return filesystemservice.Info{}, err
	}
	defer leave()
	info, err := b.staged.Stat(ctx, b.view, path)
	return info, mapStagingError(err)
}

func (b *runtimeWritableBinding) ReadDir(ctx context.Context, path string) ([]filesystemservice.DirEntry, error) {
	leave, err := b.enter()
	if err != nil {
		return nil, err
	}
	defer leave()
	entries, err := b.staged.ReadDir(ctx, b.view, path)
	return entries, mapStagingError(err)
}

func (b *runtimeWritableBinding) Open(ctx context.Context, path string) (filesystemmount.ReadHandle, error) {
	leave, err := b.enter()
	if err != nil {
		return nil, err
	}
	defer leave()
	handle, err := b.staged.Open(ctx, b.view, path)
	if err != nil {
		return nil, mapStagingError(err)
	}
	if handle == nil {
		return nil, fmt.Errorf("filesystem staging returned a nil handle")
	}
	return &runtimeReadHandle{handle: handle}, nil
}

func (b *runtimeWritableBinding) Create(ctx context.Context, path string) (filesystemservice.Info, error) {
	leave, err := b.enter()
	if err != nil {
		return filesystemservice.Info{}, err
	}
	defer leave()
	b.mutations.Lock()
	defer b.mutations.Unlock()
	if _, err := b.staged.Stat(ctx, b.view, path); err == nil {
		return filesystemservice.Info{}, filesystemmount.ErrAlreadyExists
	} else if !errors.Is(err, unixfs.ErrNotFound) {
		return filesystemservice.Info{}, mapStagingError(err)
	}
	if _, err := b.staged.StageWrite(ctx, b.view, path, nil, false); err != nil {
		return filesystemservice.Info{}, mapStagingError(err)
	}
	info, err := b.staged.Stat(ctx, b.view, path)
	return info, mapStagingError(err)
}

func (b *runtimeWritableBinding) WriteAt(ctx context.Context, path string, offset uint64, data []byte) (filesystemservice.Info, error) {
	leave, err := b.enter()
	if err != nil {
		return filesystemservice.Info{}, err
	}
	defer leave()
	b.mutations.Lock()
	defer b.mutations.Unlock()
	if _, err := b.staged.StageWriteAt(ctx, b.view, path, offset, data, false); err != nil {
		return filesystemservice.Info{}, mapStagingError(err)
	}
	info, err := b.staged.Stat(ctx, b.view, path)
	return info, mapStagingError(err)
}

func (b *runtimeWritableBinding) Truncate(ctx context.Context, path string, size uint64) (filesystemservice.Info, error) {
	leave, err := b.enter()
	if err != nil {
		return filesystemservice.Info{}, err
	}
	defer leave()
	b.mutations.Lock()
	defer b.mutations.Unlock()
	if _, err := b.staged.StageTruncate(ctx, b.view, path, size, false); err != nil {
		return filesystemservice.Info{}, mapStagingError(err)
	}
	info, err := b.staged.Stat(ctx, b.view, path)
	return info, mapStagingError(err)
}

func (b *runtimeWritableBinding) Mkdir(ctx context.Context, path string) (filesystemservice.Info, error) {
	leave, err := b.enter()
	if err != nil {
		return filesystemservice.Info{}, err
	}
	defer leave()
	b.mutations.Lock()
	defer b.mutations.Unlock()
	if _, err := b.staged.StageMkdir(ctx, b.view, path, false); err != nil {
		return filesystemservice.Info{}, mapStagingError(err)
	}
	info, err := b.staged.Stat(ctx, b.view, path)
	return info, mapStagingError(err)
}

func (b *runtimeWritableBinding) Rename(ctx context.Context, source, destination string) error {
	leave, err := b.enter()
	if err != nil {
		return err
	}
	defer leave()
	b.mutations.Lock()
	defer b.mutations.Unlock()
	if source == destination {
		_, err := b.staged.Stat(ctx, b.view, source)
		return mapStagingError(err)
	}
	_, err = b.staged.StageRename(ctx, b.view, source, destination, false)
	return mapStagingError(err)
}

func (b *runtimeWritableBinding) Unlink(ctx context.Context, path string) error {
	leave, err := b.enter()
	if err != nil {
		return err
	}
	defer leave()
	b.mutations.Lock()
	defer b.mutations.Unlock()
	_, err = b.staged.StageUnlink(ctx, b.view, path, false)
	return mapStagingError(err)
}

func (b *runtimeWritableBinding) RemoveDir(ctx context.Context, path string) error {
	leave, err := b.enter()
	if err != nil {
		return err
	}
	defer leave()
	b.mutations.Lock()
	defer b.mutations.Unlock()
	_, err = b.staged.StageRemoveDir(ctx, b.view, path, false)
	return mapStagingError(err)
}

func (b *runtimeWritableBinding) Sync(ctx context.Context) (filesystemmount.SyncResult, error) {
	leave, err := b.enter()
	if err != nil {
		return filesystemmount.SyncResult{}, err
	}
	defer leave()
	b.mutations.Lock()
	defer b.mutations.Unlock()
	local, err := b.staged.Fsync(ctx, b.view)
	result := filesystemmount.SyncResult{
		LocalDurable: local.LocalDurable, RemotePersisted: local.RemotePersisted,
		CandidateRoot: local.CandidateRoot, RootAccepted: false,
	}
	if err != nil {
		return result, mapStagingError(err)
	}
	if local.Profile != staging.LocalFsyncProfile || !local.LocalDurable || local.RootAccepted ||
		(local.RemotePersisted && strings.TrimSpace(local.CandidateRoot) == "") {
		return filesystemmount.SyncResult{}, fmt.Errorf("filesystem staging returned an invalid local fsync result")
	}
	if nilInterface(b.replay) {
		return result, fmt.Errorf("filesystem write-back replayer is nil")
	}
	replayed, err := b.replay.Replay(ctx, b.view)
	if errors.Is(err, staging.ErrNoPendingUpload) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	if replayed.Profile != writebackapp.ResultProfile || replayed.RootAccepted {
		return result, fmt.Errorf("filesystem write-back returned an invalid trust result")
	}
	if replayed.NoAuthenticatedChange {
		if replayed.RemotePersisted || replayed.CandidateRoot.Defined() || replayed.CandidateStored {
			return result, fmt.Errorf("filesystem no-change write-back returned a remote candidate claim")
		}
		return filesystemmount.SyncResult{LocalDurable: true}, nil
	}
	if !replayed.RemotePersisted || !replayed.CandidateStored || !validCandidateRoot(b.view.Root, replayed.CandidateRoot) {
		return result, fmt.Errorf("filesystem write-back did not persist and record an exact candidate")
	}
	return filesystemmount.SyncResult{
		LocalDurable: true, RemotePersisted: true,
		CandidateRoot: replayed.CandidateRoot.String(), RootAccepted: false,
	}, nil
}

func validCandidateRoot(base, candidate cid.Cid) bool {
	if !base.Defined() || !candidate.Defined() || candidate.Equals(base) {
		return false
	}
	next, _, err := maltcid.ParseRoot(candidate)
	if err != nil || next.Layout != maltcid.Prefix {
		return false
	}
	if old, _, err := maltcid.ParseRoot(base); err == nil {
		return old == next
	}
	return maltcid.SemanticKindOf(base) == maltcid.SemanticKindMap && maltcid.BackendKindOf(base) == maltcid.BackendKindOf(candidate) && next.InputRule == 1
}

func (b *runtimeWritableBinding) Close() error {
	if b == nil {
		return nil
	}
	b.lifecycle.Lock()
	defer b.lifecycle.Unlock()
	if b.closed {
		return nil
	}
	b.closing = true
	if b.staged == nil {
		return fmt.Errorf("filesystem write-back staging is nil")
	}
	if err := b.staged.Close(); err != nil {
		return err
	}
	if b.release != nil {
		if err := b.release(); err != nil {
			return err
		}
		b.release = nil
	}
	b.closed = true
	return nil
}

type runtimeReadHandle struct {
	handle *staging.Handle
}

func (h *runtimeReadHandle) Info() filesystemservice.Info {
	if h == nil || h.handle == nil {
		return filesystemservice.Info{}
	}
	return h.handle.Info()
}

func (h *runtimeReadHandle) Read(ctx context.Context, offset, length uint64) ([]byte, error) {
	if h == nil || h.handle == nil {
		return nil, filesystemservice.ErrClosed
	}
	body, err := h.handle.Read(ctx, offset, length)
	return body, mapStagingError(err)
}

func (h *runtimeReadHandle) Close() error {
	if h == nil || h.handle == nil {
		return nil
	}
	return mapStagingError(h.handle.Close())
}

func mapStagingError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, staging.ErrAlreadyExists):
		return filesystemmount.ErrAlreadyExists
	case errors.Is(err, staging.ErrNotEmpty):
		return filesystemmount.ErrNotEmpty
	case errors.Is(err, staging.ErrFileTooLarge):
		return filesystemmount.ErrFileTooLarge
	case errors.Is(err, staging.ErrClosed), errors.Is(err, staging.ErrServiceClosed):
		return filesystemservice.ErrClosed
	default:
		return err
	}
}

type gatewayClientRootRemote struct {
	client gatewayWritableRemote
}

func (r gatewayClientRootRemote) FetchUpdateView(ctx context.Context, root cid.Cid, bounds *protocol.UpdateViewBounds) (clientrootapp.ViewEnvelope, error) {
	if nilInterface(r.client) {
		return clientrootapp.ViewEnvelope{}, fmt.Errorf("Gateway client-root remote is nil")
	}
	response, err := r.client.FetchUpdateView(ctx, root, bounds)
	if err != nil {
		return clientrootapp.ViewEnvelope{}, err
	}
	if response == nil {
		return clientrootapp.ViewEnvelope{}, fmt.Errorf("Gateway returned a nil update view")
	}
	return clientrootapp.ViewEnvelope{View: response.View, WireBytes: response.WireBytes}, nil
}

func (r gatewayClientRootRemote) SubmitClientRoot(ctx context.Context, prepared clientwriter.ComputeResult) (clientrootapp.ReceiptEnvelope, error) {
	if nilInterface(r.client) {
		return clientrootapp.ReceiptEnvelope{}, fmt.Errorf("Gateway client-root remote is nil")
	}
	response, err := r.client.SubmitClientRootResult(ctx, prepared)
	if err != nil {
		return clientrootapp.ReceiptEnvelope{}, err
	}
	if response == nil {
		return clientrootapp.ReceiptEnvelope{}, fmt.Errorf("Gateway returned a nil client-root receipt")
	}
	return clientrootapp.ReceiptEnvelope{
		Receipt: response.Receipt, RequestWireBytes: response.RequestWireBytes, ResponseWireBytes: response.ResponseWireBytes,
		RequestEncodingNS: response.RequestEncodingNS, ResponseVerifyNS: response.ResponseVerifyNS,
		Idempotent: response.Idempotent,
		Gateway: clientrootapp.GatewayPhaseMetrics{
			OldStateValidationNS: response.Gateway.OldStateValidationNS,
			GatewayReplayNS:      response.Gateway.GatewayReplayNS,
			PersistNS:            response.Gateway.PersistNS, ReceiptNS: response.Gateway.ReceiptNS,
		},
		WriteAccounting: mapGatewayWriteAccounting(response.WriteAccounting, response.WriteAccountingWireBytes),
	}, nil
}

func mapGatewayWriteAccounting(source gatewayclient.ClientRootWriteAccounting, wireBytes uint64) clientrootapp.GatewayWriteAccounting {
	result := clientrootapp.GatewayWriteAccounting{
		Profile: source.Profile, Available: source.Available, UnavailableReason: source.UnavailableReason,
		ByteMethod: source.ByteMethod, ObjectLedgerSHA256: source.ObjectLedgerSHA256,
		WireBytes: wireBytes, Categories: make([]clientrootapp.GatewayWriteCategoryAccounting, len(source.Categories)),
	}
	for index, category := range source.Categories {
		result.Categories[index] = clientrootapp.GatewayWriteCategoryAccounting{
			Category: category.Category, AttemptedWrites: category.AttemptedWrites, AttemptedBytes: category.AttemptedBytes,
			AttemptedNewWrites: category.AttemptedNewWrites, AttemptedNewBytes: category.AttemptedNewBytes,
			AttemptedReplacementWrites: category.AttemptedReplacementWrites, AttemptedReplacementBytes: category.AttemptedReplacementBytes,
			AttemptedSameValueWrites: category.AttemptedSameValueWrites, AttemptedSameValueBytes: category.AttemptedSameValueBytes,
			AttemptedDeleteWrites: category.AttemptedDeleteWrites, AttemptedDeleteBytes: category.AttemptedDeleteBytes,
			NewlyPersistedWrites: category.NewlyPersistedWrites, GrossNewBytes: category.GrossNewBytes,
			NewWrites: category.NewWrites, NewBytes: category.NewBytes, ReplacedWrites: category.ReplacedWrites,
			ReplacementNewBytes: category.ReplacementNewBytes, ReplacementReclaimedBytes: category.ReplacementReclaimedBytes,
			SameValueWrites: category.SameValueWrites, DeletedWrites: category.DeletedWrites,
			DeletedReclaimedBytes: category.DeletedReclaimedBytes, ReclaimedBytes: category.ReclaimedBytes,
			NetBytes: category.NetBytes,
		}
	}
	return result
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var (
	_ filesystemmount.WritableBinding = (*runtimeWritableBinding)(nil)
	_ filesystemmount.ReadHandle      = (*runtimeReadHandle)(nil)
	_ clientrootapp.Remote            = gatewayClientRootRemote{}
)

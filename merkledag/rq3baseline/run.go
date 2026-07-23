package rq3baseline

import (
	"context"
	"fmt"
	"io/fs"
	"time"

	merkledagimport "github.com/dewebprotocol/malt-client/merkledag/importer"
)

// Run validates the complete frozen workload before creating any CAS state,
// then executes it through the current incremental UnixFS Editor.
func Run(ctx context.Context, spec RunSpec) (*RunResult, error) {
	prepared, err := prepare(spec)
	if err != nil {
		return nil, err
	}
	sourceAccounting := accountPreparedSource(prepared)
	store := newAccountingStore()
	editor, err := merkledagimport.NewEditor(store, importerOptions(prepared.spec))
	if err != nil {
		return nil, fmt.Errorf("create UnixFS editor: %w", err)
	}

	result := &RunResult{
		SchemaVersion:  RunResultSchema,
		CapabilityID:   Capability().CapabilityID,
		System:         prepared.spec.System,
		WorkloadSHA256: prepared.digest,
		Layout:         prepared.spec.Layout,
		Records:        make([]CommitRecord, 0, 1+len(prepared.commits)),
	}
	state := make(map[string]logicalFile, len(prepared.snapshot))

	store.beginPhase()
	started := time.Now()
	snapshotMutations := make([]MutationExecution, 0, len(prepared.snapshot))
	var snapshotPayloadBytes int64
	for index, file := range prepared.snapshot {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := editor.PutFile(ctx, file.path, file.data, fs.FileMode(file.mode)); err != nil {
			return nil, fmt.Errorf("snapshot commit %q put %q: %w", prepared.spec.Snapshot.CommitID, file.path, err)
		}
		state[file.path] = logicalFile{data: cloneBytes(file.data), mode: file.mode, hash: file.hash}
		snapshotPayloadBytes += int64(len(file.data))
		snapshotMutations = append(snapshotMutations, MutationExecution{
			Index:                  index,
			Kind:                   MutationInsert,
			Path:                   file.path,
			Translation:            "snapshot_put_file",
			LogicalObjectsChanged:  1,
			LogicalBindingsChanged: 1,
			LogicalPayloadBytes:    int64(len(file.data)),
		})
	}
	snapshotElapsed := time.Since(started).Nanoseconds()
	snapshotRoot := editor.Root()
	if snapshotRoot == "" {
		return nil, fmt.Errorf("snapshot commit %q produced an empty root", prepared.spec.Snapshot.CommitID)
	}
	snapshotCAS, snapshotPutNanos, snapshotGetNanos := store.finishPhase()
	result.Records = append(result.Records, CommitRecord{
		CommitID:                 prepared.spec.Snapshot.CommitID,
		Root:                     snapshotRoot,
		Snapshot:                 true,
		LogicalObjectsChanged:    len(prepared.snapshot),
		LogicalBindingsChanged:   len(prepared.snapshot),
		LogicalPayloadBytes:      snapshotPayloadBytes,
		AdapterPayloadInputBytes: sourceAccounting[0].AdapterPayloadInputBytes,
		Mutations:                snapshotMutations,
		CAS:                      snapshotCAS,
		ClientPhases:             phaseMetrics(snapshotElapsed, snapshotPutNanos, snapshotGetNanos),
	})

	parentRoot := snapshotRoot
	for commitIndex, commit := range prepared.commits {
		store.beginPhase()
		started = time.Now()
		executions := make([]MutationExecution, 0, len(commit.mutations))
		logicalObjects := 0
		logicalBindings := 0
		var logicalPayload int64
		for index, mutation := range commit.mutations {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			execution, err := executeMutation(ctx, editor, state, index, mutation)
			if err != nil {
				return nil, fmt.Errorf("commit %q mutation[%d]: %w", commit.id, index, err)
			}
			executions = append(executions, execution)
			logicalObjects += execution.LogicalObjectsChanged
			logicalBindings += execution.LogicalBindingsChanged
			logicalPayload += execution.LogicalPayloadBytes
		}
		elapsed := time.Since(started).Nanoseconds()
		root := editor.Root()
		if root == "" {
			return nil, fmt.Errorf("commit %q produced an empty root", commit.id)
		}
		casAccounting, putNanos, getNanos := store.finishPhase()
		result.Records = append(result.Records, CommitRecord{
			CommitID:                 commit.id,
			ParentRoot:               parentRoot,
			Root:                     root,
			LogicalObjectsChanged:    logicalObjects,
			LogicalBindingsChanged:   logicalBindings,
			LogicalPayloadBytes:      logicalPayload,
			AdapterPayloadInputBytes: sourceAccounting[commitIndex+1].AdapterPayloadInputBytes,
			Mutations:                executions,
			CAS:                      casAccounting,
			ClientPhases:             phaseMetrics(elapsed, putNanos, getNanos),
		})
		parentRoot = root
	}
	return result, nil
}

func importerOptions(spec RunSpec) merkledagimport.Options {
	return merkledagimport.Options{
		Model:       spec.Layout.Model,
		FileLayout:  spec.Layout.FileLayout,
		DirLayout:   spec.Layout.DirectoryLayout,
		ChunkSize:   spec.Layout.Chunking.SizeBytes,
		HAMTFanout:  spec.Layout.HAMTFanout,
		RawFileLeaf: *spec.Layout.RawFileLeaf,
	}
}

func executeMutation(ctx context.Context, editor *merkledagimport.Editor, state map[string]logicalFile, index int, prepared preparedMutation) (MutationExecution, error) {
	mutation := prepared.mutation
	execution := MutationExecution{
		Index:                 index,
		Kind:                  mutation.Kind,
		Path:                  mutation.Path,
		Destination:           mutation.Destination,
		LogicalObjectsChanged: 1,
	}
	switch mutation.Kind {
	case MutationInsert:
		if err := editor.PutFile(ctx, mutation.Path, prepared.data, fs.FileMode(*mutation.Mode)); err != nil {
			return MutationExecution{}, err
		}
		state[mutation.Path] = logicalFile{data: cloneBytes(prepared.data), mode: *mutation.Mode, hash: mutation.PayloadSHA256}
		execution.Translation = "put_file"
		execution.LogicalBindingsChanged = 1
		execution.LogicalPayloadBytes = int64(len(prepared.data))

	case MutationReplace:
		if err := editor.PutFile(ctx, mutation.Path, prepared.data, fs.FileMode(*mutation.Mode)); err != nil {
			return MutationExecution{}, err
		}
		state[mutation.Path] = logicalFile{data: cloneBytes(prepared.data), mode: *mutation.Mode, hash: mutation.PayloadSHA256}
		execution.Translation = "put_file_replace"
		execution.LogicalBindingsChanged = 1
		execution.LogicalPayloadBytes = int64(len(prepared.data))

	case MutationAppend:
		old := state[mutation.Path]
		if err := editor.PutFile(ctx, mutation.Path, prepared.data, fs.FileMode(*mutation.Mode)); err != nil {
			return MutationExecution{}, err
		}
		state[mutation.Path] = logicalFile{data: cloneBytes(prepared.data), mode: *mutation.Mode, hash: mutation.PayloadSHA256}
		execution.Translation = "put_file_full_result"
		execution.LogicalBindingsChanged = 1
		execution.LogicalPayloadBytes = int64(len(prepared.data) - len(old.data))

	case MutationModeChange:
		old := state[mutation.Path]
		if err := editor.PutFile(ctx, mutation.Path, old.data, fs.FileMode(*mutation.Mode)); err != nil {
			return MutationExecution{}, err
		}
		state[mutation.Path] = logicalFile{data: old.data, mode: *mutation.Mode, hash: old.hash}
		execution.Translation = "put_file_mode_change"
		execution.LogicalBindingsChanged = 1

	case MutationDelete:
		if err := editor.RemoveFile(ctx, mutation.Path); err != nil {
			return MutationExecution{}, err
		}
		delete(state, mutation.Path)
		execution.Translation = "remove_file"
		execution.LogicalBindingsChanged = 1

	case MutationRename, MutationMove:
		old := state[mutation.Path]
		if err := editor.RemoveFile(ctx, mutation.Path); err != nil {
			return MutationExecution{}, err
		}
		if err := editor.PutFile(ctx, mutation.Destination, old.data, fs.FileMode(old.mode)); err != nil {
			return MutationExecution{}, err
		}
		delete(state, mutation.Path)
		state[mutation.Destination] = old
		execution.Translation = "remove_file_then_put_file"
		execution.LogicalBindingsChanged = 2

	default:
		return MutationExecution{}, fmt.Errorf("unsupported mutation kind %q after validation", mutation.Kind)
	}
	return execution, nil
}

func phaseMetrics(total, put, get int64) ClientPhases {
	compute := total - put - get
	if compute < 0 {
		compute = 0
	}
	return ClientPhases{
		ClientComputeWallNanos:              total,
		CASPutWallNanos:                     put,
		CASGetWallNanos:                     get,
		EditorOverheadExcludingCASWallNanos: compute,
	}
}

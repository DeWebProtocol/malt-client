package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"slices"
	"strings"
	"testing"

	"github.com/dewebprotocol/malt-client/merkledag/rq3baseline"
	materializermemory "github.com/dewebprotocol/malt/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt/auth/commitment"
	"github.com/dewebprotocol/malt/auth/commitment/kzg"
	"github.com/dewebprotocol/malt/mutation"
	clientwriter "github.com/dewebprotocol/malt/sdk/writer"
	"github.com/dewebprotocol/malt/wire/maltcid"
)

func TestParseFlagsRequiresDistinctBootstrapAuthorization(t *testing.T) {
	instanceToken := strings.Repeat("1", 64)
	bootstrapToken := strings.Repeat("2", 64)
	config, err := parseFlags([]string{
		"-gateway-base-url", "http://127.0.0.1:9000",
		"-gateway-instance-token", instanceToken,
		"-gateway-bootstrap-authorization-token", bootstrapToken,
		"-request-timeout", "1s",
	})
	if err != nil {
		t.Fatal(err)
	}
	if config.instanceToken != instanceToken || config.bootstrapAuthorizationToken != bootstrapToken {
		t.Fatalf("config = %#v", config)
	}
	if _, err := parseFlags([]string{
		"-gateway-base-url", "http://127.0.0.1:9000",
		"-gateway-instance-token", instanceToken,
		"-gateway-bootstrap-authorization-token", instanceToken,
		"-request-timeout", "1s",
	}); err == nil {
		t.Fatal("public instance token was accepted as bootstrap authorization")
	}
}

func TestControllerDirectoryIdentityRegistrationFailsClosed(t *testing.T) {
	leased := directoryIdentity{Profile: directoryIdentityProfile, Device: 11, Inode: 22}
	if err := validateRegisteredDirectoryIdentity(leased, leased); err != nil {
		t.Fatal(err)
	}
	for name, registered := range map[string]directoryIdentity{
		"missing":        {},
		"wrong profile":  {Profile: "stale", Device: 11, Inode: 22},
		"wrong device":   {Profile: directoryIdentityProfile, Device: 12, Inode: 22},
		"wrong inode":    {Profile: directoryIdentityProfile, Device: 11, Inode: 23},
		"missing device": {Profile: directoryIdentityProfile, Inode: 22},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateRegisteredDirectoryIdentity(registered, leased); err == nil {
				t.Fatal("missing or wrong registered directory identity was accepted")
			}
		})
	}
}

func TestControllerResponseMustEchoExactDirectoryIdentity(t *testing.T) {
	identity := directoryIdentity{Profile: directoryIdentityProfile, Device: 11, Inode: 22}
	response := controllerResponse{
		SchemaVersion: controllerResponseSchema, RequestID: "start", OK: true,
		CapabilityID: controllerCapabilityID, State: "ready", BindingSHA256: strings.Repeat("a", 64),
		DirectoryIdentity: identity,
	}
	if err := validateSelfTestGatewayControllerResponse(response, "start", "ready", response.BindingSHA256, identity, false); err != nil {
		t.Fatal(err)
	}
	wrong := response
	wrong.DirectoryIdentity.Inode++
	if err := validateSelfTestGatewayControllerResponse(wrong, "start", "ready", response.BindingSHA256, identity, false); err == nil {
		t.Fatal("controller response with the wrong directory identity was accepted")
	}
	stopped := response
	stopped.RequestID, stopped.State, stopped.Quiesced = "stop", "stopped", true
	if err := validateSelfTestGatewayControllerResponse(stopped, "stop", "stopped", response.BindingSHA256, identity, true); err != nil {
		t.Fatal(err)
	}
}

func TestHybridGraphIntentComputesExactNestedKZGRoot(t *testing.T) {
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	builder := graphBuilder{chunkBytes: 4, scheme: scheme, store: materializermemory.New(true)}
	oldState := map[string]logicalFile{
		"a/b/file.bin": {data: []byte("abcdefgh"), mode: 0o644, digest: strings.Repeat("1", 64)},
		"a/peer.txt":   {data: []byte("peer"), mode: 0o644, digest: strings.Repeat("2", 64)},
	}
	oldGraph, err := builder.build(t.Context(), oldState)
	if err != nil {
		t.Fatal(err)
	}
	view := graphUpdateView(t, oldGraph)
	nextState := cloneLogicalState(oldState)
	changed := nextState["a/b/file.bin"]
	changed.data = []byte("abcdWXYZ")
	changed.mode = 0o755
	nextState["a/b/file.bin"] = changed
	changedFile := nextState["a/b/file.bin"]
	priorFile := oldState["a/b/file.bin"]
	nextGraph, err := builder.buildNext(t.Context(), oldGraph, nextState, []fileChange{{
		path: "a/b/file.bin", before: &priorFile, after: &changedFile,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(nextGraph.order, objectLogicalID("file", "a/peer.txt")) || nextGraph.objects[objectLogicalID("file", "a/peer.txt")] != oldGraph.objects[objectLogicalID("file", "a/peer.txt")] {
		t.Fatal("incremental planner rebuilt the unaffected peer file")
	}
	oracle, err := (graphBuilder{chunkBytes: 4, scheme: scheme, store: materializermemory.New(true)}).build(t.Context(), nextState)
	if err != nil || !oracle.root.Equals(nextGraph.root) {
		t.Fatalf("incremental/full oracle mismatch: root=%s oracle=%v err=%v", nextGraph.root, oracle, err)
	}
	intent, err := graphIntent(view, oldGraph, nextGraph, "nested-replace")
	if err != nil {
		t.Fatal(err)
	}
	if len(intent.Transitions) < 4 {
		t.Fatalf("transitions = %d, want file plus three directory levels", len(intent.Transitions))
	}
	runtime, err := clientwriter.NewRuntime(
		materializermemory.New(true), map[maltcid.BackendKind]commitment.IndexCommitment{maltcid.BackendKindKZG: scheme},
	)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := runtime.VerifyUpdateView(t.Context(), view)
	if err != nil {
		t.Fatal(err)
	}
	computed, err := runtime.ComputeBundle(t.Context(), "rq3-test", verified, intent)
	if err != nil {
		t.Fatal(err)
	}
	if !computed.Bundle.Candidate.Equals(nextGraph.root) {
		t.Fatalf("candidate = %s, want locally rebuilt %s", computed.Bundle.Candidate, nextGraph.root)
	}
}

func TestOutputFreeBlueprintComputesSnapshotAndIncrementalRootsOnce(t *testing.T) {
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	oracleBuilder := graphBuilder{chunkBytes: 4, scheme: scheme, store: materializermemory.New(true)}
	emptyState := map[string]logicalFile{}
	emptyGraph, err := oracleBuilder.build(t.Context(), emptyState)
	if err != nil {
		t.Fatal(err)
	}
	emptyBlueprint, err := buildBlueprint(emptyState, 4)
	if err != nil {
		t.Fatal(err)
	}
	snapshotState := map[string]logicalFile{
		"a/b/file.bin": {data: []byte("abcdefgh"), mode: 0o644, digest: strings.Repeat("1", 64)},
		"peer.txt":     {data: []byte("peer"), mode: 0o644, digest: strings.Repeat("2", 64)},
	}
	snapshotBlueprint, err := buildBlueprint(snapshotState, 4)
	if err != nil {
		t.Fatal(err)
	}
	snapshotIntent, err := blueprintIntent(graphUpdateView(t, emptyGraph), emptyGraph, emptyBlueprint, snapshotBlueprint, "snapshot")
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := clientwriter.NewRuntime(
		materializermemory.New(true), map[maltcid.BackendKind]commitment.IndexCommitment{maltcid.BackendKindKZG: scheme},
	)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := runtime.VerifyUpdateView(t.Context(), graphUpdateView(t, emptyGraph))
	if err != nil {
		t.Fatal(err)
	}
	snapshotComputed, err := runtime.ComputeBundle(t.Context(), "snapshot", verified, snapshotIntent)
	if err != nil {
		t.Fatal(err)
	}
	snapshotOracle, err := (graphBuilder{chunkBytes: 4, scheme: scheme, store: materializermemory.New(true)}).build(t.Context(), snapshotState)
	if err != nil || !snapshotComputed.Bundle.Candidate.Equals(snapshotOracle.root) {
		t.Fatalf("snapshot candidate=%s oracle=%v err=%v", snapshotComputed.Bundle.Candidate, snapshotOracle, err)
	}

	nextState := cloneLogicalState(snapshotState)
	prior := nextState["a/b/file.bin"]
	next := prior
	next.data = []byte("abcdWXYZ")
	next.digest = strings.Repeat("3", 64)
	nextState["a/b/file.bin"] = next
	nextBlueprint, err := buildBlueprintNext(snapshotBlueprint, nextState, []fileChange{{
		path: "a/b/file.bin", before: &prior, after: &next,
	}}, 4)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(nextBlueprint.order, objectLogicalID("file", "peer.txt")) ||
		nextBlueprint.objects[objectLogicalID("file", "peer.txt")] != snapshotBlueprint.objects[objectLogicalID("file", "peer.txt")] {
		t.Fatal("incremental blueprint rebuilt an unaffected peer")
	}
	nextIntent, err := blueprintIntent(snapshotComputed.NextView, snapshotOracle, snapshotBlueprint, nextBlueprint, "replace")
	if err != nil {
		t.Fatal(err)
	}
	nextVerified, err := runtime.VerifyUpdateView(t.Context(), snapshotComputed.NextView)
	if err != nil {
		t.Fatal(err)
	}
	nextComputed, err := runtime.ComputeBundle(t.Context(), "replace", nextVerified, nextIntent)
	if err != nil {
		t.Fatal(err)
	}
	nextOracle, err := (graphBuilder{chunkBytes: 4, scheme: scheme, store: materializermemory.New(true)}).build(t.Context(), nextState)
	if err != nil || !nextComputed.Bundle.Candidate.Equals(nextOracle.root) {
		t.Fatalf("incremental candidate=%s oracle=%v err=%v", nextComputed.Bundle.Candidate, nextOracle, err)
	}
}

func TestSubtreeRenameUpdatesAllBindingsIncrementallyAndMatchesFullOracle(t *testing.T) {
	digest := func(value []byte) string {
		sum := sha256.Sum256(value)
		return hex.EncodeToString(sum[:])
	}
	file := func(value string) logicalFile {
		data := []byte(value)
		return logicalFile{data: data, mode: 0o644, digest: digest(data)}
	}
	state := map[string]logicalFile{
		"old/a":        file("aaaa"),
		"old/nested/b": file("bbbbbbbb"),
		"old/nested/c": file("cccc"),
		"peer/file":    file("peer"),
	}
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	builder := graphBuilder{chunkBytes: 4, scheme: scheme, store: materializermemory.New(true)}
	oldGraph, err := builder.build(t.Context(), state)
	if err != nil {
		t.Fatal(err)
	}
	mode := uint32(0o644)
	commit := rq3baseline.Commit{CommitID: "subtree-rename", Mutations: []rq3baseline.Mutation{
		{Kind: rq3baseline.MutationRename, Path: "old/a", Destination: "new/a", FileKind: rq3baseline.FileKindRegular, ExpectedOldSHA256: digest([]byte("aaaa")), ExpectedOldMode: &mode, Mode: &mode},
		{Kind: rq3baseline.MutationRename, Path: "old/nested/b", Destination: "new/nested/b", FileKind: rq3baseline.FileKindRegular, ExpectedOldSHA256: digest([]byte("bbbbbbbb")), ExpectedOldMode: &mode, Mode: &mode},
		{Kind: rq3baseline.MutationRename, Path: "old/nested/c", Destination: "new/nested/c", FileKind: rq3baseline.FileKindRegular, ExpectedOldSHA256: digest([]byte("cccc")), ExpectedOldMode: &mode, Mode: &mode},
	}}
	_, payloadBytes, changes, err := applyFrozenCommit(state, commit, 4, false)
	if err != nil {
		t.Fatal(err)
	}
	if payloadBytes != 0 || len(changes) != 6 {
		t.Fatalf("subtree rename payload=%d changes=%#v", payloadBytes, changes)
	}
	nextGraph, err := builder.buildNext(t.Context(), oldGraph, state, changes)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := state["old/a"]; exists || string(state["new/nested/b"].data) != "bbbbbbbb" {
		t.Fatalf("subtree rename state = %#v", state)
	}
	if nextGraph.objects[objectLogicalID("file", "peer/file")] != oldGraph.objects[objectLogicalID("file", "peer/file")] {
		t.Fatal("subtree rename rebuilt an unaffected peer file")
	}
	oracle, err := (graphBuilder{chunkBytes: 4, scheme: scheme, store: materializermemory.New(true)}).build(t.Context(), state)
	if err != nil || !oracle.root.Equals(nextGraph.root) {
		t.Fatalf("subtree incremental/full oracle mismatch: root=%s oracle=%v err=%v", nextGraph.root, oracle, err)
	}
}

func TestGatewayDeleteAccountingPreservesAttemptAndReclamation(t *testing.T) {
	accounting := exactAccounting{
		profile: gatewayAccountingProfile, available: true, method: gatewayByteMethod,
		digest: strings.Repeat("a", 64), categories: []exactCategory{
			{category: gatewayCategories[0]},
			{category: gatewayCategories[1]},
			{
				category: gatewayCategories[2], attemptedWrites: 1, attemptedBytes: 3,
				attemptedDeleteWrites: 1, attemptedDeleteBytes: 3, deletedWrites: 1,
				deletedReclaimedBytes: 8, reclaimedBytes: 8, netBytes: -8,
			},
		},
	}
	result := runResult{WriteEvents: []writeEvent{}}
	if err := result.appendGatewayAccounting("commit", accounting); err != nil {
		t.Fatal(err)
	}
	if len(result.WriteEvents) != 2 {
		t.Fatalf("events = %#v", result.WriteEvents)
	}
	attempt, committed := result.WriteEvents[0], result.WriteEvents[1]
	if attempt.Stage != stageAttempted || attempt.Disposition != dispositionDelete || attempt.Bytes != 3 ||
		committed.Stage != stageCommitted || committed.Disposition != dispositionDelete || committed.Bytes != 8 ||
		committed.GrossNewBytes != 0 || committed.ReclaimedBytes != 8 || committed.NetBytes != -8 ||
		attempt.ObjectKey != committed.ObjectKey {
		t.Fatalf("delete lifecycle = %#v / %#v", attempt, committed)
	}
}

func TestGatewayAggregateRejectsUnpairableNewBytes(t *testing.T) {
	accounting := exactAccounting{
		profile: gatewayAccountingProfile, available: true, method: gatewayByteMethod,
		digest: strings.Repeat("b", 64), categories: []exactCategory{
			{
				category: gatewayCategories[0], attemptedWrites: 1, attemptedBytes: 7,
				attemptedNewWrites: 1, attemptedNewBytes: 7, newlyPersistedWrites: 1,
				grossNewBytes: 8, newWrites: 1, newBytes: 8, netBytes: 8,
			},
			{category: gatewayCategories[1]}, {category: gatewayCategories[2]},
		},
	}
	result := runResult{WriteEvents: []writeEvent{}}
	if err := result.appendGatewayAccounting("commit", accounting); err == nil || !strings.Contains(err.Error(), "do not bind") {
		t.Fatalf("error = %v", err)
	}
}

func TestGatewayAggregatePreservesExactWriteCounts(t *testing.T) {
	accounting := exactAccounting{
		profile: gatewayAccountingProfile, available: true, method: gatewayByteMethod,
		digest: strings.Repeat("f", 64), categories: []exactCategory{
			{
				category: gatewayCategories[0], attemptedWrites: 3, attemptedBytes: 21,
				attemptedNewWrites: 3, attemptedNewBytes: 21, newlyPersistedWrites: 3,
				grossNewBytes: 21, newWrites: 3, newBytes: 21, netBytes: 21,
			},
			{category: gatewayCategories[1]}, {category: gatewayCategories[2]},
		},
	}
	result := runResult{WriteEvents: []writeEvent{}}
	if err := result.appendGatewayAccounting("commit", accounting); err != nil {
		t.Fatal(err)
	}
	if len(result.WriteEvents) != 2 || result.WriteEvents[0].Count != 3 || result.WriteEvents[1].Count != 3 {
		t.Fatalf("aggregate counts collapsed: %#v", result.WriteEvents)
	}
}

func TestCanonicalEmptySetupAccountingIsAttributedToFirstSnapshot(t *testing.T) {
	setup := &runResult{PassMode: "accounting", WriteEvents: []writeEvent{
		{
			Sequence: 99, CommitID: "setup-empty-top", Stage: stageAttempted,
			Category: categoryCASMetadata, Cause: "directory-manifest",
			Disposition: dispositionNew, ObjectKey: "bafy/setup-directory-manifest",
			Count: 1, Bytes: 12, CASClassification: casNew,
		},
		{
			Sequence: 100, CommitID: "setup-empty-top", Stage: stageCommitted,
			Category: gatewayCategories[2], Cause: "gateway-client-root-object-ledger",
			Disposition: dispositionNew, ObjectKey: "gateway-accounting/" + strings.Repeat("d", 64) + "/root-version-metadata/new",
			Count: 1, Bytes: 20, GrossNewBytes: 20, NetBytes: 20, CASClassification: casNotApplicable,
		},
	}}
	result := &runResult{PassMode: "accounting", WriteEvents: []writeEvent{{
		CommitID: "snapshot", Stage: stageAttempted, Category: categoryLogicalPayload,
		Cause: "snapshot-existing", Disposition: dispositionNew, ObjectKey: "existing",
		Count: 1, Bytes: 1, CASClassification: casNew,
	}}}

	attributeCanonicalEmptySetup(result, setup, "snapshot")
	if len(result.WriteEvents) != 3 {
		t.Fatalf("attributed events = %#v", result.WriteEvents)
	}
	for index, event := range result.WriteEvents {
		if event.Sequence != uint64(index) {
			t.Fatalf("event[%d] sequence = %d", index, event.Sequence)
		}
		if index == 0 {
			continue
		}
		if event.CommitID != "snapshot" || !strings.HasPrefix(event.Cause, canonicalEmptySetupCause) {
			t.Fatalf("setup event[%d] was not explicitly attributed: %#v", index, event)
		}
	}
	if result.WriteEvents[1].ObjectKey != setup.WriteEvents[0].ObjectKey || result.WriteEvents[2].ObjectKey != setup.WriteEvents[1].ObjectKey {
		t.Fatal("setup attribution changed exact lifecycle object keys")
	}
	if setup.WriteEvents[0].CommitID != "setup-empty-top" || setup.WriteEvents[0].Cause != "directory-manifest" {
		t.Fatal("setup attribution mutated its input sink")
	}

	timing := &runResult{PassMode: "timing", WriteEvents: []writeEvent{}}
	attributeCanonicalEmptySetup(timing, &runResult{PassMode: "timing", WriteEvents: []writeEvent{}}, "snapshot")
	if len(timing.WriteEvents) != 0 {
		t.Fatal("timing pass gained setup accounting events")
	}
}

func TestGatewayAggregateRejectsCounterOverflow(t *testing.T) {
	accounting := exactAccounting{
		profile: gatewayAccountingProfile, available: true, method: gatewayByteMethod,
		digest: strings.Repeat("c", 64), categories: []exactCategory{
			{
				category: gatewayCategories[0], attemptedWrites: math.MaxUint64,
				attemptedNewWrites: math.MaxUint64, attemptedReplacementWrites: 1,
			},
			{category: gatewayCategories[1]}, {category: gatewayCategories[2]},
		},
	}
	result := runResult{WriteEvents: []writeEvent{}}
	if err := result.appendGatewayAccounting("commit", accounting); err == nil || !strings.Contains(err.Error(), "overflows uint64") {
		t.Fatalf("error = %v", err)
	}
}

func TestStrictWorkerRequestRejectsDuplicateKeysAndTrailingJSON(t *testing.T) {
	for _, raw := range []string{
		`{"schema_version":"malt-rq3-malt-worker-request/v1","request_id":"one","request_id":"two","operation":"capabilities"}`,
		`{"schema_version":"malt-rq3-malt-worker-request/v1","request_id":"one","operation":"capabilities"} {}`,
	} {
		if _, err := decodeWorkerRequest([]byte(raw)); err == nil {
			t.Fatalf("hostile JSON accepted: %s", raw)
		}
	}
}

func TestControlledListPayloadAccountingUsesChangedFixedChunks(t *testing.T) {
	state := map[string]logicalFile{"payload.bin": {data: []byte("abcdefgh"), mode: 0o644}}
	mode := uint32(0o644)
	commit := rq3baseline.Commit{CommitID: "replace", Mutations: []rq3baseline.Mutation{{
		Kind: rq3baseline.MutationReplace, Path: "payload.bin", FileKind: rq3baseline.FileKindRegular,
		PayloadBase64: "YWJjZFdYWVo=", PayloadSHA256: strings.Repeat("a", 64),
		ExpectedOldSHA256: strings.Repeat("b", 64), ExpectedOldMode: &mode, Mode: &mode,
	}}}
	_, payloadBytes, _, err := applyFrozenCommit(state, commit, 4, true)
	if err != nil {
		t.Fatal(err)
	}
	if payloadBytes != 4 {
		t.Fatalf("logical payload bytes = %d, want one changed chunk", payloadBytes)
	}
}

func TestUnixFSConformanceRunsOnlyAfterAllMALTCommitMeasurements(t *testing.T) {
	spec := rq3baseline.RunSpec{
		Snapshot: rq3baseline.Snapshot{CommitID: "snapshot"},
		Commits:  []rq3baseline.Commit{{CommitID: "commit"}},
	}
	result := &runResult{Commits: []commitRecord{
		{CommitID: "snapshot", HistoryRootsRetained: 1, NonWorkloadSetupRootsRetained: 1, LogicalObjectsChanged: 1, LogicalBindingsChanged: 1, AdapterPayloadInputBytes: 4},
		{CommitID: "commit", HistoryRootsRetained: 2, NonWorkloadSetupRootsRetained: 1, LogicalObjectsChanged: 1, LogicalBindingsChanged: 1, AdapterPayloadInputBytes: 8},
	}}
	called := false
	runner := func(context.Context, rq3baseline.RunSpec) (*rq3baseline.RunResult, error) {
		called = true
		if len(result.Commits) != len(spec.Commits)+1 {
			t.Fatal("baseline runner observed an incomplete MALT result")
		}
		return &rq3baseline.RunResult{Records: []rq3baseline.CommitRecord{
			{CommitID: "snapshot", LogicalObjectsChanged: 1, LogicalBindingsChanged: 1, AdapterPayloadInputBytes: 4},
			{CommitID: "commit", LogicalObjectsChanged: 1, LogicalBindingsChanged: 1, AdapterPayloadInputBytes: 8},
		}}, nil
	}
	if err := postMeasurementBaselineConformance(t.Context(), spec, result, runner); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("post-measurement baseline conformance was not called")
	}

	called = false
	incomplete := &runResult{Commits: result.Commits[:1]}
	if err := postMeasurementBaselineConformance(t.Context(), spec, incomplete, runner); err == nil || called {
		t.Fatalf("incomplete result conformance: err=%v called=%v", err, called)
	}
}

func TestHybridGraphRepresentsEmptyRegularFileAsMeasuredList(t *testing.T) {
	scheme, err := kzg.NewScheme()
	if err != nil {
		t.Fatal(err)
	}
	builder := graphBuilder{chunkBytes: 4, scheme: scheme, store: materializermemory.New(true)}
	graph, err := builder.build(t.Context(), map[string]logicalFile{
		"empty.txt": {data: []byte{}, mode: 0o644, digest: strings.Repeat("e", 64)},
	})
	if err != nil {
		t.Fatal(err)
	}
	file := graph.objects[objectLogicalID("file", "empty.txt")]
	if file == nil || file.kind != "list" || file.entries.Len() != 0 || file.commit.FixedList == nil ||
		file.commit.FixedList.TotalSize != 0 || file.commit.FixedList.ChunkSize != 4 {
		t.Fatalf("empty file object = %#v", file)
	}
	blocks, err := fileCASBlocks(logicalFile{data: []byte{}, mode: 0o644}, true, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 1 || blocks[0].cause != "file-mode-sidecar" {
		t.Fatalf("empty file CAS blocks = %#v", blocks)
	}
}

func TestGitReplacementToZeroBytesHasNoChangedAfterChunks(t *testing.T) {
	mode := uint32(0o644)
	state := map[string]logicalFile{
		"file.txt": {data: []byte("x"), mode: mode, digest: strings.Repeat("1", 64)},
	}
	commit := rq3baseline.Commit{CommitID: "empty", Mutations: []rq3baseline.Mutation{{
		Kind: rq3baseline.MutationReplace, Path: "file.txt", FileKind: rq3baseline.FileKindRegular,
		PayloadBase64: "", PayloadSHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		ExpectedOldSHA256: strings.Repeat("1", 64), ExpectedOldMode: &mode, Mode: &mode,
	}}}
	blocks, payloadBytes, _, err := applyFrozenCommit(state, commit, 4, true)
	if err != nil {
		t.Fatal(err)
	}
	if payloadBytes != 0 || len(blocks) != 0 || len(state["file.txt"].data) != 0 {
		t.Fatalf("zero-byte Git replace: payload=%d blocks=%#v state=%#v", payloadBytes, blocks, state["file.txt"])
	}
}

func TestWorkloadIdentityRejectsNoncanonicalControlledCoordinates(t *testing.T) {
	identity := workloadIdentity{
		ID: "controlled", Kind: "controlled", ArtifactSHA256: strings.Repeat("1", 64),
		SemanticSHA256: strings.Repeat("2", 64), ChunkBytes: 4, CommitListSHA256: strings.Repeat("3", 64),
		HistoryRetention: "all-roots", ControlledStructure: "map",
		ControlledCoordinate: &controlledCoordinate{Operation: "replace", PathDepth: 1, DirectoryWidth: 1, FileChunks: 1, BatchSize: 1},
	}
	if err := validateWorkloadIdentity(identity); err != nil {
		t.Fatal(err)
	}
	identity.ControlledCoordinate.Operation = "Replace"
	if err := validateWorkloadIdentity(identity); err == nil {
		t.Fatal("uppercase coordinate operation was accepted")
	}
	identity.ControlledCoordinate.Operation = "replace"
	identity.ControlledCoordinate.PathDepth = 0
	if err := validateWorkloadIdentity(identity); err == nil {
		t.Fatal("zero coordinate axis was accepted")
	}
}

func graphUpdateView(t *testing.T, graph *hybridGraph) mutation.UpdateView {
	t.Helper()
	objects := make([]mutation.UpdateObject, 0, len(graph.objects))
	for _, object := range graph.objects {
		objects = append(objects, mutation.UpdateObject{
			ObjectID: object.logicalID, Root: object.root, Kind: object.kind,
			Entries: object.entries, Commit: object.commit,
		})
	}
	view := mutation.UpdateView{
		Profile: mutation.UpdateViewProfile, StateProfile: mutation.StatefulCompleteVectorsProfile,
		BaseRoot: graph.root, Bounds: mutation.UpdateViewBounds{MaxObjects: 100, MaxTotalEntries: 10_000, MaxDepth: 32},
		Objects: objects,
	}
	normalized, err := mutation.NormalizeUpdateView(view)
	if err != nil {
		t.Fatal(err)
	}
	return normalized
}

func cloneLogicalState(value map[string]logicalFile) map[string]logicalFile {
	result := make(map[string]logicalFile, len(value))
	for key, file := range value {
		file.data = append([]byte(nil), file.data...)
		result[key] = file
	}
	return result
}

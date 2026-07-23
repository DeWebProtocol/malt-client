package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/dewebprotocol/malt-client/internal/evaluation/e0selftest"
	"github.com/dewebprotocol/malt-client/internal/evaluation/machine"
	"github.com/dewebprotocol/malt-client/internal/evaluation/rq2e0"
	"github.com/dewebprotocol/malt-client/internal/evaluation/rq2fixture"
	"github.com/dewebprotocol/malt-client/internal/evaluation/rq2wire"
)

func TestNativeFormalE0RunsProductionKZGAndIPAMatrices(t *testing.T) {
	fixturePath := writeNativeE0Fixture(t)
	machinePath := writeNativeE0MachineDescriptor(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	environment, err := e0selftest.BuildInvocationEnvironment(
		nativeE0CapabilityID,
		nativeE0Profile,
		e0selftest.InputFile{FileID: "rq2-native-writer", Path: executable},
		[]e0selftest.InputFile{
			{FileID: "rq2-native-source-fixture", Path: fixturePath},
			{FileID: "rq2-native-machine-descriptor", Path: machinePath},
		},
		[]string{"rq2-native-source-fixture"},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(e0selftest.InvocationEnvironment, environment)
	var output bytes.Buffer
	if err := runNativeE0SelfTest([]string{
		"-fixture", fixturePath,
		"-machine-descriptor", machinePath,
		"-request-timeout", "30s",
	}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var receipt e0selftest.Receipt
	if err := json.Unmarshal(output.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if err := receipt.Validate(); err != nil {
		t.Fatal(err)
	}
	if receipt.CapabilityID != nativeE0CapabilityID || receipt.ProfileSHA256 != nativeE0ExpectedProfileSHA256 ||
		receipt.Positive.Executed != 2 || receipt.Hostile.Executed != 5 || len(receipt.TestedInputs) != 2 {
		t.Fatalf("native E0 receipt = %+v", receipt)
	}
}

func TestNativeFormalE0ConsumesOnlyFixtureAndMachineDescriptor(t *testing.T) {
	fixturePath := writeNativeE0Fixture(t)
	machinePath := writeNativeE0MachineDescriptor(t)
	extraPath := filepath.Join(t.TempDir(), "undeclared-runtime-input")
	if err := os.WriteFile(extraPath, []byte("must not be silently accepted"), 0o600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	environment, err := e0selftest.BuildInvocationEnvironment(
		nativeE0CapabilityID,
		nativeE0Profile,
		e0selftest.InputFile{FileID: "rq2-native-writer", Path: executable},
		[]e0selftest.InputFile{
			{FileID: "rq2-native-source-fixture", Path: fixturePath},
			{FileID: "rq2-native-machine-descriptor", Path: machinePath},
			{FileID: "rq2-native-undeclared-input", Path: extraPath},
		},
		[]string{"rq2-native-source-fixture"},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(e0selftest.InvocationEnvironment, environment)
	err = runNativeE0SelfTest([]string{"-fixture", fixturePath, "-machine-descriptor", machinePath}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("native formal E0 accepted an invocation input with no typed consumer")
	}
	if _, err := parseNativeE0Flags([]string{
		"-fixture", fixturePath,
		"-machine-descriptor", machinePath,
		"-gateway-controller", "/tmp/controller",
	}, &bytes.Buffer{}); err == nil {
		t.Fatal("native formal E0 accepted retired Gateway-controller flags")
	}
}

func TestNativeE0ProfileDigestIsStable(t *testing.T) {
	if digest := nativeE0ProfileDigest(); digest != nativeE0ExpectedProfileSHA256 {
		t.Fatalf("native E0 profile digest = %s", digest)
	}
}

func TestNativeLocalRequestProtocolMatchesSharedRQ2Wire(t *testing.T) {
	if workerRequestSchema != rq2wire.WorkerRequestSchema || workerRecordSchema != rq2wire.WorkerRecordSchema ||
		clientNative != rq2wire.ClientNative || lifecycleNativeLong != rq2wire.LifecycleNativeLong ||
		recordPreflight != rq2wire.RecordPreflight || recordSessionStart != rq2wire.RecordSessionStart ||
		recordMutation != rq2wire.RecordMutation || recordSessionEnd != rq2wire.RecordSessionEnd {
		t.Fatal("native-local and shared RQ2 wire constants drifted")
	}
	fixtureRaw, err := os.ReadFile(writeNativeE0Fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := rq2fixture.Decode(fixtureRaw)
	if err != nil {
		t.Fatal(err)
	}
	root, err := fixture.Root("kzg")
	if err != nil {
		t.Fatal(err)
	}
	shared := nativeE0Request(fixture.FixtureID, "kzg", "wire-compatibility", "session-start", rq2wire.RecordSessionStart, "", false, root.String())
	if err := shared.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(shared)
	if err != nil {
		t.Fatal(err)
	}
	local, err := decodeWorkerRequest(raw)
	if err != nil {
		t.Fatalf("native local decoder rejected shared request: %v", err)
	}
	localRaw, err := json.Marshal(local)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, localRaw) {
		t.Fatalf("native local request JSON %s differs from shared JSON %s", localRaw, raw)
	}
}

func writeNativeE0Fixture(t *testing.T) string {
	t.Helper()
	seed := sha256.Sum256([]byte("native formal E0 fixture mutation seed"))
	listIndex := uint64(1)
	chunkA := make([]byte, 32)
	chunkB := make([]byte, 32)
	copy(chunkA, "native-e0-list-chunk-a")
	copy(chunkB, "native-e0-list-chunk-b")
	source := &rq2fixture.SourceDefinition{
		SchemaVersion:      rq2fixture.SourceSchemaVersion,
		FixtureID:          "rq2-native-formal-e0",
		MutationSeedSHA256: hex.EncodeToString(seed[:]),
		DirectFiles: []rq2fixture.SourceDirectFile{
			{Path: "docs/modify.txt", Coordinate: "docs/modify.txt", Bytes: []byte("modify source")},
			{Path: "docs/delete.txt", Coordinate: "docs/delete.txt", Bytes: []byte("delete source")},
			{Path: "docs/move-source.txt", Coordinate: "docs/move-source.txt", Bytes: []byte("move source")},
			{Path: "docs/rename-source.txt", Coordinate: "docs/rename-source.txt", Bytes: []byte("rename source")},
		},
		ListFiles: []rq2fixture.SourceListFile{{
			Path: "data/large.bin", Coordinate: "data/large.bin", ChunkSize: 32, TotalSize: 64,
			Chunks: []rq2fixture.SourceListChunk{{Index: 0, Bytes: chunkA}, {Index: 1, Bytes: chunkB}},
		}},
		Operations: []rq2fixture.Operation{
			{Name: "append", Kind: rq2fixture.KindListAppend, SourcePath: "data/large.bin", SourceCoordinate: "data/large.bin", PayloadBytes: 32},
			{Name: "batch-sync", Kind: rq2fixture.KindBatchInsert, Batch: []rq2fixture.BatchTarget{
				{Path: "batch/one.txt", Coordinate: "batch/one.txt", PayloadBytes: 16},
				{Path: "batch/two.txt", Coordinate: "batch/two.txt", PayloadBytes: 20},
			}},
			{Name: "create-small-file", Kind: rq2fixture.KindDirectInsert, DestinationPath: "created/small.txt", DestinationCoordinate: "created/small.txt", PayloadBytes: 32},
			{Name: "delete-directory-entry", Kind: rq2fixture.KindDirectDelete, SourcePath: "docs/delete.txt", SourceCoordinate: "docs/delete.txt"},
			{Name: "insert-directory-entry", Kind: rq2fixture.KindDirectInsert, DestinationPath: "inserted/entry.txt", DestinationCoordinate: "inserted/entry.txt", PayloadBytes: 24},
			{Name: "modify-small-file", Kind: rq2fixture.KindDirectReplace, SourcePath: "docs/modify.txt", SourceCoordinate: "docs/modify.txt", PayloadBytes: 48},
			{Name: "move", Kind: rq2fixture.KindDirectMove, SourcePath: "docs/move-source.txt", SourceCoordinate: "docs/move-source.txt", DestinationPath: "moved/destination.txt", DestinationCoordinate: "moved/destination.txt"},
			{Name: "rename", Kind: rq2fixture.KindDirectMove, SourcePath: "docs/rename-source.txt", SourceCoordinate: "docs/rename-source.txt", DestinationPath: "docs/renamed.txt", DestinationCoordinate: "docs/renamed.txt"},
			{Name: "replace-large-file-chunk", Kind: rq2fixture.KindListReplace, SourcePath: "data/large.bin", SourceCoordinate: "data/large.bin", PayloadBytes: 32, ListIndex: &listIndex},
		},
	}
	fixture, err := rq2e0.BuildFixture(t.Context(), source)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "rq2-native-fixture.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeNativeE0MachineDescriptor(t *testing.T) string {
	t.Helper()
	identity, err := machine.Probe()
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := machine.NewDescriptor("rq2-native-e0-host", machine.ClassGeneral, "test-suite:live-machine-probe", identity)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "rq2-native-machine.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

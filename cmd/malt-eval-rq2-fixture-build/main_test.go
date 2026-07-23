package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/dewebprotocol/malt-client/internal/evaluation/rq2fixture"
	"github.com/dewebprotocol/malt/wire/maltcid"
)

func TestBuildsMatchedKZGAndIPAFixtureFromDeclaredBytes(t *testing.T) {
	chunkA := make([]byte, 32)
	chunkB := make([]byte, 32)
	copy(chunkA, "chunk-a")
	copy(chunkB, "chunk-b")
	seed := sha256.Sum256([]byte("builder seed"))
	source := &rq2fixture.SourceDefinition{
		SchemaVersion: rq2fixture.SourceSchemaVersion, FixtureID: "fixture", MutationSeedSHA256: hex.EncodeToString(seed[:]),
		DirectFiles: []rq2fixture.SourceDirectFile{{Path: "document.txt", Coordinate: "document.txt", Bytes: []byte("document")}},
		ListFiles: []rq2fixture.SourceListFile{{
			Path: "list.bin", Coordinate: "list.bin", ChunkSize: 32, TotalSize: 64,
			Chunks: []rq2fixture.SourceListChunk{{Index: 0, Bytes: chunkA}, {Index: 1, Bytes: chunkB}},
		}},
		Operations: []rq2fixture.Operation{{
			Name: "document-edit-cid-binding-submit", Kind: rq2fixture.KindDocumentEdit,
			SourcePath: "document.txt", SourceCoordinate: "document.txt", PayloadBytes: 32,
		}, {
			Name: "list-append", Kind: rq2fixture.KindListAppend,
			SourcePath: "list.bin", SourceCoordinate: "list.bin", PayloadBytes: 32,
		}},
	}
	if err := source.Validate(); err != nil {
		t.Fatal(err)
	}
	kzgBuild, err := buildBackend(t.Context(), "kzg", source)
	if err != nil {
		t.Fatal(err)
	}
	ipaBuild, err := buildBackend(t.Context(), "ipa", source)
	if err != nil {
		t.Fatal(err)
	}
	if maltcid.BackendKindOf(kzgBuild.root) != maltcid.BackendKindKZG || maltcid.BackendKindOf(ipaBuild.root) != maltcid.BackendKindIPA || kzgBuild.root.Equals(ipaBuild.root) {
		t.Fatalf("backend roots = %s, %s", kzgBuild.root, ipaBuild.root)
	}
	if len(kzgBuild.objects) != 2 || len(ipaBuild.objects) != 2 {
		t.Fatalf("complete bootstrap objects = %d, %d", len(kzgBuild.objects), len(ipaBuild.objects))
	}
	fixture, err := source.Fixture([]rq2fixture.RootBinding{{Backend: "kzg", CID: kzgBuild.root.String()}, {Backend: "ipa", CID: ipaBuild.root.String()}})
	if err != nil {
		t.Fatal(err)
	}
	if len(fixture.InitialRoots) != 2 || len(fixture.DirectFiles) != 1 || len(fixture.ListFiles[0].Chunks) != 2 {
		t.Fatalf("built fixture = %#v", fixture)
	}
	blocks, err := sourceBlocks(source)
	if err != nil || len(blocks) != 3 {
		t.Fatalf("deduplicated source blocks = %d, %v", len(blocks), err)
	}
}

func TestFixturePublishIsAtomicAndExclusive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture.json")
	if err := publishAtomicExclusive(path, []byte("first\n")); err != nil {
		t.Fatal(err)
	}
	if err := publishAtomicExclusive(path, []byte("second\n")); err == nil {
		t.Fatal("exclusive fixture publication overwrote an existing artifact")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "first\n" {
		t.Fatalf("published fixture = %q, %v", data, err)
	}
}

func TestBootstrapRegistrationRequiresProtectedOriginAndDistinctSecrets(t *testing.T) {
	valid := gatewayRegistration{
		backend: "kzg", baseURL: "http://127.0.0.1:8080",
		instanceToken: stringsRepeat("a"), bootstrapToken: stringsRepeat("b"),
	}
	if _, err := validateRegistration(valid); err != nil {
		t.Fatal(err)
	}
	hostile := valid
	hostile.baseURL = "http://192.0.2.1:8080"
	if _, err := validateRegistration(hostile); err == nil {
		t.Fatal("non-loopback plaintext bootstrap origin was accepted")
	}
	hostile = valid
	hostile.bootstrapToken = hostile.instanceToken
	if _, err := validateRegistration(hostile); err == nil {
		t.Fatal("shared instance/bootstrap secret was accepted")
	}

	kzg, err := validateRegistration(valid)
	if err != nil {
		t.Fatal(err)
	}
	ipa, err := validateRegistration(gatewayRegistration{
		backend: "ipa", baseURL: "http://127.0.0.1:8081",
		instanceToken: stringsRepeat("c"), bootstrapToken: stringsRepeat("d"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateIndependentRegistrations([]gatewayRegistration{kzg, ipa}); err != nil {
		t.Fatalf("independent registrations: %v", err)
	}
	for name, mutate := range map[string]func(*gatewayRegistration){
		"ipa instance reuses kzg bootstrap": func(value *gatewayRegistration) { value.instanceToken = kzg.bootstrapToken },
		"ipa bootstrap reuses kzg instance": func(value *gatewayRegistration) { value.bootstrapToken = kzg.instanceToken },
	} {
		t.Run(name, func(t *testing.T) {
			hostileIPA := ipa
			mutate(&hostileIPA)
			if err := validateIndependentRegistrations([]gatewayRegistration{kzg, hostileIPA}); err == nil {
				t.Fatal("cross-role Gateway token reuse was accepted")
			}
		})
	}
}

func stringsRepeat(value string) string {
	result := ""
	for range 64 {
		result += value
	}
	return result
}

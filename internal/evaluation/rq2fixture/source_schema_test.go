package rq2fixture

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestSourceDefinitionSchemaMatchesStrictOperationDecoder(t *testing.T) {
	schema := compileSourceSchema(t)
	valid := testSourceDefinition()
	raw, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeSource(raw); err != nil {
		t.Fatalf("Go decoder rejected valid all-kind source: %v", err)
	}
	if err := validateSourceSchema(schema, raw); err != nil {
		t.Fatalf("schema rejected valid all-kind source: %v", err)
	}

	hostile := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "unknown operation field", mutate: func(value map[string]any) {
			operations(value)[0]["invented"] = true
		}},
		{name: "missing required payload", mutate: func(value map[string]any) {
			delete(operations(value)[0], "payload_bytes")
		}},
		{name: "forbidden append index", mutate: func(value map[string]any) {
			operations(value)[4]["list_index"] = float64(0)
		}},
		{name: "unknown batch target field", mutate: func(value map[string]any) {
			batch := operations(value)[6]["batch"].([]any)
			batch[0].(map[string]any)["source_path"] = "wrong"
		}},
	}
	for _, test := range hostile {
		t.Run(test.name, func(t *testing.T) {
			var value map[string]any
			if err := json.Unmarshal(raw, &value); err != nil {
				t.Fatal(err)
			}
			test.mutate(value)
			hostileRaw, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeSource(hostileRaw); err == nil {
				t.Fatal("Go strict decoder accepted hostile operation shape")
			}
			if err := validateSourceSchema(schema, hostileRaw); err == nil {
				t.Fatal("JSON schema accepted hostile operation shape")
			}
		})
	}
}

func compileSourceSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(SourceSchemaJSON))
	if err != nil {
		t.Fatal(err)
	}
	if err := compiler.AddResource("source-definition.schema.json", document); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("source-definition.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

func validateSourceSchema(schema *jsonschema.Schema, raw []byte) error {
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	return schema.Validate(instance)
}

func operations(value map[string]any) []map[string]any {
	raw := value["operations"].([]any)
	result := make([]map[string]any, len(raw))
	for index := range raw {
		result[index] = raw[index].(map[string]any)
	}
	return result
}

func testSourceDefinition() SourceDefinition {
	chunkA := make([]byte, 32)
	chunkB := make([]byte, 32)
	copy(chunkA, "chunk-a")
	copy(chunkB, "chunk-b")
	seed := sha256.Sum256([]byte("source schema parity seed"))
	index := uint64(0)
	return SourceDefinition{
		SchemaVersion: SourceSchemaVersion, FixtureID: "fixture", MutationSeedSHA256: hex.EncodeToString(seed[:]),
		DirectFiles: []SourceDirectFile{
			{Path: "document.txt", Coordinate: "document.txt", Bytes: []byte("document")},
			{Path: "delete.txt", Coordinate: "delete.txt", Bytes: []byte("delete")},
			{Path: "move.txt", Coordinate: "move.txt", Bytes: []byte("move")},
		},
		ListFiles: []SourceListFile{{
			Path: "list.bin", Coordinate: "list.bin", ChunkSize: 32, TotalSize: 64,
			Chunks: []SourceListChunk{{Index: 0, Bytes: chunkA}, {Index: 1, Bytes: chunkB}},
		}},
		Operations: []Operation{
			{Name: "direct-replace", Kind: KindDirectReplace, SourcePath: "document.txt", SourceCoordinate: "document.txt", PayloadBytes: 16},
			{Name: "direct-insert", Kind: KindDirectInsert, DestinationPath: "insert.txt", DestinationCoordinate: "insert.txt", PayloadBytes: 16},
			{Name: "direct-delete", Kind: KindDirectDelete, SourcePath: "delete.txt", SourceCoordinate: "delete.txt"},
			{Name: "direct-move", Kind: KindDirectMove, SourcePath: "move.txt", SourceCoordinate: "move.txt", DestinationPath: "moved.txt", DestinationCoordinate: "moved.txt"},
			{Name: "list-append", Kind: KindListAppend, SourcePath: "list.bin", SourceCoordinate: "list.bin", PayloadBytes: 32},
			{Name: "list-replace", Kind: KindListReplace, SourcePath: "list.bin", SourceCoordinate: "list.bin", PayloadBytes: 32, ListIndex: &index},
			{Name: "batch-insert", Kind: KindBatchInsert, Batch: []BatchTarget{{Path: "batch.txt", Coordinate: "batch.txt", PayloadBytes: 16}}},
			{Name: "document-edit", Kind: KindDocumentEdit, SourcePath: "document.txt", SourceCoordinate: "document.txt", PayloadBytes: 32},
		},
	}
}

func ExampleSourceDefinition() {
	value := testSourceDefinition()
	fmt.Println(value.SchemaVersion, len(value.Operations))
	// Output: malt-rq2-source-definition/v1 8
}

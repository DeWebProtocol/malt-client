package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/dewebprotocol/malt-client/internal/evaluation/e0selftest"
	"github.com/dewebprotocol/malt-client/internal/evaluation/rq2e0"
	"github.com/dewebprotocol/malt-client/internal/evaluation/rq2fixture"
)

func TestBrowserE0ProfileContractIsFrozen(t *testing.T) {
	contract, err := browserE0Profile.Contract()
	if err != nil {
		t.Fatal(err)
	}
	if contract.ProfileID != browserE0ProfileID || contract.ProfileSHA256 != browserE0ExpectedProfileSHA256 || contract.PositiveCases != 4 || contract.HostileCases != 6 {
		t.Fatalf("browser formal E0 contract = %+v", contract)
	}
	if browserE0ProfileDigest() != browserE0ExpectedProfileSHA256 {
		t.Fatal("compiled browser E0 digest helper drifted")
	}
}

func TestBrowserE0FlagsRequireFiveTypedAbsolutePaths(t *testing.T) {
	paths := browserE0TestFiles(t)
	arguments := browserE0TestArguments(paths)
	config, err := parseBrowserE0Flags(arguments, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if config.timeout != 2*time.Minute || len(config.inputPaths()) != 5 {
		t.Fatalf("parsed browser E0 config = %+v", config)
	}
	for index, argument := range arguments {
		if argument == "-wasm-exec" {
			hostile := append([]string(nil), arguments...)
			hostile[index+1] = "relative/wasm_exec.js"
			if _, err := parseBrowserE0Flags(hostile, &bytes.Buffer{}); err == nil {
				t.Fatal("relative typed E0 input was accepted")
			}
			break
		}
	}
	if _, err := parseBrowserE0Flags(arguments[:len(arguments)-4], &bytes.Buffer{}); err == nil {
		t.Fatal("browser E0 accepted a missing typed input")
	}
}

func TestBrowserE0TypedFlagsConsumeExactInvocationInputs(t *testing.T) {
	paths := browserE0TestFiles(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		t.Fatal(err)
	}
	inputs := []e0selftest.InputFile{
		{FileID: "browser-launcher", Path: paths["browser-launcher"]},
		{FileID: "machine-descriptor", Path: paths["machine-descriptor"]},
		{FileID: "rq2-source-fixture", Path: paths["fixture"]},
		{FileID: "wasm", Path: paths["wasm"]},
		{FileID: "wasm-exec", Path: paths["wasm-exec"]},
	}
	invocation, err := e0selftest.BuildInvocationEnvironment(
		browserE0CapabilityID, browserE0Profile,
		e0selftest.InputFile{FileID: "rq2-browser-worker", Path: executable},
		inputs, []string{"rq2-source-fixture"},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(e0selftest.InvocationEnvironment, invocation)
	config, err := parseBrowserE0Flags(browserE0TestArguments(paths), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateBrowserE0InvocationPaths(config.inputPaths()); err != nil {
		t.Fatal(err)
	}
	config.wasmExecPath = config.wasmPath
	if err := validateBrowserE0InvocationPaths(config.inputPaths()); err == nil {
		t.Fatal("browser formal E0 accepted typed flags that did not consume the exact invocation inputs")
	}
}

func TestBrowserFormalE0ExecutesPinnedChromiumAndWASM(t *testing.T) {
	if testing.Short() || runtime.GOOS != "linux" {
		t.Skip("formal Chromium/WASM E0 integration requires a non-short Linux test")
	}
	directory := t.TempDir()
	browserPath := os.Getenv("MALT_BROWSER_E0_BROWSER")
	var err error
	if browserPath == "" {
		browserPath, err = exec.LookPath("chromium")
		if err != nil {
			browserPath, err = exec.LookPath("google-chrome")
		}
	}
	if err != nil || browserPath == "" {
		t.Skip("Chromium-family browser is not installed")
	}
	browserPath, err = filepath.Abs(browserPath)
	if err != nil {
		t.Fatal(err)
	}
	browserInfo, err := os.Lstat(browserPath)
	if err != nil {
		t.Fatal(err)
	}
	if browserInfo.Mode()&os.ModeSymlink != 0 {
		if browserPath != "/snap/bin/chromium" {
			t.Skip("formal E0 requires MALT_BROWSER_E0_BROWSER to name a regular non-symlink launcher")
		}
		// Ubuntu's Chromium snap exposes only a symlink to the generic snap
		// dispatcher. Pin a regular launcher script while the runtime version
		// probe below independently binds the Chromium build it dispatches.
		browserPath = filepath.Join(directory, "chromium-launcher")
		if err := os.WriteFile(browserPath, []byte("#!/bin/sh\nexec /snap/bin/chromium \"$@\"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	} else {
		browserPath, err = filepath.EvalSymlinks(browserPath)
		if err != nil {
			t.Fatal(err)
		}
	}
	wasmExecPath, err := filepath.EvalSymlinks(filepath.Join(runtime.GOROOT(), "lib", "wasm", "wasm_exec.js"))
	if err != nil {
		t.Skipf("matching wasm_exec.js is unavailable: %v", err)
	}
	wasmPath := filepath.Join(directory, "writer.wasm")
	moduleRoot := filepath.Clean(filepath.Join("..", ".."))
	build := exec.Command("go", "build", "-buildvcs=false", "-o", wasmPath, "./cmd/malt-eval-rq2-browser-wasm")
	build.Dir = moduleRoot
	build.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm", "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build real Go/WASM writer: %v\n%s", err, output)
	}
	fixture := browserE0Fixture(t)
	fixtureRaw, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	fixturePath := filepath.Join(directory, "fixture.json")
	if err := os.WriteFile(fixturePath, append(fixtureRaw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	machinePin := testMachinePin(t, false)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		t.Fatal(err)
	}
	inputs := []e0selftest.InputFile{
		{FileID: "browser-launcher", Path: browserPath},
		{FileID: "machine-descriptor", Path: machinePin.path},
		{FileID: "rq2-source-fixture", Path: fixturePath},
		{FileID: "wasm", Path: wasmPath},
		{FileID: "wasm-exec", Path: wasmExecPath},
	}
	invocation, err := e0selftest.BuildInvocationEnvironment(
		browserE0CapabilityID, browserE0Profile,
		e0selftest.InputFile{FileID: "rq2-browser-worker", Path: executable},
		inputs, []string{"rq2-source-fixture"},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(e0selftest.InvocationEnvironment, invocation)
	arguments := []string{
		"-fixture", fixturePath, "-machine-descriptor", machinePin.path,
		"-browser-launcher", browserPath, "-wasm", wasmPath, "-wasm-exec", wasmExecPath,
		"-request-timeout", "3m",
	}
	var output bytes.Buffer
	if err := runBrowserE0SelfTest(arguments, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var receipt e0selftest.Receipt
	if err := strictJSON(output.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if err := receipt.Validate(); err != nil {
		t.Fatal(err)
	}
	if receipt.CapabilityID != browserE0CapabilityID || receipt.ProfileSHA256 != browserE0ExpectedProfileSHA256 || len(receipt.TestedInputs) != 5 {
		t.Fatalf("formal browser E0 receipt = %+v", receipt)
	}
}

func browserE0Fixture(t *testing.T) *rq2fixture.Fixture {
	t.Helper()
	chunkA := make([]byte, 32)
	chunkB := make([]byte, 32)
	copy(chunkA, "chunk-a")
	copy(chunkB, "chunk-b")
	listIndex := uint64(0)
	seed := sha256.Sum256([]byte("formal browser E0 fixture seed"))
	source := &rq2fixture.SourceDefinition{
		SchemaVersion: rq2fixture.SourceSchemaVersion, FixtureID: "formal-browser-e0", MutationSeedSHA256: hex.EncodeToString(seed[:]),
		DirectFiles: []rq2fixture.SourceDirectFile{{Path: "document.txt", Coordinate: "document.txt", Bytes: []byte("document")}},
		ListFiles: []rq2fixture.SourceListFile{{
			Path: "list.bin", Coordinate: "list.bin", ChunkSize: 32, TotalSize: 64,
			Chunks: []rq2fixture.SourceListChunk{{Index: 0, Bytes: chunkA}, {Index: 1, Bytes: chunkB}},
		}},
		Operations: []rq2fixture.Operation{
			{Name: "document-edit-cid-binding-submit", Kind: rq2fixture.KindDocumentEdit, SourcePath: "document.txt", SourceCoordinate: "document.txt", PayloadBytes: 32},
			{Name: "map-replace", Kind: rq2fixture.KindDirectReplace, SourcePath: "document.txt", SourceCoordinate: "document.txt", PayloadBytes: 16},
			{Name: "map-insert", Kind: rq2fixture.KindDirectInsert, DestinationPath: "inserted.txt", DestinationCoordinate: "inserted.txt", PayloadBytes: 16},
			{Name: "list-append", Kind: rq2fixture.KindListAppend, SourcePath: "list.bin", SourceCoordinate: "list.bin", PayloadBytes: 32},
			{Name: "list-replace", Kind: rq2fixture.KindListReplace, SourcePath: "list.bin", SourceCoordinate: "list.bin", PayloadBytes: 32, ListIndex: &listIndex},
		},
	}
	fixture, err := rq2e0.BuildFixture(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func browserE0TestFiles(t *testing.T) map[string]string {
	t.Helper()
	directory := t.TempDir()
	paths := map[string]string{}
	for index, name := range []string{"fixture", "machine-descriptor", "browser-launcher", "wasm", "wasm-exec"} {
		path := filepath.Join(directory, name)
		mode := os.FileMode(0o600)
		if name == "browser-launcher" {
			mode = 0o700
		}
		if err := os.WriteFile(path, []byte(name+"-"+strconv.Itoa(index)), mode); err != nil {
			t.Fatal(err)
		}
		paths[name] = path
	}
	return paths
}

func browserE0TestArguments(paths map[string]string) []string {
	return []string{
		"-fixture", paths["fixture"], "-machine-descriptor", paths["machine-descriptor"],
		"-browser-launcher", paths["browser-launcher"], "-wasm", paths["wasm"],
		"-wasm-exec", paths["wasm-exec"], "-request-timeout", "2m",
	}
}

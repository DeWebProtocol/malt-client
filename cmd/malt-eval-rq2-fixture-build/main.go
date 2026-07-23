// Command malt-eval-rq2-fixture-build constructs the exact shared native and
// browser source fixture for paper RQ2. It computes KZG and IPA complete roots
// from declared bytes, uploads every payload, bootstraps each disposable
// Gateway through the secret evaluation capability, re-fetches and verifies
// both complete views, and only then atomically publishes one strict fixture.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dewebprotocol/malt-client/internal/evaluation/rq2fixture"
	"github.com/dewebprotocol/malt-client/transport"
	"github.com/dewebprotocol/malt/auth/arcset"
	materializermemory "github.com/dewebprotocol/malt/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt/auth/commitment"
	"github.com/dewebprotocol/malt/auth/commitment/ipa"
	"github.com/dewebprotocol/malt/auth/commitment/kzg"
	listtree "github.com/dewebprotocol/malt/auth/semantic/list/tree"
	"github.com/dewebprotocol/malt/auth/semantic/mapping"
	mappingradix "github.com/dewebprotocol/malt/auth/semantic/mapping/radix"
	"github.com/dewebprotocol/malt/mutation"
	"github.com/dewebprotocol/malt/protocol"
	clientwriter "github.com/dewebprotocol/malt/sdk/writer"
	"github.com/dewebprotocol/malt/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

const (
	requestTimeout = 30 * time.Minute
	instanceHeader = "X-Malt-Evaluation-Instance-Token"
	maxSourceBytes = 96 << 20
)

type gatewayRegistration struct {
	backend        string
	baseURL        string
	instanceToken  string
	bootstrapToken string
}

type builtObject struct {
	kind    arcset.Kind
	root    cid.Cid
	entries []transport.EvaluationBootstrapEntry
	commit  mutation.CommitDescriptor
}

type builtBackend struct {
	backend string
	root    cid.Cid
	scheme  commitment.IndexCommitment
	objects []builtObject
}

type artifactDescriptor struct {
	SchemaVersion string                   `json:"schema_version"`
	Path          string                   `json:"path"`
	SHA256        string                   `json:"sha256"`
	Bytes         int64                    `json:"bytes"`
	InitialRoots  []rq2fixture.RootBinding `json:"initial_roots"`
}

type tokenTransport struct {
	base  http.RoundTripper
	token string
}

func (t tokenTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	copyRequest := request.Clone(request.Context())
	copyRequest.Header = request.Header.Clone()
	copyRequest.Header.Set(instanceHeader, t.token)
	return t.base.RoundTrip(copyRequest)
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "malt-eval-rq2-fixture-build:", err)
		os.Exit(2)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("malt-eval-rq2-fixture-build", flag.ContinueOnError)
	flags.SetOutput(stderr)
	sourcePath := flags.String("source", "", "strict RQ2 source definition JSON")
	outputPath := flags.String("out", "", "new absolute fixture JSON path")
	kzgBase := flags.String("kzg-base-url", "", "empty disposable KZG Gateway origin")
	kzgInstance := flags.String("kzg-gateway-instance-token", "", "KZG Gateway instance identity")
	kzgBootstrap := flags.String("kzg-bootstrap-authorization-token", "", "distinct KZG bootstrap capability")
	ipaBase := flags.String("ipa-base-url", "", "empty disposable IPA Gateway origin")
	ipaInstance := flags.String("ipa-gateway-instance-token", "", "IPA Gateway instance identity")
	ipaBootstrap := flags.String("ipa-bootstrap-authorization-token", "", "distinct IPA bootstrap capability")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *sourcePath == "" || *outputPath == "" {
		return fmt.Errorf("source, output, and both KZG/IPA Gateway registrations are required")
	}
	registrations := []gatewayRegistration{
		{backend: "kzg", baseURL: *kzgBase, instanceToken: *kzgInstance, bootstrapToken: *kzgBootstrap},
		{backend: "ipa", baseURL: *ipaBase, instanceToken: *ipaInstance, bootstrapToken: *ipaBootstrap},
	}
	for index := range registrations {
		registration, err := validateRegistration(registrations[index])
		if err != nil {
			return err
		}
		registrations[index] = registration
	}
	if err := validateIndependentRegistrations(registrations); err != nil {
		return err
	}
	if registrations[0].baseURL == registrations[1].baseURL {
		return fmt.Errorf("KZG and IPA fixture build requires two independently identified disposable Gateways")
	}
	sourceRaw, err := readPinnedSource(*sourcePath)
	if err != nil {
		return err
	}
	source, err := rq2fixture.DecodeSource(sourceRaw)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	kzgBuild, err := buildBackend(ctx, "kzg", source)
	if err != nil {
		return err
	}
	ipaBuild, err := buildBackend(ctx, "ipa", source)
	if err != nil {
		return err
	}
	roots := []rq2fixture.RootBinding{{Backend: "kzg", CID: kzgBuild.root.String()}, {Backend: "ipa", CID: ipaBuild.root.String()}}
	fixture, err := source.Fixture(roots)
	if err != nil {
		return err
	}
	blocks, err := sourceBlocks(source)
	if err != nil {
		return err
	}
	for index, build := range []*builtBackend{kzgBuild, ipaBuild} {
		if err := initializeGateway(ctx, registrations[index], build, fixture, blocks); err != nil {
			return fmt.Errorf("initialize %s Gateway: %w", build.backend, err)
		}
	}
	raw, err := json.Marshal(fixture)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if _, err := rq2fixture.Decode(raw); err != nil {
		return fmt.Errorf("self-verify final RQ2 fixture: %w", err)
	}
	output, err := filepath.Abs(*outputPath)
	if err != nil {
		return err
	}
	if err := publishAtomicExclusive(output, raw); err != nil {
		return err
	}
	digest := sha256.Sum256(raw)
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(artifactDescriptor{
		SchemaVersion: "malt-rq2-source-fixture-artifact/v1", Path: output,
		SHA256: hex.EncodeToString(digest[:]), Bytes: int64(len(raw)), InitialRoots: roots,
	})
}

func validateRegistration(value gatewayRegistration) (gatewayRegistration, error) {
	value.baseURL = strings.TrimRight(strings.TrimSpace(value.baseURL), "/")
	value.instanceToken, value.bootstrapToken = strings.TrimSpace(value.instanceToken), strings.TrimSpace(value.bootstrapToken)
	parsed, err := url.Parse(value.baseURL)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" || parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.Scheme != "https" && !(parsed.Scheme == "http" && loopbackHost(parsed.Hostname())) {
		return gatewayRegistration{}, fmt.Errorf("%s Gateway bootstrap origin must be HTTPS or loopback HTTP", value.backend)
	}
	if !canonicalToken(value.instanceToken) || !canonicalToken(value.bootstrapToken) || value.instanceToken == value.bootstrapToken {
		return gatewayRegistration{}, fmt.Errorf("%s Gateway instance/bootstrap tokens must be distinct canonical SHA-256 values", value.backend)
	}
	return value, nil
}

func validateIndependentRegistrations(values []gatewayRegistration) error {
	seen := make(map[string]string, len(values)*2)
	for _, value := range values {
		for _, credential := range []struct {
			role  string
			token string
		}{{role: "instance", token: value.instanceToken}, {role: "bootstrap", token: value.bootstrapToken}} {
			label := value.backend + " " + credential.role
			token := credential.token
			if previous, exists := seen[token]; exists {
				return fmt.Errorf("KZG and IPA fixture build requires four globally distinct Gateway tokens: %s reuses %s token", label, previous)
			}
			seen[token] = label
		}
	}
	return nil
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func buildBackend(ctx context.Context, backend string, source *rq2fixture.SourceDefinition) (*builtBackend, error) {
	var scheme commitment.IndexCommitment
	var err error
	if backend == "kzg" {
		scheme, err = kzg.NewScheme()
	} else if backend == "ipa" {
		scheme, err = ipa.NewScheme()
	} else {
		return nil, fmt.Errorf("unsupported RQ2 backend %q", backend)
	}
	if err != nil {
		return nil, err
	}
	store := materializermemory.New(true)
	lister, err := listtree.NewList(scheme, store)
	if err != nil {
		return nil, err
	}
	mapper, err := mappingradix.NewMap(scheme, store)
	if err != nil {
		return nil, err
	}
	bindings := make(map[string]cid.Cid, len(source.DirectFiles)+len(source.ListFiles))
	for _, file := range source.DirectFiles {
		key, err := rawCID(file.Bytes)
		if err != nil {
			return nil, err
		}
		bindings[file.Path] = key
	}
	objects := make([]builtObject, 0, len(source.ListFiles)+1)
	for index, file := range source.ListFiles {
		chunks := make([]cid.Cid, len(file.Chunks))
		entries := make([]transport.EvaluationBootstrapEntry, len(file.Chunks))
		for chunkIndex, chunk := range file.Chunks {
			key, err := rawCID(chunk.Bytes)
			if err != nil {
				return nil, err
			}
			chunks[chunkIndex] = key
			coordinate := chunk.Index
			entries[chunkIndex] = transport.EvaluationBootstrapEntry{Index: &coordinate, Target: key}
		}
		root, err := lister.CommitFixed(ctx, fmt.Sprintf("rq2-list-%03d", index), chunks, file.ChunkSize, file.TotalSize)
		if err != nil {
			return nil, err
		}
		bindings[file.Path] = root
		objects = append(objects, builtObject{
			kind: arcset.KindList, root: root, entries: entries,
			commit: mutation.CommitDescriptor{FixedList: &mutation.FixedListCommit{ChunkSize: file.ChunkSize, TotalSize: file.TotalSize}},
		})
	}
	root, err := mapper.Commit(ctx, "rq2-root", mapping.NewViewFrom(bindings))
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(bindings))
	for path := range bindings {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	rootEntries := make([]transport.EvaluationBootstrapEntry, len(paths))
	for index, pathValue := range paths {
		path := pathValue
		rootEntries[index] = transport.EvaluationBootstrapEntry{Path: &path, Target: bindings[pathValue]}
	}
	objects = append(objects, builtObject{kind: arcset.KindMap, root: root, entries: rootEntries})
	return &builtBackend{backend: backend, root: root, scheme: scheme, objects: objects}, nil
}

func sourceBlocks(source *rq2fixture.SourceDefinition) ([]transport.Block, error) {
	byCID := make(map[string]transport.Block)
	add := func(data []byte) error {
		key, err := rawCID(data)
		if err != nil {
			return err
		}
		byCID[key.KeyString()] = transport.Block{Codec: cid.Raw, Data: append([]byte(nil), data...)}
		return nil
	}
	for _, file := range source.DirectFiles {
		if err := add(file.Bytes); err != nil {
			return nil, err
		}
	}
	for _, file := range source.ListFiles {
		for _, chunk := range file.Chunks {
			if err := add(chunk.Bytes); err != nil {
				return nil, err
			}
		}
	}
	keys := make([]string, 0, len(byCID))
	for key := range byCID {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	blocks := make([]transport.Block, len(keys))
	for index, key := range keys {
		blocks[index] = byCID[key]
	}
	return blocks, nil
}

func initializeGateway(ctx context.Context, registration gatewayRegistration, build *builtBackend, fixture *rq2fixture.Fixture, blocks []transport.Block) error {
	httpClient := &http.Client{
		Timeout: requestTimeout, Transport: tokenTransport{base: http.DefaultTransport, token: registration.instanceToken},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	remote, err := transport.New(transport.Options{BaseURL: registration.baseURL, HTTPClient: httpClient})
	if err != nil {
		return err
	}
	health, err := remote.Health(ctx)
	if err != nil {
		return err
	}
	if health.Status != "ok" || health.EvaluationInstanceToken != registration.instanceToken || health.BlobBackend != "embedded" || health.ArcTableMode != "versioned" ||
		health.CommitmentBackends != "ipa,kzg" || health.ClientRootExactAcceptance != "true" || health.EvaluationClientRootBootstrap != transport.EvaluationClientRootBootstrapProfile {
		return fmt.Errorf("Gateway health does not expose the exact clean RQ2 bootstrap boundary")
	}
	results, err := remote.PutBatch(ctx, blocks)
	if err != nil {
		return fmt.Errorf("upload RQ2 source blocks: %w", err)
	}
	if len(results) != len(blocks) {
		return fmt.Errorf("upload RQ2 source blocks returned %d results, want %d", len(results), len(blocks))
	}
	for index, block := range blocks {
		expected, err := rawCID(block.Data)
		if err != nil || !results[index].CID.Equals(expected) {
			return fmt.Errorf("Gateway returned a mismatched source block CID")
		}
	}
	backendKind := maltcid.BackendKind(build.backend)
	for index, object := range build.objects {
		result, err := remote.BootstrapEvaluationObject(ctx, registration.bootstrapToken, transport.EvaluationBootstrapObject{
			OperationID: fmt.Sprintf("rq2-%s-bootstrap-%03d", build.backend, index), Kind: object.kind,
			Backend: backendKind, ExpectedRoot: object.root, Entries: object.entries, Commit: object.commit,
		})
		if err != nil {
			return fmt.Errorf("bootstrap object %d: %w", index, err)
		}
		if !result.Root.Equals(object.root) {
			return fmt.Errorf("bootstrap object %d returned root %s, want %s", index, result.Root, object.root)
		}
	}
	view, err := remote.FetchUpdateView(ctx, build.root, &protocol.UpdateViewBounds{MaxObjects: 4096, MaxTotalEntries: 65536, MaxDepth: 256})
	if err != nil {
		return fmt.Errorf("fetch bootstrapped complete update view: %w", err)
	}
	runtime, err := clientwriter.NewRuntime(materializermemory.New(true), map[maltcid.BackendKind]commitment.IndexCommitment{backendKind: build.scheme})
	if err != nil {
		return err
	}
	verified, err := runtime.VerifyUpdateView(ctx, view.View)
	if err != nil {
		return fmt.Errorf("verify bootstrapped complete update view: %w", err)
	}
	if err := fixture.ValidateInitialView(verified.View, build.backend); err != nil {
		return fmt.Errorf("bootstrapped source/root oracle: %w", err)
	}
	return nil
}

func rawCID(data []byte) (cid.Cid, error) {
	digest, err := cid.Prefix{Version: 1, Codec: cid.Raw, MhType: 0x12, MhLength: 32}.Sum(data)
	return digest, err
}

func readPinnedSource(path string) ([]byte, error) {
	lstat, err := os.Lstat(path)
	if err != nil || lstat.Mode()&os.ModeSymlink != 0 || !lstat.Mode().IsRegular() || lstat.Size() <= 0 || lstat.Size() > maxSourceBytes {
		return nil, fmt.Errorf("RQ2 source definition is not a bounded regular file: %v", err)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(lstat, opened) {
		return nil, fmt.Errorf("RQ2 source definition changed before it was opened")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxSourceBytes+1))
	if err != nil {
		return nil, err
	}
	post, err := os.Lstat(path)
	if err != nil || !os.SameFile(lstat, post) || int64(len(raw)) != lstat.Size() {
		return nil, fmt.Errorf("RQ2 source definition changed while it was read")
	}
	return raw, nil
}

func publishAtomicExclusive(path string, raw []byte) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("fixture output path must be absolute")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return fmt.Errorf("fixture output already exists")
		}
		return err
	}
	temporary, err := os.CreateTemp(directory, ".rq2-fixture-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	succeeded := false
	defer func() {
		_ = temporary.Close()
		if !succeeded {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(raw); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Link(temporaryPath, path); err != nil {
		return err
	}
	if err := os.Remove(temporaryPath); err != nil {
		_ = os.Remove(path)
		return err
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		_ = os.Remove(path)
		return err
	}
	syncErr := directoryHandle.Sync()
	closeErr := directoryHandle.Close()
	if syncErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return errors.Join(syncErr, closeErr)
	}
	succeeded = true
	return nil
}

func canonicalToken(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

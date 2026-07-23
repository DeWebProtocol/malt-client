// Command malt-eval-rq1-fixture-build materializes the paper's shared RQ1
// payload/query fixture into one token-guarded empty Gateway. It creates one
// UnixFS root for the trusted Path/CAR/Direct-CAS routes and one MALT-KZG root,
// then verifies all D={1,2,4,8} paths before publishing a fixture descriptor.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dewebprotocol/malt-client/merkledag"
	merkledagimport "github.com/dewebprotocol/malt-client/merkledag/importer"
	"github.com/dewebprotocol/malt-client/transport"
	"github.com/dewebprotocol/malt/auth/arcset"
	"github.com/dewebprotocol/malt/auth/arcset/materializer/memory"
	"github.com/dewebprotocol/malt/auth/commitment/kzg"
	"github.com/dewebprotocol/malt/auth/semantic/mapping"
	"github.com/dewebprotocol/malt/auth/semantic/mapping/radix"
	"github.com/dewebprotocol/malt/protocol"
	clientverifier "github.com/dewebprotocol/malt/sdk/verifier"
	"github.com/dewebprotocol/malt/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

const (
	fixtureSchema     = "malt-rq1-shared-fixture/v1"
	descriptorSchema  = "malt-rq1-shared-fixture-descriptor/v1"
	bootstrapProfile  = "gateway.evaluation-client-root-bootstrap-object/v1"
	instanceHeader    = "X-Malt-Evaluation-Instance-Token"
	payloadBytes      = 4096
	unixFSChunkBytes  = 262144
	maximumResponse   = 8 << 20
	requestTimeout    = 5 * time.Minute
	fixtureIdentifier = "paper-rq1-shared-payload-depths-v1"
	unixFSProfile     = "unixfs-v1/basic-directory/balanced-file/raw-leaf/fixed-262144"
	maltProfile       = "canonical-nested-map/radix-256/kzg"
	verificationMode  = "trusted-path-plus-local-car-plus-local-direct-cas-plus-local-malt-prooflist-payload-binding"
	bootstrapObjects  = uint32(12)
)

var exactDepths = []depthFixture{
	{Depth: 1, Segments: []string{"d1"}},
	{Depth: 2, Segments: []string{"d2", "payload"}},
	{Depth: 4, Segments: []string{"d4", "a", "b", "payload"}},
	{Depth: 8, Segments: []string{"d8", "a", "b", "c", "d", "e", "f", "payload"}},
}

type depthFixture struct {
	Depth    int      `json:"depth"`
	Segments []string `json:"segments"`
}

type payloadFixture struct {
	CID    string `json:"cid"`
	Bytes  uint64 `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type routeRoot struct {
	Route string `json:"route"`
	Root  string `json:"root"`
}

type fixture struct {
	SchemaVersion  string         `json:"schema_version"`
	FixtureID      string         `json:"fixture_id"`
	Payload        payloadFixture `json:"payload"`
	Depths         []depthFixture `json:"depths"`
	Routes         []routeRoot    `json:"routes"`
	UnixFSProfile  string         `json:"unixfs_profile"`
	MALTProfile    string         `json:"malt_profile"`
	Verification   string         `json:"verification"`
	BootstrapCount uint32         `json:"bootstrap_object_count"`
}

type descriptor struct {
	SchemaVersion string `json:"schema_version"`
	Path          string `json:"path"`
	SHA256        string `json:"sha256"`
	Bytes         int64  `json:"bytes"`
}

type mapObject struct {
	root    cid.Cid
	entries map[string]cid.Cid
}

type trieNode struct {
	edges map[string]*trieEdge
}

type trieEdge struct {
	child   *trieNode
	payload bool
}

type tokenTransport struct {
	base  http.RoundTripper
	token string
}

func (transportWithToken tokenTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	copyRequest := request.Clone(request.Context())
	copyRequest.Header = request.Header.Clone()
	copyRequest.Header.Set(instanceHeader, transportWithToken.token)
	return transportWithToken.base.RoundTrip(copyRequest)
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "malt-eval-rq1-fixture-build:", err)
		os.Exit(2)
	}
}

func run(arguments []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("malt-eval-rq1-fixture-build", flag.ContinueOnError)
	flags.SetOutput(stderr)
	baseURL := flags.String("base-url", "", "token-guarded empty Gateway origin")
	instanceToken := flags.String("gateway-instance-token", "", "64-character evaluation instance token")
	bootstrapAuthorizationToken := flags.String("gateway-bootstrap-authorization-token", "", "distinct 64-character secret bootstrap capability")
	outputPath := flags.String("out", "", "new absolute fixture JSON path")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *baseURL == "" || *instanceToken == "" || *bootstrapAuthorizationToken == "" || *outputPath == "" {
		return errors.New("usage: malt-eval-rq1-fixture-build --base-url URL --gateway-instance-token TOKEN --gateway-bootstrap-authorization-token SECRET --out NEW.json")
	}
	if !canonicalToken(*instanceToken) || !canonicalToken(*bootstrapAuthorizationToken) || *instanceToken == *bootstrapAuthorizationToken {
		return errors.New("gateway instance and bootstrap authorization tokens must be distinct 64-character lowercase hexadecimal values")
	}
	parsed, err := url.Parse(strings.TrimRight(*baseURL, "/"))
	if err != nil || parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("base URL must be an absolute HTTP(S) origin")
	}
	output, err := filepath.Abs(*outputPath)
	if err != nil {
		return err
	}
	httpClient := &http.Client{
		Timeout:       requestTimeout,
		Transport:     tokenTransport{base: http.DefaultTransport, token: *instanceToken},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	remote, err := transport.New(transport.Options{BaseURL: parsed.String(), HTTPClient: httpClient})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	if err := verifyGatewayHealth(ctx, remote, *instanceToken); err != nil {
		return err
	}
	payload := deterministicPayload()
	payloadCID, err := remote.Put(ctx, payload)
	if err != nil {
		return fmt.Errorf("store shared payload: %w", err)
	}
	unixRoot, err := buildUnixFS(ctx, remote, payload)
	if err != nil {
		return err
	}
	maltRoot, objects, err := buildMALT(ctx, payloadCID)
	if err != nil {
		return err
	}
	if err := bootstrapMALT(ctx, remote, *bootstrapAuthorizationToken, objects); err != nil {
		return err
	}
	if err := verifyFixture(ctx, httpClient, parsed.String(), remote, unixRoot, maltRoot, payloadCID, payload); err != nil {
		return err
	}
	digest := sha256.Sum256(payload)
	value := fixture{
		SchemaVersion: fixtureSchema, FixtureID: fixtureIdentifier,
		Payload: payloadFixture{CID: payloadCID.String(), Bytes: uint64(len(payload)), SHA256: hex.EncodeToString(digest[:])},
		Depths:  cloneDepths(exactDepths),
		Routes: []routeRoot{
			{Route: "trusted-path-gateway", Root: unixRoot.String()}, {Route: "trustless-car", Root: unixRoot.String()},
			{Route: "direct-cas", Root: unixRoot.String()}, {Route: "malt-kzg", Root: maltRoot.String()},
		},
		UnixFSProfile:  unixFSProfile,
		MALTProfile:    maltProfile,
		Verification:   verificationMode,
		BootstrapCount: uint32(len(objects)),
	}
	if err := value.validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if err := publishExclusive(output, raw); err != nil {
		return err
	}
	artifactDigest := sha256.Sum256(raw)
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(descriptor{SchemaVersion: descriptorSchema, Path: output, SHA256: hex.EncodeToString(artifactDigest[:]), Bytes: int64(len(raw))})
}

func verifyGatewayHealth(ctx context.Context, remote *transport.Client, token string) error {
	health, err := remote.Health(ctx)
	if err != nil {
		return fmt.Errorf("read Gateway health: %w", err)
	}
	if health.Status != "ok" || health.EvaluationInstanceToken != token || health.KVBackend != "badger" || health.BlobBackend != "embedded" ||
		health.ArcTableMode != "versioned" || health.CommitmentProfile != "kzg" || health.EvaluationClientRootBootstrap != bootstrapProfile {
		return errors.New("Gateway does not expose the exact empty RQ1 fixture-build capability")
	}
	return nil
}

func deterministicPayload() []byte {
	payload := make([]byte, payloadBytes)
	for index := range payload {
		payload[index] = byte((index*131 + 17) % 251)
	}
	return payload
}

func buildUnixFS(ctx context.Context, remote *transport.Client, payload []byte) (cid.Cid, error) {
	editor, err := merkledagimport.NewEditor(remote, merkledagimport.Options{
		Model: merkledagimport.ModelUnixFS, FileLayout: merkledagimport.FileLayoutBalanced,
		DirLayout: merkledagimport.DirLayoutBasic, ChunkSize: unixFSChunkBytes, RawFileLeaf: true,
	})
	if err != nil {
		return cid.Undef, err
	}
	for _, depth := range exactDepths {
		if err := editor.PutFile(ctx, strings.Join(depth.Segments, "/"), payload, 0o644); err != nil {
			return cid.Undef, fmt.Errorf("materialize UnixFS depth %d: %w", depth.Depth, err)
		}
	}
	root, err := cid.Parse(editor.Root())
	if err != nil {
		return cid.Undef, fmt.Errorf("parse UnixFS fixture root: %w", err)
	}
	return root, nil
}

func buildMALT(ctx context.Context, payload cid.Cid) (cid.Cid, []mapObject, error) {
	root := &trieNode{edges: map[string]*trieEdge{}}
	for _, depth := range exactDepths {
		if err := root.insert(depth.Segments); err != nil {
			return cid.Undef, nil, err
		}
	}
	scheme, err := kzg.NewScheme()
	if err != nil {
		return cid.Undef, nil, err
	}
	mapper, err := radix.NewMap(scheme, memory.New(true))
	if err != nil {
		return cid.Undef, nil, err
	}
	rootCID, objects, err := commitTrie(ctx, mapper, root, payload)
	if err != nil {
		return cid.Undef, nil, err
	}
	return rootCID, objects, nil
}

func (node *trieNode) insert(segments []string) error {
	if node == nil || len(segments) == 0 {
		return errors.New("MALT fixture path is empty")
	}
	current := node
	for index, segment := range segments {
		if segment == "" || strings.Contains(segment, "/") {
			return fmt.Errorf("invalid MALT fixture segment %q", segment)
		}
		edge := current.edges[segment]
		last := index == len(segments)-1
		if edge == nil {
			edge = &trieEdge{}
			current.edges[segment] = edge
		}
		if last {
			if edge.child != nil || edge.payload {
				return errors.New("MALT fixture path conflicts with an existing path")
			}
			edge.payload = true
			continue
		}
		if edge.payload {
			return errors.New("MALT fixture path crosses a payload leaf")
		}
		if edge.child == nil {
			edge.child = &trieNode{edges: map[string]*trieEdge{}}
		}
		current = edge.child
	}
	return nil
}

func commitTrie(ctx context.Context, mapper *radix.Map, node *trieNode, payload cid.Cid) (cid.Cid, []mapObject, error) {
	keys := make([]string, 0, len(node.edges))
	for key := range node.edges {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	entries := make(map[string]cid.Cid, len(keys))
	objects := make([]mapObject, 0)
	for _, key := range keys {
		edge := node.edges[key]
		if edge.payload {
			entries[key] = payload
			continue
		}
		childRoot, childObjects, err := commitTrie(ctx, mapper, edge.child, payload)
		if err != nil {
			return cid.Undef, nil, err
		}
		objects = append(objects, childObjects...)
		entries[key] = childRoot
	}
	root, err := mapper.Commit(ctx, "default", mapping.NewViewFrom(entries))
	if err != nil {
		return cid.Undef, nil, err
	}
	objects = append(objects, mapObject{root: root, entries: entries})
	return root, objects, nil
}

func bootstrapMALT(ctx context.Context, remote *transport.Client, bootstrapAuthorizationToken string, objects []mapObject) error {
	for index, object := range objects {
		keys := make([]string, 0, len(object.entries))
		for key := range object.entries {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		entries := make([]transport.EvaluationBootstrapEntry, len(keys))
		for entryIndex, key := range keys {
			path := key
			entries[entryIndex] = transport.EvaluationBootstrapEntry{Path: &path, Target: object.entries[key]}
		}
		response, err := remote.BootstrapEvaluationObject(ctx, bootstrapAuthorizationToken, transport.EvaluationBootstrapObject{
			OperationID: fmt.Sprintf("rq1-fixture-map-%03d", index+1), Kind: arcset.KindMap,
			Backend: maltcid.BackendKindKZG, ExpectedRoot: object.root, Entries: entries,
		})
		if err != nil {
			return fmt.Errorf("bootstrap MALT object %d: %w", index, err)
		}
		if !response.Root.Equals(object.root) {
			return fmt.Errorf("bootstrap MALT object %d returned a different root/profile", index)
		}
	}
	return nil
}

func verifyFixture(ctx context.Context, client *http.Client, baseURL string, remote *transport.Client, unixRoot, maltRoot, payloadCID cid.Cid, payload []byte) error {
	compatibility, err := merkledag.New(remote)
	if err != nil {
		return err
	}
	verifier, err := clientverifier.NewDefault()
	if err != nil {
		return err
	}
	for _, depth := range exactDepths {
		carResult, err := compatibility.ReadMerkleDAGCARVerified(ctx, unixRoot, depth.Segments)
		if err != nil {
			return fmt.Errorf("verify CAR depth %d: %w", depth.Depth, err)
		}
		directResult, err := merkledag.ReadMerkleDAGDirectCASVerified(ctx, remote, unixRoot, depth.Segments, nil, nil)
		if err != nil {
			return fmt.Errorf("verify Direct CAS depth %d: %w", depth.Depth, err)
		}
		if !carResult.Target.Equals(payloadCID) || !directResult.Target.Equals(payloadCID) || !bytes.Equal(carResult.Data, payload) || !bytes.Equal(directResult.Data, payload) {
			return fmt.Errorf("Merkle-DAG routes do not bind the shared payload at depth %d", depth.Depth)
		}
		if err := verifyTrustedPath(ctx, client, baseURL, unixRoot, depth.Segments, payloadCID, payload); err != nil {
			return fmt.Errorf("verify trusted Path depth %d: %w", depth.Depth, err)
		}
		request := protocol.ResolveRequest{Profile: protocol.ResolveProfile, Root: maltRoot.String(), Segments: append([]string(nil), depth.Segments...)}
		result, err := remote.Resolve(ctx, request)
		if err != nil {
			return fmt.Errorf("resolve MALT depth %d: %w", depth.Depth, err)
		}
		if err := verifier.VerifyResolve(ctx, protocol.ResolveVerification{Request: request, Result: *result}); err != nil {
			return fmt.Errorf("locally verify MALT depth %d: %w", depth.Depth, err)
		}
		target, err := cid.Parse(result.Target)
		if err != nil || !target.Equals(payloadCID) {
			return fmt.Errorf("MALT depth %d returned a different target", depth.Depth)
		}
		bound, err := remote.Get(ctx, target)
		if err != nil {
			return fmt.Errorf("MALT depth %d payload fetch failed: %w", depth.Depth, err)
		}
		if !bytes.Equal(bound, payload) {
			return fmt.Errorf("MALT depth %d payload binding returned different bytes", depth.Depth)
		}
	}
	return nil
}

func verifyTrustedPath(ctx context.Context, client *http.Client, baseURL string, root cid.Cid, segments []string, target cid.Cid, payload []byte) error {
	request := struct {
		Profile  string   `json:"profile"`
		Root     string   `json:"root"`
		Segments []string `json:"segments"`
	}{Profile: merkledag.MerkleDAGReadProfile, Root: root.String(), Segments: append([]string(nil), segments...)}
	encoded, err := json.Marshal(request)
	if err != nil {
		return err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+"/v1/compat/merkledag/path/read", bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	response, err := client.Do(httpRequest)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumResponse+1))
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK || len(body) > maximumResponse || response.Header.Get("X-Malt-MerkleDAG-Target") != target.String() || !bytes.Equal(body, payload) {
		return fmt.Errorf("trusted Path response status=%d does not match target/payload", response.StatusCode)
	}
	return nil
}

func (value fixture) validate() error {
	if value.SchemaVersion != fixtureSchema || value.FixtureID != fixtureIdentifier || value.Payload.Bytes != payloadBytes || !canonicalToken(value.Payload.SHA256) ||
		len(value.Depths) != len(exactDepths) || len(value.Routes) != 4 || value.BootstrapCount != bootstrapObjects ||
		value.UnixFSProfile != unixFSProfile || value.MALTProfile != maltProfile || value.Verification != verificationMode {
		return errors.New("constructed RQ1 fixture is incomplete")
	}
	payload := deterministicPayload()
	payloadDigest := sha256.Sum256(payload)
	if value.Payload.SHA256 != hex.EncodeToString(payloadDigest[:]) {
		return errors.New("constructed RQ1 fixture does not bind the deterministic payload digest")
	}
	payloadCID, err := cid.Parse(value.Payload.CID)
	if err != nil || payloadCID.Prefix().Codec != cid.Raw {
		return errors.New("constructed RQ1 payload requires a canonical raw CID")
	}
	expectedPayloadCID, err := payloadCID.Prefix().Sum(payload)
	if err != nil || !payloadCID.Equals(expectedPayloadCID) {
		return errors.New("constructed RQ1 payload CID does not bind the deterministic bytes")
	}
	for index, depth := range value.Depths {
		if depth.Depth != exactDepths[index].Depth || !equalStrings(depth.Segments, exactDepths[index].Segments) {
			return errors.New("constructed RQ1 depth matrix differs from the paper fixture")
		}
	}
	exactRoutes := []string{"trusted-path-gateway", "trustless-car", "direct-cas", "malt-kzg"}
	roots := make([]cid.Cid, len(value.Routes))
	for index, route := range value.Routes {
		if route.Route != exactRoutes[index] {
			return errors.New("constructed RQ1 route order differs from the paper matrix")
		}
		root, err := cid.Parse(route.Root)
		if err != nil {
			return fmt.Errorf("parse %s fixture root: %w", route.Route, err)
		}
		roots[index] = root
	}
	if roots[0].Prefix().Codec != cid.DagProtobuf || !roots[0].Equals(roots[1]) || !roots[0].Equals(roots[2]) ||
		maltcid.BackendKindOf(roots[3]) != maltcid.BackendKindKZG || maltcid.SemanticKindOf(roots[3]) != maltcid.SemanticKindMap {
		return errors.New("constructed RQ1 route roots do not preserve shared Merkle/MALT boundaries")
	}
	return nil
}

func publishExclusive(path string, raw []byte) (resultErr error) {
	if !filepath.IsAbs(path) {
		return errors.New("fixture output path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := file.Close(); resultErr == nil && closeErr != nil {
			resultErr = closeErr
		}
		if resultErr != nil {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(raw); err != nil {
		return err
	}
	return file.Sync()
}

func cloneDepths(values []depthFixture) []depthFixture {
	result := make([]depthFixture, len(values))
	for index, value := range values {
		result[index] = depthFixture{Depth: value.Depth, Segments: append([]string(nil), value.Segments...)}
	}
	return result
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func canonicalToken(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

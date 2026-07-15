# Go API and CLI contracts

This document describes the pre-release integration surface owned by
`malt-client`. MALT protocol and ProofList schemas remain defined by the MALT
core repository.

## Public gateway transport

Import `github.com/dewebprotocol/malt-client/transport` and construct a validated
transport:

```go
remote, err := transport.New(transport.Options{BaseURL: "https://gateway.example"})
```

`Options` also exposes independent JSON, blob, and error-response byte limits.
Defaults are 96 MiB, 64 MiB, and 1 MiB respectively. Limits apply after HTTP
decompression; oversized and trailing JSON responses are rejected before their
contents are trusted or returned.

The transport exposes generic `Resolve` and `Read`, immutable CAS `Get`, `Put`,
`Has`, bounded `PutBatch`/`HasBatch`, root creation, semantic mutation, typed
diagnostic metrics, diagnostic verifier calls, and two fixed Merkle DAG
compatibility methods. It intentionally has no arbitrary profile-route method.
Transport methods validate wire shape and CAS bytes, but generic resolve/read
results remain untrusted until locally verified against caller inputs.

`Metrics` returns inexpensive monotonic counters. `MetricsWithStorage` also
requests Gateway's O(live KV entries) logical scan and should be used only by
controlled evaluation or operator tooling.

No exported signature contains a type from `internal/`.

## Reusable application use cases

Package `application` is the composition layer shared by CLI and daemon
adapters:

```go
roots, err := application.NewRoots(policy)
files, err := application.NewUnixFS(reader, writer, roots)
result, err := files.ReadFile(ctx, "accepted-alias", "docs/readme.md")
candidate, err := files.RemovePath(ctx, "accepted-alias", "old.txt")
```

An explicit CID bypasses alias lookup; an alias resolves only its accepted
root. `AddFile`, streaming add, directory add, and remove return independently
checked candidates. When an alias was selected, the use case records the
candidate against that exact accepted base, but never promotes it. Promotion
requires `Roots.AcceptCandidate`.

`application.MerkleDAG` similarly exposes fixed verified `Resolve`/`Read`
operations and reusable IPFS-compatible `ImportPath`, without exposing HTTP
routes or representing CID/link evidence as a ProofList.

Bulk local-input import is reusable through `application/add`. `add.Run` owns
option normalization, ignore and symlink policy, native hybrid staging,
Merkle DAG import, accepted-alias selection, and unaccepted candidate
recording. The caller injects a narrow graph/fixed-list Gateway and CAS; Cobra
is not part of this package.

## Verified native UnixFS

Construct a reader using narrow ports:

```go
reader, err := unixfs.NewReader(unixfs.ReaderOptions{
    Remote: remote,
    Blocks: remote,
})
result, err := reader.ReadFile(ctx, trustedRoot, "docs/readme.md")
```

For writing through the managed Gateway, adapt generic mutation receipts inside
the UnixFS application boundary:

```go
lists, err := unixfs.NewGatewayMutationAdapter(remote)
writer, err := unixfs.NewWriter(unixfs.WriterOptions{
    Remote: remote,
    Blocks: remote,
    Roots:  remote,
    Lists:  lists,
})
```

The public `unixfs.MutationTransport` returns
`unixfs.CandidateRootReceipt`, not a Gateway HTTP response type. Fixed-list base
creation and mutation-result decoding live in `GatewayMutationAdapter`, not in
generic transport.

The public operations are:

- `Resolve(ctx, trustedRoot, path)`;
- `Stat(ctx, trustedRoot, path)`;
- `ReadFile(ctx, trustedRoot, path)`;
- `ReadFileRange(ctx, trustedRoot, path, offset, length)`;
- `ReadListPayloadRange(ctx, trustedListRoot, offset, length)`; and
- `EmptyDirectory`, `AddDirectory`, `AddFile`, `AddFileStream`,
  `AddFileSized`, and `RemovePath` on a writer.

Read results retain their resolve and primitive-read evidence. Raw file and
directory-manifest bytes are rehashed against authenticated CIDs. Measured-list
reads locally verify the exact list-range ProofList, every segment CID, the
resolve-to-read root transition, and the assembled byte body.

`RemovePath` rematerializes immutable changed directories and verifies the new
root for internal consistency. Its result always contains `accepted: false`.
Only an explicit trust-store action or independent publication policy can
accept the candidate. The trust store binds every candidate to the accepted
base root and rejects recording or accepting it after that base becomes stale.

`AddFileSized` streams directly into chunk materialization and checks the
declared length. `AddFileStream` accepts an unknown length by spooling to the
writer's configured temporary directory, then uses the same sized path. Both
return an independently checked candidate root with `accepted: false`; they do
not update trusted-root policy.

## Trusted-root policy

Package `trust` owns durable accepted/candidate state. `AcceptedRoot` never
falls back to response data or to a candidate. Mutation and UnixFS writer
results remain candidates until `AcceptCandidate` is called explicitly.

Transport does not import or mutate this package.

## Merkle DAG compatibility

The public transport also supports:

- `merkledag.resolve/v0alpha1` at
  `POST /v1/compat/merkledag/resolve`; and
- `merkledag.read/v0alpha1` at `POST /v1/compat/merkledag/read`.

Both wire profiles carry `segments` as an array of opaque UTF-8 coordinates.
The transport and verifier do not split or reinterpret a segment, so
coordinates such as `"."`, `".."`, `"a/b"`, `""`, and `"\u0000"` remain
valid DAG-CBOR or DAG-JSON map keys. An empty array selects the root and is distinct from
an array containing one empty-string coordinate. The profile applies only
segment-count and per-segment byte limits; textual separator policy belongs to
the calling application.

Construct `merkledag.Client` over the shared transport and use
`ResolveMerkleDAGVerified` or `ReadMerkleDAGVerified` for the safe default:

```go
compatibility, err := merkledag.New(remote)
result, err := compatibility.ResolveMerkleDAGVerified(ctx, root, segments)
```

The corresponding `VerifyMerkleDAGResolve` and `VerifyMerkleDAGRead` helpers:

1. bind traversal to the caller-selected root and segment array;
2. recompute every returned block CID;
3. reject missing, duplicate, unreachable, or unsupported evidence blocks;
4. replay dag-pb/raw UnixFS traversal and DAG-CBOR/DAG-JSON CID-link traversal locally;
   and
5. reconstruct and compare requested file bytes and range metadata.

The verifier mirrors the gateway profile limits before allocating replay state:
at most 4,096 evidence blocks, 32 MiB of raw evidence bytes, and 16 MiB of file
data per read response.

Merkle DAG evidence is intentionally not converted into a MALT ProofList.

For compatibility tools that need to inspect blocks outside UnixFS, import
`github.com/dewebprotocol/malt-client/merkledag/ipld`. Its parser verifies
bytes against the supplied CID before decoding and exposes `ParseBlock`,
`ResolveLink`, `GetAllLinks`, and `FollowLink`; applications may register
additional bounded codecs.

## CLI output

```text
malt stat <trusted-root|alias> [path]
malt cat <trusted-root|alias> [path]
malt cat <trusted-root|alias> [path] --offset N --length N
malt rm <trusted-root|alias> <path>
malt merkledag resolve <trusted-root-cid> [path]
malt merkledag cat <trusted-root-cid> [path] [--offset N --length N]
```

- `stat` writes one JSON object containing verified metadata and evidence.
- `cat` writes exact verified bytes only; diagnostics and JSON are not mixed
  into stdout.
- `--offset` and `--length` must be supplied together. Ranges past EOF are
  clipped and a zero length returns an empty body.
- `rm` writes one JSON object with `base_root`, `candidate_root`, and
  `accepted: false`. When the first argument is an alias, the candidate is
  recorded but not promoted.
- `merkledag resolve` writes the locally replayed compatibility response as
  JSON; `merkledag cat` writes exact locally replayed bytes. Both require an
  explicit CID, never consult the MALT trust store, and never claim ProofList
  verification. Their optional CLI `path` is specifically a UnixFS string-path
  adapter: it splits on `/` and rejects empty, `.`, `..`, and NUL path parts.
  Go and JSON integrations that need arbitrary IPLD coordinates should call the
  typed `segments` API directly.

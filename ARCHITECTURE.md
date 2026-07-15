# MALT Client Architecture

## Boundary

This repository is a client application, not the graph-authentication SDK and
not a managed gateway service.

It owns:

- the `malt` CLI and local daemon lifecycle;
- trusted/candidate root state and explicit acceptance;
- gateway HTTP transport;
- UnixFS path, manifest, fixed-list payload, import, and range-body semantics;
- IPFS-compatible Merkle DAG UnixFS import as an alternative client target;
- local replay verification for gateway Merkle DAG compatibility reads;
- application-level payload-byte verification.

It depends on `github.com/dewebprotocol/malt` for canonical graph types,
resolve/read/mutation protocols, ProofList verification, CID rules, and
commitment implementations. It must not copy or redefine those contracts.

It depends on a gateway for ArcTable materialization, CAS persistence, proof
generation, and mutation execution. The gateway is not a trust authority.

## Data flow

```text
UnixFS path / local files
          |
          v
  malt-client application adapter
          |
          | canonical segments, generic resolve/read/mutation/CAS requests
          v
     untrusted gateway
          |
          | result + ProofList + payload bytes
          v
  local MALT core verification
          |
          v
accepted application result or candidate root
```

Application separators are parsed here. MALT core receives typed segment
arrays and resolves canonical arcs; HTTP uses JSON arrays rather than assigning
core semantics to `/`, `.`, or `[]`.

The current native UnixFS materializer is `hybrid`: each directory becomes an
authenticated map root, and ancestor maps also retain descendant root-relative
path bindings. Pure flat and pure hierarchical materializers are possible
future client strategies, not aliases for the current implementation.

For `malt add --target merkle-dag`, the client uses Boxo to construct explicit
dag-pb UnixFS blocks and writes those immutable blocks through the same untrusted
gateway CAS. That path returns a Merkle DAG CID and does not invoke MALT
resolve/read/proof semantics. Supporting both targets is a client feature, not
an indication that Merkle DAG semantics belong in core.

The gateway may execute Merkle DAG traversal as a compatibility service. In
that flow it returns every touched CID-bound block. The public client hashes
each block and independently replays UnixFS traversal from the caller-selected
Merkle DAG root. This is Merkle DAG authentication, not MALT authentication,
and uses `merkledag.resolve/v0alpha1` and `merkledag.read/v0alpha1`, never a
ProofList. Resolve replay also follows DAG-CBOR/DAG-JSON map/list coordinates that
terminate at CID links; successful read replay still requires a UnixFS file.
The compatibility wire contract carries coordinates as a typed `segments`
array. Each segment is opaque UTF-8 data rather than a URL or filesystem path
component, so values such as `.`, `..`, `a/b`, the empty string, and U+0000 are
looked up exactly. Only the CLI's optional UnixFS string path applies `/`
splitting and portable path restrictions.

## Application, transport, and trust policy

The dependency direction is deliberate:

```text
cmd/malt -> unixfs or merkledag application
         -> trust policy
         -> transport
unixfs   -> MALT core verifier + narrow transport ports
merkledag -> CID/link replay + narrow profile transport
transport -> HTTP only; never imports unixfs, merkledag, or trust
```

`transport.Client` is one reusable HTTP connection, but consumers depend on
the narrow `Native`, `Mutations`, `CAS`, or `Diagnostics` interfaces rather
than a single mega-interface. Transport results remain untrusted. The
application layer supplies the caller-selected root, performs local proof or
CID/link replay, and binds payload bytes. The `trust` package alone persists
accepted roots and promotes candidates through an explicit action.

## Verified UnixFS facade

`unixfs` owns the transport-neutral native reader/writer facade. Its remote
port contains only generic MALT resolve/read operations; CAS and root creation
are separate narrow capabilities. The facade:

1. parses `/` as UnixFS application syntax;
2. constructs requests from a caller-selected trusted root;
3. verifies every resolve/read result locally;
4. requires primitive list reads to start at the verified resolve target;
5. checks raw blocks and directory manifests against authenticated CIDs;
6. checks list-range segments and the assembled body; and
7. returns removal output only as an unaccepted candidate root.

`Stat` uses a bounded one-byte measured-list query to authenticate size and
chunk metadata without returning an O(file-size) segment list. Actual range
reads carry their own exact range proof.

## Daemon

The daemon is a local control plane for trusted-root state. It listens only on
a user-owned Unix socket with mode `0600`, or an owner/system-only Windows
named pipe derived from the state path. It does not expose a public proof
verification endpoint and does not make a gateway-generated root trusted. A
managed background daemon is bound to its state file by a random lifecycle
instance token; `stop` and `restart` signal a PID only after the private
identity endpoint authenticates that same instance. Daemon API calls and
foreground CLI commands share a cross-process trust-store lock and reload the
latest state before every read or mutation, so neither can overwrite a newer
explicit trust decision with a stale in-memory snapshot. Candidate creation
and acceptance also carry the accepted base root: if that root has advanced,
the operation fails as stale instead of applying a sibling transition.

## Packages

- `cmd/malt`: CLI and daemon process lifecycle.
- `transport`: untrusted native MALT/CAS HTTP transport and narrow capability
  interfaces.
- `trust`: accepted and candidate root policy plus durable local persistence.
- `merkledag`: isolated compatibility profile client and local CID/link replay.
- `merkledag/importer`: IPFS-compatible UnixFS DAG construction.
- `merkledag/ipld`: generic CID-validating IPLD parsing and link traversal for
  Merkle-DAG compatibility applications.
- `internal/daemon`: local Unix-socket/Windows-pipe root-control API.
- `internal/cas`: client-side CAS helpers and byte verification.
- `unixfs/model`: UnixFS application values and path rules.
- `unixfs`: verified UnixFS reader/writer facade, staging, materialization,
  and payload verification.

The `internal` packages are not compatibility promises. The public
`transport`, `trust`, `unixfs`, and `merkledag` packages are the intended
pre-release integration surface; their profiles remain experimental until a
release policy is published. Architecture tests fail if transport begins to
import application or trust packages, or if Merkle DAG compatibility begins to
depend on MALT ProofList contracts.

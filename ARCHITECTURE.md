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

## Daemon

The daemon is a local control plane for trusted-root state. It listens only on
a user-owned Unix socket with mode `0600`. It does not expose a public proof
verification endpoint and does not make a gateway-generated root trusted. A
managed background daemon is bound to its state file by a random lifecycle
instance token; `stop` and `restart` signal a PID only after the private
identity endpoint authenticates that same instance. Daemon API calls and
foreground CLI commands share a cross-process trust-store lock and reload the
latest state before every read or mutation, so neither can overwrite a newer
explicit trust decision with a stale in-memory snapshot.

## Packages

- `cmd/malt`: CLI and daemon process lifecycle.
- `internal/gateway`: generic gateway transport.
- `internal/truststore`: accepted and candidate root persistence.
- `internal/daemon`: local Unix-socket root-control API.
- `internal/cas`: client-side CAS helpers and byte verification.
- `internal/merkledagimport`: IPFS-compatible UnixFS DAG construction.
- `unixfs/model`: UnixFS application values and path rules.
- `unixfs/sdk`: UnixFS staging, materialization, and payload verification.

The `internal` packages are not compatibility promises. The CLI and public
`unixfs` packages remain experimental until a release policy is published.

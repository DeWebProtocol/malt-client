# MALT Client Architecture

## Boundary

This repository is a client application, not the graph-authentication SDK and
not a managed gateway service.

It owns:

- the `malt` CLI and local daemon lifecycle;
- trusted/candidate root state and explicit acceptance;
- gateway HTTP transport;
- UnixFS path, manifest, fixed-list payload, import, and range-body semantics;
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

## Daemon

The daemon is a local control plane for trusted-root state. It listens only on
a user-owned Unix socket with mode `0600`. It does not expose a public proof
verification endpoint and does not make a gateway-generated root trusted.

## Packages

- `cmd/malt`: CLI and daemon process lifecycle.
- `internal/gateway`: generic gateway transport.
- `internal/truststore`: accepted and candidate root persistence.
- `internal/daemon`: local Unix-socket root-control API.
- `internal/cas`: client-side CAS helpers and byte verification.
- `unixfs/model`: UnixFS application values and path rules.
- `unixfs/sdk`: UnixFS staging, materialization, and payload verification.

The `internal` packages are not compatibility promises. The CLI and public
`unixfs` packages remain experimental until a release policy is published.

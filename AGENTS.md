# AGENTS.md

## Scope

This repository owns the trusted MALT client application: CLI, local daemon,
accepted-root policy, UnixFS application semantics, Merkle DAG import
compatibility, gateway transport, and payload-byte verification.

## Boundaries

- Do not define MALT protocol, ProofList, commitment, CID, schema, or canonical
  graph semantics here; use the `malt` module.
- Do not add ArcTable/KV persistence or managed gateway policy here; those
  belong in `gateway`.
- Treat gateway responses as untrusted and verify against caller-selected
  roots locally.
- Never promote a mutation result to a trusted root without explicit local
  acceptance or an independent root-publication policy.
- Keep application separators and UnixFS path rules in this repository. Pass
  typed segment arrays to MALT core.
- Keep IPFS-style Merkle DAG import and compatibility policy here. A Merkle DAG
  root is a compatibility output, not a MALT-authenticated root or ProofList.

## Package Ownership

- `transport/` is an untrusted HTTP capability layer. It may expose native
  MALT, mutation, CAS, and diagnostic ports, but it must not import `trust`,
  `unixfs`, or `merkledag`.
- `trust/` is the only package that persists accepted/candidate roots or
  promotes a candidate. It must not depend on network or application packages.
- `unixfs/` owns the MALT-authenticated UnixFS facade, staging,
  materialization, and payload/range verification. Keep reusable UnixFS
  behavior here rather than under `cmd/malt`.
- `merkledag/` owns the compatibility client and local CID/link-evidence
  replay; `merkledag/importer` owns import construction. Do not represent this
  evidence as a MALT ProofList.
- `cmd/malt/` is the application composition root. Command handlers should
  select capabilities and format results, not become a second UnixFS or trust
  implementation.
- Preserve `internal/architecture` dependency tests when adding packages or
  moving responsibilities.

## Validation

Run `gofmt`, `git diff --check`, `go test ./...`, `go vet ./...`, and
`go build -buildvcs=false ./...` before committing. Also run a Windows
cross-build for changes to daemon lifecycle, locking, filesystem, or CLI code.

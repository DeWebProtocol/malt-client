# AGENTS.md

## Scope

This repository owns the trusted MALT client application: CLI, local daemon,
accepted-root policy, UnixFS application semantics, gateway transport, and
payload-byte verification.

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

## Validation

Run `gofmt`, `git diff --check`, `go test ./...`, `go vet ./...`, and
`go build -buildvcs=false ./...` before committing.

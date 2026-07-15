# MALT Client

`malt-client` is the trusted local client and UnixFS application built on the
[MALT core SDK](https://github.com/DeWebProtocol/malt). It owns the concerns
that must not be part of the application-neutral authentication core:

- accepted and candidate root policy;
- application-path parsing and UnixFS materialization;
- optional IPFS-compatible Merkle DAG UnixFS import;
- calls to a remote MALT gateway;
- local verification of resolve/read proofs and returned payload bytes;
- a user-owned daemon control plane over a private Unix socket or Windows
  named pipe.

The gateway is an untrusted proof producer. A successful gateway response does
not update an accepted root automatically: mutation results are recorded as
candidates until the user explicitly accepts them.

## Status

This is an experimental, pre-v1 client. It currently provides the `malt` CLI,
a local trusted-root daemon, and a UnixFS application adapter. There is no
independent `malt-client` release tag yet; build from a pinned commit.

The current development baseline pins MALT core commit `97838dc7ab61` from
[core PR #169](https://github.com/DeWebProtocol/malt/pull/169) through Go
pseudo-version `v0.0.7-0.20260715072445-97838dc7ab61`. This is an exact
integration dependency, not a claim that MALT core v0.0.7 has been released.

## Build

Go 1.25.7 or newer is required.

```bash
go test ./...
go vet ./...
go build -o bin/malt ./cmd/malt
```

## Quick start

Start a compatible gateway, then initialize the local client:

```bash
./bin/malt init
./bin/malt daemon start
./bin/malt daemon status
```

Trust an independently obtained root, resolve a UnixFS path, and add a local
tree:

```bash
./bin/malt root trust my-data <root-cid>
./bin/malt resolve my-data docs/readme.txt
./bin/malt add ./my-data --alias my-data
./bin/malt root list
./bin/malt root accept my-data <candidate-root-cid>
```

Read verified native UnixFS content and materialize a removal candidate:

```bash
./bin/malt stat my-data docs/readme.txt
./bin/malt cat my-data docs/readme.txt
./bin/malt cat my-data media/video.bin --offset 1048576 --length 262144 > part.bin
./bin/malt rm my-data docs/obsolete.txt
./bin/malt root accept my-data <candidate-root-from-rm>
```

`stat` emits JSON including locally verified resolve/read evidence. `cat`
writes only verified file bytes to stdout. `rm` never changes the accepted root:
it emits `accepted: false` and, when given an alias, records the result as a
candidate for a later explicit `root accept` command.

The native MALT target currently exposes one UnixFS materialization strategy:
`hybrid` (the default). Each directory is an authenticated map root, while
ancestor maps retain descendant root-relative path bindings. Pure `flat` and
pure `hierarchical` strategies remain design and evaluation counterfactuals;
they are not accepted CLI values.

The same client can materialize one local file or directory as an
IPFS-compatible Merkle DAG while reusing the gateway CAS:

```bash
./bin/malt add --target merkle-dag \
  --file-layout balanced --dir-layout adaptive ./my-data
```

This returns a Merkle DAG root CID. It does not create a MALT root, ProofList,
or trusted-root candidate, so `--root` and `--alias` are intentionally rejected
for this target.

The public Go API is importable as:

```go
import (
    "github.com/dewebprotocol/malt-client/application"
    "github.com/dewebprotocol/malt-client/merkledag"
    "github.com/dewebprotocol/malt-client/transport"
    "github.com/dewebprotocol/malt-client/trust"
    "github.com/dewebprotocol/malt-client/unixfs"
)
```

Package `application` is the reusable use-case layer used by the CLI and local
daemon. It selects explicit or locally accepted roots, composes verified UnixFS
and Merkle DAG reads, records writer results as candidates, and exposes
candidate promotion only as an explicit call. Its `application/add` package
owns the CLI-independent ignore, symlink, staging, hybrid materialization, and
Merkle DAG import workflow used by `malt add`.

Explicit CIDs are selected without opening `roots.json`; the trust store is
required only for an alias. A missing, corrupt, or unwritable alias store
therefore cannot block an otherwise valid explicit-CID operation.

Package `transport` is an untrusted gateway transport. Package `trust` owns
accepted/candidate root policy. Package `unixfs`
composes it into verified `Resolve`, `Stat`, `ReadFile`, `ReadFileRange`,
`ReadListPayloadRange`, `EmptyDirectory`, `AddDirectory`, `AddFile`, streaming
file writes, and `RemovePath` operations. The UnixFS facade requires
a caller-selected root, verifies ProofLists locally, enforces resolve-to-read
continuity, and verifies raw, manifest, and measured-list payload bytes.

Package `merkledag` owns the gateway's distinct compatibility profiles over a
narrow fixed-route profile transport. `ResolveMerkleDAGVerified` and
`ReadMerkleDAGVerified` recompute every
evidence block CID and replay the UnixFS link traversal locally. These results
are never represented as MALT ProofLists.

The transport exposes only fixed Merkle DAG resolve/read route capabilities;
applications cannot supply an arbitrary Gateway route and JSON body.

The transport exposes bounded ordered CAS `PutBatch`/`HasBatch` and a
typed diagnostic metrics snapshot. Package `merkledag/ipld` restores the
generic CID-bound raw, DAG-PB, DAG-CBOR, DAG-JSON, and legacy JSON parser/link
toolkit for client-side compatibility code.

The CLI exposes the same fail-closed read path without consulting the MALT root
store:

```bash
./bin/malt merkledag resolve <merkle-dag-root-cid> docs/readme.txt
./bin/malt merkledag cat <merkle-dag-root-cid> docs/readme.txt
```

Run `malt <command> --help` for the exact flags and output contract.

Default state lives under `~/.malt-client/`. The generated configuration points
to `http://127.0.0.1:8080`; edit `gateway.base_url` to select another gateway.

## Trust model

1. The caller chooses an already trusted root.
2. The client sends canonical segments to the gateway.
3. The gateway returns the result and ProofList.
4. The client verifies the proof against the caller-selected root using MALT
   core.
5. For payload reads, the client also verifies returned bytes against the
   authenticated CID.
6. A mutation's new root remains a candidate until explicit local acceptance
   or an independent publication mechanism establishes trust.

See [ARCHITECTURE.md](./ARCHITECTURE.md) for repository boundaries.
See [docs/go-api.md](./docs/go-api.md) for the public API and CLI contracts.
The [v0.0.5 migration matrix](./docs/v0.0.5-parity.md) records which former
core application capabilities moved here and which were deliberately re-homed.

## License

MIT. See [LICENSE](./LICENSE).

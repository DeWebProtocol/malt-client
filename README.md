# MALT Client

`malt-client` is the trusted local client and UnixFS application built on the
[MALT core SDK](https://github.com/DeWebProtocol/malt). It owns the concerns
that must not be part of the application-neutral authentication core:

- accepted and candidate root policy;
- application-path parsing and UnixFS materialization;
- optional IPFS-compatible Merkle DAG UnixFS import;
- calls to a remote MALT gateway;
- local verification of resolve/read proofs and returned payload bytes;
- a user-owned daemon control plane over a Unix socket.

The gateway is an untrusted proof producer. A successful gateway response does
not update an accepted root automatically: mutation results are recorded as
candidates until the user explicitly accepts them.

## Status

This is an experimental, pre-v1 client. It currently provides the `malt` CLI,
a local trusted-root daemon, and a UnixFS application adapter. There is no
independent `malt-client` release tag yet; build from a pinned commit.

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
The [v0.0.5 migration matrix](./docs/v0.0.5-parity.md) records which former
core application capabilities moved here and which were deliberately re-homed.

## License

MIT. See [LICENSE](./LICENSE).

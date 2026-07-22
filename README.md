# MALT Client

`malt-client` is the trusted local client and UnixFS application built on the
[MALT core SDK](https://github.com/DeWebProtocol/malt). It owns the concerns
that must not be part of the application-neutral authentication core:

- accepted and candidate root policy;
- application-path parsing and UnixFS materialization;
- optional IPFS-compatible Merkle DAG UnixFS import;
- calls to a remote MALT gateway;
- durable managed-Bucket base/remote/stash synchronization state;
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

The client boundary refactor is merged on `main` at `2ac844cfeeb5`. The current
evaluation writer depends on the MALT core changes proposed in
[PR #174](https://github.com/DeWebProtocol/malt/pull/174) at
`f9bf36cdcef0`; `go.mod` pins that exact development revision as
`v0.0.7-0.20260722075700-f9bf36cdcef0`. Cross-repository verification also uses
the exact checkout through a pinned `go.work` overlay. This provenance does not
claim that PR #174 has merged or that MALT core v0.0.7 has been released.

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

For a managed Gateway, set `gateway.api_key` and `gateway.bucket` in the
generated `0600` config, then observe the initial head before producing or
pushing local work:

```bash
./bin/malt bucket list
./bin/malt bucket pull
./bin/malt bucket status
./bin/malt add ./local-change --root <observed-head-root>
./bin/malt bucket push <candidate-root-cid> -m "update docs"
./bin/malt bucket branches
```

In Bucket mode, native `malt add` and `malt rm` capture the current base before
materialization and stage the resulting candidate in
`~/.malt-client/buckets.json`. `bucket push` refuses an unstaged candidate,
fetches the remote head without changing the recorded base, and reuses the
same push ID across retries. For candidates created by another tool, use
`bucket stage <candidate> --base-commit ... --base-root ... --base-revision ...`
with the base captured before materialization. The Gateway may fast-forward,
auto-merge independent map changes, or return a preserved conflict branch.
Bucket heads remain untrusted observations and are never promoted in
`roots.json` by this workflow.

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
	"github.com/dewebprotocol/malt-client/bucketsync"
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
Explicitly typed alias inputs such as `malt add --alias` always perform alias
lookup, even when the alias text happens to be CID-shaped.

Package `transport` is an untrusted gateway transport. Package `trust` owns
accepted/candidate root policy. Package `unixfs`
composes it into verified `Resolve`, `Stat`, `ReadFile`, `ReadFileRange`,
`ReadListPayloadRange`, `EmptyDirectory`, `AddDirectory`, `AddFile`, streaming
file writes, and `RemovePath` operations. The UnixFS facade requires
a caller-selected root, verifies ProofLists locally, enforces resolve-to-read
continuity, and verifies raw, manifest, and measured-list payload bytes.

With `transport.Options{TenantBearerToken: ..., BucketID: ...}`, native
MALT/CAS calls use the authenticated Bucket routes. Package `bucketsync`
persists base, observed remote head, and local stashes under a cross-process
lock and implements stash-before-fetch push ordering. It deliberately does not
import or mutate package `trust`.

Single-value CAS `Get`/`Has` require that authenticated Bucket selection. The
transport does not attempt the Gateway's removed public raw-CAS GET/HEAD route;
unscoped calls fail locally without sending a request.

Package `merkledag` owns the gateway's distinct compatibility profiles over a
narrow fixed-route profile transport. `ResolveMerkleDAGVerified` and
`ReadMerkleDAGVerified` recompute every
evidence block CID and replay the UnixFS link traversal locally. These results
are never represented as MALT ProofLists.

The transport exposes only fixed Merkle DAG resolve/read route capabilities;
applications cannot supply an arbitrary Gateway route and JSON body. When a
Bucket is configured, these calls use its authenticated compatibility routes
and cannot fall back to the public CAS namespace.

The evaluator-only `cmd/malt-eval-rq1-worker` keeps CAR and Direct-CAS replay
inside this client repository. Each successful JSONL record brackets the real
route request(s) with the Gateway's token-bound cache-observation lease,
records live health/capability evidence, reports per-operation user/system CPU
and process-lifetime peak RSS, and emits explicit zero values for inapplicable
MALT server phases. Failed records never carry partial metrics or cache claims.

The evaluator-only RQ2 workers exercise the real client-root session rather
than a detached commitment microbenchmark. The native worker mutates a real
temporary filesystem and observes scan, chunk, hash, update-view verification,
normalization, Root computation, payload-CAS upload, bundle encoding, Gateway
replay/persist, and local receipt checks. `mutation_total` is the inclusive
client-observed latency and has `applicable=true`, `bytes=0`, and `count=1`.
For native it begins immediately before update-view Load and ends after the
exact durable receipt advances the writer; for browser it has the same boundary
inside Go/WASM. It excludes the browser host/JS/CDP boundary, cold start, and
post-image correctness oracle. Every mutation emits
`taxonomy_profile=malt-rq2-metric-taxonomy/v1`. Its executable reconciliation
contract distinguishes inclusive totals, exclusive mutation phases, nested
diagnostics, browser/cold-start phases, and orthogonal CPU/memory resources;
reports must select one compatible duration group instead of stacking all
fields. Payload upload reports only the PutBatch request body and round trip;
the client-root bundle reports request bytes, while receipt checking reports
only response bytes. Bytes and counts are field-specific resource evidence and
are never an additive phase decomposition (for example, update fetch and local
verification both observe the same update-view bytes). Unclassified wall time
remains an explicit residual under the inclusive total, not an invented phase.
The `normalization` phase measures the canonical retained-view snapshot and
semantic-intent planning performed by the application plus the writer SDK's
view and intent normalization. Those application-owned durations are also
included in `client_root_generation`; SDK digesting, bundle validation, and
next-view construction remain measured residual work inside that inclusive
subtotal. Evidence digests come from the exact canonical bundle prepared by
the SDK, so evaluator workers do not repeat digest or normalization work merely
to populate evidence fields.
The browser worker drives the WASM boundary and reports cold download,
instantiation, public-parameter loading, first mutation, steady-state mutation,
JS/WASM crossings, CPU, and peak memory. Short-session runs use independently
started cold and steady-baseline processes instead of arithmetically combining
unrelated samples.

`cmd/malt-eval-rq2-fixture-build` is the sole producer for the shared RQ2
source fixture. It consumes one pinned source definition and two independently
identified empty bootstrap-enabled Gateway origins, computes KZG and IPA Roots
locally, uploads every payload, installs every map/list object through the
secret evaluation bootstrap capability, and fetches and verifies both complete
update views before publishing the fixture create-exclusively. The matching
Gateway bootstrap controllers are sealed with those emitted Roots before their
closed state directories are passed to the Gateway-owned semantic snapshot
packer; an unverified fixture file alone is not a preloaded snapshot.

The evaluator-only RQ3 workers replay the evaluator's portable source mutation
stream through either the current MALT client/Gateway path or the Merkle
DAG/HAMT comparison path. They emit exact attempted and newly-persisted object
events by accounting category; the evaluator, not these workers, owns campaign
matching, Git first-parent trace provenance, and physical reconciliation.
The MALT adapter bootstraps one canonical empty top object outside the timed
workload, then sends the frozen snapshot and every later commit through the
same exact client-root product path. The setup Root remains retained: each
commit reports one `non_workload_setup_roots_retained` in addition to
`history_roots_retained`, which counts workload Roots only. In the accounting
pass all durable setup CAS and Gateway allocations are attributed to the first
snapshot commit with a `canonical-empty-setup:` cause prefix, so logical and
physical state reconcile without charging setup work to snapshot latency. Its
measured path retains an incremental output-free
logical blueprint and delegates the only commitment computation to the writer;
an independent full-build Root oracle runs after the timing boundary. The
legacy `client_compute_wall_ns` field is the inclusive client-observed
source-to-durable latency (payload upload and submission included). Gateway
replay/persist are server-side diagnostics nested within that observation and
must be reported separately rather than summed into it. These
commands are benchmark process boundaries, not supported user CLI.

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
Tenant bearer credentials require HTTPS except for loopback development.

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

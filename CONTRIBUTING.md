# Contributing

Keep changes on the trusted-client and UnixFS application side of the MALT
boundary. Protocol, ProofList, commitment, CID, schema, and core algorithm
changes belong in [DeWebProtocol/malt](https://github.com/DeWebProtocol/malt).
ArcTable/KV/CAS persistence, managed service policy, deployment, and gateway
product E2E belong in
[DeWebProtocol/gateway](https://github.com/DeWebProtocol/gateway).

Before submitting a change, run:

```bash
git diff --check
go test ./...
go vet ./...
go build -buildvcs=false ./...
```

Run `gofmt` on changed Go files. Tests involving a gateway should treat all
gateway results as untrusted and bind verification to a caller-selected root.

# Contributing

Keep changes on the trusted-client, UnixFS application, and Merkle DAG
compatibility side of the MALT boundary. Protocol, ProofList, commitment, CID, schema, and core algorithm
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
Merkle DAG compatibility tests must independently check the returned root CID
and stored blocks; they must not describe a DAG root as a MALT trust root.

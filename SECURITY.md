# Security Policy

`malt-client` is experimental and is not production-ready. Security fixes may
make breaking changes before v1.

Do not open a public issue for a suspected vulnerability. Use GitHub private
vulnerability reporting for this repository or email security@deweb.world with
`SECURITY` in the subject or opening line. Include reproduction steps, the
affected commit, and any proof-of-concept data needed to reproduce the issue.

High-value reports include proof/result binding failures, payload bytes accepted
without CID verification, implicit trust of a gateway-generated root, unsafe
local file traversal, Unix-socket permission issues, and trusted-root state
corruption. Merkle DAG import reports should also cover malformed dag-pb
construction, unsafe local traversal, ignore-policy bypass, or a gateway CAS
response accepted without binding it to the uploaded block bytes.

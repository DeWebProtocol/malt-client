# Typed authentication in the local runtime

`application.Authentication` composes explicit or locally accepted Root
selection with Core's input registry, Prefix/Positional engine and typed
Gateway transport. `Read` verifies the returned traversal/binding/range
against the caller's Root and query before returning it. `Store` computes a
candidate locally and requires the exact Root in the materialization receipt.
It does not promote accepted roots or publish a head. The optional previous
Root describes storage lineage only.

`transport.Client` implements Authenticate, AuthenticationCandidate and
MaterializeAuthentication for the native and managed Bucket routes. These
responses are untrusted; transport does not import application or trust policy.
Application ports remain narrow interfaces satisfied by that client.

Input values and derivation remain Core-owned. Labels are opaque base64 bytes;
uint64 positions/selectors use decimal strings on the wire. UnixFS path parsing
stays in `unixfs/model`; AuthenticationSteps produces explicit component labels.
A full-path index instead submits one opaque full-path label. A Root's AA, not
slash syntax inferred by the generic engine, chooses the conversion rule.
Existing Map/List UnixFS adapters now build V0 Roots with their retained
application semantics. Only Prefix supports system bindings; Positional
metadata is structural. New low-level clients can choose native 32-byte keys
or a registered label rule explicitly.

Writeback preserves the base Root's layout, AA and exact VC profile. Historical
V2/V3 views remain readable through Core compatibility code and are rebuilt for
new V0 candidates rather than relabeled. Payload CIDs and accepted/candidate
policy remain independent. V stays zero until an explicit maintainer
production-ready declaration, regardless of package SemVer or deployments.

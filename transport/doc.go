// Package client provides the stable Go transport for an untrusted managed
// MALT gateway.
//
// Transport success is never a trust decision. Callers must verify Resolve and
// Read results locally against caller-selected roots. Higher-level application
// application packages such as unixfs perform that verification and bind
// payload bytes.
package transport

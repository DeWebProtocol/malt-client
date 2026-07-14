// Package gateway provides the HTTP transport client for an untrusted managed
// MALT gateway. It never establishes trust in remote results; the local client
// verifies every accepted result against its own trusted-root state.
package gateway

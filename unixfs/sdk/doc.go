// Package unixfs provides the transport-neutral, locally verified native
// UnixFS reader/writer facade plus staging and materialization helpers. It
// translates application paths into portable MALT operations without owning
// ArcTable, trust-store, or gateway execution state.
package unixfs

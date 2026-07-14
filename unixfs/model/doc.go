// Package unixfs defines the MALT UnixFS application model/profile. It owns
// node metadata, manifest and chunk formats, model-specific mutation plans,
// and validation rules, but performs no ArcTable, HTTP, or executor work.
package unixfs

const DefaultChunkSize = 256 * 1024

package manifest

// MarshalDirectoryEntries returns the canonical JSON payload for a directory
// manifest with the supplied entries.
func MarshalDirectoryEntries(entries []string) ([]byte, error) {
	m := Normalize(&DirectoryManifest{Entries: entries})
	return m.MarshalJSON()
}

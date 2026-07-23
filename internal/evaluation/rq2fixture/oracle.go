package rq2fixture

import (
	"bytes"
	"fmt"

	clientcas "github.com/dewebprotocol/malt-client/internal/cas"
	"github.com/dewebprotocol/malt/auth/arcset"
	"github.com/dewebprotocol/malt/mutation"
	"github.com/dewebprotocol/malt/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

// ValidateViewAgainstSource is an independent, full post-image oracle. It
// checks every source file, direct CID binding, fixed-list descriptor, chunk
// CID, coordinate, child root, and reachable object; it does not trust the
// operation delta that produced the view.
func (f *Fixture) ValidateViewAgainstSource(view mutation.UpdateView, backend string, source map[string][]byte) error {
	if f == nil {
		return fmt.Errorf("RQ2 source fixture is nil")
	}
	if string(maltcid.BackendKindOf(view.BaseRoot)) != backend {
		return fmt.Errorf("post-image root is not typed for backend %s", backend)
	}
	root, err := rootObject(view)
	if err != nil {
		return err
	}
	if root.Kind != arcset.KindMap || root.Entries == nil {
		return fmt.Errorf("RQ2 source root must be one complete map object")
	}
	if root.Entries.Len() != len(source) {
		return fmt.Errorf("root has %d bindings, source post-image has %d files", root.Entries.Len(), len(source))
	}
	entries := make(map[string]arcset.ArcEntry, root.Entries.Len())
	for _, entry := range root.Entries.Entries() {
		path := entry.Coordinate.String()
		canonical, err := arcset.NewMapCoordinate(path)
		if err != nil || !bytes.Equal(canonical.Bytes(), entry.Coordinate.Bytes()) {
			return fmt.Errorf("root contains non-canonical coordinate %q", path)
		}
		if _, duplicate := entries[path]; duplicate {
			return fmt.Errorf("root repeats coordinate %q", path)
		}
		entries[path] = entry
	}
	objects := make(map[string]mutation.UpdateObject, len(view.Objects))
	for _, object := range view.Objects {
		objects[object.Root.KeyString()] = object
	}
	usedObjects := map[string]struct{}{root.Root.KeyString(): {}}
	for path, data := range source {
		entry, exists := entries[path]
		if !exists {
			return fmt.Errorf("source file %q is absent from authenticated root", path)
		}
		list, listBacked := f.List(path)
		if !listBacked {
			if entry.Target.Kind() != arcset.TargetKindCAS || maltcid.SemanticKindOf(entry.Target.CID()) != maltcid.SemanticKindUnknown {
				return fmt.Errorf("source file %q is not a direct CAS binding", path)
			}
			expected, err := clientcas.CIDForBlock(clientcas.Block{Codec: cid.Raw, Data: data})
			if err != nil || !entry.Target.CID().Equals(expected) {
				return fmt.Errorf("direct source bytes for %q do not bind authenticated CID", path)
			}
			continue
		}
		if entry.Target.Kind() != arcset.TargetKindList || maltcid.SemanticKindOf(entry.Target.CID()) != maltcid.SemanticKindList {
			return fmt.Errorf("source file %q is not a list target", path)
		}
		object, exists := objects[entry.Target.CID().KeyString()]
		if !exists || object.Kind != arcset.KindList || object.Entries == nil || object.Commit.FixedList == nil {
			return fmt.Errorf("source list %q has no complete fixed-list object", path)
		}
		if string(maltcid.BackendKindOf(object.Root)) != backend || object.Commit.FixedList.ChunkSize != list.ChunkSize || object.Commit.FixedList.TotalSize != uint64(len(data)) {
			return fmt.Errorf("source list %q descriptor/backend does not match post-image", path)
		}
		if err := validateListEntries(object, data, list.ChunkSize); err != nil {
			return fmt.Errorf("source list %q: %w", path, err)
		}
		usedObjects[object.Root.KeyString()] = struct{}{}
	}
	if len(view.Objects) != len(usedObjects) {
		return fmt.Errorf("update view contains %d objects, full source closure uses %d", len(view.Objects), len(usedObjects))
	}
	for _, object := range view.Objects {
		if _, used := usedObjects[object.Root.KeyString()]; !used {
			return fmt.Errorf("update view contains unrelated object %q", object.ObjectID)
		}
	}
	return nil
}

func validateListEntries(object mutation.UpdateObject, data []byte, chunkSize uint64) error {
	if chunkSize == 0 {
		return fmt.Errorf("chunk size is zero")
	}
	count := (uint64(len(data)) + chunkSize - 1) / chunkSize
	if uint64(object.Entries.Len()) != count {
		return fmt.Errorf("object has %d chunks, source bytes require %d", object.Entries.Len(), count)
	}
	for index, entry := range object.Entries.Entries() {
		expectedCoordinate := arcset.NewListCoordinateUint64(uint64(index))
		if !bytes.Equal(entry.Coordinate.Bytes(), expectedCoordinate.Bytes()) || entry.Target.Kind() != arcset.TargetKindCAS {
			return fmt.Errorf("chunk %d has a non-canonical coordinate or target kind", index)
		}
		start := uint64(index) * chunkSize
		end := min(uint64(len(data)), start+chunkSize)
		expected, err := clientcas.CIDForBlock(clientcas.Block{Codec: cid.Raw, Data: data[start:end]})
		if err != nil || !entry.Target.CID().Equals(expected) {
			return fmt.Errorf("chunk %d CID does not bind its source bytes", index)
		}
	}
	return nil
}

func rootObject(view mutation.UpdateView) (mutation.UpdateObject, error) {
	for _, object := range view.Objects {
		if object.Root.Equals(view.BaseRoot) {
			return object, nil
		}
	}
	return mutation.UpdateObject{}, fmt.Errorf("update view omits its root object")
}

package unixfs

import "fmt"

// RemoveStagedPath removes one existing entry from a staged UnixFS tree and
// marks every ancestor for bottom-up rematerialization.
func RemoveStagedPath(root *StagedNode, rawPath string) error {
	if root == nil || root.Kind != StagedKindDirectory {
		return fmt.Errorf("staged root is not a directory")
	}
	segments, err := ParseCanonicalStagedPath(rawPath)
	if err != nil {
		return err
	}
	if len(segments) == 0 {
		return fmt.Errorf("cannot remove the staged root")
	}
	return removeStagedSegments(root, segments)
}

func removeStagedSegments(parent *StagedNode, segments []string) error {
	child, ok := parent.Children[segments[0]]
	if !ok || child == nil {
		return fmt.Errorf("%w: %s", ErrNotFound, segments[0])
	}
	if len(segments) == 1 {
		delete(parent.Children, segments[0])
		parent.Changed = true
		return nil
	}
	if child.Kind != StagedKindDirectory {
		return fmt.Errorf("%w: %s", ErrNotDirectory, segments[0])
	}
	if err := removeStagedSegments(child, segments[1:]); err != nil {
		return err
	}
	parent.Changed = true
	return nil
}

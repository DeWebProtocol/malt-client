package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"

	"github.com/dewebprotocol/malt/auth/arcset"
	"github.com/dewebprotocol/malt/mutation"
	"github.com/dewebprotocol/malt/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

func graphIntent(view mutation.UpdateView, oldGraph, nextGraph *hybridGraph, commitID string) (mutation.SemanticIntent, error) {
	if oldGraph == nil || nextGraph == nil || !view.BaseRoot.Equals(oldGraph.root) {
		return mutation.SemanticIntent{}, fmt.Errorf("verified update view does not match the prior hybrid graph")
	}
	if nextGraph.root.Equals(oldGraph.root) {
		return mutation.SemanticIntent{}, fmt.Errorf("frozen commit %q has no net authenticated state transition", commitID)
	}
	viewByRoot := make(map[string]mutation.UpdateObject, len(view.Objects))
	viewIDs := make(map[string]struct{}, len(view.Objects))
	for _, object := range view.Objects {
		viewByRoot[object.Root.KeyString()] = object
		viewIDs[object.ObjectID] = struct{}{}
	}

	// One transition materializes one content-addressed post-image. Identical
	// desired objects share that output even when several logical paths consume
	// it. The top object remains distinct because it closes the accepted root.
	transitionForLogical := make(map[string]string)
	transitionForRoot := make(map[string]string)
	objectForTransition := make(map[string]*semanticObject)
	oldForTransition := make(map[string]*semanticObject)
	viewForTransition := make(map[string]mutation.UpdateObject)
	claimedViewObject := make(map[string]struct{})
	transitions := make([]mutation.IntentTransition, 0)

	for _, logicalID := range nextGraph.order {
		desired := nextGraph.objects[logicalID]
		isTop := logicalID == nextGraph.topID
		if !isTop {
			if _, alreadyMaterialized := viewByRoot[desired.root.KeyString()]; alreadyMaterialized {
				continue
			}
			if existingOutput := transitionForRoot[desired.root.KeyString()]; existingOutput != "" {
				transitionForLogical[logicalID] = existingOutput
				continue
			}
		}

		transitionID := stableIntentID("transition", commitID+"\x00"+logicalID+"\x00"+desired.root.KeyString())
		if _, duplicate := objectForTransition[transitionID]; duplicate {
			return mutation.SemanticIntent{}, fmt.Errorf("transition ID collision")
		}
		var prior *semanticObject
		var source mutation.UpdateObject
		if isTop {
			var ok bool
			source, ok = viewByRoot[view.BaseRoot.KeyString()]
			if !ok {
				return mutation.SemanticIntent{}, fmt.Errorf("verified view omits its top object")
			}
			prior = oldGraph.objects[oldGraph.topID]
		} else if candidate := oldGraph.objects[logicalID]; candidate != nil {
			if oldView, ok := viewByRoot[candidate.root.KeyString()]; ok {
				if _, claimed := claimedViewObject[oldView.ObjectID]; !claimed {
					source, prior = oldView, candidate
				}
			}
		}

		objectID := source.ObjectID
		oldRoot := cid.Undef
		if prior != nil {
			oldRoot = source.Root
			claimedViewObject[source.ObjectID] = struct{}{}
		} else {
			objectID = unusedObjectID(viewIDs, commitID, logicalID, desired.root)
			viewIDs[objectID] = struct{}{}
		}
		transition := mutation.IntentTransition{
			ID: transitionID, ObjectID: objectID, OldRoot: oldRoot, Kind: desired.kind,
			Backend: maltcid.BackendKindKZG, Commit: desired.commit,
		}
		transitions = append(transitions, transition)
		transitionForLogical[logicalID] = transitionID
		transitionForRoot[desired.root.KeyString()] = transitionID
		objectForTransition[transitionID] = desired
		oldForTransition[transitionID] = prior
		viewForTransition[transitionID] = source
	}

	for index := range transitions {
		transition := &transitions[index]
		desired := objectForTransition[transition.ID]
		var priorEntries map[string]arcset.ArcEntry
		if oldForTransition[transition.ID] != nil {
			priorEntries = mapEntriesByCoordinate(viewForTransition[transition.ID].Entries)
		} else {
			priorEntries = map[string]arcset.ArcEntry{}
		}
		desiredEntries := mapEntriesByCoordinate(desired.entries)
		keys := make([]string, 0, len(priorEntries)+len(desiredEntries))
		seen := make(map[string]struct{}, len(priorEntries)+len(desiredEntries))
		for key := range priorEntries {
			seen[key] = struct{}{}
			keys = append(keys, key)
		}
		for key := range desiredEntries {
			if _, exists := seen[key]; !exists {
				keys = append(keys, key)
			}
		}
		slices.SortFunc(keys, func(a, b string) int { return bytes.Compare([]byte(a), []byte(b)) })
		changes := make([]mutation.IntentChange, 0, len(keys))
		for _, key := range keys {
			beforeEntry, beforeOK := priorEntries[key]
			afterEntry, afterOK := desiredEntries[key]
			outputID := ""
			if childLogical := desired.refs[key]; childLogical != "" {
				outputID = transitionForLogical[childLogical]
			}
			if beforeOK && afterOK && outputID == "" && targetEqual(beforeEntry.Target, afterEntry.Target) {
				continue
			}
			coordinate := afterEntry.Coordinate
			if !afterOK {
				coordinate = beforeEntry.Coordinate
			}
			change := mutation.IntentChange{Coordinate: coordinate}
			if beforeOK {
				before := beforeEntry.Target
				change.Before = &before
			}
			if outputID != "" {
				change.OutputID = outputID
				if afterEntry.Target.Kind() == arcset.TargetKindMap {
					change.OutputKind = arcset.TargetKindMap
				} else if afterEntry.Target.Kind() == arcset.TargetKindList {
					change.OutputKind = arcset.TargetKindList
				} else {
					return mutation.SemanticIntent{}, fmt.Errorf("transition output is used by a non-semantic target")
				}
			} else if afterOK {
				after := afterEntry.Target
				change.After = &after
			}
			changes = append(changes, change)
		}
		if len(changes) == 0 {
			return mutation.SemanticIntent{}, fmt.Errorf("transition %q has no exact coordinate changes", transition.ID)
		}
		transition.Changes = changes
	}

	uses := make(map[string]uint32, len(transitions))
	for _, transition := range transitions {
		for _, change := range transition.Changes {
			if change.OutputID != "" {
				uses[change.OutputID]++
			}
		}
	}
	topOutput := transitionForLogical[nextGraph.topID]
	if topOutput == "" {
		return mutation.SemanticIntent{}, fmt.Errorf("hybrid graph transition does not close at the top root")
	}
	for index := range transitions {
		if transitions[index].ID != topOutput {
			transitions[index].ExpectedUses = uses[transitions[index].ID]
			if transitions[index].ExpectedUses == 0 {
				return mutation.SemanticIntent{}, fmt.Errorf("hybrid graph transition %q is orphaned", transitions[index].ID)
			}
		}
	}
	intent := mutation.SemanticIntent{
		Profile: mutation.SemanticIntentProfile, BaseRoot: view.BaseRoot,
		Transitions: transitions, TopOutputID: topOutput,
	}
	return mutation.NormalizeSemanticIntent(view, intent)
}

func targetEqual(a, b arcset.TargetRef) bool {
	return a.Kind() == b.Kind() && a.CID().Equals(b.CID())
}

func stableIntentID(prefix, seed string) string {
	digest := sha256.Sum256([]byte(seed))
	return prefix + "-" + hex.EncodeToString(digest[:16])
}

func unusedObjectID(existing map[string]struct{}, commitID, logicalID string, root cid.Cid) string {
	for nonce := uint64(0); ; nonce++ {
		seed := fmt.Sprintf("%s\x00%s\x00%s\x00%d", commitID, logicalID, root.KeyString(), nonce)
		candidate := stableIntentID("object", seed)
		if _, exists := existing[candidate]; !exists {
			return candidate
		}
	}
}

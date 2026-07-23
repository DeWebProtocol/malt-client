package main

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/dewebprotocol/malt/auth/arcset"
	"github.com/dewebprotocol/malt/mutation"
	"github.com/dewebprotocol/malt/wire/maltcid"
	cid "github.com/ipfs/go-cid"
)

type blueprintResolution struct {
	outputID string
	target   *arcset.TargetRef
}

// blueprintIntent turns literal CIDs plus logical child references into one
// output-free semantic intent. It never computes a desired commitment Root;
// child transitions are linked with OutputID and the writer computes each
// affected commitment exactly once inside Session.Execute.
func blueprintIntent(view mutation.UpdateView, oldGraph *hybridGraph, old, next *hybridBlueprint, commitID string) (mutation.SemanticIntent, error) {
	if oldGraph == nil || old == nil || next == nil || !view.BaseRoot.Equals(oldGraph.root) ||
		old.topID != oldGraph.topID || next.topID != old.topID || next.objects[next.topID] == nil {
		return mutation.SemanticIntent{}, fmt.Errorf("verified update view does not match the retained output-free blueprint")
	}
	viewByRoot := make(map[string]mutation.UpdateObject, len(view.Objects))
	viewIDs := make(map[string]struct{}, len(view.Objects))
	for _, object := range view.Objects {
		viewByRoot[object.Root.KeyString()] = object
		viewIDs[object.ObjectID] = struct{}{}
	}

	// A structurally identical desired child can reuse an already authenticated
	// old object. Sorting makes the representative independent of map order.
	oldIDs := make([]string, 0, len(old.objects))
	for logicalID := range old.objects {
		oldIDs = append(oldIDs, logicalID)
	}
	slices.Sort(oldIDs)
	oldByDigest := make(map[string]arcset.TargetRef, len(oldIDs))
	for _, logicalID := range oldIDs {
		blueprint := old.objects[logicalID]
		graphObject := oldGraph.objects[logicalID]
		if blueprint == nil || graphObject == nil {
			continue
		}
		if _, authenticated := viewByRoot[graphObject.root.KeyString()]; !authenticated {
			continue
		}
		if _, exists := oldByDigest[blueprint.digest]; exists {
			continue
		}
		kind := arcset.TargetKindMap
		if blueprint.kind == arcset.KindList {
			kind = arcset.TargetKindList
		}
		target, err := semanticTarget(kind, graphObject.root)
		if err != nil {
			return mutation.SemanticIntent{}, err
		}
		oldByDigest[blueprint.digest] = target
	}

	resolved := make(map[string]blueprintResolution, len(next.objects))
	nextIDs := make([]string, 0, len(next.objects))
	for logicalID := range next.objects {
		nextIDs = append(nextIDs, logicalID)
	}
	slices.Sort(nextIDs)
	for _, logicalID := range nextIDs {
		blueprint := next.objects[logicalID]
		if logicalID == next.topID {
			continue
		}
		if target, reusable := oldByDigest[blueprint.digest]; reusable {
			copy := target
			resolved[logicalID] = blueprintResolution{target: &copy}
		}
	}

	transitionForDigest := make(map[string]string)
	objectForTransition := make(map[string]*semanticBlueprint)
	viewForTransition := make(map[string]mutation.UpdateObject)
	claimedViewObject := make(map[string]struct{})
	transitions := make([]mutation.IntentTransition, 0, len(next.order))

	for _, logicalID := range next.order {
		desired := next.objects[logicalID]
		if desired == nil {
			return mutation.SemanticIntent{}, fmt.Errorf("blueprint order references missing object %q", logicalID)
		}
		isTop := logicalID == next.topID
		if !isTop {
			if _, reused := resolved[logicalID]; reused {
				continue
			}
			if outputID := transitionForDigest[desired.digest]; outputID != "" {
				resolved[logicalID] = blueprintResolution{outputID: outputID}
				continue
			}
		}

		transitionSeed := commitID + "\x00" + desired.digest
		if isTop {
			transitionSeed += "\x00top"
		}
		transitionID := stableIntentID("transition", transitionSeed)
		if _, collision := objectForTransition[transitionID]; collision {
			return mutation.SemanticIntent{}, fmt.Errorf("blueprint transition ID collision")
		}
		var source mutation.UpdateObject
		if isTop {
			var ok bool
			source, ok = viewByRoot[view.BaseRoot.KeyString()]
			if !ok {
				return mutation.SemanticIntent{}, fmt.Errorf("verified view omits its top object")
			}
		} else if previous := oldGraph.objects[logicalID]; previous != nil {
			candidate, ok := viewByRoot[previous.root.KeyString()]
			if ok {
				if _, claimed := claimedViewObject[candidate.ObjectID]; !claimed {
					source = candidate
				}
			}
		}
		objectID := source.ObjectID
		oldRoot := cid.Undef
		if objectID != "" {
			oldRoot = source.Root
			claimedViewObject[objectID] = struct{}{}
		} else {
			objectID = unusedBlueprintObjectID(viewIDs, commitID, logicalID, desired.digest)
			viewIDs[objectID] = struct{}{}
		}
		transition := mutation.IntentTransition{
			ID: transitionID, ObjectID: objectID, OldRoot: oldRoot, Kind: desired.kind,
			Backend: maltcid.BackendKindKZG, Commit: desired.commit,
		}
		transitions = append(transitions, transition)
		objectForTransition[transitionID] = desired
		viewForTransition[transitionID] = source
		resolved[logicalID] = blueprintResolution{outputID: transitionID}
		if !isTop {
			transitionForDigest[desired.digest] = transitionID
		}
	}

	for index := range transitions {
		transition := &transitions[index]
		transitionID := transition.ID
		desired := objectForTransition[transitionID]
		prior := make(map[string]arcset.ArcEntry)
		if source := viewForTransition[transitionID]; source.ObjectID != "" {
			prior = mapEntriesByCoordinate(source.Entries)
		}
		desiredEntries := make(map[string]blueprintEntry, len(desired.entries))
		keys := make([]string, 0, len(prior)+len(desired.entries))
		seen := make(map[string]struct{}, len(prior)+len(desired.entries))
		for key := range prior {
			seen[key] = struct{}{}
			keys = append(keys, key)
		}
		for _, entry := range desired.entries {
			key := string(entry.coordinate.Bytes())
			desiredEntries[key] = entry
			if _, exists := seen[key]; !exists {
				keys = append(keys, key)
			}
		}
		slices.SortFunc(keys, func(a, b string) int { return bytes.Compare([]byte(a), []byte(b)) })
		changes := make([]mutation.IntentChange, 0, len(keys))
		for _, key := range keys {
			beforeEntry, beforeOK := prior[key]
			afterEntry, afterOK := desiredEntries[key]
			change := mutation.IntentChange{}
			if afterOK {
				change.Coordinate = afterEntry.coordinate
			} else {
				change.Coordinate = beforeEntry.Coordinate
			}
			if beforeOK {
				before := beforeEntry.Target
				change.Before = &before
			}
			if afterOK && afterEntry.literal != nil {
				after := *afterEntry.literal
				change.After = &after
			} else if afterOK {
				resolution, ok := resolved[afterEntry.childID]
				if !ok {
					return mutation.SemanticIntent{}, fmt.Errorf("blueprint child %q has no authenticated or output resolution", afterEntry.childID)
				}
				if resolution.outputID != "" {
					change.OutputID = resolution.outputID
					change.OutputKind = afterEntry.childKind
				} else if resolution.target != nil {
					after := *resolution.target
					change.After = &after
				} else {
					return mutation.SemanticIntent{}, fmt.Errorf("blueprint child %q has an empty resolution", afterEntry.childID)
				}
			}
			if beforeOK && change.OutputID == "" && change.After != nil && targetEqual(beforeEntry.Target, *change.After) {
				continue
			}
			changes = append(changes, change)
		}
		if len(changes) == 0 {
			return mutation.SemanticIntent{}, fmt.Errorf("blueprint transition %q has no coordinate changes", transitionID)
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
	top := resolved[next.topID].outputID
	if top == "" {
		return mutation.SemanticIntent{}, fmt.Errorf("blueprint mutation does not produce a new top output")
	}
	for index := range transitions {
		if transitions[index].ID == top {
			continue
		}
		transitions[index].ExpectedUses = uses[transitions[index].ID]
		if transitions[index].ExpectedUses == 0 {
			return mutation.SemanticIntent{}, fmt.Errorf("blueprint transition %q is orphaned", transitions[index].ID)
		}
	}
	intent := mutation.SemanticIntent{
		Profile: mutation.SemanticIntentProfile, BaseRoot: view.BaseRoot,
		Transitions: transitions, TopOutputID: top,
	}
	return mutation.NormalizeSemanticIntent(view, intent)
}

func unusedBlueprintObjectID(existing map[string]struct{}, commitID, logicalID, digest string) string {
	for nonce := uint64(0); ; nonce++ {
		candidate := stableIntentID("object", fmt.Sprintf("%s\x00%s\x00%s\x00%d", commitID, logicalID, digest, nonce))
		if _, used := existing[candidate]; !used {
			return candidate
		}
	}
}

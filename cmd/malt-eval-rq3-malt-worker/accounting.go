package main

import (
	"context"
	"fmt"
	"math"
	"slices"

	clientrootapp "github.com/dewebprotocol/malt-client/application/clientroot"
	clientcas "github.com/dewebprotocol/malt-client/internal/cas"
	"github.com/dewebprotocol/malt-client/transport"
)

const (
	stageAttempted = "attempted"
	stageCommitted = "committed"

	dispositionNew         = "new"
	dispositionSameValue   = "same-value"
	dispositionReplacement = "replacement"
	dispositionDelete      = "delete"

	casNotApplicable = "not-applicable"
	casNew           = "new"
	casSameValue     = "same-value"

	gatewayAccountingProfile = "gateway.client-root-write-accounting/v1"
	gatewayByteMethod        = "logical-kv-key-plus-value-bytes/v1"
	canonicalEmptySetupCause = "canonical-empty-setup:"
)

var gatewayCategories = []string{"semantic-materialization", "arctable-records", "root-version-metadata"}

type exactAccounting struct {
	profile    string
	available  bool
	reason     string
	method     string
	digest     string
	categories []exactCategory
}

type exactCategory struct {
	category                   string
	attemptedWrites            uint64
	attemptedBytes             uint64
	attemptedNewWrites         uint64
	attemptedNewBytes          uint64
	attemptedReplacementWrites uint64
	attemptedReplacementBytes  uint64
	attemptedSameWrites        uint64
	attemptedSameBytes         uint64
	attemptedDeleteWrites      uint64
	attemptedDeleteBytes       uint64
	newlyPersistedWrites       uint64
	grossNewBytes              uint64
	newWrites                  uint64
	newBytes                   uint64
	replacedWrites             uint64
	replacementNewBytes        uint64
	replacementReclaimedBytes  uint64
	sameWrites                 uint64
	deletedWrites              uint64
	deletedReclaimedBytes      uint64
	reclaimedBytes             uint64
	netBytes                   int64
}

func accountingFromTransport(value transport.ClientRootWriteAccounting) exactAccounting {
	result := exactAccounting{
		profile: value.Profile, available: value.Available, reason: value.UnavailableReason,
		method: value.ByteMethod, digest: value.ObjectLedgerSHA256,
		categories: make([]exactCategory, len(value.Categories)),
	}
	for index, category := range value.Categories {
		result.categories[index] = exactCategory{
			category: category.Category, attemptedWrites: category.AttemptedWrites, attemptedBytes: category.AttemptedBytes,
			attemptedNewWrites: category.AttemptedNewWrites, attemptedNewBytes: category.AttemptedNewBytes,
			attemptedReplacementWrites: category.AttemptedReplacementWrites, attemptedReplacementBytes: category.AttemptedReplacementBytes,
			attemptedSameWrites: category.AttemptedSameValueWrites, attemptedSameBytes: category.AttemptedSameValueBytes,
			attemptedDeleteWrites: category.AttemptedDeleteWrites, attemptedDeleteBytes: category.AttemptedDeleteBytes,
			newlyPersistedWrites: category.NewlyPersistedWrites, grossNewBytes: category.GrossNewBytes,
			newWrites: category.NewWrites, newBytes: category.NewBytes, replacedWrites: category.ReplacedWrites,
			replacementNewBytes: category.ReplacementNewBytes, replacementReclaimedBytes: category.ReplacementReclaimedBytes,
			sameWrites: category.SameValueWrites, deletedWrites: category.DeletedWrites,
			deletedReclaimedBytes: category.DeletedReclaimedBytes, reclaimedBytes: category.ReclaimedBytes, netBytes: category.NetBytes,
		}
	}
	return result
}

func accountingFromApplication(value clientrootapp.GatewayWriteAccounting) exactAccounting {
	result := exactAccounting{
		profile: value.Profile, available: value.Available, reason: value.UnavailableReason,
		method: value.ByteMethod, digest: value.ObjectLedgerSHA256,
		categories: make([]exactCategory, len(value.Categories)),
	}
	for index, category := range value.Categories {
		result.categories[index] = exactCategory{
			category: category.Category, attemptedWrites: category.AttemptedWrites, attemptedBytes: category.AttemptedBytes,
			attemptedNewWrites: category.AttemptedNewWrites, attemptedNewBytes: category.AttemptedNewBytes,
			attemptedReplacementWrites: category.AttemptedReplacementWrites, attemptedReplacementBytes: category.AttemptedReplacementBytes,
			attemptedSameWrites: category.AttemptedSameValueWrites, attemptedSameBytes: category.AttemptedSameValueBytes,
			attemptedDeleteWrites: category.AttemptedDeleteWrites, attemptedDeleteBytes: category.AttemptedDeleteBytes,
			newlyPersistedWrites: category.NewlyPersistedWrites, grossNewBytes: category.GrossNewBytes,
			newWrites: category.NewWrites, newBytes: category.NewBytes, replacedWrites: category.ReplacedWrites,
			replacementNewBytes: category.ReplacementNewBytes, replacementReclaimedBytes: category.ReplacementReclaimedBytes,
			sameWrites: category.SameValueWrites, deletedWrites: category.DeletedWrites,
			deletedReclaimedBytes: category.DeletedReclaimedBytes, reclaimedBytes: category.ReclaimedBytes, netBytes: category.NetBytes,
		}
	}
	return result
}

func (result *runResult) appendGatewayAccounting(commitID string, accounting exactAccounting) error {
	if accounting.profile != gatewayAccountingProfile || accounting.method != gatewayByteMethod || !accounting.available || accounting.reason != "" || !canonicalSHA256(accounting.digest) || len(accounting.categories) != len(gatewayCategories) {
		return fmt.Errorf("Gateway did not return the locked exact client-root accounting boundary")
	}
	for index, category := range accounting.categories {
		if category.category != gatewayCategories[index] {
			return fmt.Errorf("Gateway accounting category[%d] = %q", index, category.category)
		}
		if err := validateExactCategory(category); err != nil {
			return fmt.Errorf("Gateway accounting %q: %w", category.category, err)
		}
		key := func(disposition string) string {
			return "gateway-accounting/" + accounting.digest + "/" + category.category + "/" + disposition
		}
		appendAttempt := func(disposition string, count, bytes uint64) {
			result.appendEvent(writeEvent{
				CommitID: commitID, Stage: stageAttempted, Category: category.category,
				Cause: "gateway-client-root-object-ledger", Disposition: disposition,
				ObjectKey: key(disposition), Count: count, Bytes: bytes, CASClassification: casNotApplicable,
			})
		}
		appendCommit := func(disposition string, count, gross, reclaimed uint64) error {
			net, err := signedNet(gross, reclaimed)
			if err != nil {
				return err
			}
			flowBytes, err := sumUint64(gross, reclaimed)
			if err != nil {
				return err
			}
			result.appendEvent(writeEvent{
				CommitID: commitID, Stage: stageCommitted, Category: category.category,
				Cause: "gateway-client-root-object-ledger", Disposition: disposition,
				ObjectKey: key(disposition), Count: count, Bytes: flowBytes, GrossNewBytes: gross,
				ReclaimedBytes: reclaimed, NetBytes: net, CASClassification: casNotApplicable,
			})
			return nil
		}

		if category.attemptedNewWrites > 0 {
			appendAttempt(dispositionNew, category.attemptedNewWrites, category.attemptedNewBytes)
			if err := appendCommit(dispositionNew, category.newWrites, category.newBytes, 0); err != nil {
				return err
			}
		}
		if category.attemptedReplacementWrites > 0 {
			appendAttempt(dispositionReplacement, category.attemptedReplacementWrites, category.attemptedReplacementBytes)
			if err := appendCommit(dispositionReplacement, category.replacedWrites, category.replacementNewBytes, category.replacementReclaimedBytes); err != nil {
				return err
			}
		}
		if category.attemptedSameWrites > 0 {
			appendAttempt(dispositionSameValue, category.attemptedSameWrites, category.attemptedSameBytes)
		}
		if category.attemptedDeleteWrites > 0 {
			appendAttempt(dispositionDelete, category.attemptedDeleteWrites, category.attemptedDeleteBytes)
			if err := appendCommit(dispositionDelete, category.deletedWrites, 0, category.deletedReclaimedBytes); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateExactCategory(value exactCategory) error {
	attempts, err := sumUint64(value.attemptedNewWrites, value.attemptedReplacementWrites, value.attemptedSameWrites, value.attemptedDeleteWrites)
	if err != nil {
		return fmt.Errorf("attempted write count: %w", err)
	}
	attemptBytes, err := sumUint64(value.attemptedNewBytes, value.attemptedReplacementBytes, value.attemptedSameBytes, value.attemptedDeleteBytes)
	if err != nil {
		return fmt.Errorf("attempted byte count: %w", err)
	}
	persistedWrites, err := sumUint64(value.newWrites, value.replacedWrites)
	if err != nil {
		return fmt.Errorf("persisted write count: %w", err)
	}
	grossNewBytes, err := sumUint64(value.newBytes, value.replacementNewBytes)
	if err != nil {
		return fmt.Errorf("gross-new byte count: %w", err)
	}
	reclaimedBytes, err := sumUint64(value.replacementReclaimedBytes, value.deletedReclaimedBytes)
	if err != nil {
		return fmt.Errorf("reclaimed byte count: %w", err)
	}
	netBytes, err := signedNet(value.grossNewBytes, value.reclaimedBytes)
	if err != nil {
		return err
	}
	if value.attemptedWrites != attempts || value.attemptedBytes != attemptBytes ||
		value.newlyPersistedWrites != persistedWrites || value.grossNewBytes != grossNewBytes ||
		value.reclaimedBytes != reclaimedBytes || value.netBytes != netBytes {
		return fmt.Errorf("aggregate counters are internally inconsistent")
	}
	if value.attemptedNewWrites != value.newWrites ||
		value.attemptedReplacementWrites != value.replacedWrites ||
		value.attemptedDeleteWrites != value.deletedWrites {
		return fmt.Errorf("aggregate lifecycle cannot be represented without dropping write attempts")
	}
	if value.attemptedNewBytes != value.newBytes || value.attemptedReplacementBytes != value.replacementNewBytes {
		return fmt.Errorf("aggregate attempted bytes do not bind their committed gross-new bytes")
	}
	if value.attemptedDeleteWrites > 0 && value.deletedReclaimedBytes == 0 {
		return fmt.Errorf("delete lifecycle does not reclaim an old key/value")
	}
	return nil
}

func (result *runResult) appendEvent(event writeEvent) {
	event.Sequence = uint64(len(result.WriteEvents))
	result.WriteEvents = append(result.WriteEvents, event)
}

// attributeCanonicalEmptySetup moves durable setup allocations into the first
// workload commit's ledger without moving setup work into that commit's timing
// interval. A distinct cause prefix makes the allocation separable in paper
// tables while preserving the exact CAS and Gateway object keys used for
// attempted/committed lifecycle pairing.
func attributeCanonicalEmptySetup(result, setup *runResult, firstCommitID string) {
	if result == nil || setup == nil {
		return
	}
	for _, event := range setup.WriteEvents {
		event.CommitID = firstCommitID
		event.Cause = canonicalEmptySetupCause + event.Cause
		result.appendEvent(event)
	}
}

func uploadClassifiedBlocks(ctx context.Context, remote *transport.Client, commitID string, blocks []classifiedBlock, roles map[string]string, result *runResult) error {
	for start := 0; start < len(blocks); {
		end, bytes := start, 0
		for end < len(blocks) && end-start < transport.MaxCASBatchBlocks {
			length := len(blocks[end].block.Data)
			if end > start && bytes > transport.MaxCASBatchBytes-length {
				break
			}
			if length > transport.MaxCASBatchBytes {
				return fmt.Errorf("CAS block exceeds transport batch byte bound")
			}
			bytes += length
			end++
		}
		batch := make([]transport.Block, end-start)
		for index := range batch {
			batch[index] = blocks[start+index].block
		}
		statuses, err := remote.PutBatch(ctx, batch)
		if err != nil {
			return fmt.Errorf("put exact CAS accounting batch: %w", err)
		}
		for index, status := range statuses {
			classified := blocks[start+index]
			key := status.CID.String()
			if previous := roles[key]; previous != "" && previous != classified.category {
				return fmt.Errorf("CAS object %s crosses mutually exclusive categories %q and %q", key, previous, classified.category)
			}
			roles[key] = classified.category
			length := uint64(len(classified.block.Data))
			objectKey := key + "/" + classified.suffix
			collectAccounting := result.PassMode == "accounting"
			switch status.Status {
			case clientcas.PutStatusNewlyPersisted:
				if collectAccounting {
					result.appendEvent(writeEvent{
						CommitID: commitID, Stage: stageAttempted, Category: classified.category, Cause: classified.cause,
						Disposition: dispositionNew, ObjectKey: objectKey, Bytes: length, CASClassification: casNew,
						Count: 1,
					})
					result.appendEvent(writeEvent{
						CommitID: commitID, Stage: stageCommitted, Category: classified.category, Cause: classified.cause,
						Disposition: dispositionNew, ObjectKey: objectKey, Bytes: length, GrossNewBytes: length,
						Count:    1,
						NetBytes: int64(length), CASClassification: casNew,
					})
				}
			case clientcas.PutStatusAlreadyPresent, clientcas.PutStatusDuplicateInRequest:
				if collectAccounting {
					result.appendEvent(writeEvent{
						CommitID: commitID, Stage: stageAttempted, Category: classified.category, Cause: classified.cause,
						Disposition: dispositionSameValue, ObjectKey: objectKey, Bytes: length, CASClassification: casSameValue,
						Count: 1,
					})
				}
			default:
				return fmt.Errorf("Gateway returned non-evaluation CAS disposition %q", status.Status)
			}
		}
		start = end
	}
	return nil
}

func signedNet(gross, reclaimed uint64) (int64, error) {
	if gross > math.MaxInt64 || reclaimed > math.MaxInt64 {
		return 0, fmt.Errorf("Gateway byte flow exceeds signed evaluator range")
	}
	return int64(gross) - int64(reclaimed), nil
}

func sumUint64(values ...uint64) (uint64, error) {
	var result uint64
	for _, value := range values {
		if math.MaxUint64-result < value {
			return 0, fmt.Errorf("aggregate overflows uint64")
		}
		result += value
	}
	return result, nil
}

func canonicalSHA256(value string) bool {
	return len(value) == 64 && slices.IndexFunc([]byte(value), func(character byte) bool {
		return (character < '0' || character > '9') && (character < 'a' || character > 'f')
	}) == -1
}

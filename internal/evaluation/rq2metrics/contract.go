// Package rq2metrics freezes the aggregation semantics of the RQ2 mutation
// metric wire contract. It deliberately treats duration taxonomy separately
// from bytes and counts: the latter are field-specific resource observations
// and are never an additive decomposition.
package rq2metrics

import (
	"fmt"
	"math"
	"slices"
)

const (
	// TaxonomyProfile is emitted by every successful RQ2 mutation record.
	TaxonomyProfile = "malt-rq2-metric-taxonomy/v1"
	// ResourceAggregationRule prevents reports from stacking byte/count values
	// merely because their phase durations are in one exclusive wall-time set.
	ResourceAggregationRule = "bytes-and-counts-field-specific-non-additive/v1"
)

// Taxonomy is the frozen reporting contract for duration_ns. Inclusive totals
// and nested diagnostics must never be stacked with their children/parents.
// ExclusiveMutationPhases may be stacked under mutation_total only; the
// residual is intentionally unclassified operation work. BrowserBoundaryPhases
// are exclusive only under the browser host call, outside mutation_total.
// OrthogonalResources use a different resource domain (CPU or memory).
type Taxonomy struct {
	InclusiveTotals            []string
	ExclusiveMutationPhases    []string
	NestedDiagnostics          []string
	ColdStartupPhases          []string
	BrowserBoundaryPhases      []string
	OrthogonalResources        []string
	ResourceAggregationProfile string
}

var contract = Taxonomy{
	InclusiveTotals: []string{"mutation_total", "client_root_generation", "first_mutation"},
	ExclusiveMutationPhases: []string{
		"scan", "chunk", "hash", "update_view", "verify_update_view", "normalization",
		"root_computation", "expected_root_encoding", "client_root_bundle", "upload", "receipt_check",
	},
	NestedDiagnostics:          []string{"commitment_update", "gateway_replay", "gateway_persist"},
	ColdStartupPhases:          []string{"wasm_download", "wasm_instantiate", "parameter_load"},
	BrowserBoundaryPhases:      []string{"js_wasm_boundary"},
	OrthogonalResources:        []string{"cpu_total", "peak_memory"},
	ResourceAggregationProfile: ResourceAggregationRule,
}

// Contract returns an independent copy so tests and report adapters can bind
// the exact classification without mutating the process-global definition.
func Contract() Taxonomy {
	return Taxonomy{
		InclusiveTotals:            slices.Clone(contract.InclusiveTotals),
		ExclusiveMutationPhases:    slices.Clone(contract.ExclusiveMutationPhases),
		NestedDiagnostics:          slices.Clone(contract.NestedDiagnostics),
		ColdStartupPhases:          slices.Clone(contract.ColdStartupPhases),
		BrowserBoundaryPhases:      slices.Clone(contract.BrowserBoundaryPhases),
		OrthogonalResources:        slices.Clone(contract.OrthogonalResources),
		ResourceAggregationProfile: contract.ResourceAggregationProfile,
	}
}

// Observation contains only the wall-duration attributes needed for
// reconciliation. Applicability is included so operation-specific omitted
// phases (for example delete payload upload) contribute no synthetic zero.
type Observation struct {
	Applicable bool
	DurationNS uint64
}

// Validate reconciles the overlapping duration domains. It is intentionally
// fail-closed: overflow or a child/subset exceeding its containing measurement
// invalidates the record instead of being hidden in a paper residual.
func Validate(profile string, values map[string]Observation, browser, coldMutation bool) error {
	if profile != TaxonomyProfile {
		return fmt.Errorf("RQ2 metric taxonomy profile %q is not %q", profile, TaxonomyProfile)
	}
	for _, name := range allMetricNames() {
		if _, ok := values[name]; !ok {
			return fmt.Errorf("RQ2 metric taxonomy is missing %q", name)
		}
	}
	total := values["mutation_total"]
	clientRoot := values["client_root_generation"]
	if !total.Applicable || !clientRoot.Applicable || total.DurationNS == 0 || clientRoot.DurationNS == 0 {
		return fmt.Errorf("RQ2 inclusive mutation/client-root totals are absent")
	}
	if clientRoot.DurationNS > total.DurationNS {
		return fmt.Errorf("client_root_generation exceeds inclusive mutation_total")
	}
	exclusive, err := sumApplicable(values, contract.ExclusiveMutationPhases)
	if err != nil {
		return err
	}
	if exclusive > total.DurationNS {
		return fmt.Errorf("exclusive mutation phases exceed inclusive mutation_total")
	}
	sdkExclusive, err := sumApplicable(values, []string{"normalization", "root_computation", "expected_root_encoding"})
	if err != nil {
		return err
	}
	if sdkExclusive > clientRoot.DurationNS {
		return fmt.Errorf("exclusive SDK phases exceed client_root_generation")
	}
	if values["commitment_update"].DurationNS > values["root_computation"].DurationNS {
		return fmt.Errorf("commitment_update exceeds its root_computation parent")
	}
	gateway, err := sumApplicable(values, []string{"gateway_replay", "gateway_persist"})
	if err != nil {
		return err
	}
	if gateway > total.DurationNS {
		return fmt.Errorf("nested Gateway diagnostics exceed inclusive mutation_total")
	}
	first := values["first_mutation"]
	boundary := values["js_wasm_boundary"]
	if browser {
		if !boundary.Applicable {
			return fmt.Errorf("browser metric taxonomy omits js_wasm_boundary")
		}
		if first.Applicable != coldMutation {
			return fmt.Errorf("browser first_mutation applicability=%t, want %t", first.Applicable, coldMutation)
		}
		if coldMutation {
			combined, err := add(total.DurationNS, boundary.DurationNS)
			if err != nil {
				return err
			}
			if combined > first.DurationNS {
				return fmt.Errorf("mutation_total plus JS/WASM boundary exceeds first_mutation host call")
			}
		}
	} else if first.Applicable || boundary.Applicable {
		return fmt.Errorf("native metric taxonomy contains browser host-call durations")
	}
	return nil
}

func allMetricNames() []string {
	result := make([]string, 0, len(contract.InclusiveTotals)+len(contract.ExclusiveMutationPhases)+len(contract.NestedDiagnostics)+len(contract.ColdStartupPhases)+len(contract.BrowserBoundaryPhases)+len(contract.OrthogonalResources))
	for _, names := range [][]string{
		contract.InclusiveTotals, contract.ExclusiveMutationPhases, contract.NestedDiagnostics,
		contract.ColdStartupPhases, contract.BrowserBoundaryPhases, contract.OrthogonalResources,
	} {
		result = append(result, names...)
	}
	return result
}

func sumApplicable(values map[string]Observation, names []string) (uint64, error) {
	var total uint64
	for _, name := range names {
		value := values[name]
		if !value.Applicable {
			continue
		}
		var err error
		total, err = add(total, value.DurationNS)
		if err != nil {
			return 0, fmt.Errorf("RQ2 duration reconciliation for %q: %w", name, err)
		}
	}
	return total, nil
}

func add(left, right uint64) (uint64, error) {
	return AddDurations(left, right)
}

// AddDurations performs the same checked aggregation used by the executable
// taxonomy contract. Worker adapters use it when extending an inclusive SDK
// subtotal with caller-owned canonicalization phases.
func AddDurations(values ...uint64) (uint64, error) {
	var total uint64
	for _, value := range values {
		if math.MaxUint64-total < value {
			return 0, fmt.Errorf("duration sum overflows uint64")
		}
		total += value
	}
	return total, nil
}

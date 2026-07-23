package rq2metrics

import (
	"math"
	"reflect"
	"strings"
	"testing"
)

func TestTaxonomyContractIsFrozenAndDefensivelyCopied(t *testing.T) {
	got := Contract()
	want := Taxonomy{
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
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("taxonomy = %#v, want %#v", got, want)
	}
	got.InclusiveTotals[0] = "changed"
	if Contract().InclusiveTotals[0] != "mutation_total" {
		t.Fatal("caller mutated the frozen taxonomy")
	}
}

func TestValidateReconcilesDurationDomains(t *testing.T) {
	values := validObservations(true, true)
	if err := Validate(TaxonomyProfile, values, true, true); err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(map[string]Observation){
		"exclusive exceeds mutation total": func(value map[string]Observation) {
			value["scan"] = Observation{Applicable: true, DurationNS: 101}
		},
		"sdk phases exceed subtotal": func(value map[string]Observation) {
			value["client_root_generation"] = Observation{Applicable: true, DurationNS: 5}
		},
		"commitment exceeds root": func(value map[string]Observation) {
			value["commitment_update"] = Observation{Applicable: true, DurationNS: 11}
		},
		"gateway diagnostics exceed total": func(value map[string]Observation) {
			value["gateway_replay"] = Observation{Applicable: true, DurationNS: 60}
			value["gateway_persist"] = Observation{Applicable: true, DurationNS: 60}
		},
		"browser call cannot contain mutation and boundary": func(value map[string]Observation) {
			value["first_mutation"] = Observation{Applicable: true, DurationNS: 100}
			value["js_wasm_boundary"] = Observation{Applicable: true, DurationNS: 1}
		},
		"sum overflow": func(value map[string]Observation) {
			value["mutation_total"] = Observation{Applicable: true, DurationNS: math.MaxUint64}
			value["scan"] = Observation{Applicable: true, DurationNS: math.MaxUint64}
			value["chunk"] = Observation{Applicable: true, DurationNS: 1}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			copy := cloneObservations(values)
			mutate(copy)
			if err := Validate(TaxonomyProfile, copy, true, true); err == nil {
				t.Fatal("invalid overlapping durations were accepted")
			}
		})
	}
}

func TestValidateRejectsProfileApplicabilityAndMissingMetricDrift(t *testing.T) {
	values := validObservations(false, false)
	if err := Validate(TaxonomyProfile, values, false, false); err != nil {
		t.Fatal(err)
	}
	if err := Validate("stale", values, false, false); err == nil || !strings.Contains(err.Error(), "profile") {
		t.Fatalf("profile error = %v", err)
	}
	delete(values, "peak_memory")
	if err := Validate(TaxonomyProfile, values, false, false); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing-metric error = %v", err)
	}
}

func TestAddDurationsIsExactAndFailsClosedOnOverflow(t *testing.T) {
	if total, err := AddDurations(1, 2, 3, 4); err != nil || total != 10 {
		t.Fatalf("AddDurations = %d, %v; want 10", total, err)
	}
	if _, err := AddDurations(math.MaxUint64-1, 1, 1); err == nil {
		t.Fatal("duration aggregation overflow was accepted")
	}
}

func validObservations(browser, cold bool) map[string]Observation {
	values := make(map[string]Observation)
	for _, name := range allMetricNames() {
		values[name] = Observation{}
	}
	values["mutation_total"] = Observation{Applicable: true, DurationNS: 100}
	values["client_root_generation"] = Observation{Applicable: true, DurationNS: 30}
	for _, name := range []string{"scan", "chunk", "hash", "update_view", "verify_update_view", "normalization", "root_computation", "expected_root_encoding", "client_root_bundle", "upload", "receipt_check"} {
		values[name] = Observation{Applicable: true, DurationNS: 2}
	}
	values["commitment_update"] = Observation{Applicable: true, DurationNS: 1}
	values["gateway_replay"] = Observation{Applicable: true, DurationNS: 2}
	values["gateway_persist"] = Observation{Applicable: true, DurationNS: 2}
	values["cpu_total"] = Observation{Applicable: true, DurationNS: 150}
	values["peak_memory"] = Observation{Applicable: true, DurationNS: 100}
	if browser {
		values["js_wasm_boundary"] = Observation{Applicable: true, DurationNS: 5}
		if cold {
			values["first_mutation"] = Observation{Applicable: true, DurationNS: 110}
			for _, name := range []string{"wasm_download", "wasm_instantiate", "parameter_load"} {
				values[name] = Observation{Applicable: true, DurationNS: 2}
			}
		}
	}
	return values
}

func cloneObservations(source map[string]Observation) map[string]Observation {
	result := make(map[string]Observation, len(source))
	for name, value := range source {
		result[name] = value
	}
	return result
}

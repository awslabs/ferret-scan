// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package sarif

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

// run.results must be a JSON ARRAY on every code path, never null.
//
// SARIF 2.1.0 types run.results as the single string "array" — not
// ["array","null"] — so null is schema-invalid. Verified against the OASIS schema
// (sarif-2.1/schema/sarif-schema-2.1.0.json):
//
//	"results": { "type": "array", "minItems": 0, ... }
//
// The consequence is out of proportion to the typo that causes it. GitLab ingests
// SARIF through artifacts:reports:sarif and rejects the WHOLE report on a schema
// error; github/codeql-action validates before upload. A nil Go slice marshals to
// null, so the single case where the scanner has nothing to say — a clean scan —
// was the case whose report could be discarded entirely.
//
// These assertions read the marshalled BYTES rather than the struct, because the
// defect exists only after marshalling: a nil slice and an empty slice are both
// len 0 and compare equal to any struct-level check, and differ only on the wire.
// A test that inspected report.Runs[0].Results would pass on the broken code.

// allBands is the confidence filter a real CLI run installs.
//
// A zero-valued FormatterOptions has an empty ConfidenceLevel map, and
// FilterMatchesByConfidence (internal/formatters/shared/structures.go:227) keeps a
// match only if its band's key is TRUE — so the empty map discards every finding.
// Omitting this made the with-findings case below report an empty results array and
// look like a lost finding; the loss was in the fixture, not the formatter.
func allBands() formatters.FormatterOptions {
	return formatters.FormatterOptions{
		ConfidenceLevel: map[string]bool{"high": true, "medium": true, "low": true},
	}
}

// marshalReport renders a report the way the formatter's caller does.
func marshalReport(t *testing.T, matches []detector.Match) (raw []byte, decoded map[string]any) {
	t.Helper()

	f := NewFormatter()
	out, err := f.Format(matches, nil, allBands())
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	raw = []byte(out)
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("the formatter emitted invalid JSON: %v", err)
	}
	return raw, decoded
}

// resultsField returns runs[0].results exactly as decoded, plus whether the key
// was present at all.
func resultsField(t *testing.T, decoded map[string]any) (any, bool) {
	t.Helper()

	runs, ok := decoded["runs"].([]any)
	if !ok || len(runs) == 0 {
		t.Fatalf("runs is missing or not a non-empty array: %#v", decoded["runs"])
	}
	run, ok := runs[0].(map[string]any)
	if !ok {
		t.Fatalf("runs[0] is not an object: %#v", runs[0])
	}
	v, present := run["results"]
	return v, present
}

// TestResultsIsNeverNullOnACleanScan is the regression this file exists for.
func TestResultsIsNeverNullOnACleanScan(t *testing.T) {
	raw, decoded := marshalReport(t, nil)

	v, present := resultsField(t, decoded)
	if !present {
		t.Fatal("runs[0].results is absent. The spec permits omitting it only when a " +
			"run solely exports rule metadata; a scan that examined files and found " +
			"nothing must report an empty array, not silence.")
	}
	if v == nil {
		t.Error(`runs[0].results is JSON null. SARIF 2.1.0 types it as "array", so this ` +
			`document is schema-invalid, and GitLab rejects an invalid report in full ` +
			`while codeql-action rejects it before upload. A clean scan must emit [].`)
	}
	if _, ok := v.([]any); !ok {
		t.Errorf("runs[0].results decoded as %T, want a JSON array", v)
	}

	// The wire form, asserted directly: this is the only place the defect is visible.
	if strings.Contains(string(raw), `"results": null`) ||
		strings.Contains(string(raw), `"results":null`) {
		t.Error(`the emitted bytes contain "results": null`)
	}
}

// TestResultsIsAnArrayWithFindingsToo pins the other branch, so the fix cannot be
// "special-case the empty scan".
func TestResultsIsAnArrayWithFindingsToo(t *testing.T) {
	matches := []detector.Match{{
		Text:       "130-07-5728",
		Type:       "SSN",
		Confidence: 100,
		Filename:   "t.txt",
		LineNumber: 1,
		Validator:  "ssn",
	}}

	_, decoded := marshalReport(t, matches)
	v, present := resultsField(t, decoded)
	if !present || v == nil {
		t.Fatal("runs[0].results must be present and non-null when there are findings")
	}
	arr, ok := v.([]any)
	if !ok {
		t.Fatalf("runs[0].results decoded as %T, want a JSON array", v)
	}
	if len(arr) == 0 {
		t.Error("a report built from one match has no results; the finding was lost, " +
			"which is worse than the null this file guards against")
	}
}

// TestNoTopLevelSliceMarshalsToNull generalises the rule.
//
// run.additionalProperties is false in SARIF 2.1.0, so the fields are fixed and
// small enough to check exhaustively: any array-typed member that is nil at
// marshal time is the same defect wearing a different name. This asserts the
// property on a clean scan, where nil slices are most likely.
func TestNoTopLevelSliceMarshalsToNull(t *testing.T) {
	raw, decoded := marshalReport(t, nil)

	// Every key whose SARIF type is an array. Absent is fine (omitempty); null is not.
	for _, key := range []string{"runs"} {
		v, present := decoded[key]
		if present && v == nil {
			t.Errorf("top-level %q is JSON null; a nil Go slice must be omitted or empty", key)
		}
	}

	runs := decoded["runs"].([]any)
	run := runs[0].(map[string]any)
	for _, key := range []string{"results", "versionControlProvenance", "artifacts", "invocations"} {
		if v, present := run[key]; present && v == nil {
			t.Errorf("runs[0].%s is JSON null; a nil Go slice must be omitted (omitempty) "+
				"or initialised empty. SARIF types every one of these as an array.", key)
		}
	}

	if strings.Contains(string(raw), `: null`) {
		// Not fatal on its own — a null-able scalar could legitimately appear — but
		// worth surfacing, because every array member here must never be null.
		t.Logf("note: the output contains a null value somewhere; verify it is not an array member:\n%s", raw)
	}
}

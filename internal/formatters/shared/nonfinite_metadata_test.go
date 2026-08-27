// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"encoding/json"
	"math"
	"testing"
)

// TestNonFiniteMetadataIsDroppedSoTheDocumentSurvives is the general guard for #520.
//
// encoding/json refuses to marshal a non-finite float and fails the WHOLE document rather than the
// offending field. Measured on a real 892,246-byte file: one `+Inf` `confidence_boost_percentage`, on
// ONE of 2,633 findings, turned a 2,962,657-byte report into a 52-byte error string — and across a
// 1,009-file directory it took all 57,786 findings with it.
//
// Metadata here is diagnostic. Dropping the field is strictly better than losing the findings, and the
// encoder cannot be asked to be lenient per-field.
func TestNonFiniteMetadataIsDroppedSoTheDocumentSurvives(t *testing.T) {
	meta := map[string]interface{}{
		"confidence_boost_percentage": math.Inf(1),
		"negative_inf":                math.Inf(-1),
		"not_a_number":                math.NaN(),
		"as_float32":                  float32(math.Inf(1)),
		"original_confidences":        []float64{50, math.Inf(1)},
		// Everything finite must survive: the point is to lose one field, not the map.
		"confidence_adjustment": 12.5,
		"original_confidence":   float64(75),
		"finite_slice":          []float64{1, 2, 3},
		"ip_type":               "copyright",
		"consolidated_count":    3,
	}

	out := SanitizeMetadata(meta, "some match", true)

	for _, k := range []string{"confidence_boost_percentage", "negative_inf", "not_a_number",
		"as_float32", "original_confidences"} {
		if _, present := out[k]; present {
			t.Errorf("%s survived sanitization; it cannot be marshalled and would void the whole "+
				"document", k)
		}
	}
	for _, k := range []string{"confidence_adjustment", "original_confidence", "finite_slice",
		"ip_type", "consolidated_count"} {
		if _, present := out[k]; !present {
			t.Errorf("%s was dropped; only unmarshalable values may be removed", k)
		}
	}

	// The assertion that matters: the result marshals.
	if _, err := json.Marshal(out); err != nil {
		t.Errorf("the sanitized metadata still does not marshal: %v", err)
	}
}

// TestFiniteMetadataMarshalsBeforeAndAfter keeps the guard from being vacuous.
//
// If SanitizeMetadata dropped nothing, the test above would still pass on a map that happened to hold
// only finite values. This one asserts the unfixed shape genuinely fails, so the guard is doing work.
func TestFiniteMetadataMarshalsBeforeAndAfter(t *testing.T) {
	unsafe := map[string]interface{}{"confidence_boost_percentage": math.Inf(1)}
	if _, err := json.Marshal(unsafe); err == nil {
		t.Fatal("encoding/json marshalled +Inf, so this whole guard is unnecessary — the premise " +
			"of #520 no longer holds")
	}
	if out := SanitizeMetadata(unsafe, "m", true); len(out) != 0 {
		t.Errorf("a map holding only a non-finite value should sanitize to nothing, got %v", out)
	}
}

// TestSerializableNumberCoversTheKindsThisRepoProduces.
//
// Scoped to the numeric kinds on purpose: a non-finite float is the value encoding/json rejects that
// this codebase can actually produce (a division by a zero confidence). Anything else passes through
// rather than being second-guessed, so the formatters' error path stays reachable for genuinely
// unmarshalable types.
func TestSerializableNumberCoversTheKindsThisRepoProduces(t *testing.T) {
	for name, tc := range map[string]struct {
		in   interface{}
		want bool
	}{
		"finite float64":     {12.5, true},
		"zero":               {0.0, true},
		"+Inf":               {math.Inf(1), false},
		"-Inf":               {math.Inf(-1), false},
		"NaN":                {math.NaN(), false},
		"finite float32":     {float32(1.5), true},
		"+Inf float32":       {float32(math.Inf(1)), false},
		"finite slice":       {[]float64{1, 2}, true},
		"slice with NaN":     {[]float64{1, math.NaN()}, false},
		"empty slice":        {[]float64{}, true},
		"string":             {"copyright", true},
		"int":                {3, true},
		"bool":               {true, true},
		"nil":                {nil, true},
		"map passed through": {map[string]bool{"a": true}, true},
	} {
		if got := serializableNumber(tc.in); got != tc.want {
			t.Errorf("%s: serializableNumber(%v) = %v, want %v", name, tc.in, got, tc.want)
		}
	}
}

// TestNonFiniteIsDroppedEvenWhenTheValueIsHidden.
//
// The allowlist happens to exclude the affected keys, which is why #520 looked flag-specific — it only
// reproduced with --show-match. The drop must not depend on that: a future allowlisted key computed by
// division would otherwise void every report, with or without the flag.
func TestNonFiniteIsDroppedEvenWhenTheValueIsHidden(t *testing.T) {
	// confidence_adjustment IS allowlisted, so it reaches output with showMatch=false.
	meta := map[string]interface{}{"confidence_adjustment": math.Inf(1)}

	out := SanitizeMetadata(meta, "m", false)
	if _, present := out["confidence_adjustment"]; present {
		t.Error("a non-finite ALLOWLISTED value survived with showMatch=false; it would void the " +
			"document on a default run")
	}
	if _, err := json.Marshal(out); err != nil {
		t.Errorf("sanitized metadata does not marshal: %v", err)
	}
}

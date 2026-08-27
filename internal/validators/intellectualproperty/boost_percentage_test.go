// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package intellectualproperty

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// TestBoostPercentageNeverReturnsANonFiniteValue is the root-cause guard for #520.
//
// `(boost / base) * 100` with a zero base is `+Inf`, or `NaN` when the boost is zero too.
// encoding/json refuses to marshal either and fails the WHOLE document rather than the field, so this
// one diagnostic percentage voided entire reports at exit 0.
func TestBoostPercentageNeverReturnsANonFiniteValue(t *testing.T) {
	for name, tc := range map[string]struct {
		boost, base, want float64
	}{
		"zero base, positive boost": {19, 0, 0},   // was +Inf
		"zero base, zero boost":     {0, 0, 0},    // was NaN
		"zero base, negative boost": {-19, 0, 0},  // was -Inf
		"ordinary":                  {19, 50, 38}, // unchanged arithmetic
		"no boost":                  {0, 50, 0},
		"negative boost":            {-25, 50, -50},
	} {
		got := boostPercentage(tc.boost, tc.base)
		if math.IsInf(got, 0) || math.IsNaN(got) {
			t.Errorf("%s: boostPercentage(%v, %v) = %v, which cannot be marshalled",
				name, tc.boost, tc.base, got)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: boostPercentage(%v, %v) = %v, want %v", name, tc.boost, tc.base, got, tc.want)
		}
	}
}

// TestConsolidatedMetadataAlwaysMarshals drives the real consolidation path, which is where the value
// is actually produced — a guard function with its own passing test proves nothing about its caller.
//
// Zero-confidence matches are what reach it: findPrimaryMatch scores on
// `Confidence + len(Text)*0.1`, so when every candidate has zero confidence the winner still has
// Confidence 0 and becomes the divisor.
func TestConsolidatedMetadataAlwaysMarshals(t *testing.T) {
	v := NewValidator()

	for name, conf := range map[string]float64{
		"zero confidence": 0,
		"real confidence": 50,
	} {
		t.Run(name, func(t *testing.T) {
			matches := []detector.Match{
				{Text: "Copyright (c) 2026 Example Corp.", Type: "INTELLECTUAL_PROPERTY", LineNumber: 1,
					Confidence: conf, Validator: "intellectualproperty",
					Metadata: map[string]any{"ip_type": "copyright"}},
				{Text: "All rights reserved.", Type: "INTELLECTUAL_PROPERTY", LineNumber: 1,
					Confidence: conf, Validator: "intellectualproperty",
					Metadata: map[string]any{"ip_type": "copyright"}},
			}

			out := v.reconstructLegalNotice(matches)

			// Non-vacuity: the key must actually be produced here, or "it marshals" is trivially true.
			val, present := out.Metadata["confidence_boost_percentage"]
			if !present {
				t.Fatal("confidence_boost_percentage was not produced, so this test is not exercising " +
					"the expression that failed")
			}
			if f, ok := val.(float64); ok && (math.IsInf(f, 0) || math.IsNaN(f)) {
				t.Errorf("confidence_boost_percentage = %v", f)
			}

			if _, err := json.Marshal(out.Metadata); err != nil {
				t.Errorf("consolidated metadata does not marshal: %v", err)
			}
		})
	}
}

// TestTheSingleMatchArmAndTheConsolidatedArmAgree.
//
// The single-match arm has always set this key to a literal 0.0, so the safe value was already in the
// file and only the consolidated arm divided. Asserting they agree for a zero base keeps the two from
// drifting apart again.
func TestTheSingleMatchArmAndTheConsolidatedArmAgree(t *testing.T) {
	v := NewValidator()
	one := v.reconstructLegalNotice([]detector.Match{
		{Text: "Copyright (c) 2026 Example Corp.", Type: "INTELLECTUAL_PROPERTY", LineNumber: 1,
			Confidence: 0, Validator: "intellectualproperty",
			Metadata: map[string]any{"ip_type": "copyright"}},
	})
	many := v.reconstructLegalNotice([]detector.Match{
		{Text: "Copyright (c) 2026 Example Corp.", Type: "INTELLECTUAL_PROPERTY", LineNumber: 1,
			Confidence: 0, Validator: "intellectualproperty",
			Metadata: map[string]any{"ip_type": "copyright"}},
		{Text: "All rights reserved.", Type: "INTELLECTUAL_PROPERTY", LineNumber: 1,
			Confidence: 0, Validator: "intellectualproperty",
			Metadata: map[string]any{"ip_type": "copyright"}},
	})

	a := one.Metadata["confidence_boost_percentage"]
	b := many.Metadata["confidence_boost_percentage"]
	if a != b {
		t.Errorf("the single-match arm reports %v and the consolidated arm %v for the same zero base", a, b)
	}
}

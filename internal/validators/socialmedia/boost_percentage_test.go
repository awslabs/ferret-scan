// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package socialmedia

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// TestBoostPercentageNeverReturnsANonFiniteValue is the sibling of the identical guard in
// internal/validators/intellectualproperty. Both packages computed
// `(boost / base) * 100` with no zero check, and a non-finite result fails the WHOLE
// output document rather than the field. See #520.
//
// The duplication is deliberate — the two are separate packages with no shared numeric
// helper — so each carries its own test rather than trusting the other's.
func TestBoostPercentageNeverReturnsANonFiniteValue(t *testing.T) {
	for name, tc := range map[string]struct {
		boost, base, want float64
	}{
		"zero base, positive boost": {19, 0, 0},
		"zero base, zero boost":     {0, 0, 0},
		"zero base, negative boost": {-19, 0, 0},
		"ordinary":                  {19, 50, 38},
		"no boost":                  {0, 50, 0},
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

// TestClusterMetadataAlwaysMarshals drives the CALLER, not just the guard.
//
// A guard function with its own passing test proves nothing about whether its caller uses it: a
// mutation reverting reconstructSocialMediaCluster to the raw division survived while
// TestBoostPercentageNeverReturnsANonFiniteValue stayed green. This closes that.
//
// Zero-confidence matches are what reach the division: findPrimaryClusterMatch scores on confidence,
// so when every candidate is zero the winner is zero and becomes the divisor.
func TestClusterMetadataAlwaysMarshals(t *testing.T) {
	v := NewValidator()

	for name, conf := range map[string]float64{
		"zero confidence": 0,
		"real confidence": 50,
	} {
		t.Run(name, func(t *testing.T) {
			matches := []detector.Match{
				{Text: "@handleone", Type: "SOCIAL_MEDIA", LineNumber: 1, Confidence: conf,
					Validator: "socialmedia", Metadata: map[string]any{"platform": "twitter"}},
				{Text: "@handletwo", Type: "SOCIAL_MEDIA", LineNumber: 1, Confidence: conf,
					Validator: "socialmedia", Metadata: map[string]any{"platform": "twitter"}},
			}

			out, err := v.reconstructSocialMediaCluster(matches)
			if err != nil {
				t.Fatalf("reconstructSocialMediaCluster: %v", err)
			}

			// Non-vacuity: the key must actually be produced, or "it marshals" is trivially true.
			val, present := out.Metadata["confidence_boost_percentage"]
			if !present {
				t.Fatal("confidence_boost_percentage was not produced, so this test is not exercising " +
					"the expression that failed")
			}
			if f, ok := val.(float64); ok && (math.IsInf(f, 0) || math.IsNaN(f)) {
				t.Errorf("confidence_boost_percentage = %v", f)
			}
			if _, err := json.Marshal(out.Metadata); err != nil {
				t.Errorf("cluster metadata does not marshal: %v", err)
			}
		})
	}
}

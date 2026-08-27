// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package yaml

import (
	"math"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

// TestAnOrdinaryReportStillFormatsAndReturnsNoError covers this formatter's success path after its
// failure path stopped returning the error text AS the document (#520).
//
// # Why there is no negative case here
//
// The JSON formatter has one, because encoding/json refuses a non-finite float and that is a value
// this codebase produced. YAML is different in both directions:
//
//   - yaml.Marshal renders a non-finite float happily as `.inf`, which is exactly why #520 was
//     JSON-only and why `--format yaml` was the diagnostic that identified the offending field.
//   - the one unmarshalable value I could construct — a func in metadata — makes yaml.Marshal PANIC
//     rather than return an error, so it never reaches the failure branch either.
//
// So this formatter's error branch has no reachable trigger today. The change there is for symmetry
// and correctness: an error placed where the document belongs is indistinguishable from a report, and
// the next value yaml.Marshal declines must not exit 0. Asserting the success path is what keeps that
// change from having silently broken the common case.
func TestAnOrdinaryReportStillFormatsAndReturnsNoError(t *testing.T) {
	matches := []detector.Match{{
		Text: "value", Type: "SSN", LineNumber: 1, Confidence: 100, Validator: "ssn",
		Metadata: map[string]interface{}{"ip_type": "copyright", "confidence_adjustment": 12.5},
	}}

	out, err := NewFormatter().Format(matches, nil, formatters.FormatterOptions{
		ShowMatch:       true,
		ConfidenceLevel: map[string]bool{"high": true, "medium": true, "low": true},
	})
	if err != nil {
		t.Fatalf("an ordinary report failed to format: %v", err)
	}
	if !strings.Contains(out, "results:") {
		t.Errorf("the output does not look like a report: %.200q", out)
	}
	if strings.Contains(out, "Error formatting") {
		t.Errorf("an error string reached a successful document: %.200q", out)
	}
}

// TestYAMLNoLongerRendersANonFiniteValue records the behaviour that made #520 diagnosable, and pins
// that the upstream sanitization now applies to YAML too.
//
// `--format yaml` printed `confidence_boost_percentage: .inf` where `--format json` printed a 52-byte
// error, which is how the offending field was identified. Now the field is dropped before either
// encoder sees it, so the two formats agree.
func TestYAMLNoLongerRendersANonFiniteValue(t *testing.T) {
	matches := []detector.Match{{
		Text: "value", Type: "SSN", LineNumber: 1, Confidence: 100, Validator: "ssn",
		Metadata: map[string]interface{}{
			"confidence_boost_percentage": math.Inf(1),
			"ip_type":                     "copyright",
		},
	}}

	out, err := NewFormatter().Format(matches, nil, formatters.FormatterOptions{
		ShowMatch:       true,
		ConfidenceLevel: map[string]bool{"high": true, "medium": true, "low": true},
	})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if strings.Contains(out, ".inf") || strings.Contains(out, ".nan") {
		t.Errorf("a non-finite value reached the YAML document: %.300q", out)
	}
	// Non-vacuity: the surrounding finding must still be there, or "no .inf" is trivially true.
	if !strings.Contains(out, "copyright") {
		t.Errorf("the finding was lost along with the bad field: %.300q", out)
	}
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phone_test

import (
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/core"
)

// TestPublishedCeilingsSurviveTheDocumentAdjustment runs the real pipeline, because the defect is
// downstream of the validator: the document bridge adds +20 to every finding in a CSV-typed
// document, and only a ceiling published as confidence_ceiling is applied after that. On main an
// order_id column reported 100 HIGH and the reserved fictional 415-555-0123 reported 35.
//
// Each case asserts the +20 was applied (confidence_adjustment), so the bound is shown to hold
// against the lift rather than in a document that never received one.
func TestPublishedCeilingsSurviveTheDocumentAdjustment(t *testing.T) {
	cases := []struct {
		name     string
		content  string
		min, max float64
	}{
		{"uncorroborated value in an order_id column", "customer,order_id,total\nJane Roe,2972030405,42.50\nJohn Roe,2972030406,17.00\n", 0, 85},
		{"reserved fictional number in a phone column", "name,phone,city\nJane Roe,415-555-0123,Boston\nJohn Roe,415-555-0124,Austin\n", 0, 15},
		{"value in a phone column", "name,phone,city\nJane Roe,2972010001,Boston\nJohn Roe,2972010002,Austin\n", 90, 100},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := core.ScanContent(c.content, core.ContentScanConfig{VirtualPath: "<phone-ceiling>", Checks: []string{"PHONE"}})
			if err != nil {
				t.Fatalf("ScanContent: %v", err)
			}
			if len(res.Matches) != 2 {
				t.Fatalf("want 2 PHONE findings, got %d", len(res.Matches))
			}
			for _, m := range res.Matches {
				if adj, _ := m.Metadata["confidence_adjustment"].(float64); adj != 20 {
					t.Fatalf("%q: confidence_adjustment %v; the document was not typed tabular, so this case proves nothing", m.Text, m.Metadata["confidence_adjustment"])
				}
				if m.Confidence < c.min || m.Confidence > c.max {
					t.Errorf("%q: confidence %v, want within [%v, %v]", m.Text, m.Confidence, c.min, c.max)
				}
			}
		})
	}
}

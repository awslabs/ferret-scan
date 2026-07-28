// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package csv

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

// TestRows_StableOrder locks the CSV row order. The formatter walked the
// findings slice as the scanner handed it over — per-file worker completion
// order — so every run of one unchanged scan wrote its rows in a different
// sequence, and anything that diffed or checksummed the exported spreadsheet saw
// a change that was not one.
func TestRows_StableOrder(t *testing.T) {
	// Supplied in neither the expected order nor its reverse.
	matches := []detector.Match{
		{Text: "4929381332664295", LineNumber: 4, Type: "CREDIT_CARD", Confidence: 100, Filename: "b.txt", Validator: "creditcard"},
		{Text: "Acme Corp", LineNumber: 1, Type: "BUSINESS", Confidence: 65, Filename: "b.txt", Validator: "business"},
		{Text: "212-555-0142", LineNumber: 1, Type: "PHONE", Confidence: 92, Filename: "a.txt", Validator: "phone"},
		{Text: "AKIAIOSFODNN7EXAMPLE", LineNumber: 2, Type: "AWS_ACCESS_KEY", Confidence: 95, Filename: "a.txt", Validator: "secrets"},
		{Text: "449-87-4100", LineNumber: 3, Type: "SSN", Confidence: 100, Filename: "a.txt", Validator: "ssn"},
	}

	// Shared total order: confidence desc, then type, then line, then filename.
	want := []string{
		"b.txt,CREDIT_CARD",
		"a.txt,SSN",
		"a.txt,AWS_ACCESS_KEY",
		"a.txt,PHONE",
		"b.txt,BUSINESS",
	}

	levels := map[string]bool{"high": true, "medium": true, "low": true}
	f := NewFormatter()
	for i := 0; i < 200; i++ {
		out, err := f.Format(matches, nil, formatters.FormatterOptions{ConfidenceLevel: levels})
		if err != nil {
			t.Fatalf("Format error: %v", err)
		}

		// Skip the header row; keep "filename,type" from each data row.
		var got []string
		for _, line := range strings.Split(strings.TrimSpace(out), "\n")[1:] {
			cols := strings.Split(line, ",")
			if len(cols) < 2 {
				continue
			}
			got = append(got, cols[0]+","+cols[1])
		}
		if len(got) != len(want) {
			t.Fatalf("iteration %d: got %d rows, want %d: %v", i, len(got), len(want), got)
		}
		for j := range want {
			if got[j] != want[j] {
				t.Fatalf("iteration %d: row %d = %q, want %q\nfull order: %v",
					i, j, got[j], want[j], got)
			}
		}
	}
}

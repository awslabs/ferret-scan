// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package sarif

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

// TestSARIF_NoLeakWhenHidden is a regression test for the SARIF PII leak: the
// context region snippet embedded the raw surrounding line (FullLine), and the
// metadata properties dumped value-bearing keys, both regardless of ShowMatch.
// With ShowMatch=false the matched value and the surrounding line must never
// appear anywhere in the SARIF document.
func TestSARIF_NoLeakWhenHidden(t *testing.T) {
	const secret = "4929-3813-3266-4295"
	const name = "Robert Aragon"
	matches := []detector.Match{{
		Text:       secret,
		LineNumber: 5,
		Type:       "VISA",
		Confidence: 100,
		Filename:   "cards.tsv",
		Validator:  "creditcard",
		Context: detector.ContextInfo{
			FullLine:   name + "\t" + secret + "\t",
			BeforeText: name + "\t",
			AfterText:  "\t",
		},
		Metadata: map[string]interface{}{
			"card_type":       "VISA",
			"name_components": map[string]interface{}{"FullName": name},
			"full_field":      "Author: " + name,
			"clean_number":    "4929381332664295",
		},
	}}

	// HIGH confidence (100) — include the high bucket so the match is not
	// filtered out before it reaches the mapper.
	allLevels := map[string]bool{"high": true, "medium": true, "low": true}

	f := NewFormatter()
	hidden, err := f.Format(matches, nil, formatters.FormatterOptions{ShowMatch: false, Verbose: true, ConfidenceLevel: allLevels})
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}
	for _, leak := range []string{secret, name, "4929381332664295"} {
		if strings.Contains(hidden, leak) {
			t.Errorf("SARIF leaked %q with ShowMatch=false", leak)
		}
	}

	// With ShowMatch the value is allowed to appear.
	shown, err := f.Format(matches, nil, formatters.FormatterOptions{ShowMatch: true, Verbose: true, ConfidenceLevel: allLevels})
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}
	if !strings.Contains(shown, secret) {
		t.Errorf("SARIF should include the value when ShowMatch=true")
	}
}

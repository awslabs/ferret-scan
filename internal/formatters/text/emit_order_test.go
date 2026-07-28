// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package text

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

// allLevels enables every confidence band so the fixtures are not filtered out.
func allLevels() map[string]bool {
	return map[string]bool{"high": true, "medium": true, "low": true}
}

// TestVerboseValidationChecks_StableOrder covers the validation_checks map, which
// the verbose block used to range directly. Its line order therefore varied run to
// run on identical input, so diffing two --verbose reports of the same file showed
// changes that were not there.
func TestVerboseValidationChecks_StableOrder(t *testing.T) {
	f := NewFormatter()
	matches := []detector.Match{{
		Type:       "CREDIT_CARD",
		Confidence: 95,
		LineNumber: 3,
		Filename:   "a.txt",
		Text:       "x",
		Metadata: map[string]interface{}{
			"validation_checks": map[string]bool{
				"luhn_valid":      true,
				"length_valid":    true,
				"prefix_known":    false,
				"not_test_card":   true,
				"context_keyword": false,
				"spacing_valid":   true,
			},
		},
	}}
	options := formatters.FormatterOptions{
		ConfidenceLevel: allLevels(),
		Verbose:         true,
		NoColor:         true,
	}

	first, err := f.Format(matches, nil, options)
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if !strings.Contains(first, "Validation results:") {
		t.Fatalf("fixture did not reach the validation block:\n%s", first)
	}

	for i := 0; i < 200; i++ {
		got, err := f.Format(matches, nil, options)
		if err != nil {
			t.Fatalf("iter %d: Format: %v", i, err)
		}
		if got != first {
			t.Fatalf("iter %d: verbose validation_checks order is not stable:\n--- first ---\n%s\n--- iter %d ---\n%s",
				i, first, i, got)
		}
	}

	// And the order is the intended one: sorted by raw check key. formatCheckName
	// only prettifies each name, so sorted keys yield sorted display lines here.
	wantOrder := []string{"Context Keyword", "Length Valid", "Luhn Valid", "Not Test Card", "Prefix Known", "Spacing Valid"}
	last := -1
	for _, name := range wantOrder {
		idx := strings.Index(first, "- "+name+":")
		if idx < 0 {
			t.Fatalf("expected check %q in output:\n%s", name, first)
		}
		if idx < last {
			t.Errorf("check %q is out of sorted order:\n%s", name, first)
		}
		last = idx
	}
}

// TestPrecommitOutput_StableFileOrder covers the pre-commit per-file blocks, which
// ranged the group map directly. This is the format a developer reads inside a
// pre-commit hook, and the same staged changes listed their files in a different
// order on each attempt.
func TestPrecommitOutput_StableFileOrder(t *testing.T) {
	f := NewFormatter()
	// Deliberately supplied out of alphabetical order, and with equal confidence,
	// so nothing but the grouping step can decide the block order.
	matches := []detector.Match{
		{Type: "EMAIL", Confidence: 95, LineNumber: 1, Filename: "src/zeta.go", Text: "z@example.test"},
		{Type: "EMAIL", Confidence: 95, LineNumber: 1, Filename: "src/alpha.go", Text: "a@example.test"},
		{Type: "EMAIL", Confidence: 95, LineNumber: 1, Filename: "src/mid.go", Text: "m@example.test"},
		{Type: "EMAIL", Confidence: 95, LineNumber: 2, Filename: "src/beta.go", Text: "b@example.test"},
		{Type: "EMAIL", Confidence: 95, LineNumber: 2, Filename: "docs/readme.md", Text: "r@example.test"},
	}
	options := formatters.FormatterOptions{
		ConfidenceLevel: allLevels(),
		NoColor:         true,
		PrecommitMode:   true,
	}

	first, err := f.Format(matches, nil, options)
	if err != nil {
		t.Fatalf("Format: %v", err)
	}

	for i := 0; i < 200; i++ {
		got, err := f.Format(matches, nil, options)
		if err != nil {
			t.Fatalf("iter %d: Format: %v", i, err)
		}
		if got != first {
			t.Fatalf("iter %d: pre-commit file block order is not stable:\n--- first ---\n%s\n--- iter %d ---\n%s",
				i, first, i, got)
		}
	}

	// Blocks appear in sorted order of the FULL path (so docs/ precedes src/),
	// even though each block header displays only the base name.
	wantOrder := []string{"readme.md:", "alpha.go:", "beta.go:", "mid.go:", "zeta.go:"}
	last := -1
	for _, name := range wantOrder {
		idx := strings.Index(first, name)
		if idx < 0 {
			t.Fatalf("expected file %q in pre-commit output:\n%s", name, first)
		}
		if idx < last {
			t.Errorf("file %q is out of sorted order:\n%s", name, first)
		}
		last = idx
	}
}

// TestSuppressedRows_StableOrder is the end-to-end half of the suppressed-order
// fix: it asserts the text formatter actually applies the shared total order,
// which the shared/ unit test cannot (a formatter that forgot the call would
// still pass there). The input is deliberately shuffled relative to display
// order, mimicking the arrival order the scanner really produces — suppressed
// findings reach the formatter in per-file worker completion order.
func TestSuppressedRows_StableOrder(t *testing.T) {
	f := NewFormatter()
	mk := func(typ string, conf float64, line int, file, rule string) detector.SuppressedMatch {
		return detector.SuppressedMatch{
			Match:        detector.Match{Type: typ, Confidence: conf, LineNumber: line, Filename: file, Text: "v"},
			SuppressedBy: rule,
			RuleReason:   "fixture",
		}
	}
	suppressed := []detector.SuppressedMatch{
		mk("EMAIL", 23, 2, "src/zeta.go", "SUP-4"),
		mk("SSN", 90, 1, "notes.txt", "SUP-1"),
		mk("EMAIL", 23, 2, "src/alpha.go", "SUP-3"),
		mk("PHONE", 90, 3, "src/mid.go", "SUP-2"),
	}
	matches := []detector.Match{
		{Type: "EMAIL", Confidence: 95, LineNumber: 1, Filename: "docs/readme.md", Text: "r@example.test"},
	}
	options := formatters.FormatterOptions{
		ConfidenceLevel: allLevels(),
		NoColor:         true,
	}

	first, err := f.Format(matches, suppressed, options)
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if !strings.Contains(first, "SUPP") {
		t.Fatalf("fixture did not emit suppressed rows:\n%s", first)
	}

	for i := 0; i < 200; i++ {
		// Re-shuffle the input each iteration: a formatter relying on the
		// caller's order would diverge, one that sorts will not.
		shuffled := []detector.SuppressedMatch{suppressed[(i+1)%4], suppressed[(i+2)%4], suppressed[(i+3)%4], suppressed[i%4]}
		got, err := f.Format(matches, shuffled, options)
		if err != nil {
			t.Fatalf("iter %d: Format: %v", i, err)
		}
		if got != first {
			t.Fatalf("iter %d: suppressed row order follows input order:\n--- first ---\n%s\n--- iter %d ---\n%s",
				i, first, i, got)
		}
	}

	// Confidence desc, then type, line, filename: SSN(90) then PHONE(90) is
	// PHONE first by type, then the two EMAIL(23) by filename.
	wantOrder := []string{"PHONE", "SSN", "alpha.go", "zeta.go"}
	last := -1
	for _, name := range wantOrder {
		idx := strings.Index(first, name)
		if idx < 0 {
			t.Fatalf("expected %q in suppressed output:\n%s", name, first)
		}
		if idx < last {
			t.Errorf("%q is out of the intended order:\n%s", name, first)
		}
		last = idx
	}
}

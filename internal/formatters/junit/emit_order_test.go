// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package junit

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

// iterations is high enough that a randomized Go map order over the five files
// below is overwhelmingly unlikely to yield the expected order every time.
const iterations = 200

func levels() map[string]bool {
	return map[string]bool{"high": true, "medium": true, "low": true}
}

// suiteNamed returns the named testsuite from a parsed JUnit document.
func suiteNamed(t *testing.T, doc string, name string) TestSuite {
	t.Helper()
	var suites TestSuites
	if err := xml.Unmarshal([]byte(doc), &suites); err != nil {
		t.Fatalf("unmarshal JUnit XML: %v", err)
	}
	for _, s := range suites.TestSuites {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("no testsuite named %q in output", name)
	return TestSuite{}
}

func caseNames(suite TestSuite) []string {
	out := make([]string, 0, len(suite.TestCases))
	for _, tc := range suite.TestCases {
		out = append(out, tc.Name)
	}
	return out
}

// TestActiveTestcases_StableOrder locks the <testcase> order for active
// findings. The elements were produced by ranging the per-file group map, so
// two JUnit reports of one unchanged scan listed the same testcases in
// different sequences — CI systems that diff or fingerprint the report read the
// reshuffle as new results.
func TestActiveTestcases_StableOrder(t *testing.T) {
	// Five distinct files so the map has enough entries for randomization to
	// show, supplied in neither the expected order nor its reverse.
	matches := []detector.Match{
		{Text: "a@example.com", LineNumber: 1, Type: "EMAIL", Confidence: 95, Filename: "src/zeta.go", Validator: "email"},
		{Text: "b@example.com", LineNumber: 2, Type: "EMAIL", Confidence: 95, Filename: "src/alpha.go", Validator: "email"},
		{Text: "c@example.com", LineNumber: 3, Type: "EMAIL", Confidence: 95, Filename: "docs/readme.md", Validator: "email"},
		{Text: "d@example.com", LineNumber: 4, Type: "EMAIL", Confidence: 95, Filename: "src/mid.go", Validator: "email"},
		{Text: "e@example.com", LineNumber: 5, Type: "EMAIL", Confidence: 95, Filename: "notes.txt", Validator: "email"},
	}

	// Grouping is keyed on the FULL path and sorted on it, but the testcase
	// name displays only the base name — so docs/readme.md leads.
	want := []string{"readme.md", "notes.txt", "alpha.go", "mid.go", "zeta.go"}

	f := NewFormatter()
	for i := 0; i < iterations; i++ {
		out, err := f.Format(matches, nil, formatters.FormatterOptions{ConfidenceLevel: levels()})
		if err != nil {
			t.Fatalf("Format error: %v", err)
		}
		got := caseNames(suiteNamed(t, out, "security-scan"))
		if len(got) != len(want) {
			t.Fatalf("iteration %d: got %d testcases, want %d: %v", i, len(got), len(want), got)
		}
		for j := range want {
			if got[j] != want[j] {
				t.Fatalf("iteration %d: testcase %d = %q, want %q\nfull order: %v",
					i, j, got[j], want[j], got)
			}
		}
	}
}

// TestFailureDetail_StableOrder locks the order of the detail lines INSIDE a
// single <failure> element. The local bubble sort this replaced ordered only on
// confidence band and score, so findings sharing a confidence stayed in whatever
// order the scanner produced — nondeterministic, and invisible to a testcase-level
// check because all these findings live in one file.
func TestFailureDetail_StableOrder(t *testing.T) {
	// All five in one file, three of them sharing confidence 95, supplied in
	// neither the expected order nor its reverse.
	matches := []detector.Match{
		{Text: "b@example.com", LineNumber: 8, Type: "EMAIL", Confidence: 95, Filename: "app.go", Validator: "email"},
		{Text: "Acme Corp", LineNumber: 2, Type: "BUSINESS", Confidence: 95, Filename: "app.go", Validator: "business"},
		{Text: "449-87-4100", LineNumber: 5, Type: "SSN", Confidence: 100, Filename: "app.go", Validator: "ssn"},
		{Text: "a@example.com", LineNumber: 3, Type: "EMAIL", Confidence: 95, Filename: "app.go", Validator: "email"},
		{Text: "212-555-0142", LineNumber: 9, Type: "PHONE", Confidence: 70, Filename: "app.go", Validator: "phone"},
	}

	// Shared total order: confidence desc, then type, then line.
	want := []string{
		"Line 5: SSN",
		"Line 2: BUSINESS",
		"Line 3: EMAIL",
		"Line 8: EMAIL",
		"Line 9: PHONE",
	}

	f := NewFormatter()
	for i := 0; i < iterations; i++ {
		out, err := f.Format(matches, nil, formatters.FormatterOptions{ConfidenceLevel: levels()})
		if err != nil {
			t.Fatalf("Format error: %v", err)
		}
		suite := suiteNamed(t, out, "security-scan")
		if len(suite.TestCases) != 1 || suite.TestCases[0].Failure == nil {
			t.Fatalf("want a single failing testcase, got %d cases", len(suite.TestCases))
		}

		var got []string
		for _, line := range strings.Split(suite.TestCases[0].Failure.Content, "\n") {
			if strings.HasPrefix(line, "Line ") {
				// Keep "Line N: TYPE", dropping the confidence tail.
				if idx := strings.Index(line, " detected"); idx > 0 {
					got = append(got, line[:idx])
				}
			}
		}
		if len(got) != len(want) {
			t.Fatalf("iteration %d: got %d detail lines, want %d: %v", i, len(got), len(want), got)
		}
		for j := range want {
			if got[j] != want[j] {
				t.Fatalf("iteration %d: detail %d = %q, want %q\nfull order: %v",
					i, j, got[j], want[j], got)
			}
		}
	}
}

// TestSuppressedTestcases_StableOrder locks the <testcase> order in the
// suppressed-findings suite, which had the same map-range defect plus an
// unsorted input slice.
func TestSuppressedTestcases_StableOrder(t *testing.T) {
	suppressed := []detector.SuppressedMatch{
		{Match: detector.Match{Text: "449-87-4100", LineNumber: 9, Type: "SSN", Confidence: 100, Filename: "src/zeta.go", Validator: "ssn"}, SuppressedBy: "rule-z", RuleReason: "test data"},
		{Match: detector.Match{Text: "212-555-0142", LineNumber: 2, Type: "PHONE", Confidence: 90, Filename: "docs/readme.md", Validator: "phone"}, SuppressedBy: "rule-a", RuleReason: "doc sample"},
		{Match: detector.Match{Text: "b@example.com", LineNumber: 4, Type: "EMAIL", Confidence: 95, Filename: "src/alpha.go", Validator: "email"}, SuppressedBy: "rule-m", RuleReason: "fixture"},
		{Match: detector.Match{Text: "c@example.com", LineNumber: 7, Type: "EMAIL", Confidence: 95, Filename: "notes.txt", Validator: "email"}, SuppressedBy: "rule-n", RuleReason: "scratch"},
	}

	want := []string{
		"readme.md (suppressed)",
		"notes.txt (suppressed)",
		"alpha.go (suppressed)",
		"zeta.go (suppressed)",
	}

	f := NewFormatter()
	for i := 0; i < iterations; i++ {
		// Re-shuffle the input each iteration: arrival order is per-file worker
		// completion order in production, so the formatter must not depend on it.
		n := len(suppressed)
		shuffled := make([]detector.SuppressedMatch, 0, n)
		for k := 0; k < n; k++ {
			shuffled = append(shuffled, suppressed[(i+k)%n])
		}

		out, err := f.Format(nil, shuffled, formatters.FormatterOptions{ConfidenceLevel: levels()})
		if err != nil {
			t.Fatalf("Format error: %v", err)
		}
		got := caseNames(suiteNamed(t, out, "suppressed-findings"))
		if len(got) != len(want) {
			t.Fatalf("iteration %d: got %d testcases, want %d: %v", i, len(got), len(want), got)
		}
		for j := range want {
			if got[j] != want[j] {
				t.Fatalf("iteration %d: testcase %d = %q, want %q\nfull order: %v",
					i, j, got[j], want[j], got)
			}
		}
	}
}

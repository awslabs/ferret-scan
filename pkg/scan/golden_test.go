// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const goldenDir = "testdata/golden"

func updateGolden() bool { return os.Getenv("UPDATE_GOLDEN") == "1" }

// goldenCases: a curated set of inputs that lock pkg/scan's detection + redaction
// behavior. These intentionally overlap with the internal golden corpus (same
// inputs, same validators) so the public API is proven to produce identical
// classification to the internal path.
var goldenCases = []struct {
	name   string
	input  string
	checks []string
}{
	{
		name:   "mixed_pii",
		input:  "Name: Robert Aragon\nSSN: 489-36-8350\nCard: 4929-3813-3266-4295\nEmail: robert@example.com\n",
		checks: nil, // all
	},
	{
		name:   "credit_cards",
		input:  "Visa: 4111-1111-1111-1111\nMC: 5500-0000-0000-0004\nAmex: 3782-822463-10005\n",
		checks: []string{"CREDIT_CARD"},
	},
	{
		name:   "ssn_only",
		input:  "SSNs: 856-45-6789 274-98-1234 529-11-4477\n",
		checks: []string{"SSN"},
	},
	{
		name:   "clean_text",
		input:  "The quick brown fox jumps over the lazy dog.\nNo sensitive data here.\n",
		checks: nil,
	},
	{
		name:   "aws_key",
		input:  "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
		checks: []string{"SECRETS"},
	},
}

// TestGoldenScanText locks the detection output of pkg/scan.ScanText.
func TestGoldenScanText(t *testing.T) {
	os.MkdirAll(goldenDir, 0o755)

	for _, tc := range goldenCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			result, err := ScanText(context.Background(), tc.input, TextOptions{
				Checks:  tc.checks,
				Explain: true,
			})
			if err != nil {
				t.Fatalf("ScanText error: %v", err)
			}

			got := renderFindings(result.Findings)
			checkGolden(t, tc.name+".scan.txt", got)
		})
	}
}

// TestGoldenRedactText locks the redaction output of pkg/scan.RedactText (format-preserving).
func TestGoldenRedactText(t *testing.T) {
	os.MkdirAll(goldenDir, 0o755)

	for _, tc := range goldenCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			result, err := ScanText(context.Background(), tc.input, TextOptions{Checks: tc.checks})
			if err != nil {
				t.Fatalf("ScanText error: %v", err)
			}
			redacted, err := RedactText(tc.input, result.Findings, StrategyFormatPreserving)
			if err != nil {
				t.Fatalf("RedactText error: %v", err)
			}

			checkGolden(t, tc.name+".redact.txt", redacted.Text)
		})
	}
}

// renderFindings produces a deterministic, diffable text representation of findings.
func renderFindings(findings []Finding) string {
	// Sort for determinism: by type, then line, then confidence desc.
	sorted := make([]Finding, len(findings))
	copy(sorted, findings)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Type != sorted[j].Type {
			return sorted[i].Type < sorted[j].Type
		}
		if sorted[i].LineNumber != sorted[j].LineNumber {
			return sorted[i].LineNumber < sorted[j].LineNumber
		}
		return sorted[i].Confidence > sorted[j].Confidence
	})

	var b strings.Builder
	for _, f := range sorted {
		fmt.Fprintf(&b, "[%s] %s (line %d, conf %.0f%%, %s) val=%q\n",
			f.Band(), f.Type, f.LineNumber, f.Confidence, f.Verdict, f.Text)
	}
	return b.String()
}

func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join(goldenDir, name)

	if updateGolden() {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatalf("failed to write golden file %s: %v", path, err)
		}
		t.Logf("updated golden: %s", path)
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("golden file missing: %s (run with UPDATE_GOLDEN=1 to generate)", path)
	}
	if got != string(want) {
		t.Errorf("golden mismatch for %s:\n--- want ---\n%s\n--- got ---\n%s", name, string(want), got)
	}
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package shared_test

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
	csvfmt "github.com/awslabs/ferret-scan/v2/internal/formatters/csv"
	gitlabfmt "github.com/awslabs/ferret-scan/v2/internal/formatters/gitlab-sast"
	junitfmt "github.com/awslabs/ferret-scan/v2/internal/formatters/junit"
	sariffmt "github.com/awslabs/ferret-scan/v2/internal/formatters/sarif"
)

// A truncated report must SAY it is truncated.
//
// TestLimit_EveryFormatHonorsIt next door pins that every format respects --limit.
// That fix left a second problem: the four machine-readable formats truncated
// silently, so a CI job, a security dashboard or a spreadsheet counting findings
// received the capped number with nothing anywhere saying more existed. For a
// security tool that is worse than reporting nothing, because the count looks
// authoritative.
//
// Measured before this change, one 36-finding scan at --limit 3:
//
//	text          "... and 33 more findings"      disclosed
//	json / yaml   truncated:true, total:36        disclosed
//	csv           3 rows, nothing else            SILENT
//	junit         tests/failures describe 3       SILENT
//	sarif         3 results                       SILENT
//	gitlab-sast   3 vulnerabilities               SILENT
//
// CSV is deliberately absent from the in-band assertions below and covered by an
// explicit negative test instead: see TestCSVCannotDiscloseInBand.

func truncTestMatches(n int) []detector.Match {
	out := make([]detector.Match, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, detector.Match{
			Type:       "EMAIL",
			Text:       "user@example.com",
			Confidence: 40,
			LineNumber: i + 1,
			Filename:   "many.txt",
			Validator:  "email",
		})
	}
	return out
}

func truncOptions(limit int) formatters.FormatterOptions {
	return formatters.FormatterOptions{
		ConfidenceLevel: map[string]bool{"high": true, "medium": true, "low": true},
		NoColor:         true,
		ShowMatch:       true,
		Limit:           limit,
	}
}

// The regression: each machine-readable format must declare truncation AND the
// true total, so a consumer can tell it received a partial result set and knows
// how much it is missing.
func TestMachineFormatsDiscloseTruncation(t *testing.T) {
	const total, limit = 36, 3
	matches := truncTestMatches(total)

	cases := []struct {
		name string
		f    formatters.Formatter
		// wants are substrings that must all be present. Each format declares this
		// in its own idiom, so the assertion is per-format rather than shared.
		wants []string
	}{
		{
			name:  "junit",
			f:     junitfmt.NewFormatter(),
			wants: []string{"truncated by --limit", "Showing 3 of 36", "--limit 0"},
		},
		{
			name:  "sarif",
			f:     sariffmt.NewFormatter(),
			wants: []string{"ferretScanTruncated", "ferretScanTotalFindings", "36"},
		},
		{
			name:  "gitlab-sast",
			f:     gitlabfmt.NewFormatter(),
			wants: []string{`"truncated": true`, `"total_vulnerabilities": 36`},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := tc.f.Format(matches, nil, truncOptions(limit))
			if err != nil {
				t.Fatalf("Format: %v", err)
			}
			for _, want := range tc.wants {
				if !strings.Contains(out, want) {
					t.Errorf("truncated %s output does not contain %q.\n"+
						"A consumer counting findings sees %d and has no way to learn that "+
						"%d existed — silently under-reporting is worse than reporting "+
						"nothing, because the count looks authoritative.",
						tc.name, want, limit, total)
				}
			}
		})
	}
}

// The complement, and the reason the disclosure fields are all omitempty: a
// COMPLETE report must be byte-for-byte what it was before this change. Otherwise
// every consumer and every golden snapshot churns for a case that did not truncate.
func TestCompleteReportsCarryNoTruncationMarker(t *testing.T) {
	matches := truncTestMatches(5)

	cases := map[string]formatters.Formatter{
		"csv":         csvfmt.NewFormatter(),
		"junit":       junitfmt.NewFormatter(),
		"sarif":       sariffmt.NewFormatter(),
		"gitlab-sast": gitlabfmt.NewFormatter(),
	}

	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			// Limit 0 (unlimited) and a limit ABOVE the finding count must both be
			// clean: neither truncates, so neither may claim to.
			for _, limit := range []int{0, 100} {
				out, err := f.Format(matches, nil, truncOptions(limit))
				if err != nil {
					t.Fatalf("Format(limit=%d): %v", limit, err)
				}
				for _, marker := range []string{"truncated", "Truncated", "TRUNCATED", "--limit 0"} {
					if strings.Contains(out, marker) {
						t.Errorf("a complete %s report (limit=%d, %d findings) contains %q; "+
							"the disclosure must be omitempty so an untruncated report is "+
							"unchanged", name, limit, len(matches), marker)
					}
				}
			}
		})
	}
}

// CSV genuinely cannot disclose in band, and this records that as a decision rather
// than an oversight.
//
// A "#" comment has no CSV syntax and a strict parser rejects it. An extra data row
// inflates the row count consumers use to count findings —
// TestLimit_EveryFormatHonorsIt asserts exactly that contract and caught the
// attempt during this change. So CSV's disclosure is out of band, written to stderr
// by cmd/main.go for every format, which corrupts nothing and is visible even when
// the report is redirected to a file.
//
// If someone later adds a CSV comment or trailing row, this test fails and points at
// the parity contract.
func TestCSVCannotDiscloseInBand(t *testing.T) {
	const total, limit = 36, 3
	out, err := csvfmt.NewFormatter().Format(truncTestMatches(total), nil, truncOptions(limit))
	if err != nil {
		t.Fatalf("Format: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out), "\n")
	// One header + exactly `limit` data rows. Any extra line is either a comment a
	// parser will choke on or a row that miscounts the findings.
	if got := len(lines) - 1; got != limit {
		t.Errorf("CSV emitted %d data rows at --limit %d.\n"+
			"CSV has nowhere to put metadata: a comment line is not valid CSV and an "+
			"extra row inflates the count consumers read. Truncation is disclosed on "+
			"stderr instead (cmd/main.go).", got, limit)
	}
}

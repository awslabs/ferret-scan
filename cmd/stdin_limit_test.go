// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// stdinLimitMatches builds n LOW-confidence findings on distinct lines.
func stdinLimitMatches(n int) []detector.Match {
	out := make([]detector.Match, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, detector.Match{
			Text:       fmt.Sprintf("user%02d@example.com", i),
			LineNumber: i + 1,
			Type:       "BUSINESS",
			Confidence: 48,
			Filename:   "<stdin>",
			Validator:  "email",
		})
	}
	return out
}

func stdinLimitConfig(format string) *finalConfiguration {
	return &finalConfiguration{
		format:           format,
		confidenceLevels: "all",
		noColor:          true,
		showMatch:        true,
	}
}

// TestFormatStdinFindings_HonorsLimit covers the redaction branch of --stdin.
// runStdinRedaction formats its findings through this helper, which never
// received the --limit value, so `--stdin --enable-redaction --limit 3` emitted
// every finding while the same flags without --enable-redaction emitted 3.
//
// Correctness note: capping the report cannot reduce redaction coverage.
// runStdinRedaction calls RedactString with the full match slice BEFORE
// formatting, so the limit only ever bounds how much of the report is printed.
func TestFormatStdinFindings_HonorsLimit(t *testing.T) {
	matches := stdinLimitMatches(30)

	got, err := formatStdinFindings(matches, nil, stdinLimitConfig("text"), 3, nil)
	if err != nil {
		t.Fatalf("formatStdinFindings: %v", err)
	}

	rows := 0
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, "[") && strings.Contains(line, "line ") {
			rows++
		}
	}
	if rows != 3 {
		t.Errorf("emitted %d finding rows with limit=3, want 3", rows)
	}
}

// TestFormatStdinFindings_ZeroMeansUnlimited pins the escape hatch on the same
// path, and keeps the test above from passing for the wrong reason (a helper
// that always truncated would satisfy it too).
func TestFormatStdinFindings_ZeroMeansUnlimited(t *testing.T) {
	matches := stdinLimitMatches(30)

	got, err := formatStdinFindings(matches, nil, stdinLimitConfig("text"), 0, nil)
	if err != nil {
		t.Fatalf("formatStdinFindings: %v", err)
	}

	rows := 0
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, "[") && strings.Contains(line, "line ") {
			rows++
		}
	}
	if rows != 30 {
		t.Errorf("emitted %d finding rows with limit=0, want all 30", rows)
	}
}

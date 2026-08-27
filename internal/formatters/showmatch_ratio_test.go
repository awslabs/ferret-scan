// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package formatters_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"

	// Register every formatter.
	_ "github.com/awslabs/ferret-scan/v2/internal/formatters/csv"
	_ "github.com/awslabs/ferret-scan/v2/internal/formatters/gitlab-sast"
	_ "github.com/awslabs/ferret-scan/v2/internal/formatters/json"
	_ "github.com/awslabs/ferret-scan/v2/internal/formatters/junit"
	_ "github.com/awslabs/ferret-scan/v2/internal/formatters/sarif"
	_ "github.com/awslabs/ferret-scan/v2/internal/formatters/text"
	_ "github.com/awslabs/ferret-scan/v2/internal/formatters/yaml"
)

// maxShowMatchRatio bounds how much larger --show-match output may be than plain output.
//
// A RATIO rather than a byte count, deliberately: an absolute size rots the moment the fixture or any
// formatter's boilerplate changes, whereas the ratio is the property that actually went wrong. 4 is
// generous — the measured post-fix values on a pathological single-line document are 2.6 (sarif) and
// 2.0 (gitlab-sast), and on ordinary multi-line input every format is at or below 1.3.
const maxShowMatchRatio = 4.0

// longLineMatches builds findings that all sit on ONE long line, which is the shape that made
// SARIF and gitlab-sast quadratic: they embed Context.FullLine once per finding, so N findings on an
// L-byte line cost N*L. json never did, which is what localised #521 to those two.
func longLineMatches(count, lineBytes int) ([]detector.Match, string) {
	ssn := strings.Join([]string{"449", "87", "4100"}, "-")
	var b strings.Builder
	for b.Len() < lineBytes {
		fmt.Fprintf(&b, "row%d taxpayer SSN %s owner person@corp.example | ", b.Len(), ssn)
	}
	line := b.String()

	matches := make([]detector.Match, 0, count)
	for i := 0; i < count; i++ {
		matches = append(matches, detector.Match{
			Text: ssn, Type: "SSN", LineNumber: 1, Confidence: 100, Validator: "ssn",
			Filename: "report.txt",
			Context:  detector.ContextInfo{FullLine: line},
		})
	}
	return matches, line
}

// TestShowMatchDoesNotAmplifyOutputAcrossFormats is the regression test for #521.
//
// Measured before the fix on a real 892KB single-line export with 2,633 findings: gitlab-sast 3.0MB ->
// 771MB (x254) and sarif 4.8MB -> 1.54GB (x320) under --show-match, while json stayed at x1. On a
// 284KB synthetic line with 5,200 findings the parent reached x297 (sarif) and x245 (gitlab-sast).
//
// Every formatter is asserted, not just the two that were broken: the defect is that two of the seven
// were wildly out of line with the rest, and only a cross-format comparison shows that. A test naming
// only sarif and gitlab-sast would not notice a third formatter acquiring the same shape.
func TestShowMatchDoesNotAmplifyOutputAcrossFormats(t *testing.T) {
	matches, line := longLineMatches(300, 60000)
	t.Logf("fixture: %d findings on one %d-byte line", len(matches), len(line))

	confidence := map[string]bool{"high": true, "medium": true, "low": true}

	for _, name := range formatters.List() {
		t.Run(name, func(t *testing.T) {
			f, ok := formatters.Get(name)
			if !ok {
				t.Fatalf("formatter %q is registered in ValidFormats but not gettable", name)
			}

			plain, err := f.Format(matches, nil, formatters.FormatterOptions{ConfidenceLevel: confidence})
			if err != nil {
				t.Fatalf("plain: %v", err)
			}
			shown, err := f.Format(matches, nil, formatters.FormatterOptions{
				ConfidenceLevel: confidence, ShowMatch: true,
			})
			if err != nil {
				t.Fatalf("--show-match: %v", err)
			}

			// Non-vacuity: both must actually be reports, or the ratio is meaningless.
			if len(plain) == 0 {
				t.Fatalf("plain output is empty, so the ratio below proves nothing")
			}

			ratio := float64(len(shown)) / float64(len(plain))
			t.Logf("plain=%d show-match=%d ratio=%.2f", len(plain), len(shown), ratio)

			if ratio > maxShowMatchRatio {
				t.Errorf("--show-match made the report %.1fx larger (%d -> %d bytes) for %d findings on "+
					"one %d-byte line. That is the #521 shape: the line is embedded once per finding, so "+
					"the report is quadratic in findings x line length.",
					ratio, len(plain), len(shown), len(matches), len(line))
			}
		})
	}
}

// TestShowMatchStillRevealsTheValue keeps the bound from being satisfied by simply omitting the match.
//
// A formatter that stopped revealing anything under --show-match would pass the ratio test perfectly
// and destroy the flag's only purpose. Checked on the formats that are documented to reveal it.
func TestShowMatchStillRevealsTheValue(t *testing.T) {
	ssn := strings.Join([]string{"449", "87", "4100"}, "-")
	matches := []detector.Match{{
		Text: ssn, Type: "SSN", LineNumber: 1, Confidence: 100, Validator: "ssn",
		Filename: "report.txt",
		Context:  detector.ContextInfo{FullLine: "employee ssn " + ssn + " on file"},
	}}
	confidence := map[string]bool{"high": true, "medium": true, "low": true}

	for _, name := range []string{"json", "yaml", "sarif", "gitlab-sast", "text", "csv"} {
		t.Run(name, func(t *testing.T) {
			f, ok := formatters.Get(name)
			if !ok {
				t.Skipf("formatter %q not registered", name)
			}
			shown, err := f.Format(matches, nil, formatters.FormatterOptions{
				ConfidenceLevel: confidence, ShowMatch: true,
			})
			if err != nil {
				t.Fatalf("Format: %v", err)
			}
			if !strings.Contains(shown, ssn) {
				t.Errorf("--show-match did not reveal the value, so the ratio bound could be met by "+
					"emitting nothing: %.200q", shown)
			}
		})
	}
}

// TestAShortLineIsUnchangedByTheBound is the blast-radius assertion.
//
// 91.4% of the lines carrying a finding in a 1,009-file real corpus are within the cap, so ordinary
// output must be byte-identical. If this fails, the bound is rewriting normal reports rather than
// only pathological ones.
func TestAShortLineIsUnchangedByTheBound(t *testing.T) {
	ssn := strings.Join([]string{"449", "87", "4100"}, "-")
	line := "employee ssn " + ssn + " on file"
	matches := []detector.Match{{
		Text: ssn, Type: "SSN", LineNumber: 1, Confidence: 100, Validator: "ssn",
		Filename: "report.txt",
		Context:  detector.ContextInfo{FullLine: line},
	}}
	confidence := map[string]bool{"high": true, "medium": true, "low": true}

	for _, name := range []string{"sarif", "gitlab-sast"} {
		t.Run(name, func(t *testing.T) {
			f, _ := formatters.Get(name)
			shown, err := f.Format(matches, nil, formatters.FormatterOptions{
				ConfidenceLevel: confidence, ShowMatch: true,
			})
			if err != nil {
				t.Fatalf("Format: %v", err)
			}
			// The line must appear WHOLE, with no ellipsis marker anywhere near it.
			if !strings.Contains(shown, line) {
				t.Errorf("a %d-byte line was altered even though it is far below the cap; the bound "+
					"must not touch ordinary output", len(line))
			}
		})
	}
}

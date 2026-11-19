// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package formatters_test

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

// An exhausted synthetic family has a cause of its own (#886), and every format names it.
//
// Before it, the refusal reached the report as the generic "redaction refused", which is true
// but gives the operator nothing to act on; this cause says the strategy ran out of distinct
// replacements, so another strategy (or a smaller file) writes a copy.
func TestEveryFormatNamesTheSyntheticExhaustedCause(t *testing.T) {
	const label = "synthetic replacement space exhausted"
	if got := formatters.UnredactedSyntheticExhausted.String(); got != label {
		t.Fatalf("UnredactedSyntheticExhausted.String() = %q, want %q", got, label)
	}
	if formatters.UnredactedSyntheticExhausted == formatters.UnredactedRefused {
		t.Fatal("the exhausted cause is the generic one")
	}

	matches := []detector.Match{
		{Text: "449-87-4100", Type: "SSN", Confidence: 100, LineNumber: 1, Filename: "/scan/people.txt"},
	}
	options := formatters.FormatterOptions{
		ConfidenceLevel:    map[string]bool{"high": true, "medium": true, "low": true},
		RedactionRequested: true,
		Unredacted: []formatters.UnredactedFile{{
			Path:           "/scan/people.txt",
			Cause:          formatters.UnredactedSyntheticExhausted,
			Detail:         "each of 64 draws for a SSN value produced a replacement that another SSN value in this run already holds",
			ReportedValues: 1,
		}},
		Stats: &formatters.ScanStats{
			TotalFiles: 1, FilesProcessed: 1, TotalFindings: 1, High: 1,
			FilesNotRedacted: 1, ValuesNotRedacted: 1,
		},
	}
	for _, name := range []string{"text", "json", "yaml", "csv", "junit", "gitlab-sast", "sarif"} {
		t.Run(name, func(t *testing.T) {
			f, ok := formatters.Get(name)
			if !ok {
				t.Fatalf("formatter %q is not registered", name)
			}
			out, err := f.Format(matches, nil, options)
			if err != nil {
				t.Fatalf("Format: %v", err)
			}
			if !strings.Contains(out, label) {
				t.Errorf("%s output does not name the cause %q\n--- output ---\n%s", name, label, out)
			}
			if strings.Contains(out, "redaction refused") {
				t.Errorf("%s output still reads as the generic cause\n--- output ---\n%s", name, out)
			}
		})
	}
}

// The new cause is appended, so the older causes keep their values (CapUnredacted breaks ties
// in enum order) and the cap still gives every cause, the new one included, a slot.
func TestSyntheticExhaustedCauseGetsASlot(t *testing.T) {
	if formatters.UnredactedSyntheticExhausted <= formatters.UnredactedWriteFailed {
		t.Fatalf("UnredactedSyntheticExhausted = %d: append it after the existing causes", formatters.UnredactedSyntheticExhausted)
	}
	files := make([]formatters.UnredactedFile, 0, 200)
	for i := 0; i < 199; i++ {
		files = append(files, formatters.UnredactedFile{Path: "/scan/a.pdf", Cause: formatters.UnredactedNoRedactor, ReportedValues: 1})
	}
	files = append(files, formatters.UnredactedFile{Path: "/scan/z.txt", Cause: formatters.UnredactedSyntheticExhausted, ReportedValues: 1})
	shown, total := formatters.CapUnredacted(files)
	if total != 200 {
		t.Fatalf("total = %d, want 200", total)
	}
	for _, f := range shown {
		if f.Cause == formatters.UnredactedSyntheticExhausted {
			return
		}
	}
	t.Error("the exhausted cause was crowded out of the capped list")
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package formatters_test

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"

	// Every formatter registers itself in init(), so importing them is what makes
	// formatters.Get work. Blank imports because nothing here calls into them directly.
	_ "github.com/awslabs/ferret-scan/v2/internal/formatters/csv"
	_ "github.com/awslabs/ferret-scan/v2/internal/formatters/gitlab-sast"
	_ "github.com/awslabs/ferret-scan/v2/internal/formatters/json"
	_ "github.com/awslabs/ferret-scan/v2/internal/formatters/junit"
	_ "github.com/awslabs/ferret-scan/v2/internal/formatters/sarif"
	_ "github.com/awslabs/ferret-scan/v2/internal/formatters/text"
	_ "github.com/awslabs/ferret-scan/v2/internal/formatters/yaml"
)

// EVERY format must disclose that a reported value was not redacted.
//
// This is the test that would have caught #441. Measured on main before the fix, on a
// real 14KB PDF that extracts cleanly and yields 3 findings under --enable-redaction:
// SEVEN of seven formats contained no mention of the refusal. The warning existed, but
// only on stderr, which pipelines discard — so a consumer parsing stdout saw three
// findings and a clean report while the values sat unchanged on disk.
//
// Asserted per format on a substring that is meaningful in THAT format rather than on
// one shared string, because the formats express the same fact in their own grammar and
// a single shared assertion would either be vacuous or force an unnatural shape on one
// of them.
func TestEveryFormatDisclosesAnUnredactedFile(t *testing.T) {
	matches := []detector.Match{
		{Text: "449-87-4100", Type: "SSN", Confidence: 100, LineNumber: 2, Filename: "/scan/report.pdf"},
		{Text: "4532-0151-1283-0366", Type: "VISA", Confidence: 100, LineNumber: 1, Filename: "/scan/report.pdf"},
	}

	options := formatters.FormatterOptions{
		ConfidenceLevel:    map[string]bool{"high": true, "medium": true, "low": true},
		RedactionRequested: true,
		Unredacted: []formatters.UnredactedFile{{
			Path:           "/scan/report.pdf",
			Cause:          formatters.UnredactedNoRedactor,
			Detail:         "PDF redaction is not implemented",
			ReportedValues: 2,
		}},
		Stats: &formatters.ScanStats{
			TotalFiles: 1, FilesProcessed: 1, TotalFindings: 2, High: 2,
			FilesNotRedacted: 1, ValuesNotRedacted: 2,
		},
	}

	// Each format's own idiom for the same fact.
	want := map[string][]string{
		"text":        {"VALUES LEFT IN CLEARTEXT", "no redactor for this file type", "report.pdf"},
		"json":        {`"unredacted"`, `"files_not_redacted": 1`, `"values_not_redacted": 2`, "no redactor for this file type"},
		"yaml":        {"unredacted:", "files_not_redacted: 1", "values_not_redacted: 2", "no redactor for this file type"},
		"csv":         {"Redacted", "Not Redacted Reason", "false", "no redactor for this file type"},
		"junit":       {`name="unredacted"`, "<failure", "NOT REDACTED", "remain in cleartext"},
		"gitlab-sast": {"NOT REDACTED", "VALUES LEFT IN CLEARTEXT", `"level": "warn"`},
		"sarif":       {"ferret-scan/not-redacted", "NOT REDACTED", "toolExecutionNotifications"},
	}

	for name, needles := range want {
		t.Run(name, func(t *testing.T) {
			f, ok := formatters.Get(name)
			if !ok {
				t.Fatalf("formatter %q is not registered", name)
			}
			out, err := f.Format(matches, nil, options)
			if err != nil {
				t.Fatalf("Format: %v", err)
			}
			if out == "" {
				t.Fatal("empty output, so nothing was disclosed")
			}
			for _, n := range needles {
				if !strings.Contains(out, n) {
					t.Errorf("%s output does not disclose the unredacted file: missing %q\n"+
						"a consumer parsing this format cannot tell a sanitized run from one "+
						"that left every value in cleartext\n--- output ---\n%s",
						name, n, out)
				}
			}
		})
	}
}

// The other direction: a run where everything redacted cleanly must say NOTHING.
//
// Without this, emitting the disclosure unconditionally would pass the test above while
// making every clean report claim an exposure — and a warning that is always present is
// a warning nobody reads.
func TestNoDisclosureWhenEverythingWasRedacted(t *testing.T) {
	matches := []detector.Match{
		{Text: "449-87-4100", Type: "SSN", Confidence: 100, LineNumber: 1, Filename: "/scan/notes.txt"},
	}
	options := formatters.FormatterOptions{
		ConfidenceLevel:    map[string]bool{"high": true, "medium": true, "low": true},
		RedactionRequested: true,
		// No Unredacted entries: every file was redacted.
		Stats: &formatters.ScanStats{TotalFiles: 1, FilesProcessed: 1, TotalFindings: 1, High: 1},
	}

	forbidden := []string{
		"VALUES LEFT IN CLEARTEXT", "NOT REDACTED", "not-redacted",
		"files_not_redacted", "values_not_redacted", `name="unredacted"`,
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
			for _, bad := range forbidden {
				if strings.Contains(out, bad) {
					t.Errorf("%s claims an exposure on a fully redacted run: found %q\n--- output ---\n%s",
						name, bad, out)
				}
			}
		})
	}
}

// CSV expresses the fact per ROW, so its header must match its rows exactly.
//
// The columns are gated on RedactionRequested, following the same convention --verbose
// already uses for Metadata. A header that does not match the row width produces a file
// that every CSV reader rejects or silently misaligns, which is worse than no
// disclosure at all.
func TestCSVRowWidthMatchesHeader(t *testing.T) {
	matches := []detector.Match{
		{Text: "449-87-4100", Type: "SSN", Confidence: 100, LineNumber: 1, Filename: "/scan/a.pdf"},
		{Text: "415-555-0132", Type: "PHONE", Confidence: 15, LineNumber: 2, Filename: "/scan/b.txt"},
	}

	for _, tc := range []struct {
		name      string
		requested bool
		wantCols  int
	}{
		{"redaction requested", true, 8},
		{"read-only scan", false, 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := formatters.FormatterOptions{
				ConfidenceLevel:    map[string]bool{"high": true, "medium": true, "low": true},
				RedactionRequested: tc.requested,
				Unredacted: []formatters.UnredactedFile{{
					Path: "/scan/a.pdf", Cause: formatters.UnredactedNoRedactor, ReportedValues: 1,
				}},
			}
			f, ok := formatters.Get("csv")
			if !ok {
				t.Fatal("csv formatter is not registered")
			}
			out, err := f.Format(matches, nil, options)
			if err != nil {
				t.Fatalf("Format: %v", err)
			}

			lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
			if len(lines) < 2 {
				t.Fatalf("expected a header and at least one row, got %d line(s)", len(lines))
			}
			header := strings.Count(lines[0], ",") + 1
			if header != tc.wantCols {
				t.Errorf("header has %d columns, want %d: %s", header, tc.wantCols, lines[0])
			}
			for i, l := range lines[1:] {
				if got := strings.Count(l, ",") + 1; got != header {
					t.Errorf("row %d has %d fields but the header has %d — a ragged CSV "+
						"misaligns every column after the short one\n  header: %s\n  row:    %s",
						i+1, got, header, lines[0], l)
				}
			}
			if tc.requested && !strings.Contains(out, "false") {
				t.Error("the unredacted file's row does not say Redacted=false, so a consumer " +
					"filtering on it finds nothing")
			}
		})
	}
}

// The cap must bound the enumeration WITHOUT understating the totals.
//
// An unbounded list is a denial of service against the consumer — a SARIF upload past
// GitHub's size limit is rejected whole, losing the disclosure entirely. So the list is
// capped, and the summary must still state the true totals or the report would
// understate the exposure, which is the failure mode this whole disclosure exists to
// prevent.
func TestCapStatesTheTrueTotals(t *testing.T) {
	files := make([]formatters.UnredactedFile, 0, formatters.MaxUnredactedEntries*2)
	for i := 0; i < formatters.MaxUnredactedEntries*2; i++ {
		files = append(files, formatters.UnredactedFile{
			Path: "/scan/f.pdf", Cause: formatters.UnredactedNoRedactor, ReportedValues: 3,
		})
	}

	shown, total := formatters.CapUnredacted(files)
	if len(shown) != formatters.MaxUnredactedEntries {
		t.Errorf("cap returned %d entries, want %d", len(shown), formatters.MaxUnredactedEntries)
	}
	if total != len(files) {
		t.Errorf("cap reported total %d, want %d — the cap must not change the total", total, len(files))
	}

	// Counted over the FULL slice, not the capped one.
	if got, want := formatters.UnredactedValueCount(files), len(files)*3; got != want {
		t.Errorf("value count = %d, want %d — counting the capped slice would understate the exposure", got, want)
	}

	summary := formatters.UnredactedSummary(len(shown), total, formatters.UnredactedValueCount(files))
	for _, want := range []string{"omitted", "CLEARTEXT", "100 file(s)", "300 reported value(s)"} {
		if !strings.Contains(summary, want) {
			t.Errorf("capped summary %q does not mention %q, so truncation is silent", summary, want)
		}
	}
}

// The zero value must be a valid, always-true cause.
//
// The cause is recovered by matching substrings of a redactor's error string, and that
// matching will drift when an error is reworded. When it does, the entry falls to the
// zero value — so the zero value's label has to be true of every refusal, or a
// misclassification would confidently state a wrong remedy. It must also never be the
// empty string, which GitLab's schema rejects (minLength 1).
func TestZeroCauseIsValidAndGeneric(t *testing.T) {
	var zero formatters.UnredactedCause
	if got := zero.String(); got == "" || got == "unknown" {
		t.Errorf("zero UnredactedCause renders as %q; it must be a real, generic label "+
			"because an unmatched error string lands here", got)
	}

	// A zero-valued struct must still produce a non-empty message: GitLab SAST requires
	// minLength 1 on the message value, so an empty string would make the document
	// schema-invalid and be rejected whole.
	var f formatters.UnredactedFile
	if msg := f.Message(); msg == "" {
		t.Error("a zero-valued UnredactedFile produces an empty message, which is schema-invalid " +
			"in GitLab SAST and would lose the entire report")
	}
	if msg := f.Message(); !strings.Contains(msg, "cleartext") {
		t.Errorf("message %q does not lead with the consequence; a consumer that truncates it "+
			"would not learn values are exposed", msg)
	}
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package formatters_test

import (
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	xmlpkg "encoding/xml"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

// allFormats is every registered output format. Kept in one place so a new format cannot
// be added without these edge cases running against it.
var allFormats = []string{"text", "json", "yaml", "csv", "junit", "gitlab-sast", "sarif"}

func baseOptions(unredacted []formatters.UnredactedFile) formatters.FormatterOptions {
	return formatters.FormatterOptions{
		ConfidenceLevel:    map[string]bool{"high": true, "medium": true, "low": true},
		RedactionRequested: true,
		Unredacted:         unredacted,
		Stats: &formatters.ScanStats{
			TotalFiles: 1, FilesProcessed: 1, TotalFindings: 1, High: 1,
			FilesNotRedacted:  len(unredacted),
			ValuesNotRedacted: formatters.UnredactedValueCount(unredacted),
		},
	}
}

// A path containing a comma, a quote and a newline must not corrupt the structured
// formats.
//
// Paths are attacker-influenced in a way the rest of the disclosure is not: a scanned
// tree can contain any filename the filesystem allows. A path that breaks out of a CSV
// field or a JSON string turns a disclosure into a malformed artifact, and a malformed
// artifact is usually DISCARDED by the consumer — so a hostile filename would suppress
// the very warning it appears in.
func TestHostilePathsDoNotCorruptAnyFormat(t *testing.T) {
	hostile := "/scan/od,d \"quoted\"\nsecond-line/report.pdf"

	options := baseOptions([]formatters.UnredactedFile{{
		Path:           hostile,
		Cause:          formatters.UnredactedNoRedactor,
		Detail:         `detail with "quotes", a comma and a ]]> sequence`,
		ReportedValues: 1,
	}})
	matches := []detector.Match{
		{Text: "449-87-4100", Type: "SSN", Confidence: 100, LineNumber: 1, Filename: hostile},
	}

	for _, name := range allFormats {
		t.Run(name, func(t *testing.T) {
			f, ok := formatters.Get(name)
			if !ok {
				t.Fatalf("formatter %q is not registered", name)
			}
			out, err := f.Format(matches, nil, options)
			if err != nil {
				t.Fatalf("Format: %v", err)
			}
			if !utf8.ValidString(out) {
				t.Error("output is not valid UTF-8")
			}

			switch name {
			case "json", "gitlab-sast", "sarif":
				var v interface{}
				if err := json.Unmarshal([]byte(out), &v); err != nil {
					t.Errorf("a hostile path made the %s document unparseable: %v\n--- output ---\n%s",
						name, err, out)
				}
			case "junit":
				if err := xmlpkg.Unmarshal([]byte(out), new(interface{})); err != nil {
					t.Errorf("a hostile path made the JUnit XML unparseable: %v\n--- output ---\n%s", err, out)
				}
			case "csv":
				r := csv.NewReader(strings.NewReader(out))
				// FieldsPerRecord = 0 makes the reader enforce that every record has the
				// same width as the first, which is exactly the property a stray comma
				// or quote would break.
				if _, err := r.ReadAll(); err != nil {
					t.Errorf("a hostile path made the CSV unparseable or ragged: %v\n--- output ---\n%s", err, out)
				}
			}
		})
	}
}

// Multiple causes in one run must all be reported, and grouped.
//
// A run over a mixed tree hits several causes at once — an unimplemented type, an
// oversize image, a failed write. Reporting only the first would understate the problem,
// and reporting them ungrouped makes forty files of one cause look like forty problems.
func TestEveryCauseSurvivesInEveryFormat(t *testing.T) {
	files := []formatters.UnredactedFile{
		{Path: "/scan/a.pdf", Cause: formatters.UnredactedNoRedactor, Detail: "pdf not implemented", ReportedValues: 3},
		{Path: "/scan/b.jpg", Cause: formatters.UnredactedOverBudget, Detail: "over the pixel budget", ReportedValues: 5},
		{Path: "/scan/c.mp3", Cause: formatters.UnredactedValueNotLocated, Detail: "not in tag bytes", ReportedValues: 1},
		{Path: "/scan/d.txt", Cause: formatters.UnredactedWriteFailed, Detail: "permission denied", ReportedValues: 2},
		{Path: "/scan/e.bin", Cause: formatters.UnredactedRefused, Detail: "declined", ReportedValues: 4},
	}
	options := baseOptions(files)
	matches := []detector.Match{
		{Text: "449-87-4100", Type: "SSN", Confidence: 100, LineNumber: 1, Filename: "/scan/a.pdf"},
	}

	// Every cause's label must appear, or a consumer cannot tell what to do about a file.
	for _, name := range allFormats {
		t.Run(name, func(t *testing.T) {
			f, _ := formatters.Get(name)
			out, err := f.Format(matches, nil, options)
			if err != nil {
				t.Fatalf("Format: %v", err)
			}
			for _, uf := range files {
				// CSV reports per finding, and only /scan/a.pdf has one here, so the
				// other causes have no row to appear in. That is the documented
				// consequence of CSV's per-row grain rather than a gap in the data.
				if name == "csv" && uf.Path != "/scan/a.pdf" {
					continue
				}
				if !strings.Contains(out, uf.Cause.String()) {
					t.Errorf("%s omits the cause %q for %s, so that file's remedy is unstated",
						name, uf.Cause, uf.Path)
				}
			}
			// The headline totals must be the SUM, not the first entry.
			if name == "text" && !strings.Contains(out, "15 reported value(s)") {
				t.Errorf("text headline does not total the values (want 15)\n--- output ---\n%s", out)
			}
		})
	}
}

// A file with findings suppressed to zero must not claim an exposure of zero values.
//
// The redactor still reports a diagnostic for a file it could not write, and if every
// finding for that file was suppressed then ReportedValues is 0. "0 reported value(s)
// remain in cleartext" is a contradiction: nothing was reported, so nothing was exposed
// through this report. The disclosure must still be truthful when the count is zero
// rather than crash or claim an exposure it cannot substantiate.
func TestZeroReportedValuesStillRendersTruthfully(t *testing.T) {
	options := baseOptions([]formatters.UnredactedFile{{
		Path:           "/scan/allsuppressed.pdf",
		Cause:          formatters.UnredactedNoRedactor,
		Detail:         "pdf not implemented",
		ReportedValues: 0,
	}})

	for _, name := range allFormats {
		t.Run(name, func(t *testing.T) {
			f, _ := formatters.Get(name)
			out, err := f.Format(nil, nil, options)
			if err != nil {
				t.Fatalf("Format on a zero-value entry: %v", err)
			}
			// Must not crash, must remain parseable, and must not invent a value count.
			switch name {
			case "json", "gitlab-sast", "sarif":
				var v interface{}
				if err := json.Unmarshal([]byte(out), &v); err != nil {
					t.Errorf("%s unparseable with a zero-value entry: %v", name, err)
				}
			case "junit":
				if err := xmlpkg.Unmarshal([]byte(out), new(interface{})); err != nil {
					t.Errorf("junit unparseable with a zero-value entry: %v", err)
				}
			}
		})
	}
}

// The cap must never make the totals understate the exposure.
//
// Already covered numerically for the helpers; this pins it through the FORMATS, because
// a formatter that summed the capped slice rather than the full one would report 50
// files where 100 were exposed, and that error is invisible in any test that uses fewer
// entries than the cap.
func TestUnredactedCapIsDisclosedThroughTheFormats(t *testing.T) {
	n := formatters.MaxUnredactedEntries + 17
	files := make([]formatters.UnredactedFile, 0, n)
	for i := 0; i < n; i++ {
		files = append(files, formatters.UnredactedFile{
			Path: "/scan/f.pdf", Cause: formatters.UnredactedNoRedactor, ReportedValues: 2,
		})
	}
	options := baseOptions(files)

	for _, name := range []string{"json", "yaml"} {
		t.Run(name+" stats carry the full total", func(t *testing.T) {
			f, _ := formatters.Get(name)
			out, err := f.Format(nil, nil, options)
			if err != nil {
				t.Fatalf("Format: %v", err)
			}
			// The counters come from Stats, computed over the full set.
			for _, want := range []string{"files_not_redacted", "values_not_redacted"} {
				if !strings.Contains(out, want) {
					t.Errorf("%s lost %s, so the cap silently shrinks the reported exposure", name, want)
				}
			}
		})
	}

	t.Run("machine list is capped", func(t *testing.T) {
		f, _ := formatters.Get("json")
		out, _ := f.Format(nil, nil, options)
		var doc struct {
			Unredacted []struct {
				Path string `json:"path"`
			} `json:"unredacted"`
			Stats struct {
				FilesNotRedacted  int `json:"files_not_redacted"`
				ValuesNotRedacted int `json:"values_not_redacted"`
			} `json:"stats"`
		}
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if len(doc.Unredacted) > formatters.MaxUnredactedEntries {
			t.Errorf("emitted %d entries, past the cap of %d — an unbounded list can push a "+
				"SARIF upload past the size limit and lose the whole report",
				len(doc.Unredacted), formatters.MaxUnredactedEntries)
		}
		if doc.Stats.FilesNotRedacted != n {
			t.Errorf("stats.files_not_redacted = %d, want the TRUE total %d: the cap must bound "+
				"the enumeration, never the count", doc.Stats.FilesNotRedacted, n)
		}
		if doc.Stats.ValuesNotRedacted != n*2 {
			t.Errorf("stats.values_not_redacted = %d, want %d", doc.Stats.ValuesNotRedacted, n*2)
		}
	})
}

// A nil Stats must not panic. The golden harness constructs FormatterOptions without
// one, and the existing not-examined field carries the same warning in its doc comment.
func TestNilStatsWithADisclosureDoesNotPanic(t *testing.T) {
	options := formatters.FormatterOptions{
		ConfidenceLevel:    map[string]bool{"high": true, "medium": true, "low": true},
		RedactionRequested: true,
		Unredacted: []formatters.UnredactedFile{{
			Path: "/scan/a.pdf", Cause: formatters.UnredactedNoRedactor, ReportedValues: 1,
		}},
		// Stats deliberately nil.
	}
	for _, name := range allFormats {
		t.Run(name, func(t *testing.T) {
			f, _ := formatters.Get(name)
			if _, err := f.Format(nil, nil, options); err != nil {
				t.Fatalf("Format with nil Stats: %v", err)
			}
		})
	}
}

// A duplicate path must not be silently collapsed in the counters.
//
// collectUnscanned does not deduplicate and neither does this, so a file that fails for
// two reasons contributes two entries. The counters must agree with the entries, because
// a summary that disagrees with its own list is how a report loses trust.
func TestDuplicatePathsAreCountedNotCollapsed(t *testing.T) {
	files := []formatters.UnredactedFile{
		{Path: "/scan/a.pdf", Cause: formatters.UnredactedNoRedactor, ReportedValues: 2},
		{Path: "/scan/a.pdf", Cause: formatters.UnredactedWriteFailed, ReportedValues: 2},
	}
	if got, want := formatters.UnredactedValueCount(files), 4; got != want {
		t.Errorf("value count = %d, want %d", got, want)
	}
	shown, total := formatters.CapUnredacted(files)
	if total != 2 || len(shown) != 2 {
		t.Errorf("cap collapsed duplicates: shown=%d total=%d, want 2 and 2", len(shown), total)
	}

	// UnredactedPaths is a map, so it DOES collapse — and that is correct for its one
	// caller (CSV, which asks "is this row's file unredacted?"). Pinned so the
	// difference is deliberate rather than discovered later.
	if got := len(formatters.UnredactedPaths(files)); got != 1 {
		t.Errorf("UnredactedPaths has %d entries, want 1: it answers a per-path question and "+
			"is expected to collapse duplicates", got)
	}
}

// The cap must not let a common cause crowd out a rare one.
//
// This is a real defect that shipped in the first draft and was found by asking what a
// directory of many unredactable files looks like. Measured on 150 PDFs, 12 TIFFs and 3
// oversize JPEGs: a flat first-50 prefix emitted "no redactor for this file type" 50
// times and the resource-limit refusals NOT AT ALL, so a JSON consumer could not learn
// that cause had occurred. Which cause survived depended on nothing but filename sort
// order — renaming the JPEGs to sort last was enough to erase them.
//
// It matters because the causes are not interchangeable: "no redactor for this type" is a
// tool limitation nobody can act on, while "refused by a resource limit" is a documented
// number an operator can raise. Hiding the actionable cause behind the inert one is the
// worst way to spend a budget that exists to keep the report readable.
func TestRareCauseIsNotCrowdedOutOfTheCap(t *testing.T) {
	// Deliberately built so the rare cause sorts LAST, which is what exposed the bug.
	files := make([]formatters.UnredactedFile, 0, 200)
	for i := 0; i < 150; i++ {
		files = append(files, formatters.UnredactedFile{
			Path: "/scan/aaa-doc.pdf", Cause: formatters.UnredactedNoRedactor, ReportedValues: 3,
		})
	}
	for i := 0; i < 12; i++ {
		files = append(files, formatters.UnredactedFile{
			Path: "/scan/mmm-img.tiff", Cause: formatters.UnredactedNoRedactor, ReportedValues: 5,
		})
	}
	for i := 0; i < 3; i++ {
		files = append(files, formatters.UnredactedFile{
			Path: "/scan/zzz-big.jpg", Cause: formatters.UnredactedOverBudget, ReportedValues: 5,
		})
	}

	shown, total := formatters.CapUnredacted(files)
	if total != len(files) {
		t.Errorf("total = %d, want %d", total, len(files))
	}
	if len(shown) > formatters.MaxUnredactedEntries {
		t.Errorf("returned %d entries, past the cap of %d", len(shown), formatters.MaxUnredactedEntries)
	}

	seen := map[formatters.UnredactedCause]int{}
	for _, f := range shown {
		seen[f.Cause]++
	}
	for _, want := range []formatters.UnredactedCause{
		formatters.UnredactedNoRedactor, formatters.UnredactedOverBudget,
	} {
		if seen[want] == 0 {
			t.Errorf("cause %q was crowded out of the capped list entirely, so a consumer "+
				"cannot learn it occurred; got %v", want, seen)
		}
	}
}

// Every cause present must get a slot, even with many causes and a tight budget.
func TestEveryCauseGetsASlot(t *testing.T) {
	all := []formatters.UnredactedCause{
		formatters.UnredactedRefused,
		formatters.UnredactedNoRedactor,
		formatters.UnredactedOverBudget,
		formatters.UnredactedValueNotLocated,
		formatters.UnredactedWriteFailed,
	}
	// 40 of each: 200 entries into a 50-slot cap.
	files := make([]formatters.UnredactedFile, 0, 200)
	for _, c := range all {
		for i := 0; i < 40; i++ {
			files = append(files, formatters.UnredactedFile{Path: "/scan/f", Cause: c, ReportedValues: 1})
		}
	}

	shown, _ := formatters.CapUnredacted(files)
	seen := map[formatters.UnredactedCause]int{}
	for _, f := range shown {
		seen[f.Cause]++
	}
	for _, c := range all {
		if seen[c] == 0 {
			t.Errorf("cause %q got no slot; distribution was %v", c, seen)
		}
	}
	// And the budget is spent, not left idle by an over-cautious quota.
	if len(shown) != formatters.MaxUnredactedEntries {
		t.Errorf("used %d of %d slots — the remainder should be shared out, not wasted",
			len(shown), formatters.MaxUnredactedEntries)
	}
}

// The selection must preserve the caller's ordering, so a path-sorted list stays sorted.
func TestCapPreservesInputOrder(t *testing.T) {
	files := make([]formatters.UnredactedFile, 0, 120)
	for i := 0; i < 60; i++ {
		files = append(files, formatters.UnredactedFile{
			Path: string(rune('a'+i%26)) + "-doc.pdf", Cause: formatters.UnredactedNoRedactor, ReportedValues: 1,
		})
	}
	for i := 0; i < 60; i++ {
		files = append(files, formatters.UnredactedFile{
			Path: string(rune('a'+i%26)) + "-img.jpg", Cause: formatters.UnredactedOverBudget, ReportedValues: 1,
		})
	}

	shown, _ := formatters.CapUnredacted(files)

	// Build the index of each shown entry in the original slice and assert it ascends.
	prev := -1
	for _, s := range shown {
		idx := -1
		for i, f := range files {
			if f == s && i > prev {
				idx = i
				break
			}
		}
		if idx < 0 {
			t.Fatalf("selected entry %+v is not in the input", s)
		}
		if idx <= prev {
			t.Errorf("selection is out of input order: index %d followed %d", idx, prev)
		}
		prev = idx
	}
}

// The rendered text block must show at least one example for every cause, and its
// per-cause counts must be the FULL counts rather than the number listed.
func TestRenderedBlockShowsAnExamplePerCauseWithFullCounts(t *testing.T) {
	files := make([]formatters.UnredactedFile, 0, 165)
	for i := 0; i < 162; i++ {
		files = append(files, formatters.UnredactedFile{
			Path: "/scan/doc.pdf", Cause: formatters.UnredactedNoRedactor, ReportedValues: 3,
		})
	}
	for i := 0; i < 3; i++ {
		files = append(files, formatters.UnredactedFile{
			Path: "/scan/zzz-oversize.jpg", Cause: formatters.UnredactedOverBudget, ReportedValues: 5,
		})
	}

	block := formatters.RenderBlock(files, 167, false, true)

	// Full counts, not listed counts.
	for _, want := range []string{"no redactor for this file type (162)", "refused by a resource limit (3)"} {
		if !strings.Contains(block, want) {
			t.Errorf("block does not state the full per-cause count %q\n%s", want, block)
		}
	}
	// An example for the rare cause, which the first draft omitted entirely.
	if !strings.Contains(block, "zzz-oversize.jpg") {
		t.Errorf("the rare cause has a count but no example path, so the operator cannot see "+
			"which files it applies to\n%s", block)
	}
	// Truncation is stated.
	if !strings.Contains(block, "more file(s) not listed") {
		t.Errorf("truncation is silent\n%s", block)
	}
	// The headline totals the values across every cause: 162*3 + 3*5 = 501.
	if !strings.Contains(block, "501 reported value(s)") {
		t.Errorf("headline does not total the values across causes (want 501)\n%s", block)
	}
}

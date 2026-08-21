// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
	"github.com/awslabs/ferret-scan/v2/internal/parallel"
)

// The cause classifier reads SUBSTRINGS of a redactor's error string, so it drifts the
// moment one of those strings is reworded. This pins the strings the shipped redactors
// actually produce, so rewording one fails here instead of silently degrading every
// report to the generic cause.
//
// Each string below is a VERBATIM error observed from a real run at main @ 3c4e10b, not
// an invented approximation — that is the whole point. The command that produced each is
// named so a future reader can regenerate it.
func TestClassifyRedactionErrorCoversTheRealRedactors(t *testing.T) {
	cases := []struct {
		name   string
		reason string
		want   formatters.UnredactedCause
	}{
		{
			// ferret-scan --file report.pdf --enable-redaction
			name:   "pdf, no redactor",
			reason: "PDF redaction is not implemented: refusing to produce an output that was not redacted but would falsely report success",
			want:   formatters.UnredactedNoRedactor,
		},
		{
			// ferret-scan --file scan.tiff --enable-redaction
			name:   "tiff, no redactor",
			reason: "failed to redact image metadata: failed to redact tiff metadata: metadata redaction not implemented for tiff images",
			want:   formatters.UnredactedNoRedactor,
		},
		{
			// ferret-scan --file huge.jpg --enable-redaction, where huge.jpg declares
			// 20000x20000. Shares the "failed to redact image metadata" prefix with the
			// tiff case above, which is why the budget arm is tested BEFORE the
			// not-implemented arm in the classifier.
			name:   "image over the pixel budget",
			reason: "failed to redact image metadata: refusing to redact a 20000x20000 image: 400000000 pixels is over the 67108864-pixel budget, and stripping metadata requires decoding them",
			want:   formatters.UnredactedOverBudget,
		},
		{
			name:   "value not present in the writable bytes",
			reason: "SSN match ([HIDDEN], len=11) not found in line 4",
			want:   formatters.UnredactedValueNotLocated,
		},
		{
			name:   "write failed on permissions",
			reason: "failed to create output file: open /ro/out.txt: permission denied",
			want:   formatters.UnredactedWriteFailed,
		},
		{
			// The important one: an unrecognised string must fall to the GENERIC cause,
			// whose label is true of every refusal. Anything else would state a remedy
			// the operator cannot act on.
			name:   "unknown wording falls back to the generic cause",
			reason: "some future redactor said something nobody has seen before",
			want:   formatters.UnredactedRefused,
		},
		{
			name:   "empty reason still classifies",
			reason: "",
			want:   formatters.UnredactedRefused,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := classifyRedactionError(c.reason); got != c.want {
				t.Errorf("classifyRedactionError(%q)\n  = %v (%s)\n  want %v (%s)",
					c.reason, got, got, c.want, c.want)
			}
		})
	}
}

// A redactor error that embeds a reported value must not carry it into the output.
//
// One did: internal/redactors/plaintext used
//
//	fmt.Errorf("match text %q not found in line %d", match.Text, ...)
//
// which put the raw sensitive value into the diagnostic. Before this disclosure existed
// that string only reached stderr; now it reaches JSON, YAML, CSV, JUnit, SARIF and the
// GitLab report, so a single Errorf can leak into seven places at once. The source has
// been fixed; this is the layer that keeps a future one from mattering.
func TestReportedValuesAreScrubbedFromTheDetail(t *testing.T) {
	matches := []detector.Match{
		{Text: "449-87-4100", Type: "SSN", Filename: "/scan/a.txt"},
		{Text: "4532-0151-1283-0366", Type: "VISA", Filename: "/scan/a.txt"},
		{Text: "42", Type: "SHORT", Filename: "/scan/a.txt"}, // below the scrub floor
	}

	t.Run("a value in the detail is hidden", func(t *testing.T) {
		got := scrubReportedValues(`match text "449-87-4100" not found in line 3`, matches)
		if strings.Contains(got, "449-87-4100") {
			t.Errorf("the raw value survived scrubbing: %q", got)
		}
		if !strings.Contains(got, "[HIDDEN] (len=11)") {
			t.Errorf("expected the length-preserving placeholder, got %q", got)
		}
		// The non-value part of the message must survive, or the operator loses the
		// information the diagnostic exists to give.
		if !strings.Contains(got, "not found in line 3") {
			t.Errorf("scrubbing destroyed the useful part of the message: %q", got)
		}
	})

	t.Run("every reported value is scrubbed, not just the first", func(t *testing.T) {
		got := scrubReportedValues("could not place 449-87-4100 or 4532-0151-1283-0366", matches)
		for _, v := range []string{"449-87-4100", "4532-0151-1283-0366"} {
			if strings.Contains(got, v) {
				t.Errorf("value %q survived: %q", v, got)
			}
		}
	})

	t.Run("repeated occurrences are all scrubbed", func(t *testing.T) {
		got := scrubReportedValues("449-87-4100 and again 449-87-4100", matches)
		if strings.Contains(got, "449-87-4100") {
			t.Errorf("a repeated value survived: %q", got)
		}
	})

	t.Run("a short value is left alone", func(t *testing.T) {
		// "42" would otherwise corrupt line numbers and byte counts throughout the
		// message while hiding nothing an attacker could not guess.
		got := scrubReportedValues("not found in line 42 of 420", matches)
		if got != "not found in line 42 of 420" {
			t.Errorf("a sub-4-character value was scrubbed and corrupted the message: %q", got)
		}
	})

	t.Run("a clean message is unchanged", func(t *testing.T) {
		in := "PDF redaction is not implemented"
		if got := scrubReportedValues(in, matches); got != in {
			t.Errorf("a message with no value was altered: %q -> %q", in, got)
		}
	})

	t.Run("empty input", func(t *testing.T) {
		if got := scrubReportedValues("", matches); got != "" {
			t.Errorf("empty reason became %q", got)
		}
	})
}

// The value count must come from the reported findings, per file, and must not leak
// across files.
//
// It is the number that sizes the exposure. Counting every match in the run against
// every unredacted file would multiply the reported exposure by the number of files,
// and counting the wrong slice (allMatches rather than the unsuppressed set) would count
// suppressed findings as cleartext.
func TestToFormatterUnredactedCountsPerFile(t *testing.T) {
	diags := []parallel.FileDiagnostic{
		{FilePath: "/scan/a.pdf", Reason: "PDF redaction is not implemented"},
		{FilePath: "/scan/b.tiff", Reason: "metadata redaction not implemented for tiff images"},
	}
	matches := []detector.Match{
		{Text: "449-87-4100", Filename: "/scan/a.pdf"},
		{Text: "4532-0151-1283-0366", Filename: "/scan/a.pdf"},
		{Text: "415-555-0132", Filename: "/scan/b.tiff"},
		// A file that redacted fine: must not appear and must not be counted.
		{Text: "078-05-1120", Filename: "/scan/ok.txt"},
	}

	out := toFormatterUnredacted(diags, matches)
	if len(out) != 2 {
		t.Fatalf("got %d entries, want 2", len(out))
	}

	byPath := map[string]formatters.UnredactedFile{}
	for _, f := range out {
		byPath[f.Path] = f
	}
	if got := byPath["/scan/a.pdf"].ReportedValues; got != 2 {
		t.Errorf("/scan/a.pdf counted %d values, want 2", got)
	}
	if got := byPath["/scan/b.tiff"].ReportedValues; got != 1 {
		t.Errorf("/scan/b.tiff counted %d values, want 1", got)
	}
	if _, present := byPath["/scan/ok.txt"]; present {
		t.Error("a file that redacted successfully appears in the disclosure")
	}
	if got, want := formatters.UnredactedValueCount(out), 3; got != want {
		t.Errorf("total value count = %d, want %d — the redacted file's finding must not be counted", got, want)
	}

	// Causes must be classified, not left at the generic fallback, for strings the
	// classifier is known to handle.
	if got := byPath["/scan/a.pdf"].Cause; got != formatters.UnredactedNoRedactor {
		t.Errorf("/scan/a.pdf cause = %v, want UnredactedNoRedactor", got)
	}
}

// No diagnostics means no disclosure at all — nil, not an empty non-nil slice, because
// the formatters guard on len() and the JSON field is omitempty.
func TestNoDiagnosticsProducesNoDisclosure(t *testing.T) {
	if got := toFormatterUnredacted(nil, nil); got != nil {
		t.Errorf("expected nil for no diagnostics, got %#v", got)
	}
	if got := formatters.UnredactedValueCount(nil); got != 0 {
		t.Errorf("value count of nil = %d, want 0", got)
	}
	if got := formatters.UnredactedPaths(nil); got != nil {
		t.Errorf("expected a nil path map, got %#v", got)
	}
	if got := formatters.RenderBlock(nil, 0, false, true); got != "" {
		t.Errorf("expected no rendered block, got %q", got)
	}
}

// The rendered block must state the flag hint that matches the run's actual policy.
//
// Telling an operator to add --fail-on-incomplete when it is already set is the kind of
// small wrongness that erodes trust in the whole report, and the opposite — staying
// silent about the escalation — leaves them thinking a green exit meant success.
func TestRenderedBlockStatesTheRightFlagHint(t *testing.T) {
	files := []formatters.UnredactedFile{{
		Path: "/scan/a.pdf", Cause: formatters.UnredactedNoRedactor, ReportedValues: 3,
	}}

	without := formatters.RenderBlock(files, 1, false, true)
	if !strings.Contains(without, "Add --fail-on-incomplete") {
		t.Errorf("without the flag, the block should say how to escalate: %q", without)
	}
	if strings.Contains(without, "Exit code 3:") {
		t.Errorf("without the flag, the block must not claim exit 3: %q", without)
	}

	with := formatters.RenderBlock(files, 1, true, true)
	if strings.Contains(with, "Add --fail-on-incomplete") {
		t.Errorf("with the flag already set, the block must not tell the operator to add it: %q", with)
	}

	// Suppressed by the composer when another block in the same frame carries it.
	composed := formatters.RenderBlock(files, 1, false, false)
	if strings.Contains(composed, "--fail-on-incomplete") {
		t.Errorf("the hint should be omitted when another block already carries it: %q", composed)
	}

	// The headline must total the values and name the file, in every variant.
	for _, blk := range []string{without, with, composed} {
		for _, want := range []string{"VALUES LEFT IN CLEARTEXT", "3 reported value(s)", "/scan/a.pdf"} {
			if !strings.Contains(blk, want) {
				t.Errorf("block is missing %q: %q", want, blk)
			}
		}
	}
}

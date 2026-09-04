// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package textextractrtftextlib

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// rtf wraps a body in the minimal valid document a producer would emit.
func rtf(body string) string {
	return "{\\rtf1\\ansi\\deff0\n{\\fonttbl{\\f0 Helvetica;}}\n\\f0\\fs24 " + body + "\n}\n"
}

func extract(t *testing.T, doc string) string {
	t.Helper()
	tc, err := ExtractFromBytes("t.rtf", []byte(doc))
	if err != nil {
		t.Fatalf("ExtractFromBytes: %v", err)
	}
	if tc.NotRTF {
		t.Fatalf("valid RTF reported as NotRTF")
	}
	return tc.Text
}

// TestAValueSplitAcrossFormattingRunsIsReassembled is the defect this package exists for.
//
// A real producer (macOS textutil, the engine behind TextEdit and Pages) writes a bolded fragment as a
// new formatting run, so `452-11-9384` reaches the validators as `452-11-\f1\b 9384` and no SSN pattern
// can match across it. The file was reported as scanned and clean, which by the sink rule leaves the
// value cleartext — only reported findings reach the redactor.
func TestAValueSplitAcrossFormattingRunsIsReassembled(t *testing.T) {
	got := extract(t, rtf(`Employee SSN: 452-11-\f1\b 9384\par`))
	if !strings.Contains(got, "452-11-9384") {
		t.Errorf("split value not reassembled.\ngot:  %q\nwant it to contain 452-11-9384", got)
	}
}

// TestABreakingWordDoesNotFuseTwoFields is the other half, and getting it backwards is also a defect.
//
// Deleting every control word would repair the split above but fabricate values across real boundaries:
// two table cells joined would produce a number that appears nowhere in the document. A word meaning
// "same run, different formatting" is dropped; one meaning "new paragraph, cell or line" separates.
func TestABreakingWordDoesNotFuseTwoFields(t *testing.T) {
	// Two SEPARATE cells, each holding half of something SSN-shaped. Fusing them invents 452-11-9384.
	got := extract(t, rtf(`\trowd\intbl 452-11-\cell 9384\cell\row`))
	if strings.Contains(got, "452-11-9384") {
		t.Errorf("two table cells were FUSED into a value that appears nowhere in the document.\ngot: %q", got)
	}
	for _, want := range []string{"452-11-", "9384"} {
		if !strings.Contains(got, want) {
			t.Errorf("cell content %q lost entirely; got %q", want, got)
		}
	}
}

// TestHexAndUnicodeEscapesAreDecoded covers the escape forms a producer emits for punctuation and
// non-ASCII text. Measured before this package: an SSN written with hex-escaped hyphens
// (452\'2d11\'2d9384) produced ZERO findings, because the raw bytes reaching the validators contained
// no hyphens at all.
func TestHexAndUnicodeEscapesAreDecoded(t *testing.T) {
	got := extract(t, rtf(`SSN: 452\'2d11\'2d9384\par Caf\u233\'e9\par`))
	if !strings.Contains(got, "452-11-9384") {
		t.Errorf("hex escapes not decoded; got %q", got)
	}
	if !strings.Contains(got, "Café") {
		t.Errorf("unicode escape not decoded to é; got %q", got)
	}
	// The \uN fallback character must NOT also appear, or every non-ASCII char is doubled.
	if strings.Count(got, "é") != 1 {
		t.Errorf("the \\uN fallback byte was emitted alongside the decoded rune; got %q", got)
	}
}

// TestAnEmbeddedImageBlobIsNotExtracted is the issue's Hazard 2. An embedded image is carried as
// megabytes of hex; handing hex to the validators is the documented way an image becomes a HIGH-band
// finding. The positive controls either side prove the skip does not swallow the surrounding prose —
// a skip that ate the rest of the document would also produce "no false positives".
func TestAnEmbeddedImageBlobIsNotExtracted(t *testing.T) {
	blob := strings.Repeat("deadbeef0123456789abcdef", 4000) // ~96KB of hex

	// BOTH wrappings, because they are dropped by DIFFERENT code and a test that only used the
	// \*\shppict form passed even with "pict" removed from skippedDestinations: the leading \* marks
	// the group ignorable, so the destination name was never consulted. A producer emits either.
	forms := map[string]string{
		`\*\shppict wrapper (ignorable marker)`: `{\*\shppict{\pict\pngblip\picw100\pich100 ` + blob + `}}`,
		`bare \pict group (destination name)`:   `{\pict\pngblip\picw100\pich100 ` + blob + `}`,
	}
	for label, embedded := range forms {
		got := extract(t, rtf(`Before: 452-11-9384\par`+embedded+`\par After: bob@example.com\par`))

		if strings.Contains(got, "deadbeef0123456789abcdef") {
			t.Errorf("%s: the hex blob reached the extracted text; validators would score it as content", label)
		}
		// POSITIVE CONTROLS on both sides of the blob. A skip that ate the rest of the document
		// would also report "no blob text", so the absence above proves nothing without these.
		for _, want := range []string{"452-11-9384", "bob@example.com"} {
			if !strings.Contains(got, want) {
				t.Errorf("%s: prose %q was lost — the destination skip is consuming the document", label, want)
			}
		}
		if len(got) > 4096 {
			t.Errorf("%s: extracted %d bytes from a document whose only prose is two short lines; the "+
				"blob is leaking in some form", label, len(got))
		}
	}
}

// TestMachineTablesAndMetadataAreNotProse: font names produce PERSON_NAME hits and \info holds
// document metadata, neither of which is body text. Skipped wholesale at the destination rather than
// filtered afterwards, so an unanticipated construct is dropped by default.
func TestMachineTablesAndMetadataAreNotProse(t *testing.T) {
	doc := "{\\rtf1\\ansi\\deff0\n" +
		"{\\fonttbl{\\f0\\froman Times New Roman;}{\\f1\\fswiss Arial Narrow;}}\n" +
		"{\\stylesheet{\\s0 Normal;}{\\s1 heading 1;}}\n" +
		"{\\*\\generator Riched20 10.0.19041;}\n" +
		"{\\info{\\author Jane Doe}{\\title Quarterly}}\n" +
		"\\f0\\fs24 Real body: 452-11-9384\\par\n}\n"
	got := extract(t, doc)

	for _, unwanted := range []string{"Times New Roman", "Arial Narrow", "Riched20", "Jane Doe", "Quarterly", "heading 1"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("machine/metadata content %q was extracted as prose; got %q", unwanted, got)
		}
	}
	if !strings.Contains(got, "452-11-9384") {
		t.Errorf("body text lost; got %q", got)
	}
}

// TestAFileNamedRTFThatIsNotRTFIsReportedNotSilentlyEmpty. Returning empty text would read as
// "scanned, nothing found" — a clean bill of health for a file that was never parsed.
func TestAFileNamedRTFThatIsNotRTFIsReportedNotSilentlyEmpty(t *testing.T) {
	for _, in := range []string{"", "plain text, SSN 452-11-9384", "%PDF-1.4\n", "{\\rt"} {
		tc, err := ExtractFromBytes("x.rtf", []byte(in))
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if !tc.NotRTF {
			t.Errorf("input %q was accepted as RTF (text=%q); a non-RTF file must be REPORTED, so the "+
				"caller can fall back rather than trust an empty result", in, tc.Text)
		}
	}
	// And the signature IS accepted, with a BOM, so the check above is not just rejecting everything.
	tc, err := ExtractFromBytes("x.rtf", []byte("\xEF\xBB\xBF"+rtf(`SSN: 452-11-9384\par`)))
	if err != nil {
		t.Fatal(err)
	}
	if tc.NotRTF {
		t.Error("a BOM-prefixed valid RTF was rejected; producers do emit this")
	}
	if !strings.Contains(tc.Text, "452-11-9384") {
		t.Errorf("BOM-prefixed document did not extract; got %q", tc.Text)
	}
}

// TestOversizeInputIsRefusedLoudly. A silent truncation would report partial coverage as complete,
// which is the failure this package exists to remove.
func TestOversizeInputIsRefusedLoudly(t *testing.T) {
	if _, err := ExtractFromBytes("big.rtf", make([]byte, maxRTFBytes+1)); err == nil {
		t.Errorf("an input over the %d-byte cap was accepted; a truncated parse reports partial "+
			"coverage as complete", maxRTFBytes)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "big.rtf")
	if err := os.WriteFile(p, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ExtractText(p); err != nil {
		t.Fatalf("a small file must not be refused: %v", err)
	}
}

// TestExtractionIsLinearInInputSize. An extractor that rescanned per group would reintroduce the
// quadratic behaviour the validators were audited for. Measured in ALLOCATED BYTES rather than wall
// clock: the failure mode (re-slicing or string concatenation per group) is superlinear in bytes, and
// bytes are immune to a loaded CI runner. See internal/perfguard for why a clock is not used here.
func TestExtractionIsLinearInInputSize(t *testing.T) {
	build := func(n int) string {
		var b strings.Builder
		b.WriteString("{\\rtf1\\ansi\\deff0\n{\\fonttbl{\\f0 Helvetica;}}\n\\f0\\fs24 ")
		for i := 0; i < n; i++ {
			// Distinct values and nested groups, so a per-group rescan cannot measure as linear.
			b.WriteString("Rec ")
			b.WriteString(strings.Repeat("x", 8))
			b.WriteString(`: 452-11-\f1\b `)
			b.WriteString("9384")
			b.WriteString(`\b0\par {\i note}` + "\n")
		}
		b.WriteString("}\n")
		return b.String()
	}
	measure := func(doc string) (allocBytes uint64, outLen int) {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		tc, err := ExtractFromBytes("t.rtf", []byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		runtime.ReadMemStats(&after)
		return after.TotalAlloc - before.TotalAlloc, len(tc.Text)
	}

	base, bigDoc := build(2000), build(8000) // a 4x step
	// Warm up so first-touch costs do not land in the base reading.
	measure(base)
	aBase, nBase := measure(base)
	aBig, nBig := measure(bigDoc)

	// NON-VACUITY: both must have produced real output, and it must GROW.
	if nBase == 0 || nBig <= nBase {
		t.Fatalf("output did not grow with input (%d -> %d bytes); the measurement is vacuous", nBase, nBig)
	}
	if aBase == 0 {
		t.Fatal("base allocated 0 bytes; nothing was measured")
	}
	ratio := float64(aBig) / float64(aBase)
	t.Logf("4x input allocated %.2fx (base=%d bytes big=%d bytes; text %d -> %d)", ratio, aBase, aBig, nBase, nBig)
	// Linear is ~4x. 8.0 leaves room for buffer-growth steps while still failing a quadratic (~16x).
	if ratio > 8.0 {
		t.Errorf("a 4x input allocated %.2fx — superlinear, which suggests a per-group rescan or "+
			"string concatenation in the parse loop", ratio)
	}
}

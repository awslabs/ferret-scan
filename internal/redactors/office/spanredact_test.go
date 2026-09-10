// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package office

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// A value split across adjacent runs is reported at confidence 100 and could not be redacted, so the
// whole file was refused (#627) — which also denied redaction to every OTHER value in it.
//
// Two views of the same document disagreed. The SCANNER's extractor strips tags and joins runs with
// nothing, so it reads `456-78-1234` and reports it. The REDACTOR's extractTextFromXML trims each
// character-data token and writes a SPACE between text elements, so it reads `456-78 -1234` and
// locateMatch could never find the value there. The fix locates it in the run-joined view and rewrites
// the affected tokens whole.

const spanSSN = "456-78-1234"

func spanDocx(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, buildPkgRaw(t, body), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	return path
}

// redactSpanDocx runs a real redaction and returns the rewritten word/document.xml.
func redactSpanDocx(t *testing.T, in string, values ...string) string {
	t.Helper()
	matches := make([]detector.Match, 0, len(values))
	for _, v := range values {
		matches = append(matches, detector.Match{Text: v, Type: "SSN", Confidence: 100})
	}
	out := in + ".redacted.docx"
	or := NewOfficeRedactor(nil, nil)
	if _, err := or.RedactDocument(in, out, matches, redactors.RedactionFormatPreserving); err != nil {
		t.Fatalf("RedactDocument: %v", err)
	}
	return readZipPart(t, out, "word/document.xml")
}

// TestRunSplitValueIsRedactedRatherThanRefused is #627, asserted at the sink.
func TestRunSplitValueIsRedactedRatherThanRefused(t *testing.T) {
	dir := t.TempDir()
	in := spanDocx(t, dir, "split.docx",
		`<w:p><w:r><w:t xml:space="preserve">SSN: </w:t></w:r>`+
			`<w:r><w:t>456-78</w:t></w:r><w:r><w:t>-1234</w:t></w:r></w:p>`+
			`<w:p><w:r><w:t>Employee SSN: 321-54-9876</w:t></w:r></w:p>`)

	got := redactSpanDocx(t, in, spanSSN, "321-54-9876")

	if strings.Contains(got, "456-78") {
		t.Errorf("the split value survives redaction:\n%s", got)
	}
	// The COLLATERAL half of #627: refusing the file denied redaction to this value too.
	if strings.Contains(got, "321-54-9876") {
		t.Errorf("the contiguous value in the same document was not redacted — that is the collateral "+
			"damage of refusing the whole file:\n%s", got)
	}
	if !strings.Contains(got, "***-**-1234") {
		t.Errorf("no mask for the split value; the rewrite ran but produced nothing recognisable:\n%s", got)
	}
	// EXACTLY once. The replacement belongs in the first affected token and the rest of the value is
	// deleted; putting it in every token instead leaves the value gone but the mask duplicated, which no
	// "is it absent" assertion can see.
	if n := strings.Count(got, "***-**-1234"); n != 1 {
		t.Errorf("the mask appears %d times, want 1 — the replacement is being written into every "+
			"affected token instead of only the first:\n%s", n, got)
	}
	// The markup between the runs must survive: this rewrites character data, not structure.
	if !strings.Contains(got, `xml:space="preserve"`) {
		t.Errorf("the xml:space attribute was lost, so the rewrite is destroying markup:\n%s", got)
	}
	if n := strings.Count(got, "<w:r>"); n != 4 {
		t.Errorf("run count is %d, want 4 — the rewrite must not add or remove runs:\n%s", n, got)
	}
}

// TestSurroundingTextSurvivesANonOneToOneToken is the hazard that would have made the RTF span rule
// unusable here, and it is the reason whole tokens are re-escaped rather than spliced by offset.
//
// The first run holds `Smith &amp; Co SSN: 456-7&#56;`: 30 source bytes against 22 decoded, so it is NOT
// 1:1. The RTF span map treats a non-1:1 span as atomic and takes it WHOLE, which here would delete
// `Smith & Co SSN: ` along with the value.
func TestSurroundingTextSurvivesANonOneToOneToken(t *testing.T) {
	dir := t.TempDir()
	in := spanDocx(t, dir, "esc.docx",
		`<w:p><w:r><w:t xml:space="preserve">Smith &amp; Co SSN: 456-7&#56;</w:t></w:r>`+
			`<w:r><w:t>-1234</w:t></w:r></w:p>`)

	got := redactSpanDocx(t, in, spanSSN)

	if strings.Contains(got, "456-7") {
		t.Errorf("the split value survives:\n%s", got)
	}
	if !strings.Contains(got, "Smith") || !strings.Contains(got, "Co SSN:") {
		t.Errorf("text SURROUNDING the value in the same token was destroyed — this is the atomic-span "+
			"rule failing:\n%s", got)
	}
	// The ampersand must come back out escaped, or the part is no longer well-formed XML.
	if !strings.Contains(got, "&amp;") {
		t.Errorf("the ampersand was not re-escaped, so the rewritten part is malformed:\n%s", got)
	}
	if strings.Contains(got, "&#56;") {
		t.Logf("note: the numeric reference was normalised to its decoded form, which is expected — "+
			"rewritePartText does the same for a single-token rewrite:\n%s", got)
	}
}

// TestThreeWayRunSplitIsRedacted covers a value whose MIDDLE token holds neither end of it.
func TestThreeWayRunSplitIsRedacted(t *testing.T) {
	dir := t.TempDir()
	in := spanDocx(t, dir, "three.docx",
		`<w:p><w:r><w:t>SSN: 456</w:t></w:r><w:r><w:t>-78-</w:t></w:r><w:r><w:t>1234</w:t></w:r></w:p>`)

	got := redactSpanDocx(t, in, spanSSN)
	for _, frag := range []string{"456-78", "-78-", "456</w:t>"} {
		if strings.Contains(got, frag) {
			t.Errorf("fragment %q survives, so a middle token was not cleared:\n%s", frag, got)
		}
	}
	if !strings.Contains(got, "***-**-1234") {
		t.Errorf("no mask produced:\n%s", got)
	}
}

// TestContiguousValuesTakeTheUnchangedPath is the must-not-regress half.
//
// Every value that redacted before must redact the same way, through rewritePartText, with its escaping
// untouched. A cross-run pass that also rewrote contiguous values would double-redact them.
func TestContiguousValuesTakeTheUnchangedPath(t *testing.T) {
	dir := t.TempDir()
	in := spanDocx(t, dir, "plain.docx",
		`<w:p><w:r><w:t>Employee SSN: 321-54-9876 and Smith &amp; Co</w:t></w:r></w:p>`)

	got := redactSpanDocx(t, in, "321-54-9876")

	if strings.Contains(got, "321-54-9876") {
		t.Errorf("a contiguous value was not redacted:\n%s", got)
	}
	if !strings.Contains(got, "***-**-9876") {
		t.Errorf("no mask:\n%s", got)
	}
	if !strings.Contains(got, "&amp;") {
		t.Errorf("the ampersand's escaping changed on a path this should not have touched:\n%s", got)
	}
	if n := strings.Count(got, "***-**-9876"); n != 1 {
		t.Errorf("the value was masked %d times, want 1 — it is being redacted by both paths", n)
	}
}

// TestPartSpansAgreeWithDecodedPartText pins the invariant the span map's comment promises.
//
// partSpans' runText must be byte-identical to decodedPartText's WHEN UNFILTERED, because that is the
// view the depth-1 residue guard judges and the view the scanner models. If they drift, a value the guard
// refuses over becomes one the rewrite cannot find, and the two halves of this feature disagree silently.
//
// The rewrite passes a filter instead (see rewritableText), so its view is a subset — deliberately, since
// it may only touch text the redactor is allowed to rewrite. This test pins the unfiltered equality; the
// filtered behaviour is pinned by TestTheRewriteViewExcludesNonRewritableFamilies below.
func TestPartSpansAgreeWithDecodedPartText(t *testing.T) {
	cases := []string{
		`<a><b>one</b><b>two</b></a>`,
		`<a><b xml:space="preserve">Smith &amp; Co </b><b>456-7&#56;</b></a>`,
		`<a></a>`,
		`<a><b></b><b>x</b></a>`,
		`<w:p><w:r><w:t>SSN: 456</w:t></w:r><w:r><w:t>-78-</w:t></w:r><w:r><w:t>1234</w:t></w:r></w:p>`,
	}
	for _, c := range cases {
		_, want, okA := decodedPartText([]byte(c))
		got, spans, okB := partSpans([]byte(c), nil)
		if okA != okB {
			t.Errorf("%q: ok mismatch, decodedPartText=%v partSpans=%v", c, okA, okB)
			continue
		}
		if got != want {
			t.Errorf("%q: runText differs\n got %q\nwant %q", c, got, want)
		}
		// Spans must tile runText exactly, in order, with no gaps or overlaps.
		at := 0
		for i, s := range spans {
			if s.runStart != at {
				t.Errorf("%q: span %d starts at %d, want %d — spans must tile runText with no gap",
					c, i, s.runStart, at)
			}
			if s.runEnd <= s.runStart {
				t.Errorf("%q: span %d is empty or inverted (%d..%d)", c, i, s.runStart, s.runEnd)
			}
			at = s.runEnd
		}
		if at != len(got) {
			t.Errorf("%q: spans cover %d bytes of a %d-byte runText", c, at, len(got))
		}
	}
}

// TestSpanRangeAndOverlap pins the offset arithmetic directly, because a fencepost here is a corrupted
// document rather than a failed assertion.
func TestSpanRangeAndOverlap(t *testing.T) {
	// runText "abcdefghi", three tokens of three.
	spans := []charSpan{
		{runStart: 0, runEnd: 3, srcStart: 10, srcEnd: 13},
		{runStart: 3, runEnd: 6, srcStart: 20, srcEnd: 23},
		{runStart: 6, runEnd: 9, srcStart: 30, srcEnd: 33},
	}
	for _, c := range []struct{ a, b, wantFirst, wantLast int }{
		{0, 3, 0, 0},   // exactly the first token
		{2, 4, 0, 1},   // straddles the first boundary
		{3, 6, 1, 1},   // exactly the middle
		{2, 7, 0, 2},   // spans all three
		{0, 9, 0, 2},   // the whole text
		{9, 9, -1, -1}, // empty at the end
	} {
		f, l := spanRange(spans, c.a, c.b)
		if f != c.wantFirst || l != c.wantLast {
			t.Errorf("spanRange(%d,%d) = (%d,%d), want (%d,%d)", c.a, c.b, f, l, c.wantFirst, c.wantLast)
		}
	}
	if lo, hi := overlap(spans[1], 2, 7); lo != 3 || hi != 6 {
		t.Errorf("overlap = (%d,%d), want (3,6)", lo, hi)
	}
	if lo, hi := overlap(spans[0], 5, 7); lo != hi {
		t.Errorf("overlap with a disjoint range must be empty, got (%d,%d)", lo, hi)
	}
}

// TestApplyEditsGoesRightToLeft is why an earlier edit cannot invalidate a later one's offsets.
func TestApplyEditsGoesRightToLeft(t *testing.T) {
	src := []byte("0123456789")
	// Two edits of DIFFERENT lengths, deliberately: equal-length splices would pass even if the order
	// were wrong, which is how an ordering bug survives its own test.
	got := string(applyEdits(src, []spanEdit{
		{srcStart: 2, srcEnd: 4, with: []byte("LONGER")},
		{srcStart: 6, srcEnd: 8, with: []byte("X")},
	}))
	if want := "01LONGER45X89"; got != want {
		t.Errorf("applyEdits = %q, want %q — a length change moved a later edit's offsets", got, want)
	}
}

// buildPkgRaw builds a minimal .docx whose word/document.xml body is exactly the given markup.
//
// Separate from buildPkg because that helper wraps its argument in <w:p><w:r><w:t>...</w:t></w:r></w:p>,
// and these tests need control of the run structure itself.
func buildPkgRaw(t *testing.T, body string) []byte {
	t.Helper()
	const ns = `xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"`
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name, data string) {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate})
		if err != nil {
			t.Fatalf("creating %s: %v", name, err)
		}
		if _, err := w.Write([]byte(data)); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	add("[Content_Types].xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`+
		`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">`+
		`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>`+
		`<Default Extension="xml" ContentType="application/xml"/>`+
		`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>`+
		`</Types>`)
	add("_rels/.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`+
		`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">`+
		`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>`+
		`</Relationships>`)
	add("word/document.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document `+ns+
		`><w:body>`+body+`</w:body></w:document>`)
	if err := zw.Close(); err != nil {
		t.Fatalf("closing zip: %v", err)
	}
	return buf.Bytes()
}

// readZipPart returns one part of a zip as a string.
func readZipPart(t *testing.T, path, part string) string {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatalf("opening %s: %v", path, err)
	}
	defer func() { _ = zr.Close() }()
	for _, f := range zr.File {
		if f.Name != part {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("opening %s in %s: %v", part, path, err)
		}
		data, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatalf("reading %s: %v", part, err)
		}
		return string(data)
	}
	t.Fatalf("%s not found in %s", part, path)
	return ""
}

// TestTheRewriteViewExcludesNonRewritableFamilies pins the filter that stops the rewrite reaching text
// nothing may rewrite.
//
// docProps' vt:blob holds base64. A replacement inside it produces invalid base64, so this repo refuses a
// value found there instead of rewriting it. Without the filter the locate fallback claimed such a part
// and the file was WRITTEN where it must be REFUSED.
func TestTheRewriteViewExcludesNonRewritableFamilies(t *testing.T) {
	const blob = `<Properties xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">` +
		`<property name="Blobbed"><vt:blob>SSN ` + spanSSN + ` payload</vt:blob></property></Properties>`

	or := NewOfficeRedactor(nil, nil)

	// Unfiltered: the value IS visible, which is what a residue view needs in order to refuse over it.
	unfiltered, _, ok := partSpans([]byte(blob), nil)
	if !ok {
		t.Fatal("partSpans refused a well-formed part")
	}
	if !strings.Contains(unfiltered, spanSSN) {
		t.Errorf("the unfiltered view cannot see a value in a vt:blob, so a residue check built on it "+
			"could not refuse over one: %q", unfiltered)
	}

	// Filtered for rewriting: it must NOT be visible, or the rewrite would corrupt the base64.
	filtered, _, ok := partSpans([]byte(blob), or.rewritableText(DocumentTypeDOCX))
	if !ok {
		t.Fatal("partSpans refused a well-formed part under the filter")
	}
	if strings.Contains(filtered, spanSSN) {
		t.Errorf("the REWRITE view can see a value inside a vt:blob (%q). Rewriting there produces "+
			"invalid base64, and the repo's contract is to refuse instead — this is what "+
			"TestResidueRefusalNamesTypesNotValues asserts end to end.", filtered)
	}
}

// TestTwoSplitValuesSharingATokenAreBothRedacted covers a token touched by MORE THAN ONE occurrence.
//
// The middle token here holds the tail of one value and the head of the next, so two sub-edits land in it
// and their order matters: applied left-to-right, the first one's length change moves the second.
func TestTwoSplitValuesSharingATokenAreBothRedacted(t *testing.T) {
	const a, b = "456-78-1234", "321-54-9876"
	dir := t.TempDir()
	// runText: "SSN: 456-78" + "-1234 and 321-54" + "-9876"
	in := spanDocx(t, dir, "two.docx",
		`<w:p><w:r><w:t>SSN: 456-78</w:t></w:r>`+
			`<w:r><w:t xml:space="preserve">-1234 and 321-54</w:t></w:r>`+
			`<w:r><w:t>-9876</w:t></w:r></w:p>`)

	got := redactSpanDocx(t, in, a, b)

	for _, frag := range []string{"456-78", "321-54", "-1234", "-9876"} {
		if strings.Contains(got, frag) && !strings.Contains(got, "***") {
			t.Errorf("fragment %q survives:\n%s", frag, got)
		}
	}
	if strings.Contains(got, a) || strings.Contains(got, b) {
		t.Errorf("a value survives intact:\n%s", got)
	}
	// The word BETWEEN the two values, in the shared token, must survive: two sub-edits applied in the
	// wrong order corrupt exactly this text.
	if !strings.Contains(got, "and") {
		t.Errorf("the text between the two values was destroyed, which is what happens when sub-edits "+
			"inside one token are applied left-to-right:\n%s", got)
	}
	for _, mask := range []string{"***-**-1234", "***-**-9876"} {
		if n := strings.Count(got, mask); n != 1 {
			t.Errorf("mask %q appears %d times, want 1:\n%s", mask, n, got)
		}
	}
}

// TestOverlappingValuesDoNotBothRewrite is the precedence half.
//
// Two reported values can overlap in the run text -- a longer value and a substring of it both get
// reported often enough. Letting both rewrite the same region produces nonsense, so the first (longest,
// since the caller sorts that way) wins and the other is skipped.
func TestOverlappingValuesDoNotBothRewrite(t *testing.T) {
	dir := t.TempDir()
	// The long value spans the run boundary; the short one is a substring of it, also spanning it.
	in := spanDocx(t, dir, "ovl.docx",
		`<w:p><w:r><w:t>ID 456-78</w:t></w:r><w:r><w:t>-1234-XY</w:t></w:r></w:p>`)

	// Longest first, which is the order applyPendingRedactions produces.
	got := redactSpanDocx(t, in, "456-78-1234-XY", "456-78-1234")

	if strings.Contains(got, "456-78") {
		t.Errorf("the value survives:\n%s", got)
	}
	// One rewrite, not two stacked on the same bytes. A doubly-applied replacement shows up as a mask
	// inside a mask or as leftover fragments of the first replacement.
	if n := strings.Count(got, "***"); n == 0 {
		t.Errorf("no mask at all:\n%s", got)
	}
	if strings.Count(got, "ID ") != 1 {
		t.Errorf("the surrounding text was disturbed by a second overlapping rewrite:\n%s", got)
	}
	if !xmlIsWellFormed(got) {
		t.Errorf("the rewritten part is not well-formed XML, which is what stacking two overlapping "+
			"rewrites on the same bytes produces:\n%s", got)
	}

	// EXACT, because the failure mode is a garbled mask rather than a surviving value, and no
	// "is it absent" assertion can see that. Measured with the guard removed:
	//
	//	correct   ID ***-**-1234-XY
	//	unguarded ID ***-**-1234-1234-XY      <- "-1234" written twice
	//
	// Both are well-formed, both lack the original value, and both contain a mask, so only the exact
	// string distinguishes them.
	const wantBody = `<w:body><w:p><w:r><w:t>ID ***-**-1234-XY</w:t></w:r>` +
		`<w:r><w:t></w:t></w:r></w:p></w:body>`
	if !strings.Contains(got, wantBody) {
		t.Errorf("body is not the expected single rewrite.\n got %s\nwant to contain %s", got, wantBody)
	}
}

// xmlIsWellFormed reports whether s parses, which is the floor for any rewrite of a document part.
func xmlIsWellFormed(s string) bool {
	dec := xml.NewDecoder(strings.NewReader(s))
	for {
		_, err := dec.Token()
		if err == io.EOF {
			return true
		}
		if err != nil {
			return false
		}
	}
}

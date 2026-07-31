// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package textextractofficetextlib

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests cover part-name evasion: the document body must be extracted no
// matter what case, or what conventional-but-unexpected name, the producer used
// for the archive member holding it.
//
// The stakes are recall, not cosmetics. Body text that is not extracted is not
// scanned, so it is not reported, so it is not redacted — the value leaves the
// tool in cleartext. Measured before the fix with a prebuilt binary: renaming
// word/document.xml to word/Document.xml took a .docx from 4 findings
// {SSN, VISA, AUTHOR_INFO, LAST_MODIFIED_BY} to 2 (metadata only).

const (
	testSSN  = "449-87-4100"
	testCard = "4532-0151-1283-0366"
)

const xmlDecl = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`

// part is one archive member.
type part struct {
	name string
	body string
}

// writeZip builds a zip at dir/name from parts and returns its path.
func writeZip(t *testing.T, dir, name string, parts []part) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, p := range parts {
		w, err := zw.Create(p.name)
		if err != nil {
			t.Fatalf("zip create %q: %v", p.name, err)
		}
		if _, err := w.Write([]byte(p.body)); err != nil {
			t.Fatalf("zip write %q: %v", p.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write %q: %v", path, err)
	}
	return path
}

func docBody() string {
	return xmlDecl + `<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>` +
		`<w:p><w:r><w:t>Employee SSN ` + testSSN + ` on file.</w:t></w:r></w:p>` +
		`<w:p><w:r><w:t>Card ` + testCard + ` expires soon.</w:t></w:r></w:p>` +
		`</w:body></w:document>`
}

func pkgRels(target string) string {
	return xmlDecl + `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
		`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="` + target + `"/>` +
		`</Relationships>`
}

// docxWith builds a .docx whose main document part is named mainPart, with the
// package relationship pointing at relTarget (mainPart when empty).
func docxWith(t *testing.T, dir, name, mainPart, relTarget string) string {
	t.Helper()
	if relTarget == "" {
		relTarget = mainPart
	}
	return writeZip(t, dir, name, []part{
		{"_rels/.rels", pkgRels(relTarget)},
		{mainPart, docBody()},
	})
}

// assertBodyExtracted fails when either sensitive value is missing from the
// extracted text. Both values are checked because the two live in different
// paragraphs of the same part, so a partial extraction is distinguishable from
// none.
func assertBodyExtracted(t *testing.T, path string) {
	t.Helper()
	got, err := ExtractText(path)
	if err != nil {
		t.Fatalf("ExtractText(%s): %v", filepath.Base(path), err)
	}
	for _, want := range []string{testSSN, testCard} {
		if !strings.Contains(got.Text, want) {
			t.Errorf("%s: extracted text is missing %s, so no validator can see it and "+
				"redaction cannot rewrite it — the value leaves the tool in cleartext.\n"+
				"  extracted %d bytes: %q",
				filepath.Base(path), want, len(got.Text), got.Text)
		}
	}
	if got.ExtractionWarning != "" {
		t.Errorf("%s: unexpected extraction warning %q for a document whose body WAS found",
			filepath.Base(path), got.ExtractionWarning)
	}
}

// TestDocxMainPartNameVariants is the primary non-vacuity test for the docx half.
// Every case here returns zero body text on the pre-fix code.
func TestDocxMainPartNameVariants(t *testing.T) {
	dir := t.TempDir()

	cases := []struct {
		name      string
		mainPart  string
		relTarget string
	}{
		// The conventional name — the only one that worked before.
		{"conventional", "word/document.xml", ""},
		// One capital letter. This is the measured 3-findings-to-2 case.
		{"capitalized_basename", "word/Document.xml", ""},
		// Whole path uppercased, as some producers and archivers emit.
		{"all_caps", "WORD/DOCUMENT.XML", ""},
		// Capitalized directory only.
		{"capitalized_dir", "Word/document.xml", ""},
		// A name that is not a case variant at all: found only by following the
		// package relationship, which is what the format actually specifies.
		{"unconventional_name", "word/main.xml", ""},
		{"arbitrary_name", "word/body-content.xml", ""},
		// A relationship target given package-absolute, and one that has to be
		// resolved relative to the owning part's directory.
		{"absolute_rel_target", "word/document2.xml", "/word/document2.xml"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := docxWith(t, dir, tc.name+".docx", tc.mainPart, tc.relTarget)
			assertBodyExtracted(t, path)
		})
	}
}

// TestDocxTwoMainPartsBothExtracted pins the union rule. A package that names one
// main document through its relationship while ALSO carrying a conventionally-named
// part must have both scanned: selecting only the relationship target would newly
// drop content that the old name-matching code did find, turning a recall fix into
// a recall regression.
func TestDocxTwoMainPartsBothExtracted(t *testing.T) {
	dir := t.TempDir()
	decoy := xmlDecl + `<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` +
		`<w:body><w:p><w:r><w:t>Card ` + testCard + ` expires soon.</w:t></w:r></w:p></w:body></w:document>`
	unreferenced := xmlDecl + `<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` +
		`<w:body><w:p><w:r><w:t>Employee SSN ` + testSSN + ` on file.</w:t></w:r></w:p></w:body></w:document>`

	path := writeZip(t, dir, "two_parts.docx", []part{
		{"_rels/.rels", pkgRels("word/elsewhere.xml")},
		{"word/elsewhere.xml", decoy},
		{"word/document.xml", unreferenced},
	})

	got, err := ExtractText(path)
	if err != nil {
		t.Fatalf("ExtractText: %v", err)
	}
	if !strings.Contains(got.Text, testCard) {
		t.Errorf("relationship-named part was not extracted; missing %s from %q", testCard, got.Text)
	}
	if !strings.Contains(got.Text, testSSN) {
		t.Errorf("conventionally-named part was not extracted; missing %s. Selecting ONLY the "+
			"relationship target would drop bytes the old code did scan.\n  got %q", testSSN, got.Text)
	}
}

// TestDocxDuplicateCaseVariantsExtractOnce guards against the union double-counting
// a single part reached by two routes.
func TestDocxDuplicateCaseVariantsExtractOnce(t *testing.T) {
	dir := t.TempDir()
	// The relationship and the conventional-name fallback both resolve to this one
	// part, so its text must appear exactly once.
	path := docxWith(t, dir, "once.docx", "word/document.xml", "")

	got, err := ExtractText(path)
	if err != nil {
		t.Fatalf("ExtractText: %v", err)
	}
	if n := strings.Count(got.Text, testSSN); n != 1 {
		t.Errorf("SSN appears %d times, want 1: the same part was extracted twice, which "+
			"would double-report every finding in it.\n  got %q", n, got.Text)
	}
}

// --- xlsx -------------------------------------------------------------------

func xlsxParts(sheetPart, sharedPart string) []part {
	shared := xmlDecl + `<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="2" uniqueCount="2">` +
		`<si><t>Employee SSN ` + testSSN + `</t></si>` +
		`<si><t>Card ` + testCard + `</t></si></sst>`
	sheet := xmlDecl + `<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>` +
		`<row r="1"><c r="A1" t="s"><v>0</v></c></row>` +
		`<row r="2"><c r="A2" t="s"><v>1</v></c></row>` +
		`</sheetData></worksheet>`
	workbook := xmlDecl + `<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" ` +
		`xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">` +
		`<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>`
	wbRels := xmlDecl + `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
		`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="/` + sheetPart + `"/>` +
		`<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="/` + sharedPart + `"/>` +
		`</Relationships>`
	return []part{
		{"_rels/.rels", pkgRels("xl/workbook.xml")},
		{"xl/workbook.xml", workbook},
		{"xl/_rels/workbook.xml.rels", wbRels},
		{sharedPart, shared},
		{sheetPart, sheet},
	}
}

// TestXlsxPartNameVariants covers the spreadsheet half. Cell text lives in the
// shared-strings table, so a missed sharedStrings part empties every sheet even
// when the sheet part itself is found — two distinct ways to lose the whole body.
func TestXlsxPartNameVariants(t *testing.T) {
	dir := t.TempDir()

	cases := []struct {
		name       string
		sheetPart  string
		sharedPart string
	}{
		{"conventional", "xl/worksheets/sheet1.xml", "xl/sharedStrings.xml"},
		{"capitalized_sheet", "xl/worksheets/Sheet1.xml", "xl/sharedStrings.xml"},
		{"capitalized_sheet_dir", "xl/Worksheets/sheet1.xml", "xl/sharedStrings.xml"},
		{"lowercased_sharedstrings", "xl/worksheets/sheet1.xml", "xl/sharedstrings.xml"},
		{"capitalized_sharedstrings", "xl/worksheets/sheet1.xml", "xl/SharedStrings.xml"},
		{"both_capitalized", "xl/Worksheets/Sheet1.xml", "xl/SharedStrings.xml"},
		{"unconventional_sheet", "xl/data/grid1.xml", "xl/strings.xml"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeZip(t, dir, tc.name+".xlsx", xlsxParts(tc.sheetPart, tc.sharedPart))
			assertBodyExtracted(t, path)
		})
	}
}

// TestXlsxSheetLabelDropsDirectory pins the emitted section label. The label is
// derived from the part name and written into the same text stream the content
// router re-parses, so leaving a capitalized directory in it ("Worksheets/sheet1"
// instead of "sheet1") changes what downstream sees.
func TestXlsxSheetLabelDropsDirectory(t *testing.T) {
	dir := t.TempDir()
	path := writeZip(t, dir, "label.xlsx", xlsxParts("xl/Worksheets/sheet1.xml", "xl/sharedStrings.xml"))

	got, err := ExtractText(path)
	if err != nil {
		t.Fatalf("ExtractText: %v", err)
	}
	if !strings.Contains(got.Text, "--- sheet1 ---") {
		t.Errorf("expected the section label %q; a case-sensitive prefix trim left the "+
			"directory in it.\n  got %q", "--- sheet1 ---", got.Text)
	}
}

// --- pptx -------------------------------------------------------------------

func pptxParts(slidePart string) []part {
	slide := xmlDecl + `<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" ` +
		`xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><p:cSld><p:spTree><p:sp><p:txBody>` +
		`<a:p><a:r><a:t>Employee SSN ` + testSSN + ` on file.</a:t></a:r></a:p>` +
		`<a:p><a:r><a:t>Card ` + testCard + ` expires soon.</a:t></a:r></a:p>` +
		`</p:txBody></p:sp></p:spTree></p:cSld></p:sld>`
	pres := xmlDecl + `<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" ` +
		`xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">` +
		`<p:sldIdLst><p:sldId id="256" r:id="rId1"/></p:sldIdLst></p:presentation>`
	presRels := xmlDecl + `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
		`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="/` + slidePart + `"/>` +
		`</Relationships>`
	return []part{
		{"_rels/.rels", pkgRels("ppt/presentation.xml")},
		{"ppt/presentation.xml", pres},
		{"ppt/_rels/presentation.xml.rels", presRels},
		{slidePart, slide},
	}
}

// TestPptxPartNameVariants covers the presentation half.
func TestPptxPartNameVariants(t *testing.T) {
	dir := t.TempDir()

	cases := []struct{ name, slidePart string }{
		{"conventional", "ppt/slides/slide1.xml"},
		{"capitalized_slide", "ppt/slides/Slide1.xml"},
		{"capitalized_slide_dir", "ppt/Slides/slide1.xml"},
		{"all_caps", "PPT/SLIDES/SLIDE1.XML"},
		{"unconventional_slide", "ppt/pages/page1.xml"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeZip(t, dir, tc.name+".pptx", pptxParts(tc.slidePart))
			assertBodyExtracted(t, path)
		})
	}
}

// TestPptxNotesResolvedThroughRels keeps the notes-attachment behavior that the
// relationship refactor inherited: notes come from the slide's own .rels, and the
// rels part is found regardless of case.
func TestPptxNotesResolvedThroughRels(t *testing.T) {
	dir := t.TempDir()
	notes := xmlDecl + `<p:notes xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" ` +
		`xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><p:cSld><p:spTree><p:sp><p:txBody>` +
		`<a:p><a:r><a:t>Speaker note SSN 529-11-2233</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:notes>`
	slideRels := xmlDecl + `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
		`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/notesSlide" Target="../NotesSlides/notesSlide1.xml"/>` +
		`</Relationships>`

	parts := append(pptxParts("ppt/slides/slide1.xml"),
		part{"ppt/slides/_Rels/slide1.xml.rels", slideRels},
		part{"ppt/NotesSlides/notesSlide1.xml", notes},
	)
	path := writeZip(t, dir, "notes.pptx", parts)

	got, err := ExtractText(path)
	if err != nil {
		t.Fatalf("ExtractText: %v", err)
	}
	if !strings.Contains(got.Text, "529-11-2233") {
		t.Errorf("speaker-note text was not extracted; the slide's .rels was not resolved.\n  got %q", got.Text)
	}
}

// --- empty extraction -------------------------------------------------------

// TestEmptyExtractionIsReported pins the visibility half of the fix. A container
// with no recognizable body part must say so, because "extracted nothing" and
// "the document is empty" were previously the same observable outcome: Success,
// textLen 0, exit 0.
func TestEmptyExtractionIsReported(t *testing.T) {
	dir := t.TempDir()

	// An .xlsx carrying only a workbook with no sheet part at all.
	workbook := xmlDecl + `<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets/></workbook>`
	path := writeZip(t, dir, "nobody.xlsx", []part{
		{"_rels/.rels", pkgRels("xl/workbook.xml")},
		{"xl/workbook.xml", workbook},
	})

	got, err := ExtractText(path)
	if err != nil {
		t.Fatalf("ExtractText: %v", err)
	}
	if got.Text != "" {
		t.Fatalf("expected no extracted text, got %q", got.Text)
	}
	if got.BodyParts != 0 {
		t.Errorf("BodyParts = %d, want 0", got.BodyParts)
	}
	if got.ExtractionWarning == "" {
		t.Fatal("a container with no document body part produced no ExtractionWarning, so a " +
			"file whose body was skipped is indistinguishable from a genuinely empty one and " +
			"the scan reports it clean")
	}
	if !strings.Contains(got.ExtractionWarning, "NOT scanned") {
		t.Errorf("warning does not say the content went unscanned: %q", got.ExtractionWarning)
	}
}

// TestEmptyDocumentIsAlsoReported covers the other zero-text shape: the body part
// EXISTS and is genuinely empty. It still warns — a scan that examined no text is
// worth surfacing either way — but the reason distinguishes the two, so an
// operator can tell a naming problem from an empty file.
func TestEmptyDocumentIsAlsoReported(t *testing.T) {
	dir := t.TempDir()
	empty := xmlDecl + `<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body/></w:document>`
	path := writeZip(t, dir, "empty.docx", []part{
		{"_rels/.rels", pkgRels("word/document.xml")},
		{"word/document.xml", empty},
	})

	got, err := ExtractText(path)
	if err != nil {
		t.Fatalf("ExtractText: %v", err)
	}
	if got.BodyParts != 1 {
		t.Errorf("BodyParts = %d, want 1 (the part exists, it is just empty)", got.BodyParts)
	}
	if got.ExtractionWarning == "" {
		t.Fatal("an empty document produced no warning")
	}
	if strings.Contains(got.ExtractionWarning, "no document body part was found") {
		t.Errorf("an EXISTING but empty body part was reported as a missing part, which "+
			"points the operator at the wrong problem: %q", got.ExtractionWarning)
	}
}

// TestNonEmptyExtractionHasNoWarning is the false-positive guard: an ordinary
// document must not carry a warning, or the signal is noise and gets ignored.
func TestNonEmptyExtractionHasNoWarning(t *testing.T) {
	dir := t.TempDir()
	path := docxWith(t, dir, "normal.docx", "word/document.xml", "")

	got, err := ExtractText(path)
	if err != nil {
		t.Fatalf("ExtractText: %v", err)
	}
	if got.ExtractionWarning != "" {
		t.Errorf("ordinary document carries a warning: %q", got.ExtractionWarning)
	}
}

// --- relationship-target resolution ----------------------------------------

// TestResolveTarget pins the relative-target rules, including the "../" form real
// slide rels use and the package-absolute form.
func TestResolveTarget(t *testing.T) {
	cases := []struct{ owner, target, want string }{
		{"", "word/document.xml", "word/document.xml"},
		{"", "/word/document.xml", "word/document.xml"},
		{"xl/workbook.xml", "worksheets/sheet1.xml", "xl/worksheets/sheet1.xml"},
		{"xl/workbook.xml", "/xl/worksheets/sheet1.xml", "xl/worksheets/sheet1.xml"},
		{"ppt/slides/slide1.xml", "../notesSlides/notesSlide1.xml", "ppt/notesSlides/notesSlide1.xml"},
		{"ppt/slides/slide1.xml", "slide2.xml", "ppt/slides/slide2.xml"},
		{"word/document.xml", "", ""},
	}
	for _, tc := range cases {
		if got := resolveTarget(tc.owner, tc.target); got != tc.want {
			t.Errorf("resolveTarget(%q, %q) = %q, want %q", tc.owner, tc.target, got, tc.want)
		}
	}
}

// TestRelsPartFor pins where a part's relationships live.
func TestRelsPartFor(t *testing.T) {
	cases := []struct{ owner, want string }{
		{"", "_rels/.rels"},
		{"xl/workbook.xml", "xl/_rels/workbook.xml.rels"},
		{"ppt/slides/slide1.xml", "ppt/slides/_rels/slide1.xml.rels"},
		{"word/document.xml", "word/_rels/document.xml.rels"},
	}
	for _, tc := range cases {
		if got := relsPartFor(tc.owner); got != tc.want {
			t.Errorf("relsPartFor(%q) = %q, want %q", tc.owner, got, tc.want)
		}
	}
}

// TestExternalRelationshipTargetIgnored keeps an external target (a URL) from
// being treated as a package part.
func TestExternalRelationshipTargetIgnored(t *testing.T) {
	dir := t.TempDir()
	rels := xmlDecl + `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
		`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" ` +
		`Target="https://example.com/document.xml" TargetMode="External"/>` +
		`</Relationships>`
	path := writeZip(t, dir, "external.docx", []part{
		{"_rels/.rels", rels},
		{"word/document.xml", docBody()},
	})

	// The conventional-name fallback still finds the real body.
	assertBodyExtracted(t, path)
}

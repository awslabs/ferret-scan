// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package office

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	textextractofficetextlib "github.com/awslabs/ferret-scan/v2/internal/preprocessors/text-extractors/text-extract-officetextlib"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// #914 at the sink: a value the scanner reads ACROSS a node boundary -- a slide's next paragraph, a
// sheet's next cell, an OpenDocument spreadsheet's next cell -- was reported, then left in the copy, and
// the copy was written at exit 0 with nothing said. Measured on main @ 2fb4719 with these fixtures: every
// spanning value below survived under both strategies and RedactDocument returned success.
//
// The matches are the ones the scanner reports for these fixtures (the CLI, --confidence all), so the test
// exercises the shapes the validators really produce. The fixtures use only the public API and the
// scanner's own reader, so this file also runs, and fails, against the parent commit.

// spanFixture is one container whose text the scanner reads across a node boundary.
type spanFixture struct {
	name    string
	ext     string
	parts   [][2]string // written in order; "mimetype" is stored, as ODF requires
	matches []detector.Match
	// spanning are the reported values held whole by no single node of the input.
	spanning []string
}

const (
	boundaryFirst = "Mary"
	boundaryLast  = "Johnson"
	boundarySSN   = "234-56-0001"
)

func spanPPTX() spanFixture {
	para := func(runs ...string) string {
		var b strings.Builder
		b.WriteString("<a:p>")
		for _, r := range runs {
			b.WriteString(`<a:r><a:rPr lang="en-US"/><a:t>` + r + `</a:t></a:r>`)
		}
		b.WriteString("</a:p>")
		return b.String()
	}
	slide := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" ` +
		`xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:cSld><p:spTree><p:sp><p:txBody>` +
		para("Contact:") + para(boundaryFirst+" "+boundaryLast) + para("English Language Arts &amp; Assessment") +
		para("Employee SSN: "+boundarySSN) +
		`</p:txBody></p:sp></p:spTree></p:cSld></p:sld>`
	name := boundaryFirst + " " + boundaryLast + " English" // the paragraph join reads as a third name token
	return spanFixture{
		name: "pptx paragraphs",
		ext:  ".pptx",
		parts: [][2]string{
			{"[Content_Types].xml", `<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
				`<Default Extension="xml" ContentType="application/xml"/></Types>`},
			{"ppt/slides/slide1.xml", slide},
		},
		matches: []detector.Match{
			{Text: name, Type: "PERSON_NAME", Confidence: 100, LineNumber: 2, Validator: "PERSON_NAME"},
			{Text: boundarySSN, Type: "SSN", Confidence: 100, LineNumber: 2, Validator: "ssn"},
		},
		spanning: []string{name},
	}
}

const spanSheetNS = `xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"`

func spanXLSX() spanFixture {
	sst := `<?xml version="1.0" encoding="UTF-8"?><sst ` + spanSheetNS + ` count="4" uniqueCount="4">` +
		`<si><t>Name</t></si><si><t>` + boundaryFirst + `</t></si><si><t>` + boundaryLast + `</t></si><si><t>Phone</t></si></sst>`
	sheet := `<?xml version="1.0" encoding="UTF-8"?><worksheet ` + spanSheetNS + `><sheetData>` +
		`<row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>3</v></c></row>` +
		// Two shared-string cells, then three numeric ones: the scanner reads "Mary\tJohnson\t600\t600\t1250".
		`<row r="2"><c r="A2" t="s"><v>1</v></c><c r="B2" t="s"><v>2</v></c>` +
		`<c r="C2"><v>600</v></c><c r="D2"><v>600</v></c><c r="E2"><v>1250</v></c></row>` +
		// The first name's shared string again, beside a contiguous control value: this cell is not part of
		// any spanning value, so it must still show the name after redaction.
		`<row r="3"><c r="A3" t="s"><v>1</v></c><c r="B3"><v>234560001</v></c></row>` +
		`</sheetData></worksheet>`
	return spanFixture{
		name: "xlsx cells",
		ext:  ".xlsx",
		parts: [][2]string{
			{"[Content_Types].xml", `<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
				`<Default Extension="xml" ContentType="application/xml"/></Types>`},
			{"xl/sharedStrings.xml", sst},
			{"xl/worksheets/sheet1.xml", sheet},
		},
		matches: []detector.Match{
			{Text: boundaryFirst + "\t" + boundaryLast, Type: "PERSON_NAME", Confidence: 90, LineNumber: 4, Validator: "PERSON_NAME"},
			{Text: "600\t600\t1250", Type: "PHONE", Confidence: 85, LineNumber: 4, Validator: "phone"},
			{Text: "234560001", Type: "SSN", Confidence: 80, LineNumber: 5, Validator: "ssn"},
		},
		spanning: []string{boundaryFirst + "\t" + boundaryLast, "600\t600\t1250"},
	}
}

const spanODFNS = `xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" ` +
	`xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" ` +
	`xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"`

func spanODS() spanFixture {
	cell := func(s string) string {
		return `<table:table-cell office:value-type="string"><text:p>` + s + `</text:p></table:table-cell>`
	}
	content := `<?xml version="1.0" encoding="UTF-8"?><office:document-content ` + spanODFNS + `>` +
		`<office:body><office:spreadsheet><table:table table:name="Sheet1">` +
		`<table:table-row>` + cell("Contact") + cell(boundaryFirst) + cell(boundaryLast) + `</table:table-row>` +
		`<table:table-row>` + cell("SSN "+boundarySSN) + `</table:table-row>` +
		`</table:table></office:spreadsheet></office:body></office:document-content>`
	name := "Contact " + boundaryFirst + " " + boundaryLast
	return spanFixture{
		name: "ods cells",
		ext:  ".ods",
		parts: [][2]string{
			{"mimetype", "application/vnd.oasis.opendocument.spreadsheet"},
			{"content.xml", content},
		},
		matches: []detector.Match{
			{Text: name, Type: "PERSON_NAME", Confidence: 80, LineNumber: 1, Validator: "PERSON_NAME"},
			{Text: boundarySSN, Type: "SSN", Confidence: 100, LineNumber: 1, Validator: "ssn"},
		},
		spanning: []string{name},
	}
}

// spanDOCXTab is the disclosure case: Word's reader turns <w:tab/> into a tab between two runs, and no
// boundary view models Word, so the value cannot be placed and the copy must be refused, not written.
func spanDOCXTab() spanFixture {
	doc := `<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>` +
		`<w:p><w:r><w:t>Holder: ` + boundaryFirst + `</w:t></w:r><w:r><w:tab/></w:r><w:r><w:t>` + boundaryLast + `</w:t></w:r></w:p>` +
		`<w:p><w:r><w:t>SSN ` + boundarySSN + `</w:t></w:r></w:p></w:body></w:document>`
	name := boundaryFirst + "\t" + boundaryLast
	return spanFixture{
		name: "docx tab",
		ext:  ".docx",
		parts: [][2]string{
			{"[Content_Types].xml", `<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
				`<Default Extension="xml" ContentType="application/xml"/>` +
				`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`},
			{"word/document.xml", doc},
		},
		matches: []detector.Match{
			{Text: name, Type: "PERSON_NAME", Confidence: 90, LineNumber: 1, Validator: "PERSON_NAME"},
			{Text: boundarySSN, Type: "SSN", Confidence: 100, LineNumber: 2, Validator: "ssn"},
		},
		spanning: []string{name},
	}
}

// write builds the fixture in memory and writes it where RedactDocument, which takes a path, can read it.
func (f spanFixture) write(t *testing.T) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, p := range f.parts {
		method := zip.Deflate
		if p[0] == "mimetype" {
			method = zip.Store
		}
		w, err := zw.CreateHeader(&zip.FileHeader{Name: p[0], Method: method})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(w, p[1]); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "span"+f.ext)
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// scannerReads is the text the scanner's Office reader extracts from path: what a re-scan would see.
func scannerReads(t *testing.T, path string) string {
	t.Helper()
	tc, err := textextractofficetextlib.ExtractText(path)
	if err != nil {
		t.Fatalf("the scanner's reader cannot read %s: %v", filepath.Base(path), err)
	}
	return tc.Text
}

// zipPart returns one member of a zip file.
func zipPart(t *testing.T, path, name string) string {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name != name {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		defer rc.Close()
		b, err := io.ReadAll(rc)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	t.Fatalf("%s has no part %s", filepath.Base(path), name)
	return ""
}

// assertFixtureSpans is the non-vacuity check: the scanner reads each spanning value, and no part holds
// it whole, so only a rewrite across nodes can remove it.
func assertFixtureSpans(t *testing.T, f spanFixture, in string) {
	t.Helper()
	read := scannerReads(t, in)
	for _, v := range f.spanning {
		if !strings.Contains(read, v) {
			t.Fatalf("the scanner does not read %q out of the fixture, so it tests nothing: %q", v, read)
		}
		for _, p := range f.parts {
			if strings.Contains(p[1], v) {
				t.Fatalf("part %s holds %q whole; the fixture must split it across nodes", p[0], v)
			}
		}
	}
}

func TestValueReadAcrossANodeBoundaryIsRedacted(t *testing.T) {
	for _, f := range []spanFixture{spanPPTX(), spanXLSX(), spanODS()} {
		for _, st := range []redactors.RedactionStrategy{redactors.RedactionSimple, redactors.RedactionFormatPreserving} {
			t.Run(f.name+"/"+st.String(), func(t *testing.T) {
				in := f.write(t)
				assertFixtureSpans(t, f, in)

				out := filepath.Join(t.TempDir(), "out"+f.ext)
				if _, err := NewOfficeRedactor(nil, nil).RedactDocument(in, out, f.matches, st); err != nil {
					t.Fatalf("RedactDocument refused a value the boundary views can place: %v", err)
				}
				read := scannerReads(t, out)
				for _, m := range f.matches {
					if strings.Contains(read, m.Text) {
						t.Errorf("%s %q is still in the copy the scanner reads: a re-scan reports it again", m.Type, m.Text)
					}
				}
			})
		}
	}
}

// TestAValueNoViewCanPlaceRefusesTheCopy is the disclosure half, which must hold even where nothing can
// rewrite the value: the copy is refused with a cause the CLI classifies as "reported value not found in
// the writable bytes", so it lands in stats.files_not_redacted, the not-redacted warning prints, and
// --fail-on-incomplete fails. On the parent commit the copy was written.
func TestAValueNoViewCanPlaceRefusesTheCopy(t *testing.T) {
	f := spanDOCXTab()
	for _, st := range []redactors.RedactionStrategy{redactors.RedactionSimple, redactors.RedactionFormatPreserving} {
		t.Run(st.String(), func(t *testing.T) {
			in := f.write(t)
			assertFixtureSpans(t, f, in)

			out := filepath.Join(t.TempDir(), "out"+f.ext)
			_, err := NewOfficeRedactor(nil, nil).RedactDocument(in, out, f.matches, st)
			if err == nil {
				t.Fatalf("RedactDocument wrote a copy the scanner still reads %q out of", f.spanning[0])
			}
			msg := err.Error()
			if !strings.Contains(msg, "could not locate") || !strings.Contains(msg, "PERSON_NAME") {
				t.Errorf("the refusal must say the value could not be located and name its type: %v", err)
			}
			for _, m := range f.matches {
				if strings.Contains(msg, m.Text) {
					t.Errorf("the refusal reprints a reported value: %v", err)
				}
			}
			if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
				t.Errorf("a refused copy was left on disk at %s", out)
			}
		})
	}
}

// TestFormatPreservingCutsTheMaskAtNodeBoundaries pins how a same-length mask is placed: each node gets
// its own slice, so a cell keeps a cell's width and a node whose slice keeps its bytes is not touched.
func TestFormatPreservingCutsTheMaskAtNodeBoundaries(t *testing.T) {
	f := spanXLSX()
	in := f.write(t)
	out := filepath.Join(t.TempDir(), "out.xlsx")
	if _, err := NewOfficeRedactor(nil, nil).RedactDocument(in, out, f.matches, redactors.RedactionFormatPreserving); err != nil {
		t.Fatal(err)
	}
	sheet := zipPart(t, out, "xl/worksheets/sheet1.xml")
	// "600\t600\t1250" masks to "***\t***\t1250": the phone mask keeps the last four digits.
	for _, want := range []string{
		`<c r="C2" t="inlineStr"><is><t xml:space="preserve">***</t></is></c>`,
		`<c r="D2" t="inlineStr"><is><t xml:space="preserve">***</t></is></c>`,
		`<c r="E2"><v>1250</v></c>`,
		`<c r="A2" t="inlineStr"><is><t xml:space="preserve">****</t></is></c>`,
		`<c r="B2" t="inlineStr"><is><t xml:space="preserve">*******</t></is></c>`,
	} {
		if !strings.Contains(sheet, want) {
			t.Errorf("worksheet lacks %s:\n%s", want, sheet)
		}
	}

	p := spanPPTX()
	in = p.write(t)
	out = filepath.Join(t.TempDir(), "out.pptx")
	if _, err := NewOfficeRedactor(nil, nil).RedactDocument(in, out, p.matches, redactors.RedactionFormatPreserving); err != nil {
		t.Fatal(err)
	}
	slide := zipPart(t, out, "ppt/slides/slide1.xml")
	for _, want := range []string{"<a:t>************</a:t>", "<a:t>******* Language Arts &amp; Assessment</a:t>"} {
		if !strings.Contains(slide, want) {
			t.Errorf("slide lacks %s:\n%s", want, slide)
		}
	}
}

// TestSimplePutsTheTokenInTheFirstNode pins the simple strategy's placement: the token whole in the first
// node, the rest of the value removed from the others, and the markup between them left alone.
func TestSimplePutsTheTokenInTheFirstNode(t *testing.T) {
	p := spanPPTX()
	in := p.write(t)
	out := filepath.Join(t.TempDir(), "out.pptx")
	if _, err := NewOfficeRedactor(nil, nil).RedactDocument(in, out, p.matches, redactors.RedactionSimple); err != nil {
		t.Fatal(err)
	}
	slide := zipPart(t, out, "ppt/slides/slide1.xml")
	want := `<a:t>[PERSON-NAME-REDACTED]</a:t></a:r></a:p><a:p><a:r><a:rPr lang="en-US"/><a:t> Language Arts &amp; Assessment</a:t>`
	if !strings.Contains(slide, want) {
		t.Errorf("slide lacks %s:\n%s", want, slide)
	}
}

// TestASharedStringIsNotRewrittenForAFragment: a shared string is shown by every cell that indexes it,
// and here only one of the two cells showing the first name is part of the spanning value. The covered
// cells become inline strings; the table and the other cell are untouched.
func TestASharedStringIsNotRewrittenForAFragment(t *testing.T) {
	f := spanXLSX()
	in := f.write(t)
	out := filepath.Join(t.TempDir(), "out.xlsx")
	if _, err := NewOfficeRedactor(nil, nil).RedactDocument(in, out, f.matches, redactors.RedactionSimple); err != nil {
		t.Fatal(err)
	}
	if got, want := zipPart(t, out, "xl/sharedStrings.xml"), f.parts[1][1]; got != want {
		t.Errorf("the shared-string table changed:\n got %s\nwant %s", got, want)
	}
	sheet := zipPart(t, out, "xl/worksheets/sheet1.xml")
	for _, want := range []string{
		`<c r="A2" t="inlineStr"><is><t xml:space="preserve">[PERSON-NAME-REDACTED]</t></is></c>`,
		`<c r="B2" t="inlineStr"><is><t xml:space="preserve"></t></is></c>`,
		`<c r="C2" t="inlineStr"><is><t xml:space="preserve">[PHONE-REDACTED]</t></is></c>`,
		`<c r="A3" t="s"><v>1</v></c>`,
	} {
		if !strings.Contains(sheet, want) {
			t.Errorf("worksheet lacks %s:\n%s", want, sheet)
		}
	}
	if read := scannerReads(t, out); !strings.Contains(read, boundaryFirst+"\t[SSN-REDACTED]") {
		t.Errorf("row 3 should still read the first name beside the masked SSN: %q", read)
	}
}

// TestAUnitOnlyTheBoundaryPassPlacedIsAudited: "600\t600\t1250" is found by no other route, so before
// this pass it had no audit entry at all; now it has one that says how it was placed.
func TestAUnitOnlyTheBoundaryPassPlacedIsAudited(t *testing.T) {
	f := spanXLSX()
	in := f.write(t)
	out := filepath.Join(t.TempDir(), "out.xlsx")
	res, err := NewOfficeRedactor(nil, nil).RedactDocument(in, out, f.matches, redactors.RedactionSimple)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range res.RedactionMap {
		if m.DataType != "PHONE" {
			continue
		}
		found = true
		if got := m.Metadata["position_method"]; got != "boundary_joined_text" {
			t.Errorf("position_method = %v, want boundary_joined_text", got)
		}
		if m.RedactedText != "[PHONE-REDACTED]" {
			t.Errorf("RedactedText = %q, want the replacement written", m.RedactedText)
		}
		if m.Position.StartChar != -1 {
			t.Errorf("StartChar = %d; a value with no contiguous position must not claim one", m.Position.StartChar)
		}
	}
	if !found {
		t.Errorf("no audit entry for the PHONE value the copy no longer holds: %+v", res.RedactionMap)
	}
}

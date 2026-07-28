// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package textextractofficetextlib

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
)

// zipEntry builds an in-memory zip containing a single named entry and returns
// the *zip.File handle for it. The xlsx extraction helpers take a *zip.File
// directly, so tests can exercise them without writing to disk — which also
// avoids the extractor's on-disk path guard rejecting temp directories.
func zipEntry(t *testing.T, name, body string) *zip.File {
	t.Helper()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(name)
	if err != nil {
		t.Fatalf("zip create: %v", err)
	}
	if _, err := w.Write([]byte(body)); err != nil {
		t.Fatalf("zip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("zip open: %v", err)
	}
	if len(zr.File) != 1 {
		t.Fatalf("expected 1 zip entry, got %d", len(zr.File))
	}
	return zr.File[0]
}

// TestExtractSharedStrings_MultilineEntriesKeepTheirIndex is the regression test
// for the positional-index shift.
//
// The shared-string table is referenced by *ordinal*: a cell says <v>7</v>,
// meaning "the eighth <si>". So an <si> the extractor fails to match is not one
// lost string — it renumbers the whole table from that point on, and every later
// cell renders some other cell's text. That is worse than a gap: a spreadsheet
// scan reports values against the wrong rows.
//
// The trigger is mundane. A cell containing a line break (an answer list, an
// address block) has literal newlines inside its <si>, and a non-(?s) `.*?`
// cannot cross them. Measured on a real 15 KB workbook: 12 of 123 entries
// skipped, first divergence at index 89.
func TestExtractSharedStrings_MultilineEntriesKeepTheirIndex(t *testing.T) {
	// Index 1 is deliberately multi-line, so a non-(?s) pattern drops it and
	// shifts indices 2 and 3 down by one.
	sst := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><si><t>first</t></si>` +
		"<si><t>answer one\nanswer two\nanswer three</t></si>" +
		`<si><t>Payment card 4532015112830366</t></si><si><t>last</t></si></sst>`

	got := extractSharedStringsSimple(zipEntry(t, "xl/sharedStrings.xml", sst))

	if len(got) != 4 {
		t.Fatalf("expected 4 shared strings, got %d: %q", len(got), got)
	}

	want := []string{
		"first",
		"answer one\nanswer two\nanswer three",
		"Payment card 4532015112830366",
		"last",
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("shared string %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

// TestExtractWorksheet_SelfClosingCellDoesNotSwallowNeighbour covers the second
// extraction defect: `<c[^>]*>` matched a self-closing `<c r="A2"/>` — an empty
// but styled cell, which real spreadsheets are full of (16 of 52 cells in one
// sheet of a real workbook). Having consumed it as an *opening* tag, the old
// `.*?</c>` then ran on to the next cell's closing tag, so the empty cell
// reported its neighbour's value and the neighbour itself was consumed.
//
// Go's RE2 has no lookahead, so "not self-closing" is expressed by requiring the
// last character before `>` to not be `/`.
func TestExtractWorksheet_SelfClosingCellDoesNotSwallowNeighbour(t *testing.T) {
	shared := []string{"alpha", "SSN 536-22-8765", "omega"}

	sheet := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>` +
		`<row r="1"><c r="A1" t="s"><v>0</v></c></row>` +
		`<row r="2"><c r="A2" s="3"/><c r="B2" t="s"><v>1</v></c></row>` +
		`<row r="3"><c r="A3" t="s"><v>2</v></c></row>` +
		`</sheetData></worksheet>`

	got := extractWorksheetText(zipEntry(t, "xl/worksheets/sheet1.xml", sheet), shared)

	for _, want := range shared {
		if !strings.Contains(got, want) {
			t.Errorf("extracted text lost %q; got:\n%s", want, got)
		}
	}

	// The empty cell must not have borrowed its neighbour's value: "SSN ..."
	// belongs to B2 and must appear exactly once, not twice.
	if n := strings.Count(got, shared[1]); n != 1 {
		t.Errorf("value %q appears %d times, want exactly 1; got:\n%s", shared[1], n, got)
	}
}

// TestExtractWorksheet_SelfClosingValueDoesNotSwallowNeighbour covers the
// self-closing <v/> variant of the same swallowing bug: a cell with a cached-but-
// empty formula result writes <v/>, and the old single-pattern `.*?</c>` ran past
// it into the following cell's value. The two-stage match bounds each cell at its
// own </c> first, so an empty <v/> simply yields no text for that cell.
func TestExtractWorksheet_SelfClosingValueDoesNotSwallowNeighbour(t *testing.T) {
	sheet := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>` +
		`<row r="1"><c r="A1" t="s"><v/></c><c r="B1" t="s"><v>0</v></c></row>` +
		`</sheetData></worksheet>`

	got := extractWorksheetText(zipEntry(t, "xl/worksheets/sheet1.xml", sheet), []string{"real value"})

	if !strings.Contains(got, "real value") {
		t.Errorf("cell after self-closing <v/> was lost; got %q", got)
	}
	// The empty <v/> cell must not have resolved the ordinal 0 twice.
	if n := strings.Count(got, "real value"); n != 1 {
		t.Errorf("value appears %d times, want 1; got %q", n, got)
	}
}

// TestExtractWorksheet_AttributedAndInlineText covers two narrower misses that
// hid real values: Excel writes <t xml:space="preserve"> whenever a value has
// leading or trailing whitespace, which a bare `<t>` pattern does not match, and
// inline strings (t="inlineStr", used by whole workbooks that have no
// sharedStrings.xml at all — one of the two real files tested was entirely
// inline) went the same way.
func TestExtractWorksheet_AttributedAndInlineText(t *testing.T) {
	sheet := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>` +
		`<row r="1"><c r="A1" t="inlineStr"><is><t xml:space="preserve">Inline phone 415-555-0199 </t></is></c></row>` +
		`<row r="2"><c r="A2" t="str"><t xml:space="preserve"> trailing space value </t></c></row>` +
		`</sheetData></worksheet>`

	got := extractWorksheetText(zipEntry(t, "xl/worksheets/sheet1.xml", sheet), nil)

	for _, want := range []string{"Inline phone 415-555-0199", "trailing space value"} {
		if !strings.Contains(got, want) {
			t.Errorf("extracted text lost %q; got:\n%s", want, got)
		}
	}
}

// TestExtractWorksheet_MultilineInlineString pins (?s) on the row and cell
// patterns themselves, not just on the shared-string table: a multi-line inline
// string means literal newlines inside <row> and <c>, so a non-(?s) pattern
// fails to match the row at all and the entire row disappears.
func TestExtractWorksheet_MultilineInlineString(t *testing.T) {
	sheet := "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n" +
		`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>` +
		"<row r=\"1\"><c r=\"A1\" t=\"inlineStr\"><is><t>line one\nSSN 536-22-8765\nline three</t></is></c></row>" +
		`</sheetData></worksheet>`

	got := extractWorksheetText(zipEntry(t, "xl/worksheets/sheet1.xml", sheet), nil)

	if !strings.Contains(got, "536-22-8765") {
		t.Errorf("multi-line inline string lost its content; got:\n%s", got)
	}
}

// TestDecodeXMLEntities_AmpersandExpandedLast guards the ordering trap in entity
// decoding. If `&amp;` is expanded before `&lt;`, then the encoded *literal*
// `&amp;lt;` becomes `&lt;` and then `<` — inventing markup the document never
// contained. Expanding `&amp;` last keeps a literal literal.
func TestDecodeXMLEntities_AmpersandExpandedLast(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"no entities passes through", "plain text", "plain text"},
		{"basic entities", "a &lt;b&gt; c &quot;d&quot; e &apos;f&apos;", `a <b> c "d" e 'f'`},
		{"bare ampersand", "Smith &amp; Sons", "Smith & Sons"},
		{"encoded literal stays literal", "&amp;lt;notatag&amp;gt;", "&lt;notatag&gt;"},
		{"decimal numeric refs", "&#65;&#66;&#67;", "ABC"},
		{"hex numeric refs", "&#x41;&#x42;", "AB"},
		{"malformed ref left as written", "&#;", "&#;"},
		{"out-of-range ref left as written", "&#x110000;", "&#x110000;"},
		{"surrogate ref left as written", "&#xD800;", "&#xD800;"},
		{"numeric ref for ampersand is not re-expanded", "&#38;lt;", "&lt;"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := decodeXMLEntities(tc.in); got != tc.want {
				t.Errorf("decodeXMLEntities(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestExtractWorksheet_SharedStringIndexOutOfRange asserts the extractor stays
// quiet on malformed input rather than panicking: an index past the end of the
// table (a truncated or mismatched sharedStrings.xml) must yield no text for
// that cell while leaving valid neighbours intact.
func TestExtractWorksheet_SharedStringIndexOutOfRange(t *testing.T) {
	sheet := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>` +
		`<row r="1"><c r="A1" t="s"><v>99</v></c><c r="B1" t="s"><v>0</v></c><c r="C1" t="s"><v>-3</v></c></row>` +
		`</sheetData></worksheet>`

	got := extractWorksheetText(zipEntry(t, "xl/worksheets/sheet1.xml", sheet), []string{"only entry"})

	if !strings.Contains(got, "only entry") {
		t.Errorf("valid shared-string reference lost; got %q", got)
	}
	if strings.Contains(got, "99") || strings.Contains(got, "-3") {
		t.Errorf("out-of-range index leaked its raw ordinal into the text: %q", got)
	}
}

// TestExtractWorksheet_NumericCellsAreNotSharedStrings checks the cell-type
// discrimination: a numeric cell has no t="s", so its <v> is the value itself
// and must never be dereferenced through the shared-string table.
func TestExtractWorksheet_NumericCellsAreNotSharedStrings(t *testing.T) {
	sheet := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>` +
		`<row r="1"><c r="A1"><v>4532015112830366</v></c><c r="B1" t="n"><v>42</v></c></row>` +
		`</sheetData></worksheet>`

	got := extractWorksheetText(zipEntry(t, "xl/worksheets/sheet1.xml", sheet), []string{"decoy", "another decoy"})

	for _, want := range []string{"4532015112830366", "42"} {
		if !strings.Contains(got, want) {
			t.Errorf("numeric cell value %q lost; got %q", want, got)
		}
	}
	if strings.Contains(got, "decoy") {
		t.Errorf("numeric cell was wrongly dereferenced through the shared-string table: %q", got)
	}
}

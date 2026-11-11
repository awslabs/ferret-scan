// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package office

import (
	"reflect"
	"strings"
	"testing"
)

// The pieces of #914's fix, each pinned alone. The sink tests are in boundary_span_e2e_test.go.

func TestSurvivingValuesNamesEveryValuePresent(t *testing.T) {
	text := "Contact: Mary Johnson English Language\tArts 600\t600\t1250"
	values := []string{"600\t600\t1250", "absent value", "Mary Johnson English", "Language\tArts"}
	if got, want := survivingValues(text, values), []int{0, 2, 3}; !reflect.DeepEqual(got, want) {
		t.Errorf("survivingValues = %v, want %v", got, want)
	}
	if got := survivingValues(text, []string{"absent value", "also absent"}); got != nil {
		t.Errorf("survivingValues = %v for values that are not there, want nil", got)
	}
	if got := survivingValues("", values); got != nil {
		t.Errorf("survivingValues = %v over no text, want nil", got)
	}
}

// TestSurvivingValuesPrefersTheLongerOverlap: where two values overlap, the marker pass names the longer,
// the precedence every rewrite here uses. The shorter is named on the next look, once the longer is gone.
func TestSurvivingValuesPrefersTheLongerOverlap(t *testing.T) {
	values := []string{"Johnson Eng", "Mary Johnson"}
	if got, want := survivingValues("Mary Johnson English", values), []int{1}; !reflect.DeepEqual(got, want) {
		t.Errorf("survivingValues = %v, want %v (the longer value at the overlap)", got, want)
	}
	if got, want := survivingValues("[X] English Johnson English", values), []int{0}; !reflect.DeepEqual(got, want) {
		t.Errorf("survivingValues = %v, want %v once the longer value is gone", got, want)
	}
}

// TestSurvivingValuesDoesNotTrustMarkersInTextHoldingNUL: the markers are NUL-delimited, so text that
// already holds a NUL (the scanner reads bytes with a regex, not a parser) must not be parsed for them.
func TestSurvivingValuesDoesNotTrustMarkersInTextHoldingNUL(t *testing.T) {
	text := "head\x001\x00 Mary Johnson tail"
	values := []string{"Mary Johnson", "never present"}
	if got, want := survivingValues(text, values), []int{0}; !reflect.DeepEqual(got, want) {
		t.Errorf("survivingValues = %v, want %v: a forged marker named a value that is not there", got, want)
	}
}

// TestCollapsedViewSplitsATokenAtADroppedSpace: the scanner folds a run of spaces to one after joining a
// slide's runs, so the view does too, and the spans keep pointing at the right bytes of each token.
func TestCollapsedViewSplitsATokenAtADroppedSpace(t *testing.T) {
	v := &boundaryView{collapse: true}
	v.addText(0, "Mary ")
	v.addSeparator(' ')
	v.addText(1, "  Johnson  x")
	v.addSeparator(' ')
	if got, want := v.sb.String(), "Mary Johnson x "; got != want {
		t.Fatalf("view = %q, want %q", got, want)
	}
	want := []boundarySpan{
		{at: 0, end: 5, tok: 0, dec: 0},  // "Mary "
		{at: 5, end: 13, tok: 1, dec: 2}, // "Johnson " after the two leading spaces dropped
		{at: 13, end: 14, tok: 1, dec: 11},
	}
	if !reflect.DeepEqual(v.spans, want) {
		t.Errorf("spans = %+v, want %+v", v.spans, want)
	}
	for _, s := range v.spans {
		token := []string{"Mary ", "  Johnson  x"}[s.tok]
		if got := token[s.dec : s.dec+(s.end-s.at)]; got != v.sb.String()[s.at:s.end] {
			t.Errorf("span %+v maps to %q in its token, but the view holds %q", s, got, v.sb.String()[s.at:s.end])
		}
	}
}

func TestWithCellTypeSetsOrAddsTheAttribute(t *testing.T) {
	for _, tc := range []struct{ tag, typ, want string }{
		{`<c r="A1" t="s">`, "inlineStr", `<c r="A1" t="inlineStr">`},
		{`<c r="A1" s="3">`, "inlineStr", `<c r="A1" s="3" t="inlineStr">`},
		{`<c r="A1" t='n' s="3">`, "str", `<c r="A1" t="str" s="3">`},
		// A prefixed attribute is not the cell's type and must be left alone.
		{`<c r="A1" x:t="s">`, "inlineStr", `<c r="A1" x:t="s" t="inlineStr">`},
	} {
		if got := string(withCellType([]byte(tc.tag), tc.typ)); got != tc.want {
			t.Errorf("withCellType(%s, %s) = %s, want %s", tc.tag, tc.typ, got, tc.want)
		}
	}
}

// TestSharedStringsAreCountedAsTheScannerCountsThem: shared strings are indexed by POSITION, so an entry
// the scanner's pattern skips (a self-closing or attributed <si>) must be skipped here too, or every
// index after it would resolve to its neighbour.
func TestSharedStringsAreCountedAsTheScannerCountsThem(t *testing.T) {
	sst := `<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">` +
		`<si><t>A</t></si><si/><si><r><t>B</t></r><r><t xml:space="preserve">C</t></r></si>` +
		`<si foo="1"><t>skipped</t></si><si><t>D</t><rPh><t>phonetic</t></rPh></si></sst>`
	got, ok := xlsxSharedStrings([]byte(sst))
	if !ok {
		t.Fatal("xlsxSharedStrings refused a well-formed table")
	}
	if want := []string{"A", "BC", "Dphonetic"}; !reflect.DeepEqual(got, want) {
		t.Errorf("xlsxSharedStrings = %q, want %q", got, want)
	}

	// And the reader agrees: cells indexing 0, 1 and 2 read the same three strings.
	f := spanFixture{ext: ".xlsx", parts: [][2]string{
		{"xl/sharedStrings.xml", sst},
		{"xl/worksheets/sheet1.xml", `<worksheet ` + spanSheetNS + `><sheetData><row r="1">` +
			`<c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c><c r="C1" t="s"><v>2</v></c></row></sheetData></worksheet>`},
	}}
	if read := scannerReads(t, f.write(t)); !strings.Contains(read, "A\tBC\tDphonetic\t\n") {
		t.Errorf("the scanner reads the cells as %q; the model above no longer matches it", read)
	}
}

// TestBoundaryViewsReadWhatTheScannerReads pins the model to the reader it models: for each fixture,
// every view's text is a piece of what the scanner's reader extracts from the same package.
func TestBoundaryViewsReadWhatTheScannerReads(t *testing.T) {
	for _, f := range []struct {
		fx      spanFixture
		docType OfficeDocumentType
	}{
		{spanPPTX(), DocumentTypePPTX},
		{spanXLSX(), DocumentTypeXLSX},
		{spanODS(), DocumentTypeODF},
	} {
		t.Run(f.fx.name, func(t *testing.T) {
			read := scannerReads(t, f.fx.write(t))
			files := make(map[string][]byte, len(f.fx.parts))
			names := make([]string, 0, len(f.fx.parts))
			for _, p := range f.fx.parts {
				files[p[0]] = []byte(p[1])
				names = append(names, p[0])
			}
			views, toks := boundaryViews(files, names, f.docType)
			if len(views) == 0 || len(toks) == 0 {
				t.Fatalf("no boundary view for %s", f.fx.name)
			}
			for _, v := range views {
				text := strings.TrimRight(v.sb.String(), " \t\n")
				if !strings.Contains(read, text) {
					t.Errorf("the view reads %q, which is not in what the scanner reads:\n%q", text, read)
				}
				for _, s := range v.spans {
					tk := toks[s.tok]
					if got := tk.decoded[s.dec : s.dec+(s.end-s.at)]; got != v.sb.String()[s.at:s.end] {
						t.Errorf("span %+v reads %q from its token, the view holds %q", s, got, v.sb.String()[s.at:s.end])
					}
				}
			}
		})
	}
}

// TestADOCXHasNoBoundaryView: Word is deliberately not modelled (its reader joins runs inside a paragraph
// with nothing, which #627's run-joined rewrite covers), so a value across its other joins is refused.
func TestADOCXHasNoBoundaryView(t *testing.T) {
	f := spanDOCXTab()
	files := map[string][]byte{}
	var names []string
	for _, p := range f.parts {
		files[p[0]] = []byte(p[1])
		names = append(names, p[0])
	}
	if views, toks := boundaryViews(files, names, DocumentTypeDOCX); len(views) != 0 || len(toks) != 0 {
		t.Errorf("a DOCX produced %d views and %d tokens; the refusal is its only path", len(views), len(toks))
	}
}

// TestAFormulaCellKeepsItsFormula: a covered cell with an <f> keeps the formula and takes the new text as
// a string result (t="str"); the shared formula it may anchor stays intact for the cells that use it.
func TestAFormulaCellKeepsItsFormula(t *testing.T) {
	sheet := `<worksheet ` + spanSheetNS + `><sheetData><row r="1">` +
		`<c r="A1"><v>600</v></c><c r="B1" s="2"><f t="shared" ref="B1:B4" si="0">A1+0</f><v>600</v></c>` +
		`</row></sheetData></worksheet>`
	contents := &OfficeZipContents{Files: map[string][]byte{"xl/worksheets/sheet1.xml": []byte(sheet)}}
	contents.Order = []string{"xl/worksheets/sheet1.xml"}
	got := rewriteAcrossBoundaries(contents, DocumentTypeXLSX, []string{"600\t600"}, map[string]string{"600\t600": "[PHONE-REDACTED]"}, false)
	if len(got["600\t600"]) != 1 {
		t.Fatalf("rewriteAcrossBoundaries placed nothing: %v", got)
	}
	out := string(contents.Files["xl/worksheets/sheet1.xml"])
	for _, want := range []string{
		`<c r="A1" t="inlineStr"><is><t xml:space="preserve">[PHONE-REDACTED]</t></is></c>`,
		`<c r="B1" s="2" t="str"><f t="shared" ref="B1:B4" si="0">A1+0</f><v></v></c>`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("worksheet lacks %s:\n%s", want, out)
		}
	}
}

// TestASliceThatWouldCutACharacterFallsBackToTheFirstNode: a same-length replacement is cut at the node
// boundaries only when every piece is still text; otherwise the whole replacement goes to the first node.
func TestASliceThatWouldCutACharacterFallsBackToTheFirstNode(t *testing.T) {
	slide := `<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" ` +
		`xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><a:p><a:r><a:t>ab</a:t></a:r></a:p>` +
		`<a:p><a:r><a:t>cd</a:t></a:r></a:p></p:sld>`
	contents := &OfficeZipContents{Files: map[string][]byte{"ppt/slides/slide1.xml": []byte(slide)}}
	contents.Order = []string{"ppt/slides/slide1.xml"}
	with := "x\u00e9yz" // five bytes, like "ab cd", with a two-byte character across the first cut
	if len(with) != len("ab cd") {
		t.Fatalf("fixture: %q is %d bytes, want %d", with, len(with), len("ab cd"))
	}
	rewriteAcrossBoundaries(contents, DocumentTypePPTX, []string{"ab cd"}, map[string]string{"ab cd": with}, true)
	out := string(contents.Files["ppt/slides/slide1.xml"])
	if !strings.Contains(out, "<a:t>"+with+"</a:t>") || !strings.Contains(out, "<a:t></a:t>") {
		t.Errorf("the replacement was not given whole to the first node:\n%s", out)
	}
}

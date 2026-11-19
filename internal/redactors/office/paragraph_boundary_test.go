// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package office

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// A paragraph is a boundary the scanner's validators respect (#914 box 3): the reader ends a slide's
// DrawingML paragraph (a:p) and an OpenDocument paragraph (text:p) of a text or a presentation with a
// newline, so a name at the end of one paragraph and a capitalised word at the start of the next are not
// one PERSON_NAME. Runs of one paragraph and the cells of a spreadsheet stay joined.

// spanPPTXSpaced is a slide whose paragraphs carry the edge cases of the reader's whitespace handling:
// spaces at both ends of a run, an empty paragraph, a paragraph with no run at all.
func spanPPTXSpaced() spanFixture {
	f := spanPPTX()
	run := func(s string) string { return `<a:r><a:t>` + s + `</a:t></a:r>` }
	slide := `<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" ` +
		`xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:cSld><p:spTree><p:sp><p:txBody>` +
		`<a:p>` + run("  Mary  ") + run(" Johnson ") + `</a:p>` +
		`<a:p><a:endParaRPr lang="en-US"/></a:p>` +
		`<a:p>` + run("") + `</a:p>` +
		`<a:p>` + run("   English   Language") + `</a:p>` +
		`<a:p>` + run("Last") + `</a:p>` +
		`</p:txBody></p:sp></p:spTree></p:cSld></p:sld>`
	f.name = "pptx spaced paragraphs"
	f.parts = [][2]string{f.parts[0], {"ppt/slides/slide1.xml", slide}}
	return f
}

func spanODT() spanFixture {
	content := `<?xml version="1.0" encoding="UTF-8"?><office:document-content ` + spanODFNS + `><office:body><office:text>` +
		`<text:p>  Mary  </text:p><text:p></text:p><text:p>Johnson<text:span> x </text:span>y </text:p>` +
		`<text:p>   English</text:p>` +
		`<table:table><table:table-row><table:table-cell><text:p>Cell one </text:p></table:table-cell>` +
		`<table:table-cell><text:p> Cell two</text:p></table:table-cell></table:table-row></table:table>` +
		`</office:text></office:body></office:document-content>`
	return spanFixture{
		name: "odt paragraphs",
		ext:  ".odt",
		parts: [][2]string{
			{"mimetype", "application/vnd.oasis.opendocument.text"},
			{"content.xml", content},
		},
	}
}

// TestParagraphViewsReadWhatTheScannerReads pins the model to the reader for the whitespace the reader
// drops around a paragraph's newline: every view's text is a piece of what the reader extracts.
func TestParagraphViewsReadWhatTheScannerReads(t *testing.T) {
	for _, f := range []struct {
		fx      spanFixture
		docType OfficeDocumentType
	}{
		{spanPPTXSpaced(), DocumentTypePPTX},
		{spanODT(), DocumentTypeODF},
	} {
		t.Run(f.fx.name, func(t *testing.T) {
			read := scannerReads(t, f.fx.write(t))
			files := make(map[string][]byte)
			var names []string
			for _, p := range f.fx.parts {
				files[p[0]] = []byte(p[1])
				names = append(names, p[0])
			}
			views, toks := boundaryViews(files, names, f.docType, "x"+f.fx.ext)
			if len(views) != 1 {
				t.Fatalf("%d views, want 1", len(views))
			}
			v := views[0]
			text := strings.TrimRight(v.sb.String(), " \t\n")
			if !strings.Contains(read, text) {
				t.Errorf("the view reads %q, which is not in what the scanner reads:\n%q", text, read)
			}
			if strings.Contains(text, "\n\n") || strings.Contains(text, " \n") || strings.Contains(text, "\n ") {
				t.Errorf("the view keeps whitespace the reader drops around a newline: %q", text)
			}
			if !strings.Contains(text, "\n") {
				t.Errorf("the view has no paragraph boundary: %q", text)
			}
			for _, s := range v.spans {
				if got := toks[s.tok].decoded[s.dec : s.dec+(s.end-s.at)]; got != v.sb.String()[s.at:s.end] {
					t.Errorf("span %+v reads %q from its token, the view holds %q", s, got, v.sb.String()[s.at:s.end])
				}
			}
		})
	}
}

// TestASpreadsheetsCellsStayJoinedByASpace: the reader joins an .ods's cells with a space and does not
// end them with a newline, so a value across two cells is still one the views place (option A of #914
// leaves cells alone).
func TestASpreadsheetsCellsStayJoinedByASpace(t *testing.T) {
	f := spanODS()
	files := map[string][]byte{}
	var names []string
	for _, p := range f.parts {
		files[p[0]] = []byte(p[1])
		names = append(names, p[0])
	}
	views, _ := boundaryViews(files, names, DocumentTypeODF, "x.ods")
	if len(views) != 1 || strings.Contains(views[0].sb.String(), "\n") {
		t.Fatalf("an .ods view holds a newline between cells: %q", views[0].sb.String())
	}
	if !strings.Contains(scannerReads(t, f.write(t)), "Mary Johnson") {
		t.Fatal("the reader no longer joins an .ods's cells with a space")
	}
}

// TestRedactingANameLeavesTheNextParagraphAlone is the over-redaction half of #914: a name in its own
// paragraph is rewritten, and the heading below it, which the validators used to read as part of the name,
// is not touched. Both strategies.
func TestRedactingANameLeavesTheNextParagraphAlone(t *testing.T) {
	f := spanPPTX()
	f.matches = []detector.Match{
		{Text: boundaryFirst + " " + boundaryLast, Type: "PERSON_NAME", Confidence: 100, LineNumber: 2, Validator: "PERSON_NAME"},
	}
	for _, st := range []redactors.RedactionStrategy{redactors.RedactionSimple, redactors.RedactionFormatPreserving} {
		t.Run(st.String(), func(t *testing.T) {
			in := f.write(t)
			if read := scannerReads(t, in); strings.Contains(read, boundaryLast+" English") {
				t.Fatalf("the scanner reads a name across the paragraph boundary: %q", read)
			}
			out := filepath.Join(t.TempDir(), "out.pptx")
			if _, err := NewOfficeRedactor(nil, nil).RedactDocument(in, out, f.matches, st); err != nil {
				t.Fatal(err)
			}
			slide := zipPart(t, out, "ppt/slides/slide1.xml")
			if !strings.Contains(slide, "<a:t>English Language Arts &amp; Assessment</a:t>") {
				t.Errorf("the paragraph after the name was changed:\n%s", slide)
			}
			if read := scannerReads(t, out); strings.Contains(read, boundaryFirst+" "+boundaryLast) {
				t.Errorf("the name is still in the copy: %q", read)
			}
		})
	}
}

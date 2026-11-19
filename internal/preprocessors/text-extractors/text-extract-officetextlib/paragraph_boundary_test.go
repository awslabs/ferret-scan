// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package textextractofficetextlib

import (
	"archive/zip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A paragraph is a boundary the validators respect (#914 box 3, option A): a DrawingML paragraph (a:p)
// and an OpenDocument paragraph (text:p) of a text or a presentation end with a newline, so a name that
// closes one paragraph and a capitalised word that opens the next are not one PERSON_NAME. Runs of one
// paragraph stay joined with a space, and so do an .ods's cells.

func writeODF(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	w, err := zw.Create("content.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

const odfNS = `xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" ` +
	`xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" ` +
	`xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"`

func TestPptxParagraphsAreEndedWithANewlineAndRunsAreJoined(t *testing.T) {
	run := func(s string) string { return `<a:r><a:t>` + s + `</a:t></a:r>` }
	slide := `<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" ` +
		`xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:cSld><p:spTree>` +
		// a table: <a:tbl>, <a:tc> and <a:tailEnd/> are not runs and must not swallow what follows them
		`<a:tbl><a:tr><a:tc><a:txBody><a:p>` + run("Cell") + `</a:p></a:txBody></a:tc></a:tr></a:tbl>` +
		`<a:p>` + run("Mary ") + run("Johnson") + `</a:p>` +
		`<a:p><a:endParaRPr lang="en-US"/></a:p><a:p>` + run("") + `</a:p>` +
		`<a:p><a:ln><a:tailEnd/></a:ln>` + run("English Language") + `</a:p>` +
		`</p:spTree></p:cSld></p:sld>`
	p := writePptx(t, t.TempDir(), []pptxPart{{"ppt/slides/slide1.xml", slide}})
	tc, err := ExtractText(p)
	if err != nil {
		t.Fatal(err)
	}
	want := "--- Slide 1 ---\nCell\nMary Johnson\nEnglish Language\n"
	if !strings.HasPrefix(tc.Text, want) {
		t.Errorf("slide text = %q, want it to start with %q", tc.Text, want)
	}
	if strings.Contains(tc.Text, "Johnson English") {
		t.Errorf("a name at the end of one paragraph and a word at the start of the next are joined: %q", tc.Text)
	}
}

func TestOdtAndOdpParagraphsAreEndedWithANewline(t *testing.T) {
	content := `<office:document-content ` + odfNS + `><office:body><office:text>` +
		`<text:p>Mary Johnson</text:p><text:p>English <text:span>Language</text:span></text:p>` +
		`<table:table><table:table-row><table:table-cell><text:p>Cell one</text:p></table:table-cell>` +
		`<table:table-cell><text:p>Cell two</text:p></table:table-cell></table:table-row></table:table>` +
		`</office:text></office:body></office:document-content>`
	for _, ext := range []string{".odt", ".odp", ".ott"} {
		t.Run(ext, func(t *testing.T) {
			tc, err := ExtractText(writeODF(t, "doc"+ext, content))
			if err != nil {
				t.Fatal(err)
			}
			if want := "Mary Johnson\nEnglish Language\nCell one\nCell two\n"; !strings.HasPrefix(tc.Text, want) {
				t.Errorf("text = %q, want it to start with %q", tc.Text, want)
			}
		})
	}
}

func TestOdsCellsStayJoinedByASpace(t *testing.T) {
	cell := func(s string) string {
		return `<table:table-cell office:value-type="string"><text:p>` + s + `</text:p></table:table-cell>`
	}
	content := `<office:document-content ` + odfNS + `><office:body><office:spreadsheet><table:table><table:table-row>` +
		cell("Mary") + cell("Johnson") + `</table:table-row></table:table></office:spreadsheet></office:body></office:document-content>`
	for _, ext := range []string{".ods", ".ots"} {
		tc, err := ExtractText(writeODF(t, "sheet"+ext, content))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(tc.Text, "Mary Johnson") || strings.Contains(tc.Text, "\n") {
			t.Errorf("%s: cells = %q, want them joined with a space and no newline", ext, tc.Text)
		}
	}
}

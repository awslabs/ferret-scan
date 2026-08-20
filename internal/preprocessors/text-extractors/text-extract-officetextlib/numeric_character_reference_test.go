// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package textextractofficetextlib

import (
	"strings"
	"testing"
)

// A numeric character reference is a legitimate XML spelling of an ordinary character, and Word
// renders it as that character — so `51&#57;-42-8836` is an SSN on screen and was invisible to
// every validator.
//
// decodeXMLEntities has handled both reference forms since the xlsx path was written, and three
// other paths kept a hand-rolled five-call strings.Replace chain instead. Measured on a .docx
// holding four paragraphs (plain, one decimal reference, every digit a reference, one hex
// reference): the scan reported the plain SSN and NOTHING else — a 75% miss — while a
// byte-identical .xlsx reported all four at HIGH 100. See #371.
//
// These values are the same four the issue measured, so a reader can line the tests up with it.
const (
	ncrPlain  = "449-87-4100"
	ncrDec    = "519-42-8836" // 51&#57;-42-8836
	ncrAllDec = "563-18-7249" // every digit a decimal reference
	ncrHex    = "607-31-9284" // 60&#x37;-31-9284
)

// ncrRawParagraphs is the RAW w:t content: references written as references, which is the whole
// point. A helper that escaped them would produce `&amp;#57;` and test nothing.
var ncrRawParagraphs = []string{
	"Employee SSN: " + ncrPlain,
	"Employee SSN: 51&#57;-42-8836",
	"Employee SSN: &#53;&#54;&#51;-&#49;&#56;-&#55;&#50;&#52;&#57;",
	"Employee SSN: 60&#x37;-31-9284",
}

func wordDocument(paras []string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` +
		`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>`)
	for _, p := range paras {
		b.WriteString(`<w:p><w:r><w:t xml:space="preserve">` + p + `</w:t></w:r></w:p>`)
	}
	b.WriteString(`</w:body></w:document>`)
	return b.String()
}

func assertAllDecoded(t *testing.T, where, text string) {
	t.Helper()
	for _, want := range []string{ncrPlain, ncrDec, ncrAllDec, ncrHex} {
		if !strings.Contains(text, want) {
			t.Errorf("%s: %q is not in the extracted text, so no validator can ever see it.\n"+
				"Only reported findings are redacted, so a value invisible here survives "+
				"--enable-redaction in a file the tool calls clean.\ngot: %q", where, want, text)
		}
	}
	// The references must not survive alongside their decoded form either: text still holding
	// "&#57;" means something decoded a copy rather than the value the validators will scan.
	if strings.Contains(text, "&#57;") || strings.Contains(text, "&#x37;") {
		t.Errorf("%s: an undecoded reference remains in the extracted text: %q", where, text)
	}
}

// TestDocxBodyDecodesNumericCharacterReferences covers extractDocxText — the path the issue
// measured.
func TestDocxBodyDecodesNumericCharacterReferences(t *testing.T) {
	path := writeZip(t, t.TempDir(), "ncr.docx", []part{
		{"[Content_Types].xml", ctypesDocx},
		{"word/document.xml", wordDocument(ncrRawParagraphs)},
	})

	got, err := ExtractText(path)
	if err != nil {
		t.Fatalf("ExtractText: %v", err)
	}
	assertAllDecoded(t, "docx body", got.Text)
}

// TestDocxHeaderAndFooterDecodeNumericCharacterReferences covers extractWordXMLText, the third
// hand-rolled chain. A header is where a document template puts the account or case number it
// stamps on every page, so a miss here is not an exotic case.
func TestDocxHeaderAndFooterDecodeNumericCharacterReferences(t *testing.T) {
	path := writeZip(t, t.TempDir(), "hdr.docx", []part{
		{"[Content_Types].xml", ctypesDocx},
		{"word/document.xml", wordDocument([]string{"Body text with nothing sensitive."})},
		{"word/header1.xml", wordDocument([]string{"Case ref 51&#57;-42-8836"})},
		{"word/footer1.xml", wordDocument([]string{"Account 60&#x37;-31-9284"})},
	})

	got, err := ExtractText(path)
	if err != nil {
		t.Fatalf("ExtractText: %v", err)
	}
	for _, want := range []string{ncrDec, ncrHex} {
		if !strings.Contains(got.Text, want) {
			t.Errorf("%q is not in the extracted header/footer text: %q", want, got.Text)
		}
	}
}

// TestPresentationAndOpenDocumentDecodeNumericCharacterReferences covers extractTextFromXML, the
// second chain — it serves .pptx slides, notes and masters, plus .odt/.ods/.odp.
func TestPresentationAndOpenDocumentDecodeNumericCharacterReferences(t *testing.T) {
	slide := `<?xml version="1.0" encoding="UTF-8"?>` +
		`<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" ` +
		`xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><p:cSld><p:spTree>` +
		`<p:sp><p:txBody><a:p><a:r><a:t>Employee SSN: 51&#57;-42-8836</a:t></a:r></a:p></p:txBody></p:sp>` +
		`</p:spTree></p:cSld></p:sld>`
	pptx := writeZip(t, t.TempDir(), "deck.pptx", []part{
		{"[Content_Types].xml", ctypesPptx},
		{"ppt/presentation.xml", `<?xml version="1.0"?><p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"/>`},
		{"ppt/slides/slide1.xml", slide},
	})

	got, err := ExtractText(pptx)
	if err != nil {
		t.Fatalf("pptx ExtractText: %v", err)
	}
	if !strings.Contains(got.Text, ncrDec) {
		t.Errorf("pptx: %q is not in the extracted slide text: %q", ncrDec, got.Text)
	}

	odtContent := `<?xml version="1.0" encoding="UTF-8"?>` +
		`<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" ` +
		`xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"><office:body><office:text>` +
		`<text:p>Employee SSN: 60&#x37;-31-9284</text:p></office:text></office:body></office:document-content>`
	odt := writeZip(t, t.TempDir(), "notes.odt", []part{
		{"mimetype", "application/vnd.oasis.opendocument.text"},
		{"content.xml", odtContent},
	})

	got, err = ExtractText(odt)
	if err != nil {
		t.Fatalf("odt ExtractText: %v", err)
	}
	if !strings.Contains(got.Text, ncrHex) {
		t.Errorf("odt: %q is not in the extracted text: %q", ncrHex, got.Text)
	}
}

// TestASingleNonOverlappingPassDoesNotReReadItsOwnOutput is the second defect the chains had,
// and the issue's description of it needed correcting.
//
// The chain ran lt, gt, amp, quot, apos in that order, so only the entities AFTER &amp; could be
// re-read: `&amp;quot;` became `"` and `&amp;apos;` became `'`, both wrong — the document says
// the literal text `&quot;`. The issue's own example, `&amp;lt;`, does NOT reproduce, because
// &lt; is replaced before &amp; creates one. Measured both ways before writing this.
//
// It matters beyond tidiness: a value written `&amp;#57;` means the literal five characters
// `&#57;`, and a decoder that re-read its own output would turn it into a digit — inventing a
// number the document does not contain, in the text the validators score.
func TestASingleNonOverlappingPassDoesNotReReadItsOwnOutput(t *testing.T) {
	cases := map[string]string{
		"&amp;lt;":         "&lt;",   // the chain got this one right
		"&amp;gt;":         "&gt;",   // and this one
		"&amp;amp;":        "&amp;",  // and this one
		"&amp;quot;":       "&quot;", // the chain returned `"`
		"&amp;apos;":       "&apos;", // the chain returned `'`
		"&amp;#57;":        "&#57;",  // must stay text, not become "9"
		"&lt;tag&gt;":      "<tag>",  // ordinary decoding still works
		"no entities here": "no entities here",
	}
	for in, want := range cases {
		if got := decodeXMLEntities(in); got != want {
			t.Errorf("decodeXMLEntities(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestAnUnparseableReferenceIsLeftAsWritten is the non-vacuity floor for the decoder's own
// guard: a reference naming no valid code point must reach the validators as the raw text it is,
// not as U+FFFD, which would be unsearchable and unredactable.
func TestAnUnparseableReferenceIsLeftAsWritten(t *testing.T) {
	for _, in := range []string{"&#0;", "&#xD800;", "&#999999999;", "&#x110000;"} {
		if got := decodeXMLEntities(in); got != in {
			t.Errorf("decodeXMLEntities(%q) = %q, want it left as written", in, got)
		}
	}
}

const ctypesDocx = `<?xml version="1.0" encoding="UTF-8"?>` +
	`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
	`<Default Extension="xml" ContentType="application/xml"/>` +
	`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
	`</Types>`

const ctypesPptx = `<?xml version="1.0" encoding="UTF-8"?>` +
	`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
	`<Default Extension="xml" ContentType="application/xml"/>` +
	`<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>` +
	`<Override PartName="/ppt/slides/slide1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>` +
	`</Types>`

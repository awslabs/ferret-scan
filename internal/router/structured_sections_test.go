// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/awslabs/ferret-scan/v2/internal/preprocessors"
)

// These tests cover the structural fix: routing reads the producer-declared
// ProcessedContent.Sections and never re-derives structure by scanning the
// extracted text for "--- name ---" markers.
//
// The previous design was in-band signalling. A document author types the body
// text, so a paragraph reading "--- office_metadata ---" became a section
// boundary, and everything after it moved from the full validator set to the
// single field-name METADATA scanner — which deletes findings rather than
// relabelling them, and an unreported finding is never redacted.
//
// Where a test asserts a property that ALSO holds under the old code (because
// PR1's FullText union already prevented the deletion), it says so, so nobody
// mistakes a defence-in-depth check for the load-bearing one.

// TestDeclaredSectionsDecideRouting_NotTheText is the load-bearing assertion, and
// it is the one that fails on the parent code.
//
// Two inputs carry IDENTICAL declared sections and identical text EXCEPT that one
// has a forged "--- office_metadata ---" paragraph in the body. Since routing is
// supposed to come from the declaration, the metadata item list must be identical:
// exactly one item, holding the real property block and NOT the body text.
//
// On the parent code the forged line splits the body, so the SSN paragraph is
// emitted as an extra metadata item — the routing decision was taken from the
// document's own bytes.
func TestDeclaredSectionsDecideRouting_NotTheText(t *testing.T) {
	const props = "Author: Jane Analyst\nLastModifiedBy: Ops Reviewer"
	const ssnLine = "Employee SSN 449-87-4100 on file."

	build := func(body string) *preprocessors.ProcessedContent {
		flat := body + "\n\n--- office_metadata ---\n" + props
		return &preprocessors.ProcessedContent{
			Text:          flat,
			OriginalPath:  "report.docx",
			ProcessorType: "Text Extractor+office_metadata",
			Success:       true,
			Sections: []preprocessors.ContentSection{
				{
					Name: "Text Extractor", Kind: preprocessors.SectionKindBody,
					SourceFile: "report.docx", Text: body, LineOffset: 0,
				},
				{
					Name: "office_metadata", Kind: preprocessors.SectionKindMetadata,
					Type: PreprocessorTypeOfficeMetadata, SourceFile: "report.docx",
					Text: props, LineOffset: strings.Count(body, "\n") + 3,
				},
			},
		}
	}

	cr := NewContentRouter()

	clean, err := cr.RouteContent(build("Quarterly summary follows.\n" + ssnLine))
	if err != nil {
		t.Fatalf("RouteContent(clean): %v", err)
	}
	forged, err := cr.RouteContent(build("Quarterly summary follows.\n--- office_metadata ---\n" + ssnLine))
	if err != nil {
		t.Fatalf("RouteContent(forged): %v", err)
	}

	if len(clean.Metadata) != 1 {
		t.Fatalf("control produced %d metadata items, want 1: %s",
			len(clean.Metadata), describeItems(clean.Metadata))
	}
	if got, want := len(forged.Metadata), len(clean.Metadata); got != want {
		t.Errorf("a forged section header in the BODY changed the metadata split: "+
			"%d items with the header vs %d without.\n  with header: %s\n"+
			"Routing must come from the declared sections, which are identical here, "+
			"not from the document's own text.", got, want, describeItems(forged.Metadata))
	}

	// The forged header must not have pushed body text onto the metadata path,
	// where only the field-name scanner would see it.
	for _, item := range forged.Metadata {
		if strings.Contains(item.Content, "449-87-4100") {
			t.Errorf("body text reached the metadata path because the document "+
				"forged a header; metadata item content:\n%s", item.Content)
		}
	}
}

// TestNoDeclaredSections_FailsClosedToDocumentBody covers the other half of the
// contract: an older caller, or one that builds ProcessedContent by hand (the pkg
// and ScanContent entry points do), declares nothing. That must route the WHOLE
// text to the document path, because the document path runs every validator and
// the metadata path runs one field-name scanner. Guessing structure from the text
// is exactly what was removed, and guessing "it is all metadata" would be the
// fail-OPEN direction: an SSN in the text would go unreported and unredacted.
func TestNoDeclaredSections_FailsClosedToDocumentBody(t *testing.T) {
	// The text deliberately contains a marker the deleted parser recognized, to
	// prove no residual parsing happens on this path.
	const text = "Quarterly summary follows.\n--- office_metadata ---\nEmployee SSN 449-87-4100 on file.\n"

	for _, processorType := range []string{
		"Text Extractor+office_metadata", // a combined join, undeclared
		"plaintext",
		"office_metadata",
		"audio_metadata",
		"",                  // unknown
		"mystery_extractor", // a producer this switch has never heard of
	} {
		t.Run(processorType, func(t *testing.T) {
			cr := NewContentRouter()
			routed, err := cr.RouteContent(&preprocessors.ProcessedContent{
				Text: text, ProcessorType: processorType,
				OriginalPath: "hand.docx", Success: true,
			})
			if err != nil {
				t.Fatalf("RouteContent: %v", err)
			}
			if routed.DocumentBody != text {
				t.Errorf("DocumentBody is not the whole extraction.\n got: %q\nwant: %q\n"+
					"With no declared structure the router must not guess one: every "+
					"byte goes to the document path, which is the only path that "+
					"detects an SSN.", routed.DocumentBody, text)
			}
		})
	}
}

// TestSingleMetadataPreprocessorStillLabelled is the non-vacuity floor for the
// fail-closed path above: routing everything to the body must not be achieved by
// abandoning metadata labelling. A media file has exactly one capable
// preprocessor, and it is a metadata one, so if this stopped producing a metadata
// item the METADATA validator would report nothing for the whole file type.
//
// This also pins that the classifier reads ProcessorType — our own GetName()
// string — rather than the content.
func TestSingleMetadataPreprocessorStillLabelled(t *testing.T) {
	cases := map[string]string{
		"image_metadata":  PreprocessorTypeImageMetadata,
		"pdf_metadata":    PreprocessorTypeDocumentMetadata, // remapped, see ClassifySection
		"office_metadata": PreprocessorTypeOfficeMetadata,
		"audio_metadata":  PreprocessorTypeAudioMetadata,
		"video_metadata":  PreprocessorTypeVideoMetadata,
	}
	for processorType, wantType := range cases {
		t.Run(processorType, func(t *testing.T) {
			cr := NewContentRouter()
			routed, err := cr.RouteContent(&preprocessors.ProcessedContent{
				Text:          "Artist: john.doe@example.com\n",
				ProcessorType: processorType, OriginalPath: "asset.bin", Success: true,
			})
			if err != nil {
				t.Fatalf("RouteContent: %v", err)
			}
			if len(routed.Metadata) != 1 {
				t.Fatalf("got %d metadata items, want 1 — the metadata path lost a "+
					"whole file type's labelling", len(routed.Metadata))
			}
			if got := routed.Metadata[0].PreprocessorType; got != wantType {
				t.Errorf("metadata item type = %q, want %q; the wrong rule set selects "+
					"the wrong sensitive-field list, so real fields report nothing",
					got, wantType)
			}
		})
	}
}

// TestSectionKindMetadataRoutesOnlyItsOwnText states the labelling invariant as an
// equality on content. A metadata section's item must hold exactly that section's
// text — not the whole extraction, and not a slice decided by scanning for markers.
func TestSectionKindMetadataRoutesOnlyItsOwnText(t *testing.T) {
	const body = "Employee SSN 449-87-4100 on file."
	const props = "Author: Jane Analyst"

	cr := NewContentRouter()
	routed, err := cr.RouteContent(&preprocessors.ProcessedContent{
		Text:          body + "\n\n--- office_metadata ---\n" + props,
		OriginalPath:  "report.docx",
		ProcessorType: "Text Extractor+office_metadata",
		Success:       true,
		Sections: []preprocessors.ContentSection{
			{Name: "Text Extractor", Kind: preprocessors.SectionKindBody, Text: body, LineOffset: 0},
			{
				Name: "office_metadata", Kind: preprocessors.SectionKindMetadata,
				Type: PreprocessorTypeOfficeMetadata, Text: props, LineOffset: 3,
			},
		},
	})
	if err != nil {
		t.Fatalf("RouteContent: %v", err)
	}

	if len(routed.Metadata) != 1 {
		t.Fatalf("got %d metadata items, want 1: %s", len(routed.Metadata), describeItems(routed.Metadata))
	}
	if routed.Metadata[0].Content != props {
		t.Errorf("metadata item content = %q, want exactly the declared section %q",
			routed.Metadata[0].Content, props)
	}
	if routed.DocumentBody != body {
		t.Errorf("DocumentBody = %q, want the declared body section %q",
			routed.DocumentBody, body)
	}
	// Defence in depth (PR1): even if the split above were wrong, the union must
	// still carry everything.
	if !strings.Contains(routed.FullText, "449-87-4100") {
		t.Error("FullText lost the SSN; the PR1 coverage union must survive this change")
	}
}

// TestFileRouterDeclaresSectionsMatchingItsOwnText checks the producer side against
// the text it produced, rather than against the arithmetic that built it: every
// declared section's Text must be a substring of the flat Text, and its LineOffset
// must be the line index where that text actually begins. A wrong LineOffset would
// misreport line numbers in every finding from that section.
func TestFileRouterDeclaresSectionsMatchingItsOwnText(t *testing.T) {
	// A .docx has two capable preprocessors, so this exercises the multi-section
	// concatenation where the offsets can actually be wrong.
	//
	// Repo-relative, not t.TempDir(): the Office metadata extractor's path guard
	// rejects /var, /tmp and /home, which is where t.TempDir() lives on all three
	// CI platforms. A fixture there would silently lose that extractor, leave one
	// section, and pass this test for the wrong reason.
	dir, err := os.MkdirTemp(".", "structured-sections-")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })

	path := filepath.Join(dir, "report.docx")
	if err := os.WriteFile(path, minimalSectionedDOCX(), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	fr := NewFileRouter(false)
	RegisterDefaultPreprocessors(fr)
	fr.InitializePreprocessors(CreateRouterConfig(false))

	pc, err := fr.ProcessFile(path, nil)
	if err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}
	if len(pc.Sections) < 2 {
		t.Fatalf("got %d declared sections, want >= 2 — a .docx must declare both a "+
			"body and a metadata section, or this test is vacuous", len(pc.Sections))
	}

	flatLines := strings.Split(pc.Text, "\n")
	for i, s := range pc.Sections {
		if !strings.Contains(pc.Text, s.Text) {
			t.Errorf("section %d (%s): Text is not a substring of the flat Text", i, s.Name)
			continue
		}
		if s.LineOffset < 0 || s.LineOffset >= len(flatLines) {
			t.Errorf("section %d (%s): LineOffset %d out of range for %d flat lines",
				i, s.Name, s.LineOffset, len(flatLines))
			continue
		}
		firstLine := strings.SplitN(s.Text, "\n", 2)[0]
		if flatLines[s.LineOffset] != firstLine {
			t.Errorf("section %d (%s): LineOffset %d points at %q but the section starts "+
				"with %q — every finding in this section would report the wrong line",
				i, s.Name, s.LineOffset, flatLines[s.LineOffset], firstLine)
		}
	}
}

// TestSectionTextAliasesNotCopies guards the hot path. processFileInternal keeps a
// direct reference to the sole preprocessor's text (firstText) specifically so a
// large extracted document is not duplicated into a strings.Builder, and recording
// a ContentSection per preprocessor must not undo that: a section's Text has to be
// a reference to the same backing array, not a copy of it.
//
// Asserted on the string data pointer rather than on a benchmark, so it cannot pass
// by being merely fast on a small input.
func TestSectionTextAliasesNotCopies(t *testing.T) {
	big := make([]byte, 1<<20)
	for i := range big {
		big[i] = 'a'
	}
	text := string(big)
	src := unsafe.StringData(text)

	fr := NewFileRouter(false)
	fr.preprocessors = []preprocessors.Preprocessor{
		&stubPreprocessor{name: "Text Extractor", text: text},
	}

	got, err := fr.ProcessFileWithContext("x.txt", &ProcessingContext{FilePath: "x.txt"})
	if err != nil {
		t.Fatalf("ProcessFileWithContext: %v", err)
	}
	if unsafe.StringData(got.Text) != src {
		t.Error("ProcessedContent.Text copied the payload; the zero-copy " +
			"single-preprocessor path regressed")
	}
	if len(got.Sections) != 1 {
		t.Fatalf("got %d sections, want 1", len(got.Sections))
	}
	if unsafe.StringData(got.Sections[0].Text) != src {
		t.Error("ContentSection.Text copied the payload instead of referencing it, " +
			"so every scan now holds a second copy of the whole extracted document")
	}
}

func describeItems(items []MetadataContent) string {
	var b strings.Builder
	for i, it := range items {
		fmt.Fprintf(&b, "\n  [%d] type=%s content=%q", i, it.PreprocessorType, it.Content)
	}
	return b.String()
}

// minimalSectionedDOCX builds a .docx carrying BOTH a document body and core
// properties, so the text extractor and the office metadata extractor are both
// capable and the router assembles a two-section concatenation. A .docx with only
// word/document.xml takes the single-preprocessor fast path, where the section
// offsets are trivially 0 and the arithmetic under test never runs.
func minimalSectionedDOCX() []byte {
	const decl = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`
	body := ""
	for _, p := range []string{
		"Quarterly summary follows.",
		"Employee SSN 449-87-4100 on file.",
		"Card 4532-0151-1283-0366 expires soon.",
	} {
		body += `<w:p><w:r><w:t xml:space="preserve">` + p + `</w:t></w:r></w:p>`
	}

	parts := []struct{ name, body string }{
		{"[Content_Types].xml", decl +
			`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
			`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
			`<Default Extension="xml" ContentType="application/xml"/>` +
			`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
			`<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>` +
			`</Types>`},
		{"_rels/.rels", decl +
			`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>` +
			`<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>` +
			`</Relationships>`},
		{"docProps/core.xml", decl +
			`<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">` +
			`<dc:creator>Jane Analyst</dc:creator><cp:lastModifiedBy>Ops Reviewer</cp:lastModifiedBy>` +
			`</cp:coreProperties>`},
		{"word/document.xml", decl +
			`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>` +
			body + `</w:body></w:document>`},
	}

	out := new(bytes.Buffer)
	zw := zip.NewWriter(out)
	for _, p := range parts {
		w, err := zw.Create(p.name)
		if err != nil {
			panic(err)
		}
		if _, err := io.WriteString(w, p.body); err != nil {
			panic(err)
		}
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return out.Bytes()
}

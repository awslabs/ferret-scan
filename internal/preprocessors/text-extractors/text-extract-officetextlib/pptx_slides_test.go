// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package textextractofficetextlib

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pptxPart is one entry to write into the test .pptx archive.
type pptxPart struct {
	name string
	body string
}

// writePptx builds a minimal .pptx from the given parts, in the given archive
// order (so a test can deliberately write slides out of numeric order), and
// returns its path.
func writePptx(t *testing.T, dir string, parts []pptxPart) string {
	t.Helper()
	p := filepath.Join(dir, "deck.pptx")
	f, err := os.Create(p)
	if err != nil {
		t.Fatalf("create pptx: %v", err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	for _, part := range parts {
		w, err := zw.Create(part.name)
		if err != nil {
			t.Fatalf("zip create %s: %v", part.name, err)
		}
		if _, err := w.Write([]byte(part.body)); err != nil {
			t.Fatalf("zip write %s: %v", part.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return p
}

func slideXML(text string) string {
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:cSld><p:spTree><a:t>` +
		text + `</a:t></p:spTree></p:cSld></p:sld>`
}

func notesXML(text string) string {
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:notes xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"><p:cSld><p:spTree><a:t>` +
		text + `</a:t></p:spTree></p:cSld></p:notes>`
}

func slideRels(notesTarget string) string {
	rel := ""
	if notesTarget != "" {
		rel = `<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/notesSlide" Target="` + notesTarget + `"/>`
	}
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` + rel + `</Relationships>`
}

// TestExtractPptx_SlideOrderAndNotesByRels covers both pptx defects at once:
//
//   - Slides written to the archive OUT of numeric order (slide10 before slide2)
//     must still be labelled and emitted in slide order.
//   - Notes must be attached to the slide their .rels points at, NOT by array
//     position. notesSlide files here are deliberately misaligned with slide
//     numbers, and only some slides have notes — the shape that made the old
//     notes[i] pairing attach the wrong slide's speaker notes.
func TestExtractPptx_SlideOrderAndNotesByRels(t *testing.T) {
	dir := t.TempDir()

	// slide1 -> notesSlide3, slide2 -> (none), slide3 -> notesSlide1, slide10 -> notesSlide2.
	// Archive order is deliberately scrambled (slide10 first, notes before slides).
	parts := []pptxPart{
		{"ppt/notesSlides/notesSlide2.xml", notesXML("NOTES-FOR-SLIDE-10")},
		{"ppt/slides/slide10.xml", slideXML("SLIDE-TEN-BODY")},
		{"ppt/slides/_rels/slide10.xml.rels", slideRels("../notesSlides/notesSlide2.xml")},
		{"ppt/slides/slide2.xml", slideXML("SLIDE-TWO-BODY")},
		{"ppt/slides/_rels/slide2.xml.rels", slideRels("")}, // no notes
		{"ppt/notesSlides/notesSlide1.xml", notesXML("NOTES-FOR-SLIDE-3")},
		{"ppt/slides/slide1.xml", slideXML("SLIDE-ONE-BODY")},
		{"ppt/slides/_rels/slide1.xml.rels", slideRels("../notesSlides/notesSlide3.xml")},
		{"ppt/notesSlides/notesSlide3.xml", notesXML("NOTES-FOR-SLIDE-1")},
		{"ppt/slides/slide3.xml", slideXML("SLIDE-THREE-BODY")},
		{"ppt/slides/_rels/slide3.xml.rels", slideRels("../notesSlides/notesSlide1.xml")},
	}
	path := writePptx(t, dir, parts)

	content, err := ExtractText(path)
	if err != nil {
		t.Fatalf("ExtractText: %v", err)
	}
	got := content.Text

	// 1. Slides appear in numeric order: 1, 2, 3, 10.
	order := []string{"SLIDE-ONE-BODY", "SLIDE-TWO-BODY", "SLIDE-THREE-BODY", "SLIDE-TEN-BODY"}
	last := -1
	for _, marker := range order {
		idx := strings.Index(got, marker)
		if idx < 0 {
			t.Fatalf("slide body %q missing from output:\n%s", marker, got)
		}
		if idx < last {
			t.Errorf("slide body %q is out of order:\n%s", marker, got)
		}
		last = idx
	}

	// 2. Slide labels count up 1..4 in that order.
	for i, marker := range order {
		label := fmt.Sprintf("--- Slide %d ---", i+1)
		li := strings.Index(got, label)
		mi := strings.Index(got, marker)
		if li < 0 || li > mi {
			t.Errorf("expected %q immediately before %q:\n%s", label, marker, got)
		}
	}

	// 3. Notes are attached to the correct slide via rels.
	//    slide1 -> NOTES-FOR-SLIDE-1, slide3 -> NOTES-FOR-SLIDE-3, slide10 -> NOTES-FOR-SLIDE-10.
	assertNotesUnderSlide(t, got, "SLIDE-ONE-BODY", "NOTES-FOR-SLIDE-1")
	assertNotesUnderSlide(t, got, "SLIDE-THREE-BODY", "NOTES-FOR-SLIDE-3")
	assertNotesUnderSlide(t, got, "SLIDE-TEN-BODY", "NOTES-FOR-SLIDE-10")

	// 4. Slide 2 has no notes: NOTES-FOR-SLIDE-* must not appear between
	//    SLIDE-TWO-BODY and the next slide.
	two := sliceBetween(got, "SLIDE-TWO-BODY", "SLIDE-THREE-BODY")
	if strings.Contains(two, "SPEAKER NOTES") {
		t.Errorf("slide 2 has no notes but got a SPEAKER NOTES block:\n%s", two)
	}
}

// assertNotesUnderSlide checks that noteText appears after slideMarker and
// before the next "--- Slide" boundary — i.e. it is attached to that slide.
func assertNotesUnderSlide(t *testing.T, full, slideMarker, noteText string) {
	t.Helper()
	start := strings.Index(full, slideMarker)
	if start < 0 {
		t.Fatalf("slide %q missing", slideMarker)
	}
	rest := full[start:]
	next := strings.Index(rest[len(slideMarker):], "--- Slide ")
	region := rest
	if next >= 0 {
		region = rest[:len(slideMarker)+next]
	}
	if !strings.Contains(region, noteText) {
		t.Errorf("expected notes %q attached to slide %q, region was:\n%s", noteText, slideMarker, region)
	}
}

func sliceBetween(s, from, to string) string {
	i := strings.Index(s, from)
	if i < 0 {
		return ""
	}
	j := strings.Index(s[i:], to)
	if j < 0 {
		return s[i:]
	}
	return s[i : i+j]
}

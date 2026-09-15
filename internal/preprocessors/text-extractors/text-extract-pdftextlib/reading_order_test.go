// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package textextractpdftextlib

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Page content must come out in reading order — top of the page before bottom.
//
// # Why this is not cosmetic
//
// Several detections are cross-line: a label above its value (the passport and medicalid validators
// both depend on it), the before/after window that drives keyword proximity and therefore confidence,
// and table header to data row association. On an inverted page every one of those reads the document
// backwards, so a label FOLLOWS its value instead of preceding it. That is a recall loss and an
// invisible one, because the findings that survive look normal.
//
// Measured against `pdftotext -layout` on 40 real PDFs before the fix: reading order was INVERTED on
// 15 of them and correct on 12, with the expected token missing entirely from 13. The extractor sorted
// rows by ascending average Y while its own comment two lines above correctly said that PDF Y
// increases from bottom to top — so it emitted bottom-to-top wherever the library's Y was genuinely
// PDF-oriented (#666).
//
// # Why the fixtures are built here rather than committed as files
//
// The golden corpus contains ZERO PDFs, which is why nothing caught this. Real PDFs cannot be
// committed — they are third-party documents — so these are minimal PDFs written byte by byte, which
// has the advantage that the coordinate system is explicit and reviewable rather than whatever a
// producer happened to emit.
//
// The flipped-CTM case matters specifically: the reason flipping the comparator was NOT the fix is
// that Y orientation is not consistent across producers. Sorting descending, or not sorting at all,
// each moved the corpus from 15 inverted to 5 — fixing 15 files and breaking 5 that had been correct.
// A fixture with `1 0 0 -1 0 H cm` proves the extractor no longer depends on orientation at all.
func TestPageTextComesOutInReadingOrder(t *testing.T) {
	const (
		topToken    = "ZTOPMARKERZ"
		bottomToken = "ZBOTMARKERZ"
	)

	cases := []struct {
		name string
		// content is the page content stream. Both fixtures draw the SAME two tokens at the same
		// visual positions; they differ only in the coordinate system.
		content string
		why     string
	}{
		{
			name: "standard-coordinates",
			// PDF user space: origin bottom-left, Y increases upward. The top of the page is the
			// HIGHER Y, so 700 is near the top of a 792-unit page and 100 is near the bottom.
			content: "BT /F1 12 Tf 1 0 0 1 72 700 Tm (" + topToken + ") Tj ET\n" +
				"BT /F1 12 Tf 1 0 0 1 72 100 Tm (" + bottomToken + ") Tj ET\n",
			why: "The ordinary case. Sorting by ASCENDING Y emits this bottom-to-top, which is what " +
				"the extractor did.",
		},
		{
			name: "flipped-ctm",
			// The producer flips the axis with a CTM, so within this stream Y increases DOWNWARD.
			// The visual top is now the LOWER Y. A comparator that assumed either orientation is
			// wrong for one of these two fixtures; an extractor that does not sort by Y is right for
			// both.
			content: "1 0 0 -1 0 792 cm\n" +
				"BT /F1 12 Tf 1 0 0 1 72 92 Tm (" + topToken + ") Tj ET\n" +
				"BT /F1 12 Tf 1 0 0 1 72 692 Tm (" + bottomToken + ") Tj ET\n",
			why: "Y increases downward here. This is the population that made flipping the comparator " +
				"the wrong fix: it would repair the standard case and break this one.",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), c.name+".pdf")
			if err := os.WriteFile(path, buildSinglePagePDF(c.content), 0o600); err != nil {
				t.Fatalf("writing fixture: %v", err)
			}

			content, err := ExtractText(path)
			if err != nil {
				t.Fatalf("extracting %s: %v", c.name, err)
			}
			text := content.Text

			ti := strings.Index(text, topToken)
			bi := strings.Index(text, bottomToken)

			// Non-vacuity first: an ordering assertion over text that does not contain the tokens
			// would pass for the wrong reason. Before the fix, the expected token was missing
			// entirely from 13 of 40 real PDFs, so this is a real failure mode and not a formality.
			if ti < 0 || bi < 0 {
				t.Fatalf("%s: extraction lost a token (top found=%v, bottom found=%v). Ordering "+
					"cannot be checked.\n  extracted: %q", c.name, ti >= 0, bi >= 0, truncate(text))
			}

			if ti > bi {
				t.Errorf("%s: the page is emitted BOTTOM-TO-TOP — %q appears at %d, after %q at %d.\n"+
					"  %s\n"+
					"  Reading order is not cosmetic: a label above its value now follows it, so "+
					"cross-line detections read the document backwards and lose findings silently.",
					c.name, topToken, ti, bottomToken, bi, c.why)
			}
		})
	}
}

// TestReadingOrderIsIndependentOfCoordinateOrientation states the property directly: the two fixtures
// above describe the same visual page in opposite coordinate systems, so they must extract to the same
// reading order.
//
// Asserted separately from the per-case rows because it is the property that makes the fix correct
// rather than lucky. Any implementation that decides order from Y satisfies exactly one of the two
// rows and fails this one.
func TestReadingOrderIsIndependentOfCoordinateOrientation(t *testing.T) {
	const topToken, bottomToken = "ZTOPMARKERZ", "ZBOTMARKERZ"

	standard := buildSinglePagePDF(
		"BT /F1 12 Tf 1 0 0 1 72 700 Tm (" + topToken + ") Tj ET\n" +
			"BT /F1 12 Tf 1 0 0 1 72 100 Tm (" + bottomToken + ") Tj ET\n")
	flipped := buildSinglePagePDF(
		"1 0 0 -1 0 792 cm\n" +
			"BT /F1 12 Tf 1 0 0 1 72 92 Tm (" + topToken + ") Tj ET\n" +
			"BT /F1 12 Tf 1 0 0 1 72 692 Tm (" + bottomToken + ") Tj ET\n")

	dir := t.TempDir()
	order := func(name string, data []byte) bool {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
		content, err := ExtractText(p)
		if err != nil {
			t.Fatalf("extracting %s: %v", name, err)
		}
		text := content.Text
		ti, bi := strings.Index(text, topToken), strings.Index(text, bottomToken)
		if ti < 0 || bi < 0 {
			t.Fatalf("%s: a token is missing, so orientation cannot be compared", name)
		}
		return ti < bi
	}
	if order("standard.pdf", standard) != order("flipped.pdf", flipped) {
		t.Error("the two coordinate systems describe the same visual page and extracted to DIFFERENT " +
			"reading orders. An implementation that decides order from the Y coordinate can only be " +
			"right for one of them, which is why sorting by Y was replaced rather than reversed.")
	}
}

// buildSinglePagePDF writes a minimal one-page PDF with an uncompressed content stream.
//
// The text is positioned with Tm (the text matrix) rather than Td, and that detail is what makes these
// fixtures exercise the code under test. With Td, ledongthuc/pdf reports Y=0 for every element, so
// GetTextByRow returns ONE row containing both tokens and any row sort has nothing to order — the
// first version of this test used Td and passed on the unfixed extractor, which is a fixture that
// asserts nothing. With Tm the library reports Y=700 and Y=100 in two rows, the sort is live, and the
// unfixed extractor emits them bottom-to-top.
//
// Written by hand rather than with a library so the byte offsets in the xref table are computed from
// the actual output — a PDF whose xref is wrong is one the parser may reject, which would make every
// assertion above fail for a reason that has nothing to do with reading order.
func buildSinglePagePDF(content string) []byte {
	var buf bytes.Buffer
	offsets := make([]int, 0, 6)

	obj := func(body string) {
		offsets = append(offsets, buf.Len())
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", len(offsets), body)
	}

	buf.WriteString("%PDF-1.4\n")
	obj("<< /Type /Catalog /Pages 2 0 R >>")
	obj("<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
	obj("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] " +
		"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>")
	obj(fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(content), content))
	obj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

	xref := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n", len(offsets)+1)
	buf.WriteString("0000000000 65535 f \n")
	for _, off := range offsets {
		fmt.Fprintf(&buf, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n",
		len(offsets)+1, xref)
	return buf.Bytes()
}

func truncate(s string) string {
	if len(s) > 300 {
		return s[:300] + "…"
	}
	return s
}

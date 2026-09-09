// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/coverage"
	textextractpdftextlib "github.com/awslabs/ferret-scan/v2/internal/preprocessors/text-extractors/text-extract-pdftextlib"
)

// The page budget stops PDF extraction at 50 pages. That is a defensible cost decision; doing it in
// SILENCE is not. Measured on the parent commit, a 60-page PDF with an SSN on page 1 and six more on
// pages 55-60:
//
//	1 finding, exit 0, files_skipped: 0, no files_not_examined, 0 bytes of stderr
//
// Six cleartext SSNs never reported and, under this project's sink rule, never redacted, with nothing
// anywhere saying the scan had stopped. See #626.

// multiPagePDF builds a PDF with pageCount pages, each carrying a distinct line of text, with an SSN
// on the pages named in ssnPages (1-based).
//
// Distinct text per page on purpose: identical pages would let a truncation that silently dropped the
// tail still produce the same extracted string, so the test could not tell 50 pages from 60.
func multiPagePDF(pageCount int, ssnPages ...int) string {
	wantSSN := make(map[int]bool, len(ssnPages))
	for _, p := range ssnPages {
		wantSSN[p] = true
	}

	// Object numbering: 1 catalog, 2 pages, then a (page, contents) pair per page, then the font.
	pageIDs := make([]int, pageCount)
	contentIDs := make([]int, pageCount)
	for i := 0; i < pageCount; i++ {
		pageIDs[i] = 3 + 2*i
		contentIDs[i] = 4 + 2*i
	}
	fontID := 3 + 2*pageCount

	var kids strings.Builder
	for i, id := range pageIDs {
		if i > 0 {
			kids.WriteString(" ")
		}
		kids.WriteString(itoa(id) + " 0 R")
	}

	objs := []string{
		"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
		"2 0 obj\n<< /Type /Pages /Kids [" + kids.String() + "] /Count " + itoa(pageCount) + " >>\nendobj\n",
	}
	for i := 0; i < pageCount; i++ {
		page := i + 1
		text := "Page " + itoa(page) + " filler line"
		if wantSSN[page] {
			// A distinct valid-shaped SSN per page, so a finding can be attributed to its page.
			text = "Page " + itoa(page) + " has SSN 536-90-42" + pad2(page%100)
		}
		stream := "BT /F1 12 Tf 72 700 Td (" + text + ") Tj ET\n"
		objs = append(objs,
			itoa(pageIDs[i])+" 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents "+
				itoa(contentIDs[i])+" 0 R /Resources << /Font << /F1 "+itoa(fontID)+" 0 R >> >> >>\nendobj\n",
			itoa(contentIDs[i])+" 0 obj\n<< /Length "+itoa(len(stream))+" >>\nstream\n"+stream+"endstream\nendobj\n")
	}
	objs = append(objs, itoa(fontID)+" 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")
	return assemblePDF(objs)
}

func pad2(n int) string {
	s := itoa(n)
	for len(s) < 2 {
		s = "0" + s
	}
	return s
}

func writePDF(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "doc.pdf")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestPDFPageBudgetKeepsTheRealPageCount pins the two counts apart.
//
// The cap used to be applied by overwriting PageCount, which destroyed the only record that the
// document was longer than what was read — so no consumer, and no disclosure, could tell a 50-page
// document from the first 50 pages of a 200-page one.
func TestPDFPageBudgetKeepsTheRealPageCount(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		pages                  int
		wantCount, wantScanned int
		wantTruncated          bool
	}{
		{"well under the budget", 3, 3, 3, false},
		// Exactly at the budget must NOT report truncation: an off-by-one here would disclose a
		// truncation that did not happen on every 50-page document.
		{"exactly at the budget", 50, 50, 50, false},
		{"one page over", 51, 51, 50, true},
		{"well over", 60, 60, 50, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content, err := textextractpdftextlib.ExtractText(writePDF(t, multiPagePDF(tc.pages, 1)))
			if err != nil {
				t.Fatalf("extracting a %d-page PDF: %v", tc.pages, err)
			}

			// Non-vacuity: if the fixture stopped parsing, every count below would be zero and the
			// assertions would pass on a document that was never read.
			if !strings.Contains(content.Text, "SSN 536-90-42") {
				t.Fatalf("the page-1 SSN is missing from the extracted text, so this PDF did not "+
					"parse and the counts below mean nothing. Text: %q", truncateForLog(content.Text))
			}

			if content.PageCount != tc.wantCount {
				t.Errorf("PageCount = %d, want %d — the document's real length must survive the "+
					"budget", content.PageCount, tc.wantCount)
			}
			if content.PagesScanned != tc.wantScanned {
				t.Errorf("PagesScanned = %d, want %d", content.PagesScanned, tc.wantScanned)
			}
			if got := content.Truncated(); got != tc.wantTruncated {
				t.Errorf("Truncated() = %v, want %v (PageCount=%d PagesScanned=%d)",
					got, tc.wantTruncated, content.PageCount, content.PagesScanned)
			}
		})
	}
}

// TestPDFPageBudgetIsDisclosed is the assertion that matters: the truncation reaches the coverage
// channel, so it reaches stderr, files_not_examined, the structured formats and the exit code under
// --fail-on-incomplete.
func TestPDFPageBudgetIsDisclosed(t *testing.T) {
	path := writePDF(t, multiPagePDF(60, 1, 55, 60))

	content, err := tpForTest().Process(path)
	if err != nil {
		t.Fatalf("processing: %v", err)
	}

	// Non-vacuity, both directions. The scanned part must have produced text (or the disclosure would
	// be about a file that failed to parse), and the unscanned part must genuinely be absent (or there
	// was no truncation to disclose and the test proves nothing).
	if !strings.Contains(content.Text, "Page 1 has SSN") {
		t.Fatalf("page 1's text is missing, so this is a parse failure rather than a truncation: %q",
			truncateForLog(content.Text))
	}
	if strings.Contains(content.Text, "Page 55") || strings.Contains(content.Text, "Page 60") {
		t.Fatalf("pages 55/60 ARE in the extracted text, so the budget did not fire and there is " +
			"nothing to disclose — this test would pass for the wrong reason")
	}

	if content.ExtractionCause != coverage.CauseCutShort {
		t.Errorf("ExtractionCause = %v, want CauseCutShort. CauseCutShort is defined as \"a budget, "+
			"size cap or timeout fired, so the file is PARTLY scanned\", which is exactly this; "+
			"CauseNoText would tell an operator to OCR a document that in fact needs splitting or a "+
			"larger budget", content.ExtractionCause)
	}
	if content.ExtractionWarning == "" {
		t.Fatal("no ExtractionWarning: the cause alone does not reach the operator, and a cause with " +
			"no note is how a disclosure becomes a number nobody can act on")
	}
	// A count without the numbers is not a disclosure: "partly scanned" is identical for 50 of 51 and
	// 50 of 5000, and the remedy differs.
	for _, want := range []string{"50", "60", "10", "NOT scanned"} {
		if !strings.Contains(content.ExtractionWarning, want) {
			t.Errorf("ExtractionWarning does not contain %q, so the operator cannot tell how much was "+
				"missed: %q", want, content.ExtractionWarning)
		}
	}
}

// TestAPDFUnderTheBudgetDisclosesNothing is the must-NOT-fire half. A disclosure on every PDF is one
// operators learn to ignore, and it would also make every ordinary scan's output differ.
func TestAPDFUnderTheBudgetDisclosesNothing(t *testing.T) {
	content, err := tpForTest().Process(writePDF(t, multiPagePDF(10, 1, 10)))
	if err != nil {
		t.Fatalf("processing: %v", err)
	}
	if !strings.Contains(content.Text, "Page 10 has SSN") {
		t.Fatalf("page 10's text is missing from a 10-page document, so this fixture is broken and "+
			"the silence below proves nothing: %q", truncateForLog(content.Text))
	}
	if content.ExtractionCause == coverage.CauseCutShort {
		t.Errorf("a 10-page PDF reported CauseCutShort: %q", content.ExtractionWarning)
	}
	if strings.Contains(content.ExtractionWarning, "page budget") {
		t.Errorf("a 10-page PDF carries a page-budget warning: %q", content.ExtractionWarning)
	}
}

// TestTruncationIsReportedBeforeEmptiness pins the ORDER, which the SVG extractor's comment already
// warns about: a document whose first 50 pages carry no text layer is both truncated and empty, and
// testing emptiness first reports "the file parsed but held no document text" about a document that
// was cut short — a true disclosure under a false heading.
func TestTruncationIsReportedBeforeEmptiness(t *testing.T) {
	// 60 pages, no text on any of them: every content stream is a rectangle rather than a BT/Tj run.
	content, err := tpForTest().Process(writePDF(t, textlessMultiPagePDF(60)))
	if err != nil {
		t.Fatalf("processing: %v", err)
	}

	// Non-vacuity: the fixture must really be empty, or this is just the truncation test again.
	if strings.TrimSpace(content.Text) != "" {
		t.Fatalf("the textless fixture yielded text, so the both-conditions case is not being "+
			"exercised: %q", truncateForLog(content.Text))
	}
	if content.ExtractionCause != coverage.CauseCutShort {
		t.Errorf("ExtractionCause = %v for a document that is BOTH truncated and textless, want "+
			"CauseCutShort. CauseNoText here would say the pages were read and found empty, when 10 "+
			"of them were never read at all", content.ExtractionCause)
	}
}

// textlessMultiPagePDF builds a PDF with pageCount pages whose content streams draw a filled
// rectangle and hold no text-showing operator at all.
func textlessMultiPagePDF(pageCount int) string {
	pageIDs := make([]int, pageCount)
	contentIDs := make([]int, pageCount)
	for i := 0; i < pageCount; i++ {
		pageIDs[i] = 3 + 2*i
		contentIDs[i] = 4 + 2*i
	}
	var kids strings.Builder
	for i, id := range pageIDs {
		if i > 0 {
			kids.WriteString(" ")
		}
		kids.WriteString(itoa(id) + " 0 R")
	}
	objs := []string{
		"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
		"2 0 obj\n<< /Type /Pages /Kids [" + kids.String() + "] /Count " + itoa(pageCount) + " >>\nendobj\n",
	}
	for i := 0; i < pageCount; i++ {
		stream := "0 0 0 rg 72 700 100 50 re f\n"
		objs = append(objs,
			itoa(pageIDs[i])+" 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents "+
				itoa(contentIDs[i])+" 0 R >>\nendobj\n",
			itoa(contentIDs[i])+" 0 obj\n<< /Length "+itoa(len(stream))+" >>\nstream\n"+stream+"endstream\nendobj\n")
	}
	return assemblePDF(objs)
}

// TestScannedPageSpanPicksTheTextsSpan covers the accessor the page estimator divides by.
//
// While the budget overwrote PageCount, passing it to estimatePageNumber was accidentally correct —
// the two were the same number. Keeping the real count makes the choice load-bearing: 50 pages of
// extracted text spread across 60 puts every estimate early.
func TestScannedPageSpanPicksTheTextsSpan(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		pageCount, pagesScanned int
		want                    int
	}{
		{"a producer that sets neither", 0, 0, 0},
		{"a producer that does not bound (PagesScanned unset)", 12, 0, 12},
		{"not truncated: the two agree", 40, 40, 40},
		{"truncated: the text spans the scanned pages", 60, 50, 50},
		// Defensive: PagesScanned above PageCount is incoherent, and trusting it would put estimates
		// past the end of the document.
		{"incoherent, PagesScanned over PageCount", 10, 99, 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pc := &ProcessedContent{PageCount: tc.pageCount, PagesScanned: tc.pagesScanned}
			if got := pc.scannedPageSpan(); got != tc.want {
				t.Errorf("scannedPageSpan() = %d, want %d (PageCount=%d PagesScanned=%d)",
					got, tc.want, tc.pageCount, tc.pagesScanned)
			}
		})
	}
}

func truncateForLog(s string) string {
	const max = 200
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

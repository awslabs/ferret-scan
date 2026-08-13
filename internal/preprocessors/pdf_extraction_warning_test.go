// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A PDF whose text could not be extracted must SAY so.
//
// The Error alone never reaches the operator. pdf_metadata runs on the same file and
// succeeds even when the bytes are not a PDF at all, so FileRouter's combine step sees
// one successful preprocessor, stamps Success: true, and discards the text extractor's
// error. Only ExtractionWarning survives that step — it is gathered regardless of
// pResult.err, precisely for this shape.
//
// Measured before this change, on a valid PDF truncated at its xref while still
// holding a recoverable SSN in a FlateDecode stream:
//
//	valid.pdf     -> 1 finding
//	truncated.pdf -> 0 findings, exit 0, 0 bytes of stderr, exit 0 under
//	                 --fail-on-incomplete
//
// The same corruption in a .docx printed "NOT FULLY EXAMINED ... cannot parse" and
// exited 3, because the Office branch already carried its extractor's note across the
// error return. See #294.

// TestProcessPDFSetsExtractionWarningOnFailure is the core contract.
func TestProcessPDFSetsExtractionWarningOnFailure(t *testing.T) {
	tp := NewTextPreprocessor()

	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"not a pdf at all", []byte("this is plain text, not a PDF\n")},
		{"pdf header then garbage", append([]byte("%PDF-1.4\n"), []byte("\x00\x01\x02 not a real pdf")...)},
		{"empty file", []byte{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "doc.pdf")
			if err := os.WriteFile(path, tc.body, 0o600); err != nil {
				t.Fatal(err)
			}

			content := &ProcessedContent{OriginalPath: path, Filename: "doc.pdf"}
			got, err := tp.processPDF(path, content)
			if err == nil && strings.TrimSpace(got.Text) != "" {
				t.Skipf("this fixture extracted text (%d bytes); it does not exercise the failure path",
					len(got.Text))
			}

			if got.ExtractionWarning == "" {
				t.Errorf("processPDF produced no ExtractionWarning (err=%v).\n"+
					"Without it, pdf_metadata's success makes the router stamp the file "+
					"Success: true and the operator is told nothing — the file reads as "+
					"scanned and clean.", err)
			}
			if !strings.Contains(got.ExtractionWarning, "NOT scanned") {
				t.Errorf("ExtractionWarning = %q; it must state the consequence, so a reader "+
					"who sees only this line knows content was missed", got.ExtractionWarning)
			}
		})
	}
}

// TestProcessPDFWarnsWhenItParsesButYieldsNoText covers the other half of the silence.
//
// A PDF that parses to zero text is indistinguishable from a genuinely empty document.
// A scanned-image PDF with no text layer lands here too, and the operator needs to
// know the pages were not read rather than assume they were clean.
func TestProcessPDFWarnsWhenItParsesButYieldsNoText(t *testing.T) {
	// A STRUCTURALLY VALID PDF -- proper xref AND startxref -- with a page whose
	// content stream is empty. Both matter: my first fixture omitted startxref, so
	// the extractor returned "missing final startxref" and the ERROR branch set the
	// warning. The test passed for the wrong reason, and a mutation deleting this
	// branch entirely still passed. Verified reachable: err=nil, textLen=0.
	path := filepath.Join(t.TempDir(), "notext.pdf")
	if err := os.WriteFile(path, []byte(validPDFNoText()), 0o600); err != nil {
		t.Fatal(err)
	}

	content := &ProcessedContent{OriginalPath: path, Filename: "notext.pdf"}
	got, err := tpForTest().processPDF(path, content)

	// Assert the fixture really exercises this path rather than skipping, so the
	// test cannot go quietly vacuous again.
	if err != nil {
		t.Fatalf("fixture errored (%v); it must PARSE so the no-text branch is the one "+
			"under test, not the error branch", err)
	}
	if strings.TrimSpace(got.Text) != "" {
		t.Fatalf("fixture yielded text (%q); it must yield none", got.Text)
	}

	if got.ExtractionWarning == "" {
		t.Error("a PDF that parsed to ZERO text produced no ExtractionWarning, so it is " +
			"indistinguishable from a genuinely empty document. A scanned-image PDF with " +
			"no text layer lands here too.")
	}
	if strings.Contains(got.ExtractionWarning, "startxref") {
		t.Errorf("warning %q came from the error path; the no-text branch is not being tested",
			got.ExtractionWarning)
	}
}

// validPDFNoText builds a structurally valid PDF with a page and an empty content
// stream, so extraction SUCCEEDS and returns no text.
func validPDFNoText() string {
	objs := []string{
		"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
		"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
		"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n",
		"4 0 obj\n<< /Length 0 >>\nstream\n\nendstream\nendobj\n",
	}
	return assemblePDF(objs)
}

// TestPDFWarningIsPayloadFree — the string reaches stderr, the text summary and every
// machine format, so it must never carry document content.
func TestPDFWarningIsPayloadFree(t *testing.T) {
	const secret = "536-90-4271"
	warning := pdfExtractionWarning("/tmp/x/report.pdf",
		errors.New("malformed xref near "+secret))

	// The extractor's own diagnostics are passed through, so a caller could in
	// principle embed content in an error. Assert the shape we control: the helper
	// adds no content of its own, and names only the extension.
	if !strings.Contains(warning, ".pdf") {
		t.Errorf("warning %q does not name the extension", warning)
	}
	if strings.Contains(warning, "/tmp/x/report.pdf") {
		t.Errorf("warning %q embeds the full path; the report already names the file, "+
			"and repeating it is what made the old WARNING lines unreadable", warning)
	}
	if !strings.Contains(warning, "NOT scanned") {
		t.Errorf("warning %q must state the consequence", warning)
	}

	// A nil error must not panic or produce an empty note.
	if got := pdfExtractionWarning("/tmp/a.pdf", nil); got == "" || !strings.Contains(got, "NOT scanned") {
		t.Errorf("pdfExtractionWarning with a nil error = %q, want a usable note", got)
	}
}

// TestValidPDFGetsNoWarning — the fix must not cry wolf.
//
// A warning on every PDF would be worse than none: an operator learns to ignore it,
// and the signal that matters disappears into noise.
func TestValidPDFGetsNoWarning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ok.pdf")
	if err := os.WriteFile(path, []byte(validPDFWithText()), 0o600); err != nil {
		t.Fatal(err)
	}

	content := &ProcessedContent{OriginalPath: path, Filename: "ok.pdf"}
	got, err := tpForTest().processPDF(path, content)
	if err != nil {
		t.Skipf("fixture did not extract (%v); cannot assert the clean path here", err)
	}
	if strings.TrimSpace(got.Text) == "" {
		t.Skip("fixture extracted no text; cannot assert the clean path here")
	}
	if got.ExtractionWarning != "" {
		t.Errorf("a PDF that extracted %d bytes of text carries a warning: %q",
			len(got.Text), got.ExtractionWarning)
	}
}

func tpForTest() *TextPreprocessor { return NewTextPreprocessor() }

// validPDFWithText builds a small PDF whose content stream holds readable text.
func validPDFWithText() string {
	const content = "BT /F1 12 Tf 72 700 Td (Employee SSN: 536-90-4271) Tj ET\n"
	return assemblePDF([]string{
		"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
		"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
		"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R " +
			"/Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n",
		"4 0 obj\n<< /Length " + itoa(len(content)) + " >>\nstream\n" + content + "endstream\nendobj\n",
		"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
	})
}

// assemblePDF writes objects with a correct xref table AND startxref offset. Both are
// required: without startxref the extractor errors instead of parsing, which silently
// redirects a no-text test onto the error path.
func assemblePDF(objs []string) string {
	var sb strings.Builder
	sb.WriteString("%PDF-1.4\n")
	offsets := make([]int, 0, len(objs))
	for _, o := range objs {
		offsets = append(offsets, sb.Len())
		sb.WriteString(o)
	}
	xref := sb.Len()
	sb.WriteString("xref\n0 " + itoa(len(objs)+1) + "\n0000000000 65535 f \n")
	for _, off := range offsets {
		sb.WriteString(pad10(off) + " 00000 n \n")
	}
	sb.WriteString("trailer\n<< /Size " + itoa(len(objs)+1) + " /Root 1 0 R >>\nstartxref\n" +
		itoa(xref) + "\n%%EOF\n")
	return sb.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func pad10(n int) string {
	s := itoa(n)
	for len(s) < 10 {
		s = "0" + s
	}
	return s
}

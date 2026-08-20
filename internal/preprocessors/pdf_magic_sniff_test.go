// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// realPDFHeader is the first 512 bytes of an ordinary PDF as browsers and Office write them:
// the mandatory "%PDF-1.x" magic followed by a large ASCII metadata dictionary. Every byte of
// it is printable and there is not a single NUL, which is precisely why a printability sniff
// cannot judge it.
const realPDFHeader = "%PDF-1.4\n" +
	"1 0 obj\n" +
	"<< /Title (Quarterly Security Awareness Training - Module 3 of 4 - Completion Record)\n" +
	"/Creator (Mozilla/5.0 \\(Macintosh; Intel Mac OS X 10_15_7\\) AppleWebKit/537.36 " +
	"\\(KHTML, like Gecko\\) Chrome/129.0.0.0 Safari/537.36)\n" +
	"/Producer (Skia/PDF m129)\n" +
	"/CreationDate (D:20240115120000+00'00') >>\nendobj\n"

// A PDF must never sniff as text, however ASCII its header is.
//
// The sniff below judges printability, and a PDF header is printable BY SPECIFICATION — so it
// returned true and the plaintext preprocessor claimed real PDFs, handing raw PDF source to
// every validator. Measured on one real 957KB PDF: 533,976 characters of "text", 33% of it
// non-printable, producing 200 TWITTER findings at HIGH 100 on compressed stream bytes and 41
// PHONE findings on xref table offsets (#419).
func TestLooksLikeText_RejectsPDFHeaderHoweverPrintable(t *testing.T) {
	// Proof that the guard is load-bearing rather than incidental: strip the magic and the very
	// same bytes ARE judged text. So nothing else in the sniff would have caught this.
	withoutMagic := strings.TrimPrefix(realPDFHeader, "%PDF-")
	if !LooksLikeText([]byte(withoutMagic)) {
		t.Fatalf("the PDF header minus its magic does not sniff as text, so this test would " +
			"pass for the wrong reason — some other rule is rejecting it and the magic check " +
			"is not what is being exercised")
	}

	if LooksLikeText([]byte(realPDFHeader)) {
		t.Error("a real PDF header sniffs as TEXT. The plaintext preprocessor will claim the " +
			"file and hand raw PDF source — xref tables, dictionary syntax, compressed streams " +
			"— to every validator, which is what produced 200 TWITTER findings at HIGH 100 on " +
			"stream bytes (#419)")
	}
}

// The mislabelled case #271 exists for must keep working: a genuine text file that merely
// carries a .pdf name has no magic, so it is still text, still scanned, still redacted.
func TestLooksLikeText_TextFileNamedPDFIsStillText(t *testing.T) {
	for name, content := range map[string]string{
		"prose":                 "Employee SSN: 452-11-9384\nthis is really just text\n",
		"csv mislabelled":       "name,ssn\nJane Roe,452-11-9384\n",
		"mentions pdf in prose": "See the attached PDF for the SSN 452-11-9384\n",
		"percent but not magic": "%PDQ-1.4 is not a PDF header\nSSN: 452-11-9384\n",
	} {
		t.Run(name, func(t *testing.T) {
			if !LooksLikeText([]byte(content)) {
				t.Errorf("%q was classified binary; a text file named .pdf must still be "+
					"scanned, which is the whole point of #271", content[:min(len(content), 48)])
			}
		})
	}
}

// The end-to-end consequence: the plaintext preprocessor must not CLAIM a real PDF.
//
// LooksLikeText is the shared sniff behind three callers — this preprocessor, the router's
// isTextFile, and the redactor's looksLikeTextFile — so asserting the claim here covers the
// routing decision that actually leaked.
func TestPlainTextPreprocessorDoesNotClaimARealPDF(t *testing.T) {
	dir := t.TempDir()
	ptp := NewPlainTextPreprocessor()

	realPDF := filepath.Join(dir, "training.pdf")
	if err := os.WriteFile(realPDF, []byte(realPDFHeader), 0o600); err != nil {
		t.Fatal(err)
	}
	if ptp.CanProcess(realPDF) {
		t.Error("the plaintext preprocessor claims a real PDF, so raw PDF source reaches every " +
			"validator as if it were text (#419)")
	}

	// And the converse, so the guard cannot be satisfied by refusing every .pdf: a text file
	// with a .pdf name is still claimed.
	textPDF := filepath.Join(dir, "notes.pdf")
	if err := os.WriteFile(textPDF, []byte("Employee SSN: 452-11-9384\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !ptp.CanProcess(textPDF) {
		t.Error("a text file named .pdf is no longer claimed; that is the mislabelled-container " +
			"case #271 added this branch for, and dropping it would leave its contents unscanned")
	}
}

// Why PDF is the ONLY container extension needing a magic check — and the honest reason, which
// is narrower than "their magic is binary".
//
// ZIP fails on its magic alone: PK\x03\x04 carries NUL bytes, and a NUL means binary. OLE's
// 8-byte magic does NOT — \xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1 has no NUL, and the legacy
// fallback counts every byte >= 0xA0 as printable, so the magic padded with printable bytes
// sniffs as TEXT. Real .doc/.xls/.ppt files are rejected because the OLE header REGION that
// follows (the CLSID and reserved fields) is NUL-filled, not because of the magic.
//
// That distinction matters: OLE's safety rests on the shape of real files rather than on a
// signature check, so if a future OLE-ish variant ever arrives with a NUL-free header it needs
// the same treatment PDF has. Verified empirically at the same time: real .docx/.pptx/.xlsx/
// .doc/.xls/.ppt files are all correctly refused by the plaintext preprocessor today.
func TestLooksLikeText_WhyOnlyPDFNeedsAMagicCheck(t *testing.T) {
	t.Run("zip magic alone is binary (it contains NULs)", func(t *testing.T) {
		buf := append([]byte{'P', 'K', 0x03, 0x04, 0x14, 0x00, 0x00, 0x00},
			[]byte(strings.Repeat("A", 200))...)
		if LooksLikeText(buf) {
			t.Error("a ZIP magic sniffs as text; .docx/.xlsx/.pptx would need a magic check too")
		}
	})

	oleMagic := []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}

	t.Run("ole magic ALONE is not enough to look binary", func(t *testing.T) {
		buf := append(append([]byte{}, oleMagic...), []byte(strings.Repeat("A", 200))...)
		if !LooksLikeText(buf) {
			t.Skip("the OLE magic now fails the sniff on its own; the note above is stale and " +
				"can be simplified")
		}
	})

	t.Run("a REAL ole header region is binary (NUL-filled CLSID)", func(t *testing.T) {
		// Real OLE: magic, then a 16-byte CLSID that is zero in practice, then more.
		buf := append(append([]byte{}, oleMagic...), make([]byte, 200)...)
		if LooksLikeText(buf) {
			t.Error("a real OLE header region sniffs as text, so .doc/.xls/.ppt would reach the " +
				"plaintext preprocessor the way PDF did (#419)")
		}
	})
}

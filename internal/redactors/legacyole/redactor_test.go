// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package legacyole

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// The same-length invariant is the whole reason this redactor can work without a
// CFB writer: if no stream changes size, every sector offset, FAT chain and
// length prefix in the container stays exactly as written. A replacement of the
// wrong length would corrupt the file while appearing to succeed, so length is
// asserted for every strategy and value shape rather than assumed from
// FormatPreserving's documentation.
func TestSameLengthReplacementAlwaysMatchesLength(t *testing.T) {
	values := []struct{ typ, val string }{
		{"SSN", "449-87-4100"},
		{"CREDIT_CARD", "4111111111111111"},
		{"EMAIL", "jane.analyst@example.com"},
		{"AUTHOR_INFO", "Jane Analyst"},
		{"PHONE", "212-555-0142"},
		{"APPLICATION_INFO", "Microsoft Office Word"},
		{"TEMPLATE_INFO", `\\corp-fs01\unreleased\t.dotx`},
		// Shapes chosen to break naive implementations.
		{"SSN", "1"},                         // shorter than any token
		{"UNKNOWN_TYPE", "abcdefghijklmnop"}, // type FormatPreserving may not know
		{"EMAIL", "a@b.co"},                  // minimal valid-ish email
	}
	strategies := []redactors.RedactionStrategy{
		redactors.RedactionSimple,
		redactors.RedactionFormatPreserving,
		redactors.RedactionSynthetic, // not advertised, but must still be length-safe
	}
	for _, v := range values {
		for _, st := range strategies {
			got := sameLengthReplacement(v.val, v.typ, st)
			if len(got) != len(v.val) {
				t.Errorf("sameLengthReplacement(%q, %s, %s) = %q: %d bytes, want %d — "+
					"a length change breaks every offset in the container",
					v.val, v.typ, st.String(), got, len(got), len(v.val))
			}
			if got == v.val {
				t.Errorf("sameLengthReplacement(%q, %s, %s) returned the value unchanged — "+
					"that writes the secret back out", v.val, v.typ, st.String())
			}
		}
	}
}

// Legacy Word stores much of its text as UTF-16LE, so a value in the document may
// exist in the bytes only as interleaved zeros. An ASCII-only overwrite would
// report success while leaving that copy in cleartext — the exact "reported but
// not redacted" failure this whole area keeps producing.
func TestOverwriteHandlesBothEncodings(t *testing.T) {
	secret := "449-87-4100"
	mask := strings.Repeat("*", len(secret))

	t.Run("ascii", func(t *testing.T) {
		buf := []byte("padding..........Employee SSN: " + secret + " trailing")
		ranges := []byteRange{{0, len(buf)}}
		if n := overwriteAll(buf, ranges, secret, mask); n != 1 {
			t.Fatalf("replaced %d occurrences, want 1", n)
		}
		if bytes.Contains(buf, []byte(secret)) {
			t.Error("ASCII copy of the value survived")
		}
	})

	t.Run("utf16le", func(t *testing.T) {
		buf := append([]byte("padding.........."), toUTF16LE("Employee SSN: "+secret)...)
		ranges := []byteRange{{0, len(buf)}}
		if n := overwriteAll(buf, ranges, secret, mask); n != 1 {
			t.Fatalf("replaced %d occurrences, want 1 — UTF-16LE text was not reached", n)
		}
		if bytes.Contains(buf, toUTF16LE(secret)) {
			t.Error("UTF-16LE copy of the value survived; an ASCII-only pass would miss it")
		}
	})

	t.Run("both encodings in one file", func(t *testing.T) {
		buf := []byte("ascii " + secret + " then wide ")
		buf = append(buf, toUTF16LE(secret)...)
		ranges := []byteRange{{0, len(buf)}}
		if n := overwriteAll(buf, ranges, secret, mask); n != 2 {
			t.Fatalf("replaced %d occurrences, want 2 (one per encoding)", n)
		}
		if bytes.Contains(buf, []byte(secret)) || bytes.Contains(buf, toUTF16LE(secret)) {
			t.Error("a copy of the value survived in one of the two encodings")
		}
	})

	t.Run("every occurrence, not just the first", func(t *testing.T) {
		buf := []byte(secret + " middle " + secret + " end " + secret)
		ranges := []byteRange{{0, len(buf)}}
		if n := overwriteAll(buf, ranges, secret, mask); n != 3 {
			t.Fatalf("replaced %d occurrences, want 3 — leaving a repeat behind is still a leak", n)
		}
		if bytes.Contains(buf, []byte(secret)) {
			t.Error("a repeated occurrence survived")
		}
	})
}

// Overwrites must stay inside the content ranges. A short value that coincides
// with header or FAT bytes must not be patched, or the container becomes
// unreadable — trading a leak for a corrupt document.
func TestOverwriteRespectsRanges(t *testing.T) {
	secret := "SECRETVAL"
	buf := []byte(secret + "|||" + secret)
	// Only the SECOND half is content; the first is "structure".
	ranges := []byteRange{{len(secret) + 3, len(buf)}}

	n := overwriteAll(buf, ranges, secret, strings.Repeat("*", len(secret)))
	if n != 1 {
		t.Fatalf("replaced %d occurrences, want 1 (only the in-range copy)", n)
	}
	if !bytes.HasPrefix(buf, []byte(secret)) {
		t.Error("the out-of-range copy was modified; structural bytes must be untouched")
	}
	if bytes.Contains(buf[len(secret)+3:], []byte(secret)) {
		t.Error("the in-range copy survived")
	}
}

// A same-length pattern is required by construction. These guard the helper
// against being called with mismatched lengths, which would either corrupt
// neighbouring bytes or silently do nothing.
func TestOverwriteEncodedRejectsLengthMismatch(t *testing.T) {
	buf := []byte("hello world")
	orig := append([]byte(nil), buf...)
	ranges := []byteRange{{0, len(buf)}}

	if n := overwriteEncoded(buf, ranges, []byte("hello"), []byte("hi")); n != 0 {
		t.Errorf("mismatched lengths replaced %d occurrences, want 0", n)
	}
	if n := overwriteEncoded(buf, ranges, nil, nil); n != 0 {
		t.Errorf("empty pattern replaced %d occurrences, want 0", n)
	}
	if !bytes.Equal(buf, orig) {
		t.Error("buffer was modified despite a rejected replacement")
	}
}

// toUTF16LE must encode non-ASCII CORRECTLY, not refuse it.
//
// It used to return nil for any non-ASCII rune. That looked conservative and was a
// cleartext leak: legacy Word stores property values and much of its body text as
// UTF-16LE, so for "José Ramírez" the narrow pass searched UTF-8 bytes that are not
// in the file, and the wide pass was skipped entirely. The redactor found nothing,
// reported Success with zero mappings, and wrote the name into the "redacted"
// output. Most of the world's names are affected.
//
// The encoding has to be exact: a wrong pattern either misses the value (a leak) or
// matches unrelated bytes (corruption). These cases pin the byte-level result rather
// than only the length, including a non-BMP rune needing a surrogate pair — the case
// a hand-rolled encoder gets wrong.
func TestToUTF16LEEncodesNonASCII(t *testing.T) {
	cases := []struct {
		in   string
		want []byte
	}{
		{"AB", []byte{'A', 0x00, 'B', 0x00}},
		// U+00E9: one code unit, low byte 0xE9.
		{"é", []byte{0xE9, 0x00}},
		// U+65E5: one code unit, little-endian E5 65.
		{"日", []byte{0xE5, 0x65}},
		// U+1F600 is outside the BMP: surrogate pair D83D DE00, little-endian.
		{"\U0001F600", []byte{0x3D, 0xD8, 0x00, 0xDE}},
	}
	for _, tc := range cases {
		got := toUTF16LE(tc.in)
		if !bytes.Equal(got, tc.want) {
			t.Errorf("toUTF16LE(%q) = % x, want % x", tc.in, got, tc.want)
		}
	}

	// Every non-ASCII string must yield a usable pattern; nothing means the wide
	// pass is skipped and the value survives redaction.
	for _, s := range []string{"café", "naïve", "日本語",
		"José Ramírez", "Björn Öhlund"} {
		if got := toUTF16LE(s); len(got) == 0 {
			t.Errorf("toUTF16LE(%q) returned nothing — the UTF-16LE pass would be skipped "+
				"and the value would stay in the redacted output", s)
		}
	}

	// An empty value has nothing to search for, and an empty pattern would match at
	// every offset.
	if got := toUTF16LE(""); got != nil {
		t.Errorf("toUTF16LE(\"\") = %v, want nil", got)
	}
}

// Non-compound input must be refused outright. Pattern-overwriting a file that is
// not the format we believe it is would corrupt arbitrary content.
func TestRejectsNonCompoundFile(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string][]byte{
		"plain.doc": []byte("this is not a compound file, just text"),
		"zip.doc":   {0x50, 0x4B, 0x03, 0x04, 0, 0, 0, 0}, // a ZIP masquerading as .doc
		"empty.doc": {},
		"short.doc": {0xD0, 0xCF},
	} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, content, 0o600); err != nil {
			t.Fatal(err)
		}
		r := NewLegacyOLERedactor(nil, nil)
		out := filepath.Join(dir, "out-"+name)
		_, err := r.RedactDocument(p, out, []detector.Match{
			{Text: "not a compound file", Type: "TEST", Confidence: 100},
		}, redactors.RedactionFormatPreserving)
		if err == nil {
			t.Errorf("%s: expected an error, got nil — refusing is the only safe answer for "+
				"input that is not an OLE container", name)
		}
		if _, statErr := os.Stat(out); statErr == nil {
			t.Errorf("%s: an output file was written despite the refusal; a caller would "+
				"treat it as a redacted copy", name)
		}
	}
}

// isCompoundFile is the gate in front of every byte modification.
func TestIsCompoundFile(t *testing.T) {
	cfb := []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, 0x00}
	if !isCompoundFile(cfb) {
		t.Error("valid CFB signature not recognized")
	}
	for _, b := range [][]byte{
		nil,
		{},
		{0xD0, 0xCF, 0x11},                   // truncated signature
		{0x50, 0x4B, 0x03, 0x04, 0, 0, 0, 0}, // ZIP
		{0x25, 0x50, 0x44, 0x46, 0, 0, 0, 0}, // PDF
		{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE0, 0x00}, // last byte wrong
	} {
		if isCompoundFile(b) {
			t.Errorf("non-CFB input %v accepted", b)
		}
	}
}

// The declared strategy set must be honest. Synthetic generates a value whose
// length is unrelated to the original, which this redactor cannot honour, so
// advertising it would promise something the output does not deliver.
func TestSupportedStrategiesExcludeSynthetic(t *testing.T) {
	r := NewLegacyOLERedactor(nil, nil)
	for _, s := range r.GetSupportedStrategies() {
		if s == redactors.RedactionSynthetic {
			t.Error("Synthetic is advertised but cannot preserve length; the redactor would " +
				"silently substitute a mask and misreport what the output contains")
		}
	}
	if len(r.GetSupportedStrategies()) == 0 {
		t.Error("no strategies advertised; the manager would never select this redactor")
	}
}

// The type list is what the manager matches on. A missing entry means the format
// silently falls back to "no redactor registered" and values stay in cleartext.
func TestSupportedTypesCoverLegacyFormats(t *testing.T) {
	r := NewLegacyOLERedactor(nil, nil)
	got := map[string]bool{}
	for _, tp := range r.GetSupportedTypes() {
		got[tp] = true
	}
	for _, want := range []string{".doc", ".xls", ".ppt"} {
		if !got[want] {
			t.Errorf("%s not advertised; the manager would report no redactor for it", want)
		}
	}
	// Must NOT claim the OOXML formats — the Office redactor owns those, and two
	// redactors claiming one extension is an ambiguous registration.
	for _, notOurs := range []string{".docx", ".xlsx", ".pptx", ".pdf"} {
		if got[notOurs] {
			t.Errorf("%s is claimed but belongs to another redactor", notOurs)
		}
	}
}

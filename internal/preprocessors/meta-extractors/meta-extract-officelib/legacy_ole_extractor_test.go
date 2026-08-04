// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractofficelib

import (
	"strings"
	"testing"
)

// recoverPrintableRuns is the approximate half of legacy extraction, so its
// limits are pinned deliberately rather than left to chance.
//
// Legacy Word interleaves character data with binary structures and mixes
// single-byte and UTF-16LE runs. Both encodings must be recovered: scanning only
// single bytes sees every OTHER character of a UTF-16 run, which silently halves
// the text a validator gets and can split a value down the middle.
func TestRecoverPrintableRuns(t *testing.T) {
	t.Run("single-byte run", func(t *testing.T) {
		in := []byte("\x00\x01Employee SSN: 449-87-4100\x00\xff")
		got := recoverPrintableRuns(in)
		if !strings.Contains(got, "449-87-4100") {
			t.Errorf("single-byte text not recovered from %q, got %q", in, got)
		}
	})

	t.Run("UTF-16LE run", func(t *testing.T) {
		// "Employee SSN: 449-87-4100" as UTF-16LE, the way legacy Word often
		// stores it. The single-byte pass alone would yield "EpoeSN 4-741"-style
		// garbage, not a matchable value.
		var wide []byte
		for _, c := range "Employee SSN: 449-87-4100" {
			wide = append(wide, byte(c), 0x00)
		}
		got := recoverPrintableRuns(wide)
		if !strings.Contains(got, "449-87-4100") {
			t.Errorf("UTF-16LE text not recovered; got %q", got)
		}
	})

	t.Run("short runs dropped", func(t *testing.T) {
		// Below minLegacyRun, binary structure bytes coincide with printable ASCII
		// often enough to produce garbage. "abc" must not survive; a real value
		// must.
		got := recoverPrintableRuns([]byte("\x00abc\x01de\x02Employee SSN 449-87-4100\x03"))
		if strings.Contains(got, "abc") {
			t.Errorf("run shorter than minLegacyRun=%d was kept: %q", minLegacyRun, got)
		}
		if !strings.Contains(got, "449-87-4100") {
			t.Errorf("value long enough to keep was dropped: %q", got)
		}
	})

	t.Run("no false text from pure binary", func(t *testing.T) {
		bin := []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0x00, 0x03, 0x04}
		if got := strings.TrimSpace(recoverPrintableRuns(bin)); got != "" {
			t.Errorf("pure binary produced text %q — this becomes validator noise", got)
		}
	})

	t.Run("value long enough to matter survives both passes", func(t *testing.T) {
		// An SSN is 11 chars, a card 15+, an email longer. minLegacyRun must sit
		// below all of them or legacy extraction silently drops the very values
		// the scanner exists to find.
		for _, v := range []string{"449-87-4100", "4111111111111111", "jane.analyst@example.com"} {
			if len(v) < minLegacyRun {
				t.Errorf("minLegacyRun=%d is longer than %q (%d chars) — that value could never be recovered",
					minLegacyRun, v, len(v))
			}
		}
	})
}

// The stream-name tables are the whole selection mechanism, so a typo in one is
// a silently unscanned format. These are exact, case-sensitive names as written
// by Office.
func TestLegacyStreamTables(t *testing.T) {
	for _, name := range []string{"WordDocument", "Workbook", "Book", "PowerPoint Document"} {
		if !legacyBodyStreams[name] {
			t.Errorf("body stream %q not recognized — that format's text would go unscanned", name)
		}
	}
	for _, name := range []string{"SummaryInformation", "DocumentSummaryInformation"} {
		if !legacyPropertyStreams[name] {
			t.Errorf("property stream %q not recognized — author/company/template would go unreported", name)
		}
	}
	// Guard against over-matching: a body stream must not be treated as
	// properties or vice versa, since each is parsed a different way.
	for name := range legacyBodyStreams {
		if legacyPropertyStreams[name] {
			t.Errorf("%q is in BOTH tables; it would be parsed twice, two different ways", name)
		}
	}
}

// embeddedMediaType is the gate that decides what an embedded part is. Two
// properties matter and are easy to break by adding a case:
//
//   - legacy OLE must be admitted (it is a leaf format: the extractor reads its
//     streams and does not follow embeddings, so it adds no recursion)
//   - embedded OOXML documents must NOT be admitted yet, because an embedded
//     .docx routes back through the Office preprocessor and recurses without a
//     bound. Measured before this scoping: a 7KB self-nesting .docx was followed
//     to all nine of its levels.
func TestEmbeddedMediaTypeScoping(t *testing.T) {
	admits := map[string]string{
		".jpg": "image", ".png": "image", ".webp": "image",
		".mp3": "audio", ".wav": "audio",
		".doc": "legacy_document", ".xls": "legacy_document", ".ppt": "legacy_document",
	}
	for ext, want := range admits {
		if got := embeddedMediaType(ext); got != want {
			t.Errorf("embeddedMediaType(%q) = %q, want %q", ext, got, want)
		}
	}

	// The load-bearing negative. If this starts returning non-empty, unbounded
	// recursion is live again and a self-nesting document becomes a
	// decompression-bomb amplifier.
	for _, ext := range []string{".docx", ".xlsx", ".pptx"} {
		if got := embeddedMediaType(ext); got != "" {
			t.Errorf("embeddedMediaType(%q) = %q, want \"\" — admitting embedded OOXML "+
				"documents re-enables UNBOUNDED recursion; a depth bound must land first",
				ext, got)
		}
	}

	for _, ext := range []string{".exe", ".bin", ".unknown", ""} {
		if got := embeddedMediaType(ext); got != "" {
			t.Errorf("embeddedMediaType(%q) = %q, want \"\"", ext, got)
		}
	}
}

// The part-path gate must cover where Word actually stores an embedded document.
// "/media/" alone missed word/embeddings/, which is the OLE-object location and
// therefore the realistic one.
func TestIsEmbeddedPartPath(t *testing.T) {
	yes := []string{
		"word/media/image1.png",
		"word/embeddings/Microsoft_Word_Document.docx",
		"xl/media/image1.jpeg",
		"ppt/media/audio1.wav",
		"WORD/MEDIA/IMAGE1.PNG", // producers vary in case
	}
	for _, p := range yes {
		if !isEmbeddedPartPath(p) {
			t.Errorf("isEmbeddedPartPath(%q) = false, want true", p)
		}
	}
	no := []string{
		"word/document.xml",
		"docProps/core.xml",
		"[Content_Types].xml",
		"_rels/.rels",
	}
	for _, p := range no {
		if isEmbeddedPartPath(p) {
			t.Errorf("isEmbeddedPartPath(%q) = true, want false", p)
		}
	}
}

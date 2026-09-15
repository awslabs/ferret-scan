// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"bytes"
	"math/rand"
	"strings"
	"testing"
	"unicode/utf8"
)

// TestLegacy8BitRoundTripsAnyBytes is the contract EncodingLegacy8Bit exists for.
//
// The defect: plaintext extraction ran strings.ToValidUTF8(content, ""), which replaces
// every invalid byte WITH NOTHING. Measured, "Employee José García" was extracted as
// "Employee Jos Garca" — three failures at once. The redacted copy was corrupted; DETECTION
// ran on the corrupted text, so a name with an accent was not reported at all; and every
// offset after the first legacy byte shifted.
//
// Latin-1 identity is a TOTAL BIJECTION over all 256 byte values, so this is provable by
// exhaustion rather than by sampling: every single byte, and then every ADJACENT PAIR,
// round-trips exactly. A real Windows-1252 table could not pass this — 0x81, 0x8D, 0x8F,
// 0x90 and 0x9D are undefined there and would decode to U+FFFD and be lost.
func TestLegacy8BitRoundTripsAnyBytes(t *testing.T) {
	// Every single byte.
	for b := 0; b < 256; b++ {
		in := []byte{byte(b)}
		dec, ok := DecodeToUTF8(in, EncodingLegacy8Bit)
		if !ok {
			t.Fatalf("DecodeToUTF8 refused byte 0x%02x", b)
		}
		if !utf8.ValidString(dec) {
			t.Errorf("byte 0x%02x decoded to invalid UTF-8 %q — the whole point is that the "+
				"decoded form is scannable", b, dec)
		}
		if got := EncodeFromUTF8(dec, EncodingLegacy8Bit); !bytes.Equal(got, in) {
			t.Errorf("byte 0x%02x round-tripped to % x", b, got)
		}
	}

	// Every adjacent pair, which is where a stateful or multi-byte-aware decoder would
	// break: 256*256 = 65,536 cases, cheap and exhaustive.
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			in := []byte{byte(a), byte(b)}
			dec, _ := DecodeToUTF8(in, EncodingLegacy8Bit)
			if got := EncodeFromUTF8(dec, EncodingLegacy8Bit); !bytes.Equal(got, in) {
				t.Fatalf("pair % x round-tripped to % x", in, got)
			}
		}
	}

	// And random longer buffers, so a length- or chunk-dependent bug shows up.
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 400; i++ {
		in := make([]byte, 1+rng.Intn(300))
		for j := range in {
			in[j] = byte(rng.Intn(256))
		}
		dec, _ := DecodeToUTF8(in, EncodingLegacy8Bit)
		if got := EncodeFromUTF8(dec, EncodingLegacy8Bit); !bytes.Equal(got, in) {
			t.Fatalf("random buffer of %d bytes did not round-trip", len(in))
		}
	}
}

// TestLegacy8BitEncodesIntroducedRunesAsUTF8 pins the one case that cannot round-trip.
//
// A redaction token or a synthetic name may contain runes at or above U+0100, which cannot
// have come from a single-byte file. Writing them as UTF-8 is the only lossless choice; the
// alternative is dropping them, which is the corruption this change removes. So the
// guarantee is precise, and worth stating precisely: original bytes are byte-identical,
// introduced runes are UTF-8.
func TestLegacy8BitEncodesIntroducedRunesAsUTF8(t *testing.T) {
	// "café" from a legacy file, plus an em dash a replacement introduced.
	legacy := "café"           // both runes below U+0100: from the file
	introduced := "—REDACTED—" // em dashes: not from the file

	got := EncodeFromUTF8(legacy+introduced, EncodingLegacy8Bit)

	if !bytes.HasPrefix(got, []byte{'c', 'a', 'f', 0xe9}) {
		t.Errorf("the original bytes were not preserved: % x", got[:4])
	}
	if !bytes.Contains(got, []byte("—")) {
		t.Errorf("an introduced rune above U+0100 was not written as UTF-8: % x", got)
	}
}

// TestDetectionIgnoresATruncatedFinalRune guards the subtlety that would have made this
// change catastrophic rather than helpful.
//
// One caller — the redactor's re-encode decision — passes only the first 512 bytes. A valid
// UTF-8 document whose 512-byte boundary lands mid-character is NOT a legacy file, and
// classifying it as one would re-encode every multi-byte character in the whole document
// byte-for-byte. That failure would be silent and would look exactly like the corruption
// being fixed.
func TestDetectionIgnoresATruncatedFinalRune(t *testing.T) {
	// A multi-byte rune deliberately cut at every possible offset.
	for _, r := range []rune{'é', '€', '\U0001F600'} { // 2, 3 and 4 byte runes
		full := "ascii prefix " + string(r)
		enc := []byte(full)
		for cut := 1; cut < utf8.RuneLen(r); cut++ {
			trunc := enc[:len(enc)-cut]
			if got := DetectTextEncoding(trunc); got != EncodingUTF8 {
				t.Errorf("a UTF-8 buffer cut %d byte(s) into U+%04X was detected as %v; it must "+
					"stay utf-8, or the redactor would re-encode a valid UTF-8 document as "+
					"single-byte and mangle every multi-byte character in it", cut, r, got)
			}
		}
	}

	// But genuinely legacy bytes must still be detected, or the fix does nothing.
	for _, raw := range [][]byte{
		[]byte("Employee Jos\xe9 Garc\xeda"),
		[]byte("R\xe9sum\xe9 caf\xe9 na\xefve"),
		{0x80, 0x81, 0x8d, 0x8f, 0x90, 0x9d}, // the five cp1252-undefined bytes plus 0x80
	} {
		if got := DetectTextEncoding(raw); got != EncodingLegacy8Bit {
			t.Errorf("legacy bytes % x detected as %v, want legacy-8bit", raw, got)
		}
	}
}

// TestExtractionNoLongerDeletesLegacyBytes is the end of the chain: what the validators and
// the redaction write path actually see.
// The lossless decode is what saves the accented bytes — NOT the ToValidUTF8 replacement.
//
// This test was originally named TestExtractionNoLongerDeletesLegacyBytes and its failure
// message blamed strings.ToValidUTF8(content, ""). Both were wrong, and a four-binary A/B
// proved it: with the encoding classification present but the ToValidUTF8 deletion restored,
// this test and both binary tests still PASSED, because DetectTextEncoding now routes a legacy
// file through DecodeToUTF8 and the content reaching that line is already valid UTF-8 with
// nothing to delete. Substituting U+FFFD instead of deleting, on its own, does NOT fix the
// defect: it converts 10 lost bytes into 10 replacement runes and the file still reads
// "Jos Garca" with one fewer finding.
//
// So this test pins the mechanism that actually works: classify, then decode losslessly.
func TestLegacyDecodeKeepsEveryAccentedByte(t *testing.T) {
	raw := []byte("R\xe9sum\xe9 notes: caf\xe9 receipts and na\xefve estimates.\n")
	dec, ok := DecodeToUTF8(raw, DetectTextEncoding(raw))
	if !ok {
		t.Fatal("DecodeToUTF8 refused the buffer")
	}
	if !utf8.ValidString(dec) {
		t.Fatal("decoded text is not valid UTF-8, so validators could not scan it")
	}
	// Four legacy bytes in, four non-ASCII runes out.
	nonASCII := 0
	for _, r := range dec {
		if r > 127 {
			nonASCII++
		}
	}
	if nonASCII != 4 {
		t.Errorf("decoded text has %d non-ASCII runes, want 4 — before EncodingLegacy8Bit "+
			"existed these bytes were not decoded at all, they stayed invalid UTF-8 and were "+
			"then dropped downstream, so the text read %q",
			nonASCII, "Rsum notes: caf receipts and nave estimates.")
	}
	if strings.Contains(dec, "Rsum") {
		t.Error("decoded text contains \"Rsum\": the accented bytes were deleted, which is the " +
			"defect this test exists for")
	}
}

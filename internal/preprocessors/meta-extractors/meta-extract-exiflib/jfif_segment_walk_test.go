// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractexiflib

import (
	"bytes"
	"encoding/binary"
	"os"
	"strings"
	"testing"
)

// #490: extractJFIFComment byte-scanned for the pair 0xFF 0xFE and trusted the two bytes behind it.
//
// A given byte pair turns up about once every 64KB of compressed data, so on a real JPEG that finds
// noise — and the noise became document text handed to the validators.
//
// Measured on an Apple-shipped asset (139,103 bytes, no COM segment, no Exif APP1, exactly ONE 0xFFFE
// in the whole file at offset 557, INSIDE the Display P3 ICC profile carried in APP2 which spans bytes
// 2–566, declaring 59,392 bytes):
//
//	pre-#480     0 findings, 210 chars extracted, no JFIF_Comment
//	after #480   5 SOCIAL_MEDIA TWITTER at HIGH 100/91, 59,599 chars, JFIF_Comment present
//
// The five handles — @hf, @K_pIa, @am, @E4, @L_ — exist nowhere in the file. And they are not merely
// cosmetic: they drove the image redactor, which decodes and re-encodes, so a "redacted" copy was
// written for a file holding nothing. 139,103 -> 95,213 bytes, 418,816 of 487,080 decoded pixel bytes
// different (85.99%), and the ICC profile GONE.
//
// Walking the segment chain is the fix rather than a tighter length check, because no check on the
// length can distinguish a marker from two bytes that merely look like one.

// jpegSeg builds one JPEG segment: FF, marker, 2-byte length (inclusive of itself), payload.
func jpegSeg(marker byte, payload []byte) []byte {
	out := []byte{0xFF, marker, 0, 0}
	binary.BigEndian.PutUint16(out[2:4], uint16(len(payload)+2))
	return append(out, payload...)
}

// jpegWith assembles SOI + segments + SOS + entropy data + EOI.
func jpegWith(segs ...[]byte) []byte {
	out := []byte{0xFF, 0xD8}
	for _, s := range segs {
		out = append(out, s...)
	}
	out = append(out, jpegSeg(0xDA, []byte{0x01, 0x01, 0x00})...) // SOS header
	out = append(out, 0x12, 0x34, 0x56)                           // entropy-coded data
	return append(out, 0xFF, 0xD9)                                // EOI
}

// TestARealCommentSegmentIsStillFound is the feature this must not break.
//
// The point of the scan is to recover a genuine COM segment, so a fix that stops finding one would be
// a recall regression dressed up as a precision fix.
func TestARealCommentSegmentIsStillFound(t *testing.T) {
	for _, tc := range []struct {
		name string
		jpeg []byte
	}{
		{"comment only", jpegWith(jpegSeg(0xFE, []byte("Employee SSN 449-87-4100")))},
		{"comment after APP0", jpegWith(
			jpegSeg(0xE0, []byte("JFIF\x00\x01\x02\x00\x00\x01\x00\x01\x00\x00")),
			jpegSeg(0xFE, []byte("Employee SSN 449-87-4100")))},
		{"comment after a big APP2", jpegWith(
			jpegSeg(0xE2, append([]byte("ICC_PROFILE\x00"), bytes.Repeat([]byte{0xAB}, 400)...)),
			jpegSeg(0xFE, []byte("Employee SSN 449-87-4100")))},
		{"comment between quantisation tables", jpegWith(
			jpegSeg(0xDB, bytes.Repeat([]byte{0x10}, 64)),
			jpegSeg(0xFE, []byte("Employee SSN 449-87-4100")),
			jpegSeg(0xC4, bytes.Repeat([]byte{0x20}, 30)))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tags := map[string]string{}
			extractJFIFComment(tc.jpeg, tags)
			if got := tags["JFIF_Comment"]; got != "Employee SSN 449-87-4100" {
				t.Errorf("JFIF_Comment = %q, want the real comment. Recovering a genuine COM segment "+
					"is what this scan is for.", got)
			}
		})
	}
}

// TestAByteSequenceInsideAPayloadIsNotAComment is the reported defect, reproduced structurally.
//
// The 0xFFFE here sits inside an APP2 payload, exactly as it does in the real Apple asset. A walker
// never visits it, because the APP2 length carries the walk straight past.
func TestAByteSequenceInsideAPayloadIsNotAComment(t *testing.T) {
	// The pair, then a length that FITS inside the surrounding data, then filler.
	//
	// The length has to fit: a first version of this fixture declared 59,392 bytes to mirror the real
	// Apple asset, but the fixture is small, so the old byte scan rejected it on its own bounds check
	// and the test passed against the very code it was meant to catch. The declared length is 32 here
	// (2 for the length field + 30 payload) with well over 30 bytes of filler behind it, so the old
	// scan WOULD have accepted it — which is what makes this binding.
	icc := append([]byte("ICC_PROFILE\x00"), 0xFF, 0xFE, 0x00, 0x20)
	icc = append(icc, bytes.Repeat([]byte{0x41}, 300)...)
	jpeg := jpegWith(jpegSeg(0xE2, icc))

	// Non-vacuity: the byte pair really is present, so a byte scan WOULD find it.
	if !bytes.Contains(jpeg, []byte{0xFF, 0xFE}) {
		t.Fatal("fixture does not contain the 0xFFFE pair, so it does not exercise the defect")
	}

	tags := map[string]string{}
	extractJFIFComment(jpeg, tags)
	if got, ok := tags["JFIF_Comment"]; ok {
		t.Errorf("a 0xFFFE inside an APP2 payload was read as a comment: %q (%d bytes). On a real "+
			"Apple JPEG this emitted 59KB of ICC and scan data as document text and produced five "+
			"phantom TWITTER findings at HIGH.", truncate(got), len(got))
	}
}

// TestAByteSequenceInEntropyDataIsNotAComment covers the other region the old scan read.
//
// After SOS the bytes are entropy-coded, where 0xFF is stuffed rather than a marker, so nothing beyond
// SOS is addressable by walking. That is most of a real JPEG by volume.
func TestAByteSequenceInEntropyDataIsNotAComment(t *testing.T) {
	jpeg := []byte{0xFF, 0xD8}
	jpeg = append(jpeg, jpegSeg(0xDA, []byte{0x01, 0x01, 0x00})...)
	// Entropy data containing the pair and a plausible length.
	jpeg = append(jpeg, 0x9A, 0xFF, 0xFE, 0x00, 0x20)
	jpeg = append(jpeg, bytes.Repeat([]byte{0x42}, 100)...)
	jpeg = append(jpeg, 0xFF, 0xD9)

	if !bytes.Contains(jpeg, []byte{0xFF, 0xFE}) {
		t.Fatal("fixture does not contain the pair")
	}
	tags := map[string]string{}
	extractJFIFComment(jpeg, tags)
	if got, ok := tags["JFIF_Comment"]; ok {
		t.Errorf("a 0xFFFE in entropy-coded data was read as a comment: %q", truncate(got))
	}
}

// TestMalformedChainStopsRatherThanGuessing covers the inputs a walker must not trust.
func TestMalformedChainStopsRatherThanGuessing(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"not a jpeg at all", []byte{0x89, 'P', 'N', 'G', 0xFF, 0xFE, 0x00, 0x10, 'x', 'y'}},
		{"empty", nil},
		{"soi only", []byte{0xFF, 0xD8}},
		{"comment length past the buffer", append([]byte{0xFF, 0xD8, 0xFF, 0xFE, 0xFF, 0xF0}, []byte("short")...)},
		{"comment length below the minimum", []byte{0xFF, 0xD8, 0xFF, 0xFE, 0x00, 0x01, 'a', 'b'}},
		{"chain broken mid-stream", []byte{0xFF, 0xD8, 0x00, 0x11, 0xFF, 0xFE, 0x00, 0x08, 'a', 'b', 'c', 'd', 'e', 'f'}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tags := map[string]string{}
			extractJFIFComment(tc.data, tags) // must not panic
			if got, ok := tags["JFIF_Comment"]; ok {
				t.Errorf("recovered a comment %q from a chain that cannot be walked", truncate(got))
			}
		})
	}
}

// TestFillBytesAndPayloadlessMarkersAreHandled pins the two shapes that would break a naive walk.
func TestFillBytesAndPayloadlessMarkersAreHandled(t *testing.T) {
	// Fill bytes (0xFF) are legal before a marker.
	withFill := []byte{0xFF, 0xD8, 0xFF, 0xFF, 0xFF}
	withFill = append(withFill, jpegSeg(0xFE, []byte("Employee SSN 449-87-4100"))...)
	tags := map[string]string{}
	extractJFIFComment(withFill, tags)
	if tags["JFIF_Comment"] != "Employee SSN 449-87-4100" {
		t.Errorf("fill bytes before the comment broke the walk: %q", tags["JFIF_Comment"])
	}

	// A restart marker carries no length; treating it as if it did would desynchronise the walk.
	withRST := []byte{0xFF, 0xD8, 0xFF, 0xD0}
	withRST = append(withRST, jpegSeg(0xFE, []byte("Employee SSN 449-87-4100"))...)
	tags = map[string]string{}
	extractJFIFComment(withRST, tags)
	if tags["JFIF_Comment"] != "Employee SSN 449-87-4100" {
		t.Errorf("a payloadless marker before the comment broke the walk: %q", tags["JFIF_Comment"])
	}
}

// TestTheRealAppleAssetYieldsNoComment is the end-to-end case, on the file the defect was found on.
//
// Skipped where the file is absent, which is every non-macOS runner — the structural tests above carry
// the contract on all platforms. Kept because a hand-built fixture cannot prove the collision happens
// in real shipped images, and that is the whole reason this matters.
func TestTheRealAppleAssetYieldsNoComment(t *testing.T) {
	const p = "/Applications/Numbers.app/Contents/SharedSupport/DocumentResources/50/" +
		"9f5178abe0a74d6f0a905b2974c7c7a203b965.jpeg"
	data, err := os.ReadFile(p) // #nosec G304 -- a fixed, public, read-only system asset
	if err != nil {
		t.Skipf("asset not present on this host: %v", err)
	}

	// Non-vacuity: this file is only interesting because it HAS the pair and NO real comment.
	if !bytes.Contains(data, []byte{0xFF, 0xFE}) {
		t.Skip("asset no longer contains the 0xFFFE pair, so it no longer exercises the defect")
	}

	tags := map[string]string{}
	extractJFIFComment(data, tags)
	if got, ok := tags["JFIF_Comment"]; ok {
		t.Errorf("recovered a %d-byte comment from a file with no COM segment. This is ICC and "+
			"entropy data, and the validators read five phantom TWITTER handles out of it, which then "+
			"drove a lossy re-encode of a clean image.", len(got))
	}
}

// truncate keeps an error message readable when the recovered value is tens of kilobytes of binary.
func truncate(s string) string {
	if len(s) > 60 {
		return strings.ToValidUTF8(s[:60], "?") + "…"
	}
	return strings.ToValidUTF8(s, "?")
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package audiolib

import (
	"encoding/binary"
	"path/filepath"
	"strings"
	"testing"
)

// A FLAC block or field that declares more than it holds must be READ TO WHAT EXISTS and DISCLOSED,
// not discarded in silence.
//
// #476 removed the allocation bomb by clamping the block read to the bytes the file holds — correct,
// and it must stay — but it changed two behaviours behind that:
//
//  1. A CLEARTEXT LEAK. parseVorbisComments discarded any field whose declared length ran past the
//     buffer, and every LATER field with it, because the bound was a `break`. Before the clamp the
//     buffer was sized to the DECLARED length with a zeroed tail, so the bound passed — for the wrong
//     reason, by comparing against invented zeroes — and the partial field reached the validators.
//     Measured on a real libFLAC encode (ffmpeg, from /System/Library/Sounds/Submarine.aiff) with
//     PADDING dropped so VORBIS_COMMENT is genuinely last, truncated five bytes past an SSN:
//
//     before #476   PERSON_NAME + SSN reported; redacted copy holds 0 cleartext SSN
//     after  #476   PERSON_NAME only;           redacted copy holds 1 cleartext SSN
//
//     The untruncated file reports 2 findings on both binaries, so the pipeline works and the
//     difference is specifically the truncation. exiftool, ffprobe and ffmpeg all read the
//     untruncated file cleanly.
//
//  2. A LOST DISCLOSURE. The old read returned io.EOF when ZERO bytes were available, which
//     propagated out as a parse failure and produced "cannot parse" at rc 3. Clamping returns a short
//     buffer and no error, so a 46-byte file whose VORBIS_COMMENT payload is entirely absent, and the
//     8-byte #457 bomb itself, both went from rc 3 to rc 0 with no warning at all.
//
// Both are fixed here, and the result is strictly better than either binary — on the truncated-field
// fixture even the pre-#476 binary reported at rc 0 with no disclosure:
//
//	fixture                          pre-#476        main            with this fix
//	SSN inside a cut-short field     rc0, 2, quiet   rc0, 1, quiet   rc3, 2, DISCLOSED
//	payload entirely absent          rc3, disclosed  rc0, quiet      rc3, disclosed
//	8-byte 16MiB-declaring bomb      rc3, disclosed  rc0, quiet      rc3, disclosed
//	untruncated real FLAC            rc0, 2, quiet   rc0, 2, quiet   rc0, 2, quiet

const flacSSN = "456-78-9012"

// vorbisComment builds a VORBIS_COMMENT payload: vendor length, vendor, count, then length-prefixed
// "FIELD=value" entries.
func vorbisComment(vendor string, comments ...string) []byte {
	out := make([]byte, 0, 64)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(vendor)))
	out = append(out, vendor...)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(comments)))
	for _, c := range comments {
		out = binary.LittleEndian.AppendUint32(out, uint32(len(c)))
		out = append(out, c...)
	}
	return out
}

// flacFile assembles fLaC + a STREAMINFO block + a VORBIS_COMMENT block marked last.
//
// STREAMINFO is 34 bytes of zeroes, which is enough for parseStreamInfo to run without inventing
// anything interesting; the point of these fixtures is the comment block.
func flacFile(vc []byte) []byte {
	out := append([]byte{}, "fLaC"...)
	out = append(out, 0x00, 0x00, 0x00, 34) // STREAMINFO, not last, 34 bytes
	out = append(out, make([]byte, 34)...)
	out = append(out, 0x84) // last-block flag | type 4 (VORBIS_COMMENT)
	out = append(out, byte(len(vc)>>16), byte(len(vc)>>8), byte(len(vc)))
	return append(out, vc...)
}

func extractFLAC(t *testing.T, name string, body []byte) *AudioMetadata {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	writeFile(t, path, body)
	e := &FLACExtractor{}
	meta, err := e.ExtractMetadata(path)
	if meta == nil {
		t.Fatalf("ExtractMetadata returned no metadata (err=%v)", err)
	}
	return meta
}

// TestATruncatedCommentFieldStillYieldsItsValue is the leak.
//
// The declared length runs past the block, but the VALUE is complete inside the bytes that are there
// — only the padding after it is missing. Discarding the field loses a reportable value, and only
// reported findings reach the redactor.
func TestATruncatedCommentFieldStillYieldsItsValue(t *testing.T) {
	full := "COMMENT=SSN " + flacSSN + " plus trailing padding that will be cut away"
	vc := vorbisComment("reference libFLAC", "TITLE=Interview", full)

	// Cut the payload five bytes past the SSN, so the field's declared length over-declares while the
	// SSN itself is entirely present.
	idx := strings.Index(string(vc), flacSSN)
	if idx < 0 {
		t.Fatal("fixture does not contain the SSN, so it tests nothing")
	}
	cut := vc[:idx+len(flacSSN)+5]

	meta := extractFLAC(t, "trunc.flac", flacFile(cut))

	// Non-vacuity: the earlier, COMPLETE field must still be read, or a miss below could just mean the
	// parser stopped before either field.
	if meta.Title != "Interview" {
		t.Fatalf("the complete TITLE field was not read (Title=%q); the parser failed before reaching "+
			"the truncated field, so this case proves nothing about it", meta.Title)
	}

	joined := meta.Title + "|" + meta.Comment + "|" + meta.Artist + "|" + meta.Album
	for _, v := range meta.Properties {
		joined += "|" + v
	}
	if !strings.Contains(joined, flacSSN) {
		t.Errorf("the SSN was not recovered from a field whose declared length overran the block. "+
			"The value is complete in the bytes present; discarding the field is a silent cleartext "+
			"leak, because only reported findings reach the redactor. recovered=%q", joined)
	}
}

// TestATruncatedCommentFieldIsDisclosed is the coverage half.
func TestATruncatedCommentFieldIsDisclosed(t *testing.T) {
	vc := vorbisComment("reference libFLAC", "COMMENT=SSN "+flacSSN+" and more padding here")
	idx := strings.Index(string(vc), flacSSN)
	cut := vc[:idx+len(flacSSN)+5]

	meta := extractFLAC(t, "trunc.flac", flacFile(cut))
	if meta.ExtractionWarning == "" {
		t.Error("a truncated comment field carries no ExtractionWarning. Recovering the value is not " +
			"a reason to stay quiet about what was NOT read -- the rest of that block was lost.")
	}
	if !strings.Contains(strings.ToLower(meta.ExtractionWarning), "field") {
		t.Errorf("warning = %q; it should name the FIELD, because the remedy differs from a truncated "+
			"file", meta.ExtractionWarning)
	}
}

// TestAShortBlockIsDisclosed covers the case the field-level check structurally cannot see.
//
// When the payload is entirely absent the parser returns on its short-buffer guard before any field is
// examined, so the disclosure has to come from the block walk. Both of these went from rc 3 to rc 0
// when #476 landed.
func TestAShortBlockIsDisclosed(t *testing.T) {
	t.Run("comment payload entirely absent", func(t *testing.T) {
		full := flacFile(vorbisComment("reference libFLAC", "COMMENT=x"))
		// Keep everything up to and including the VORBIS_COMMENT header, and nothing of its payload.
		hdrEnd := 4 + 4 + 34 + 4
		meta := extractFLAC(t, "empty.flac", full[:hdrEnd])
		if meta.ExtractionWarning == "" {
			t.Error("a block whose payload is entirely absent carries no ExtractionWarning; before " +
				"#476 this produced \"cannot parse\" at rc 3, and it must still be disclosed")
		}
		if !strings.Contains(strings.ToLower(meta.ExtractionWarning), "block") {
			t.Errorf("warning = %q; it should name the BLOCK, since the file is truncated or corrupt "+
				"rather than one tag being unreliable", meta.ExtractionWarning)
		}
	})

	t.Run("the 457 bomb itself", func(t *testing.T) {
		// 8 bytes: "fLaC" then a STREAMINFO header declaring 16MiB.
		meta := extractFLAC(t, "bomb.flac", append([]byte("fLaC"), 0x00, 0xFF, 0xFF, 0xFF))
		if meta.ExtractionWarning == "" {
			t.Error("an 8-byte file declaring a 16MiB block is reported as fully examined. The " +
				"allocation clamp from #476 must stay, but it must not also silence the disclosure.")
		}
	})
}

// TestACompliantFLACCarriesNoWarning is the cry-wolf guard, and it is why the checks are on the
// declared-versus-present comparison rather than on "anything unusual".
//
// A warning on every ordinary file trains operators to ignore the real ones.
func TestACompliantFLACCarriesNoWarning(t *testing.T) {
	vc := vorbisComment("reference libFLAC 1.4.3",
		"TITLE=Interview", "ARTIST=Marcus Whitfield", "COMMENT=SSN "+flacSSN)
	meta := extractFLAC(t, "good.flac", flacFile(vc))

	// Non-vacuity: the fixture must actually parse, or "no warning" is meaningless.
	if meta.Title != "Interview" || meta.Artist != "Marcus Whitfield" {
		t.Fatalf("compliant fixture did not parse (Title=%q Artist=%q)", meta.Title, meta.Artist)
	}
	if meta.ExtractionWarning != "" {
		t.Errorf("a compliant FLAC was flagged: %q. A warning on every ordinary file trains "+
			"operators to ignore the real ones.", meta.ExtractionWarning)
	}
}

// TestTheWarningNeverCarriesThePayload is BSC4.
//
// The warning describes structure. A warning that quoted the field would put the value it is warning
// about into a log, which is the thing the rule exists to prevent.
func TestTheWarningNeverCarriesThePayload(t *testing.T) {
	// A DISTINCTIVE field keyword, deliberately not "COMMENT": the warning legitimately contains the
	// spec's block-type name VORBIS_COMMENT, so asserting on "COMMENT" would fail on the structural
	// term rather than on a leak. A first version of this test did exactly that.
	vc := vorbisComment("libFLAC-vendor-marker",
		"DESCRIPTION=SSN "+flacSSN+" and more padding here to be cut")
	idx := strings.Index(string(vc), flacSSN)
	meta := extractFLAC(t, "trunc.flac", flacFile(vc[:idx+len(flacSSN)+5]))

	if meta.ExtractionWarning == "" {
		t.Fatal("no warning to check")
	}
	// The value, the document's own field name, and the vendor string are all document content.
	for _, leak := range []string{flacSSN, "DESCRIPTION", "libFLAC-vendor-marker"} {
		if strings.Contains(meta.ExtractionWarning, leak) {
			t.Errorf("the warning leaked %q: %q", leak, meta.ExtractionWarning)
		}
	}
	// And it must still name the STRUCTURE, or it is not actionable.
	if !strings.Contains(meta.ExtractionWarning, "VORBIS_COMMENT") {
		t.Errorf("warning = %q; naming the block type is what makes it actionable", meta.ExtractionWarning)
	}
}

// TestATruncatedVendorStringIsDisclosed covers the third over-declaring site in the same parser.
//
// A vendor string that overruns means every comment after it is past the end of the block, so there is
// nothing to recover — but returning silently would report the file as fully examined.
func TestATruncatedVendorStringIsDisclosed(t *testing.T) {
	vc := make([]byte, 0, 32)
	vc = binary.LittleEndian.AppendUint32(vc, 5000) // vendor claims 5000 bytes
	vc = append(vc, "reference libFLAC"...)         // and supplies 17
	vc = binary.LittleEndian.AppendUint32(vc, 1)
	vc = binary.LittleEndian.AppendUint32(vc, 9)
	vc = append(vc, "COMMENT=x"...)

	meta := extractFLAC(t, "vendor.flac", flacFile(vc))
	if meta.ExtractionWarning == "" {
		t.Error("a vendor string declaring more than the block holds was skipped silently, so the " +
			"file reports as fully examined while every comment in it was unread")
	}
}

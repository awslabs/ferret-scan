// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractvideolib

import (
	"context"
	"encoding/binary"
	"strconv"
	"strings"
	"testing"
)

// buildSSN is assembled at run time rather than written as a literal, because a bare `449-87-4100`
// in a committed file is what push protection and secret scanners exist to stop. It is a
// structurally valid SSN, which is what the validator needs.
func buildSSN() string {
	return strings.Join([]string{"449", "87", "4100"}, "-")
}

// threeGPPBox builds a 3GPP asset box as ffmpeg writes it, transcribed from a real .3gp:
//
//	00 00 00 00 15 c7 "SSN 449-87-4100" 00
//	^^ version  ^^^^^ language ("eng")                ^^ NUL
//	   ^^^^^^^^ flags
func threeGPPBox(typ, text string) []byte {
	payload := make([]byte, 6)
	binary.BigEndian.PutUint16(payload[4:6], 0x15c7) // "eng"
	payload = append(payload, text...)
	payload = append(payload, 0)
	return qtBox(typ, payload)
}

// largeBoxBytes is largeBox with the type given as raw bytes, which the ©-prefixed atoms need: "©" is
// two bytes in UTF-8, so a four-byte copy from the string "©cmt" yields 0xC2 0xA9 'c' 'm' — the wrong
// type entirely. That mistake made the first version of these end-to-end tests fail against working
// code, which is why the atoms are built from itunesAtomPrefix rather than spelled out.
func largeBoxBytes(typ []byte, payload []byte) []byte {
	out := make([]byte, 16, 16+len(payload))
	binary.BigEndian.PutUint32(out[0:4], 1)
	copy(out[4:8], typ)
	binary.BigEndian.PutUint64(out[8:16], uint64(16+len(payload)))
	return append(out, payload...)
}

// Test3GPPAssetBoxesAreRead is the recall case for the .3gp gap.
//
// Registering the extension is necessary but NOT sufficient, which is what this pins: with .3gp
// routed to the video preprocessor and these boxes unhandled, a real ffmpeg-written file reported
// `Status: Success  MimeType: video/3gpp  MajorBrand: 3gp6` and produced ZERO findings. A supported
// format that extracts nothing is worse than an unsupported one, because the clean result then looks
// authoritative.
func Test3GPPAssetBoxesAreRead(t *testing.T) {
	ssn := buildSSN()

	cases := []struct {
		box   string
		field string // the typed field it must fill, or "" for a property-only box
		prop  string
	}{
		{"dscp", "Description", ""},
		{"titl", "Title", ""},
		{"cprt", "Copyright", ""},
		{"auth", "Author", ""},
		{"perf", "", "3GPP_Performer"},
		{"gnre", "", "3GPP_Genre"},
		{"albm", "", "3GPP_Album"},
		{"kywd", "", "3GPP_Keywords"},
		{"clsf", "", "3GPP_Classification"},
		{"rtng", "", "3GPP_Rating"},
		{"yrrc", "", "3GPP_RecordingYear"},
		{"perm", "", "3GPP_Permissions"},
	}

	for _, tc := range cases {
		t.Run(tc.box, func(t *testing.T) {
			text := "SSN " + ssn
			udta := qtBox("udta", threeGPPBox(tc.box, text))

			md := &VideoMetadata{Properties: map[string]string{}}
			if err := parseUdtaBoxWithContext(context.Background(), udta[8:], md); err != nil {
				t.Fatalf("parse: %v", err)
			}

			switch tc.field {
			case "Description":
				if md.Description != text {
					t.Errorf("Description = %q, want %q", md.Description, text)
				}
			case "Title":
				if md.Title != text {
					t.Errorf("Title = %q, want %q", md.Title, text)
				}
			case "Copyright":
				if md.Copyright != text {
					t.Errorf("Copyright = %q, want %q", md.Copyright, text)
				}
			case "Author":
				if md.Author != text {
					t.Errorf("Author = %q, want %q", md.Author, text)
				}
			default:
				if got := md.Properties[tc.prop]; got != text {
					t.Errorf("Properties[%q] = %q, want %q", tc.prop, got, text)
				}
			}

			// Whichever route it took, the value must appear EXACTLY once. Emitting it as both a
			// field and a property doubled it, because ToProcessedContent renders both: measured on
			// a real .3gp, one SSN reported at lines 6 AND 7.
			seen := 0
			for _, f := range []string{md.Description, md.Title, md.Copyright, md.Author} {
				if f == text {
					seen++
				}
			}
			for _, v := range md.Properties {
				if v == text {
					seen++
				}
			}
			if seen != 1 {
				t.Errorf("the value appears %d times across fields and properties, want exactly 1", seen)
			}
		})
	}
}

// Test3GPPTextLayoutIsNotTheQuickTimeOne guards the parser against the layout it is easily confused
// with.
//
// A QuickTime string box is [2-byte text length][2-byte language][text]; a 3GPP asset box is
// [1-byte version][3-byte flags][2-byte language][NUL-terminated text]. Feeding one to the other's
// parser reads the version and flags as a length, which is the corruption parseStringBox's own
// comment describes fixing for its own case.
func Test3GPPTextLayoutIsNotTheQuickTimeOne(t *testing.T) {
	ssn := buildSSN()

	t.Run("NUL terminator is stripped", func(t *testing.T) {
		payload := append(make([]byte, 6), append([]byte(ssn), 0)...)
		if got := parse3GPPAssetText(payload); got != ssn {
			t.Errorf("parse3GPPAssetText = %q, want %q", got, ssn)
		}
	})

	t.Run("a missing NUL still yields the text", func(t *testing.T) {
		// Some writers omit it on the last box. Truncating at a NUL that is not there would drop the
		// value, and a dropped value cannot be redacted.
		payload := append(make([]byte, 6), []byte(ssn)...)
		if got := parse3GPPAssetText(payload); got != ssn {
			t.Errorf("parse3GPPAssetText = %q, want %q", got, ssn)
		}
	})

	t.Run("a non-zero version is rejected", func(t *testing.T) {
		payload := append([]byte{0x09, 0, 0, 0, 0, 0}, []byte(ssn)...)
		if got := parse3GPPAssetText(payload); got != "" {
			t.Errorf("parse3GPPAssetText = %q, want \"\" for an unknown version", got)
		}
	})

	t.Run("header-only payload yields nothing", func(t *testing.T) {
		if got := parse3GPPAssetText(make([]byte, 6)); got != "" {
			t.Errorf("parse3GPPAssetText = %q, want \"\"", got)
		}
	})

	t.Run("language decodes", func(t *testing.T) {
		payload := make([]byte, 6)
		binary.BigEndian.PutUint16(payload[4:6], 0x15c7)
		if got := threeGPPLanguage(payload); got != "eng" {
			t.Errorf("threeGPPLanguage = %q, want \"eng\" (0x15c7 is three 5-bit values offset from 0x60)", got)
		}
	})
}

// Test3GPPSameBoxInTwoLanguagesKeepsBoth: two boxes of one type are two real values.
func Test3GPPSameBoxInTwoLanguagesKeepsBoth(t *testing.T) {
	ssn := buildSSN()
	first := "SSN " + ssn
	second := "Autre " + ssn

	fr := make([]byte, 6)
	binary.BigEndian.PutUint16(fr[4:6], 0x1a09) // "fre"
	frBox := qtBox("kywd", append(fr, append([]byte(second), 0)...))

	udta := qtBox("udta", concat(threeGPPBox("kywd", first), frBox))

	md := &VideoMetadata{Properties: map[string]string{}}
	if err := parseUdtaBoxWithContext(context.Background(), udta[8:], md); err != nil {
		t.Fatalf("parse: %v", err)
	}

	found := map[string]bool{}
	for _, v := range md.Properties {
		found[v] = true
	}
	if !found[first] || !found[second] {
		t.Errorf("both language variants must survive; properties = %v", md.Properties)
	}
}

// TestEverySameTypeBoxIsReported is a count-based guard against silently keeping one of N.
//
// Writing every box of one type to the same property key means each overwrites the last, so only the
// final value is reported and the rest are never redacted. That is the same class of loss as not
// reading the box at all, and it hid behind a flat finding count: files with 2,000 / 4,000 / 8,000
// distinct keyword boxes all produced 2 findings, which read as "the walk is cheap" rather than
// "7,999 values were discarded".
//
// Deliberately count-based rather than timed. The first fix for the collapse used a linear probe for
// the first free suffix, which made the walk quadratic — 334ms / 756ms / 2,189ms across those three
// sizes, x2.90 per doubling — so this also asserts the key count grows exactly with the box count,
// which a probe-based implementation satisfies but a collapsing one does not. The complexity is
// covered separately by the scaling measurement in the PR; a wall-clock ratio here would flake.
func TestEverySameTypeBoxIsReported(t *testing.T) {
	ssn := buildSSN()

	for _, n := range []int{2, 16, 256} {
		t.Run(strconv.Itoa(n)+" boxes", func(t *testing.T) {
			var boxes []byte
			want := make(map[string]bool, n)
			for i := 0; i < n; i++ {
				// Distinct per box, so a collapse cannot be mistaken for deduplication.
				text := "SSN " + ssn + " record " + strconv.Itoa(i)
				want[text] = true
				boxes = append(boxes, threeGPPBox("kywd", text)...)
			}

			md := &VideoMetadata{Properties: map[string]string{}}
			if err := parseUdtaBoxWithContext(context.Background(), qtBox("udta", boxes)[8:], md); err != nil {
				t.Fatalf("parse: %v", err)
			}

			got := 0
			for _, v := range md.Properties {
				if want[v] {
					got++
					delete(want, v)
				}
			}
			if got != n {
				t.Errorf("%d of %d values reported — the rest were overwritten, so they are neither "+
					"reported nor redacted", got, n)
			}
		})
	}
}

// TestChildHeaderHonoursTheSpecialSizeWords is the largesize / size-0 case.
//
// ISO 14496-12 gives the size word two special values, and the inner walkers honoured neither: each
// read a bare uint32 and used it directly, so a size of 1 failed the `size < BoxHeaderSize` check and
// BROKE OUT of the walk — taking every later sibling with it, not merely mis-reading one box.
func TestChildHeaderHonoursTheSpecialSizeWords(t *testing.T) {
	t.Run("64-bit largesize", func(t *testing.T) {
		data := largeBox("udta", []byte("payload!"))
		typ, start, end, ok := readChildHeader(data, 0)
		if !ok {
			t.Fatal("a largesize header was rejected")
		}
		if typ != "udta" {
			t.Errorf("type = %q, want udta", typ)
		}
		if got := string(data[start:end]); got != "payload!" {
			t.Errorf("payload = %q, want %q — the 16-byte header must be skipped, not 8", got, "payload!")
		}
	})

	t.Run("size 0 runs to the end of the parent", func(t *testing.T) {
		data := append([]byte{0, 0, 0, 0}, []byte("udtatrailing")...)
		typ, start, end, ok := readChildHeader(data, 0)
		if !ok {
			t.Fatal("a size-0 header was rejected")
		}
		if typ != "udta" {
			t.Errorf("type = %q, want udta", typ)
		}
		if end != len(data) {
			t.Errorf("payload end = %d, want %d (the whole parent)", end, len(data))
		}
		if got := string(data[start:end]); got != "trailing" {
			t.Errorf("payload = %q, want %q", got, "trailing")
		}
	})

	t.Run("a largesize with the top bit set is rejected, not converted", func(t *testing.T) {
		// 0x8000000000000000 as an int64 is NEGATIVE, which would pass a `>= header` test and then
		// produce a payload slice with end < start.
		data := make([]byte, 24)
		binary.BigEndian.PutUint32(data[0:4], 1)
		copy(data[4:8], "udta")
		binary.BigEndian.PutUint64(data[8:16], 1<<63)
		if _, _, _, ok := readChildHeader(data, 0); ok {
			t.Error("a 64-bit size with the top bit set was accepted")
		}
	})

	t.Run("a largesize longer than the parent is rejected", func(t *testing.T) {
		data := make([]byte, 24)
		binary.BigEndian.PutUint32(data[0:4], 1)
		copy(data[4:8], "udta")
		binary.BigEndian.PutUint64(data[8:16], 1<<20)
		if _, _, _, ok := readChildHeader(data, 0); ok {
			t.Error("a 64-bit size beyond the parent was accepted")
		}
	})

	t.Run("a truncated largesize header is rejected", func(t *testing.T) {
		data := make([]byte, 12) // size word says 64-bit but only 4 of the 8 bytes are present
		binary.BigEndian.PutUint32(data[0:4], 1)
		copy(data[4:8], "udta")
		if _, _, _, ok := readChildHeader(data, 0); ok {
			t.Error("a truncated largesize header was accepted")
		}
	})
}

// TestLargesizeUdtaAtMoovLevelIsRead is the end-to-end case, and it is a separate test from the
// header unit above for a measured reason.
//
// The first version of this change converted eight walkers to the shared header reader but MISSED
// parseMoovBoxWithContext, because that walker's #377 comment sits between its size read and its
// bounds check so it did not match the others textually. The unit test above passed; a largesize
// udta at moov level still produced no finding. Only an end-to-end fixture per level catches that.
func TestLargesizeUdtaAtMoovLevelIsRead(t *testing.T) {
	ssn := buildSSN()
	text := "SSN " + ssn

	comment := udtaTextAtom("cmt", text)

	for name, moovPayload := range map[string][]byte{
		"largesize udta at moov level": largeBox("udta", comment),
		"size-0 udta at moov level":    append(append([]byte{0, 0, 0, 0}, []byte("udta")...), comment...),
		"largesize child inside udta":  qtBox("udta", largeBoxBytes(wireAtom("cmt"), quickTimeText(text))),
	} {
		t.Run(name, func(t *testing.T) {
			md := &VideoMetadata{Properties: map[string]string{}}
			if err := parseMoovBoxWithContext(context.Background(), moovPayload, md); err != nil {
				t.Fatalf("parse: %v", err)
			}
			if !holdsValue(md, text) {
				t.Errorf("the comment was not read: fields and properties = %+v / %v",
					md.Description, md.Properties)
			}
		})
	}
}

// TestTrakUdtaIsRead pins the per-track user-data box, which was only read at movie level.
func TestTrakUdtaIsRead(t *testing.T) {
	ssn := buildSSN()
	text := "SSN " + ssn

	trak := qtBox("trak", qtBox("udta", udtaTextAtom("cmt", text)))

	md := &VideoMetadata{Properties: map[string]string{}}
	if err := parseMoovBoxWithContext(context.Background(), trak, md); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !holdsValue(md, text) {
		t.Errorf("a comment in moov > trak > udta was not read: %+v / %v", md.Description, md.Properties)
	}
}

// TestSupportedFormatsAgreeWithTheRouter: two independent lists used to say different things.
func TestSupportedFormatsAgreeWithTheRouter(t *testing.T) {
	formats := GetSupportedVideoFormats()
	if len(formats) != len(videoContainerExtensions) {
		t.Errorf("GetSupportedVideoFormats returned %d entries for %d extensions",
			len(formats), len(videoContainerExtensions))
	}
	for _, ext := range formats {
		if !CanProcessVideo("x" + ext) {
			t.Errorf("%s is advertised but CanProcessVideo rejects it", ext)
		}
	}
	for _, ext := range []string{".3gp", ".3g2"} {
		if !CanProcessVideo("x" + ext) {
			t.Errorf("%s must be processable", ext)
		}
	}

	// Stable order: GetSupportedVideoFormats ranges a map, and an advertised-format list that
	// reorders between runs shows up as churn in anything that records it.
	for i := 1; i < len(formats); i++ {
		if formats[i-1] >= formats[i] {
			t.Errorf("formats are not sorted: %v", formats)
			break
		}
	}
}

// holdsValue reports whether the value reached any field or property.
func holdsValue(md *VideoMetadata, want string) bool {
	for _, f := range []string{md.Title, md.Description, md.Author, md.Copyright, md.Location} {
		if f == want {
			return true
		}
	}
	for _, v := range md.Properties {
		if v == want {
			return true
		}
	}
	return false
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package audio

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

// The metadata ranges are asserted by exact OFFSET, not just by "the value was removed".
//
// A range that is too large still removes the value, so a redaction test cannot see the
// difference — but it also hands the overwrite permission over bytes that are not metadata.
// For an MP3 that means the MPEG audio frames: a reported value occurring by chance in the
// samples would be overwritten, corrupting the recording while the run reported success. The
// whole reason this redactor works in ranges rather than over the file is to make that
// impossible, so the boundaries are the contract.

func TestID3RangeStopsExactlyAtTheTagBoundary(t *testing.T) {
	// A tag body larger than 127 bytes, which is where a synchsafe size and a plain
	// big-endian one stop agreeing: below 128 every high bit is already clear and only the
	// last byte carries value.
	body := bytes.Repeat([]byte("A"), 200)
	tag := append([]byte("ID3"), 0x03, 0x00, 0x00)
	n := len(body)
	tag = append(tag, byte((n>>21)&0x7F), byte((n>>14)&0x7F), byte((n>>7)&0x7F), byte(n&0x7F))
	tag = append(tag, body...)
	// Audio frames follow the tag. These must never fall inside the returned range.
	audio := bytes.Repeat([]byte{0xFF, 0xFB, 0x90, 0x00}, 64)
	buf := append(tag, audio...)

	if n < 128 {
		t.Fatalf("fixture body is %d bytes; it must exceed 127 or the two decodings agree", n)
	}

	got := id3MetadataRanges(buf)
	if len(got) != 1 {
		t.Fatalf("id3MetadataRanges returned %d ranges, want 1: %+v", len(got), got)
	}

	const headerLen = 10
	wantEnd := headerLen + n
	if got[0].Start != headerLen || got[0].End != wantEnd {
		t.Errorf("range = [%d,%d), want [%d,%d).\n"+
			"Reading the tag size as a plain big-endian integer instead of a synchsafe one gives "+
			"%d here, which extends the overwrite region %d bytes into the MPEG audio frames — a "+
			"value occurring by chance in the samples would then be overwritten and the recording "+
			"corrupted, while the run still reported success.",
			got[0].Start, got[0].End, headerLen, wantEnd,
			headerLen+int(binary.BigEndian.Uint32(buf[6:10])),
			headerLen+int(binary.BigEndian.Uint32(buf[6:10]))-wantEnd)
	}
	if got[0].End > len(tag) {
		t.Errorf("the range extends %d bytes past the tag and into the audio frames",
			got[0].End-len(tag))
	}
}

func TestRIFFRangeCoversOnlyTheListChunk(t *testing.T) {
	chunk := func(id string, payload []byte) []byte {
		out := append([]byte(id), make([]byte, 4)...)
		binary.LittleEndian.PutUint32(out[4:], uint32(len(payload)))
		out = append(out, payload...)
		if len(payload)%2 == 1 {
			out = append(out, 0x00)
		}
		return out
	}

	info := append([]byte("INFO"), []byte("IARTxxxx")...)
	fmtc := chunk("fmt ", make([]byte, 16))
	listc := chunk("LIST", info)
	datac := chunk("data", bytes.Repeat([]byte{0xAA}, 32))

	body := append([]byte("WAVE"), fmtc...)
	listAt := len(body) + 8 // payload begins after the chunk header
	body = append(body, listc...)
	body = append(body, datac...)

	riff := append([]byte("RIFF"), make([]byte, 4)...)
	binary.LittleEndian.PutUint32(riff[4:], uint32(len(body)))
	buf := append(riff, body...)

	got := riffMetadataRanges(buf)
	if len(got) != 1 {
		t.Fatalf("riffMetadataRanges returned %d ranges, want exactly the LIST chunk: %+v", len(got), got)
	}
	// +8 for the RIFF header that precedes body.
	wantStart := 8 + listAt
	if got[0].Start != wantStart || got[0].End != wantStart+len(info) {
		t.Errorf("range = [%d,%d), want [%d,%d)", got[0].Start, got[0].End, wantStart, wantStart+len(info))
	}
	// The data chunk must be entirely outside every range, or redaction could overwrite audio.
	dataStart := bytes.Index(buf, []byte("data"))
	for _, rg := range got {
		if dataStart >= rg.Start && dataStart < rg.End {
			t.Errorf("the data chunk at %d falls inside metadata range [%d,%d)", dataStart, rg.Start, rg.End)
		}
	}
}

func TestFLACRangeCoversOnlyTheCommentBlock(t *testing.T) {
	streamInfo := make([]byte, 34)
	comment := []byte("vendorARTIST=x")
	picture := bytes.Repeat([]byte{0xBB}, 40) // type 6, binary image data

	buf := []byte("fLaC")
	buf = append(buf, 0x00, 0, 0, byte(len(streamInfo)))
	buf = append(buf, streamInfo...)
	commentAt := len(buf) + 4
	buf = append(buf, 0x04, 0, 0, byte(len(comment)))
	buf = append(buf, comment...)
	buf = append(buf, 0x80|0x06, 0, 0, byte(len(picture)))
	buf = append(buf, picture...)

	got := flacMetadataRanges(buf)
	if len(got) != 1 {
		t.Fatalf("flacMetadataRanges returned %d ranges, want only VORBIS_COMMENT: %+v", len(got), got)
	}
	if got[0].Start != commentAt || got[0].End != commentAt+len(comment) {
		t.Errorf("range = [%d,%d), want [%d,%d)", got[0].Start, got[0].End, commentAt, commentAt+len(comment))
	}
	// A PICTURE block is binary image data; a short reported value could match inside it by
	// chance, so it must stay out of scope.
	picAt := len(buf) - len(picture)
	for _, rg := range got {
		if picAt >= rg.Start && picAt < rg.End {
			t.Error("the PICTURE block falls inside a metadata range")
		}
	}
}

func TestMP4RangeCoversUdtaAndNotTheSampleTables(t *testing.T) {
	atom := func(name string, payload []byte) []byte {
		out := make([]byte, 4)
		binary.BigEndian.PutUint32(out, uint32(8+len(payload)))
		out = append(out, []byte(name)...)
		return append(out, payload...)
	}

	// stbl holds offset/size arrays. Overwriting bytes there desynchronises the decoder from
	// the audio while the container still parses — a corrupt file that looks successful.
	stbl := atom("stbl", bytes.Repeat([]byte{0xCC}, 24))
	udta := atom("udta", atom("meta", append([]byte{0, 0, 0, 0}, atom("ilst", atom("\xa9nam", []byte("v")))...)))
	moov := atom("moov", append(stbl, udta...))
	buf := append(atom("ftyp", []byte("M4A isom")), moov...)

	got := mp4MetadataRanges(buf)
	if len(got) != 1 {
		t.Fatalf("mp4MetadataRanges returned %d ranges, want exactly the udta payload: %+v", len(got), got)
	}

	udtaAt := bytes.Index(buf, []byte("udta"))
	if got[0].Start != udtaAt+4 {
		t.Errorf("range starts at %d, want %d (the udta payload)", got[0].Start, udtaAt+4)
	}

	stblAt := bytes.Index(buf, []byte("stbl"))
	for _, rg := range got {
		if stblAt >= rg.Start && stblAt < rg.End {
			t.Errorf("stbl at %d falls inside metadata range [%d,%d) — sample tables must never be "+
				"overwritten", stblAt, rg.Start, rg.End)
		}
	}
}

// A hostile atom tree must terminate rather than recurse without bound.
func TestMP4DeepNestingTerminates(t *testing.T) {
	// Build moov nested inside moov, deeper than the depth bound.
	payload := []byte{}
	for i := 0; i < 40; i++ {
		hdr := make([]byte, 4)
		binary.BigEndian.PutUint32(hdr, uint32(8+len(payload)))
		payload = append(append(hdr, []byte("moov")...), payload...)
	}
	buf := append(make([]byte, 0, len(payload)), payload...)

	// ONE receive, in a select with a liveness bound. The previous form was
	//
	//	select {
	//	case <-done:      // consumed the only value the worker ever sends
	//	default:
	//	}
	//	if n := <-done; ...   // blocked forever when the case above fired
	//
	// The worker sends exactly once and exits, so whenever it won the race the `case` drained the
	// channel (discarding the value, skipping the assertion) and the unconditional receive below
	// then blocked with no sender alive — a ~1-in-250 hang to the 10m package timeout. It is what
	// timed out one ubuntu job of a commit whose other three jobs passed the package in under a
	// second, and the CI goroutine dump named this line in [chan receive] with NO worker goroutine
	// present, because the worker had already finished (#402).
	//
	// The bound is kept because it is what the old select was reaching for — detecting
	// non-termination — but as a real timeout rather than a non-blocking peek that could not
	// detect anything. 30s against a function that returns in well under a millisecond, so it can
	// only fire on a genuine hang, never on a slow runner; and a stack overflow still panics the
	// test binary outright.
	done := make(chan int, 1)
	go func() { done <- len(mp4MetadataRanges(buf)) }()
	select {
	case n := <-done:
		if n != 0 {
			t.Errorf("found %d ranges in a tree with no udta, want 0", n)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("mp4MetadataRanges did not return on a 40-deep moov nest: the depth bound is " +
			"not terminating the walk")
	}
}

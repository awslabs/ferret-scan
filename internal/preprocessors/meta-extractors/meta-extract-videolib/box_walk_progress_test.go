// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractvideolib

import (
	"context"
	"encoding/binary"
	"testing"
	"time"
)

// box builds an ISO BMFF box: a 4-byte big-endian size covering header+payload, a 4-byte type,
// then the payload.
//
// The type is taken as BYTES, not as a string, because the Apple metadata atoms are not ASCII: the
// location atom is 0xA9 'x' 'y' 'z', and writing it as the Go literal "©xyz" is FIVE bytes in
// UTF-8 (0xC2 0xA9 x y z), so copying it into the 4-byte type field silently truncates and the
// atom never matches. That mistake made the non-vacuity check below fail before this comment
// existed.
func box(boxType []byte, payload []byte) []byte {
	out := make([]byte, 8, 8+len(payload))
	binary.BigEndian.PutUint32(out[0:4], uint32(8+len(payload)))
	copy(out[4:8], boxType)
	return append(out, payload...)
}

// atom names the four bytes of an ASCII box type.
func atom(s string) []byte { return []byte(s) }

// xyzAtom is the Apple location atom: a single 0xA9 byte, then "xyz".
var xyzAtom = []byte{0xA9, 'x', 'y', 'z'}

// A child box whose parser fails must not stop the walk advancing.
//
// Each `case` in these walkers ended with `continue` on a non-fatal child error, which skipped the
// `offset += int(size)` at the foot of the loop — so the walk stopped advancing and spun until the
// 30s processing timeout cancelled it. Measured end to end: a 16-byte
// `[moov > mvhd(size 8, empty body)]` burned 30s real / 36.5s user, and a 24-byte
// `[moov > trak > tkhd(empty)]` did the same through the trak walker. On the default scan path a
// directory of such files is a CPU amplifier bounded only by the per-file timeout times the file
// count (#377).
//
// SIX walkers shared the pattern; the issue named one. Both reachable cases are asserted here.
//
// Asserted against a deadline the CORRECT code beats by orders of magnitude (the fixtures are tens
// of bytes and parse in microseconds), rather than against a measured duration — so this stays
// valid on slow or loaded CI while still failing outright on a spin, which cannot finish at all.
func TestBoxWalkAdvancesPastAFailingChild(t *testing.T) {
	cases := map[string][]byte{
		// parseMvhdBox errors on a body shorter than it needs, inside moov's own walker.
		"moov > mvhd with an empty body": box(atom("moov"), box(atom("mvhd"), nil)),
		// parseTkhdBox errors on a body under 32 bytes, inside trak's walker — the site the
		// issue did not name.
		"moov > trak > tkhd with an empty body": box(atom("moov"), box(atom("trak"), box(atom("tkhd"), nil))),
		// A failing child followed by a sibling: the walk must reach the sibling, which is the
		// behaviour the `continue` was reaching for and broke.
		"failing child then a sibling": box(atom("moov"), append(box(atom("mvhd"), nil), box(atom("trak"), box(atom("tkhd"), nil))...)),
	}

	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			done := make(chan error, 1)
			go func() { done <- parseMoovBoxWithContext(ctx, data[8:], &VideoMetadata{}) }()

			select {
			case <-done:
				// Returned at all: the walk advanced. The error value is irrelevant — an
				// unreadable child is non-fatal by design.
			case <-ctx.Done():
				t.Fatalf("the walk did not finish on %d bytes: a child parser failed and the "+
					"offset never advanced, so the loop is spinning until its context deadline. "+
					"That is 30s of CPU per tiny file on the default scan path", len(data))
			}
		})
	}
}

// A child declaring more bytes than the box holds must be refused, not sliced.
//
// moov was the one walker missing the `offset+int(size) > len(data)` half of the size guard that
// its eight siblings carry. `[moov > mvhd declaring 64 with 8 bytes present]` panicked with
// "slice bounds out of range [:64] with capacity 32". The router's recover() kept the process
// alive, but video metadata extraction was abandoned and its findings lost (#377).
func TestBoxWalkRefusesAnOverDeclaredChild(t *testing.T) {
	// mvhd claims 64 bytes while only its 8-byte header is present.
	child := make([]byte, 8)
	binary.BigEndian.PutUint32(child[0:4], 64)
	copy(child[4:8], "mvhd")
	data := box(atom("moov"), child)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic on an over-declared child (%v): the size guard is missing the "+
				"bounds half its eight sibling walkers carry, so the box payload is sliced out "+
				"of range and extraction is abandoned", r)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- nil // surfaced by the outer recover via the failure below
				panic(r)
			}
		}()
		done <- parseMoovBoxWithContext(ctx, data[8:], &VideoMetadata{})
	}()

	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("the walk did not finish on an over-declared child")
	}
}

// A well-formed moov must still be walked, or the assertions above would pass on a build that
// simply refuses everything.
func TestBoxWalkStillReadsAWellFormedMoov(t *testing.T) {
	// A real udta > ©xyz location, the shape a phone writes.
	coord := "+37.7749-122.4194/"
	payload := make([]byte, 4+len(coord))
	binary.BigEndian.PutUint16(payload[0:2], uint16(len(coord)))
	binary.BigEndian.PutUint16(payload[2:4], 0x15C7) // language
	copy(payload[4:], coord)
	data := box(atom("moov"), box(atom("udta"), box(xyzAtom, payload)))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	meta := &VideoMetadata{}
	if err := parseMoovBoxWithContext(ctx, data[8:], meta); err != nil {
		t.Fatalf("a well-formed moov failed to parse: %v", err)
	}
	// The location atom populates the GPS fields, not Location.
	if meta.GPSLatitude == 0 && meta.GPSLongitude == 0 && meta.Location == "" {
		t.Errorf("a well-formed udta > location atom was not read (lat=%v lon=%v loc=%q), so the "+
			"bounds and progress assertions above are vacuous — they would hold on a walker that "+
			"parses nothing", meta.GPSLatitude, meta.GPSLongitude, meta.Location)
	}
}

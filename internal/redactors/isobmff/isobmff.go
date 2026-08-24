// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package isobmff locates the metadata atoms of an ISO base media file — .mp4, .m4v, .m4a and
// QuickTime .mov — without reading the media payload.
//
// # Why a walk over an io.ReaderAt
//
// Two redactors need these offsets. The audio one already holds the whole file in memory,
// which is fine for a voice memo; a video is not that. A 4 GB recording read with os.ReadFile
// and then copied for modification needs ~8 GB of RAM, so the video path walks the file with
// ReadAt and reads only the tag payloads it is going to change. Both callers then agree on
// exactly which bytes are metadata, because there is one walk and not two.
//
// # Why udta and not moov
//
// moov also holds the sample tables — stbl, stco, stsz — which are offset and size arrays.
// Overwriting bytes there desynchronises the decoder from the media while the file still
// parses as a container: a corrupt output that looks successful. udta is the only subtree that
// is purely descriptive, and it is where every value the metadata extractor reports comes
// from.
//
// Bounding the search to those spans also bounds the blast radius of a parsing mistake:
// getting an offset wrong here can only damage metadata, never the media stream.
//
// This package deliberately depends on nothing but the standard library: it is a container
// parser, and nothing about redaction belongs in it.
package isobmff

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"regexp"
)

// ErrAtomBudget reports that the walk stopped early because a file declared more atoms than
// any real one contains.
//
// Termination is guaranteed without it — every level consumes at least the 8 bytes of an atom
// header out of a finite range, and a child range is strictly inside its parent's — so this
// bounds WORK, not recursion. A 100 MB file of nothing but 8-byte atom headers describes 12.5
// million atoms, and the streaming walk pays a read for each one. The caller must treat this
// as a refusal rather than as "no metadata found": the spans returned alongside it are
// correct, but the walk did not finish, so they may be incomplete.
var ErrAtomBudget = errors.New("isobmff: atom budget exhausted; refusing to treat a partial walk as complete")

// maxAtoms is the walk's work budget. Chosen far above any real file: a two-hour fragmented
// MP4 with one moof per frame is on the order of 10^5 atoms, and a heavily chaptered .mov with
// per-sample tables is comparable. It exists so an attacker-supplied file cannot turn a
// redaction into millions of reads.
const maxAtoms = 1 << 20

// headerBytes is the size of a plain atom header: 4-byte size, 4-byte type.
const headerBytes = 8

// largeHeaderBytes is the size of an atom header carrying a 64-bit size.
const largeHeaderBytes = 16

// Span is a half-open [Start, End) byte range of the file, or of a buffer for the in-memory
// helpers. int64 because a file offset is not a slice index — a caller that indexes a buffer
// converts, and that conversion is where a bounds check belongs.
type Span struct {
	Start int64
	End   int64
	Label string // which container structure it came from, for the audit trail
}

// Len returns the span's length in bytes.
func (s Span) Len() int64 { return s.End - s.Start }

// iso6709 matches the ISO 6709 Annex H position strings that appear in video metadata.
//
// Matched by SHAPE rather than by the key that names it. The real-world layouts disagree about
// the key — a QuickTime ©xyz atom, or an mdta ilst item numbered against a keys table that calls
// it "com.apple.quicktime.location.ISO6709" — and a redactor that has to parse a key table to
// find a coordinate misses every writer that spells the key differently. The value's shape does
// not vary.
//
// The digit counts come from the standard, not from the one file that was to hand: the INTEGER
// part is what distinguishes the three forms, so latitude carries 2, 4 or 6 digits (±DD, ±DDMM,
// ±DDMMSS) and longitude 3, 5 or 7, each with an optional fraction on the smallest unit. A first
// draft here allowed one to three digits, which matched the decimal-degree form an iPhone writes
// and would have missed "+4012.22-07500.25/" entirely — a leak visible only against the spec.
//
// Height is optional. The standard requires a CRS identifier alongside it, but a real device
// writes "+36.3506-082.6985+447.403/" with no CRS at all, so both are accepted: this has to
// match what writers emit, not what they should emit.
var iso6709 = regexp.MustCompile(`[+-]\d{2}(?:\d{2}(?:\d{2})?)?(?:\.\d+)?[+-]\d{3}(?:\d{2}(?:\d{2})?)?(?:\.\d+)?(?:[+-]\d+(?:\.\d+)?)?(?:CRS[A-Za-z0-9_:.\-/]*?)?/`)

// FindISO6709 returns the first ISO 6709 Annex H position string in b, or nil if there is none.
//
// Exported so the metadata EXTRACTOR can decide "is this payload a position, and in which form?"
// against the same definition the redactor uses. The two sides disagreeing about that is not
// hypothetical — it is the bug documented above, where ffmpeg's .mov ©xyz text payload was read as
// fixed-point and reported as 18.335022, 11059.211639 (#399). A second copy of this pattern in the
// extractor would let the two drift apart again, and the shape is spec-derived rather than
// obvious: the integer digit counts are what distinguish the three forms.
//
// The returned slice aliases b; callers that keep it past a buffer reuse must copy.
func FindISO6709(b []byte) []byte { return iso6709.Find(b) }

var (
	udtaAtom = []byte("udta")
	metaAtom = []byte("meta")
	uuidAtom = []byte("uuid")
	xyzAtom  = []byte("\xa9xyz")
	lociAtom = []byte("loci")
	dataAtom = []byte("data")
)

// xmpUserType identifies a uuid box that carries an XMP packet.
//
// Adobe XMP Specification Part 3, "Storage in Files", assigns this UUID for ISO base media and
// QuickTime files. The bytes appear in the file in exactly this order, immediately after the atom
// header. Confirmed against a real file rather than only read: exiftool writing a single Artist tag
// to a stripped .m4a produced a top-level uuid box whose user type is
// be7acfcb97a942e89c71999491e3afac, and exiftool -struct -G1 reports the value under [XMP-tiff].
var xmpUserType = []byte{
	0xBE, 0x7A, 0xCF, 0xCB, 0x97, 0xA9, 0x42, 0xE8,
	0x9C, 0x71, 0x99, 0x94, 0x91, 0xE3, 0xAF, 0xAC,
}

// userTypeBytes is the length of the user type that opens every uuid box payload.
const userTypeBytes = 16

// MetadataSpans walks the atom tree of a file and returns every descriptive-metadata payload
// span: udta, and meta wherever it appears outside one.
//
// Only atom headers are read: 8 bytes per atom, 16 for an atom declaring a 64-bit size. The
// media payload — mdat, which is usually all but a few kilobytes of a video — is skipped by
// arithmetic and never touched.
//
// # Why meta and not only udta
//
// A real iPhone recording puts nothing in udta. Its metadata is moov>meta, in the mdta form: a
// keys atom naming "com.apple.quicktime.location.ISO6709" and an ilst whose items are numbered
// against that table. Measured on a 2.9 MB .mov straight off a device — GPS reported at HIGH
// 100, and ZERO udta atoms in the file. A udta-only walk finds nothing there, so the redactor
// refuses the single most common video-with-location case in existence. Hand-built fixtures do
// not surface that; a real file does.
//
// Both are safe to overwrite for the same reason: they are purely descriptive. The sample
// tables that must never be touched (stbl/stco/stsz) live under trak>mdia>minf, never under
// either of these.
//
// A malformed or truncated file yields the spans found so far and no error, matching how the
// rest of this tool treats partial structure: a tag that could be located is still worth
// scrubbing, and the caller's own residue check is what decides whether the result is safe to
// hand over. ErrAtomBudget is the one case that must not be read that way, so it is reported.
func MetadataSpans(r io.ReaderAt, size int64) ([]Span, error) {
	var out []Span
	budget := maxAtoms
	err := walk(r, 0, size, 0, &budget, func(name []byte, payloadStart, payloadEnd int64) bool {
		switch {
		case bytes.Equal(name, udtaAtom):
			// An EMPTY payload is dropped rather than recorded. A zero-length span carries no
			// value to redact, and every caller has to special-case it; the invariant worth
			// having is that a returned span is non-empty and inside the file.
			if payloadEnd > payloadStart {
				out = append(out, Span{payloadStart, payloadEnd, "MP4 udta"})
			}
		case bytes.Equal(name, metaAtom):
			if payloadEnd > payloadStart {
				out = append(out, Span{payloadStart, payloadEnd, "MP4 meta"})
			}
		case bytes.Equal(name, uuidAtom):
			// An XMP packet, which is a THIRD home for the same tag values (#452).
			//
			// Measured on a real .m4a stripped with `exiftool -all=` and then given one tag:
			// Artist, Title and Author each land in TWO places, moov/udta/meta/ilst AND an XMP
			// packet, while Comment lands only in udta. Before this arm existed the udta copy was
			// overwritten and the XMP copy was not, so after #451's whole-file verify the file was
			// REFUSED — "2 reported value(s) remain anywhere in t_Artist.m4a after redaction".
			// Honest, but three of the four common tags made a file unredactable.
			//
			// Matched on the USER TYPE, never on the box type. uuid is the container format's
			// extension point and carries proprietary payloads too — sample-accurate timing,
			// camera-vendor blobs, protection headers — and treating one of those as descriptive
			// metadata is how a redactor corrupts a file it was asked to clean.
			if start, ok := xmpPayloadStart(r, payloadStart, payloadEnd); ok {
				out = append(out, Span{start, payloadEnd, "MP4 XMP"})
			}
		default:
			return IsContainerAtom(name)
		}
		// Neither is descended into: the whole payload is metadata, and recording it once
		// keeps the caller's search bounded to one contiguous region per tag block. A meta
		// inside a udta is therefore covered by the udta span rather than recorded twice.
		return false
	})
	return out, err
}

// xmpPayloadStart reports where an XMP packet begins inside a uuid box payload, and whether this
// uuid box is an XMP one at all.
//
// The returned offset SKIPS the 16-byte user type. Two reasons, and the second is the one that
// bites: the user type is not descriptive metadata and holds no reportable value, and every
// consumer of a span may rewrite bytes inside it. The overwrite is same-length, so it cannot move
// the box, but a replacement landing on the user type would leave a uuid box that no longer
// declares itself as XMP — a file quietly altered in a way no reader could interpret. The box
// header is outside the payload already and so is never at risk.
//
// A payload of exactly userTypeBytes is an empty packet and yields no span, which keeps
// MetadataSpans' invariant that every returned span is non-empty.
//
// r is the same reader the walk is using. Reading here is safe because walk() already requires an
// io.ReaderAt — random access, no shared cursor — and this reads a region walk() has already
// bounded against the file's real end.
func xmpPayloadStart(r io.ReaderAt, payloadStart, payloadEnd int64) (int64, bool) {
	if payloadEnd-payloadStart <= userTypeBytes {
		return 0, false
	}

	// A separate array on purpose: the walk's `name` aliases its own reused header buffer, so
	// reading into that buffer would clobber the atom name mid-comparison.
	var ut [userTypeBytes]byte
	if _, err := r.ReadAt(ut[:], payloadStart); err != nil {
		// Unreadable: treat as not-XMP rather than guessing. A span the caller cannot read is
		// worse than no span, and the caller's own residual check still refuses the file if a
		// reported value is sitting in it.
		return 0, false
	}
	if !bytes.Equal(ut[:], xmpUserType) {
		return 0, false
	}
	return payloadStart + userTypeBytes, true
}

// MetadataSpansIn is MetadataSpans over a buffer already in memory.
func MetadataSpansIn(buf []byte) ([]Span, error) {
	return MetadataSpans(bytes.NewReader(buf), int64(len(buf)))
}

// Coordinates returns the spans of a metadata buffer that hold a GPS position,
// buffer-relative.
//
// Coordinates need their own treatment because they are the one reported video value that is
// NEVER present in the file as the text that was reported:
//
//   - a QuickTime "©xyz" child of udta holds three 32-bit fixed-point numbers, which the
//     extractor divides by 65536 and formats as "%.6f, %.6f";
//   - an iTunes-style "©xyz" and an mdta ilst item both hold an ISO 6709 string such as
//     "+36.3506-082.6985+447.403/", which is re-formatted to six decimals as well.
//
// Either way a search for the reported "36.350600, -82.698500" finds nothing, so the value
// survives a text-only redaction AND survives the residue check that is supposed to catch
// that — the check agrees with the bug, because the string genuinely is not there. Measured
// both on a hand-built .mp4 and on a real device recording: GPS reported at HIGH 100, zero
// occurrences of the reported text anywhere in the file.
//
// So the fix is structural rather than textual, and it is found two ways because real files
// need both. The atom walk locates a ©xyz payload wherever it is nested. The pattern scan
// locates an ISO 6709 string in a layout the walk cannot name — the mdta form numbers its ilst
// items against a keys table, so the atom that holds the position is called "\x00\x00\x00\x01".
// Requiring the key to be recognised would miss every writer that spells it differently; the
// value's shape does not vary.
//
// # Why the whole payload, and why zeroes
//
// Every returned span is meant to be filled with ZERO bytes, and for a ©xyz atom the span is the
// entire payload rather than just the position string inside it. Both details are forced by real
// files:
//
//   - ffmpeg writes a .mov ©xyz payload as a 2-byte text length, a 2-byte language code, and
//     then the ISO 6709 string. This tool'"'"'s extractor reads that payload as FIXED-POINT — the
//     length and language bytes become a latitude — and reports "18.335022, 11059.211639". So
//     masking only the string leaves the first coordinate exactly as it was, and the redacted
//     file still reports a GPS finding. The same bytes are genuinely read both ways by different
//     readers, so the only safe scope is the whole payload.
//   - '"'"'*'"'"' bytes are a perfectly valid fixed-point number: 0x2A2A2A2A is 10794.66°. Masking a
//     binary position therefore replaces one coordinate with another. Zero is the one fill that
//     no reader turns back into a location — and the extractor drops a 0/0 position outright,
//     which makes the result verifiable by rescanning the redacted file.
//
// An atom HEADER is never included: zeroing a size field would make the enclosing atom
// unparseable, which is the corrupt-but-looks-redacted outcome this whole approach exists to
// avoid. For a data atom only the value half is returned, leaving its type and locale words
// intact.
func Coordinates(buf []byte) []Span {
	var out []Span
	budget := maxAtoms
	_ = walk(bytes.NewReader(buf), 0, int64(len(buf)), 0, &budget, func(name []byte, payloadStart, payloadEnd int64) bool {
		if bytes.Equal(name, lociAtom) {
			// A SECOND copy of the same position, in a different atom. ffmpeg writes location
			// into loci for .mp4 and into ©xyz for .mov, and a file can carry both — measured on
			// a fixture holding each: zeroing only ©xyz left loci decoding to 37.7749,-122.4194
			// in a file the run reported as redacted. Removing one copy of a value and reporting
			// success is the same defect as not removing it at all.
			//
			// The whole payload, because the position sits after a variable-length location NAME
			// (itself location data) and a role byte. Parsing to the exact field offsets buys
			// nothing here: every byte of a loci payload is descriptive, so zeroing all of it
			// leaves an empty, unlocated atom of exactly the same size.
			if payloadEnd > payloadStart {
				out = append(out, Span{payloadStart, payloadEnd, "MP4 loci"})
			}
			return false
		}
		if !bytes.Equal(name, xyzAtom) {
			// Descend through meta/ilst as well as the structural atoms: in the iTunes layout
			// the coordinate sits at udta > meta > ilst > ©xyz.
			return IsContainerAtom(name) || isMetaContainer(name)
		}

		// The whole payload, both forms, deliberately — see the note above on why the prefix
		// bytes cannot be left alone.
		if inner, ok := dataPayload(buf, payloadStart, payloadEnd); ok {
			out = append(out, inner)
			return false
		}
		if payloadEnd > payloadStart {
			out = append(out, Span{payloadStart, payloadEnd, "MP4 ©xyz"})
		}
		return false
	})

	for _, loc := range iso6709.FindAllIndex(buf, -1) {
		span := Span{int64(loc[0]), int64(loc[1]), "ISO 6709 position"}
		if overlapsAny(out, span) {
			continue // already covered by the atom walk
		}
		out = append(out, span)
	}
	return out
}

// overlapsAny reports whether span intersects a coordinate already found.
func overlapsAny(found []Span, span Span) bool {
	for _, c := range found {
		if span.Start < c.End && c.Start < span.End {
			return true
		}
	}
	return false
}

// dataPayload returns the text half of an iTunes data atom nested at [start, end), if that is
// what is there.
func dataPayload(buf []byte, start, end int64) (Span, bool) {
	const typeAndLocale = 8
	if start < 0 || end > int64(len(buf)) || end-start < headerBytes {
		return Span{}, false
	}
	size := int64(binary.BigEndian.Uint32(buf[start : start+4]))
	if !bytes.Equal(buf[start+4:start+8], dataAtom) {
		return Span{}, false
	}
	if size < headerBytes+typeAndLocale || start+size > end {
		return Span{}, false
	}
	return Span{start + headerBytes + typeAndLocale, start + size, "MP4 ©xyz data"}, true
}

// IsContainerAtom reports whether an atom holds child atoms worth descending into on the way
// to udta.
//
// Listed explicitly rather than descending into everything: descending into a leaf would
// interpret its payload bytes as atom headers and produce nonsense spans, and the nonsense
// would then be overwritten.
func IsContainerAtom(name []byte) bool {
	switch string(name) {
	case "moov", "trak", "mdia", "minf", "stbl", "edts", "moof", "traf", "mvex":
		return true
	}
	return false
}

// isMetaContainer reports the two atoms that sit between udta and an iTunes tag. They are not
// in IsContainerAtom because the udta walk stops at udta and never needs them.
func isMetaContainer(name []byte) bool {
	switch string(name) {
	case "meta", "ilst":
		return true
	}
	return false
}

// HasHeader reports whether the head of a file looks like an ISO base media or QuickTime
// container.
//
// "ftyp" covers .mp4/.m4v/.m4a and any .mov written with a brand. A classic QuickTime movie
// has no ftyp at all and begins with one of the other atoms listed here, so an extension-only
// check would call it unrecognised and an extension-only ROUTER would send a text file named
// .mp4 to a container redactor that must refuse it.
func HasHeader(head []byte) bool {
	if len(head) < headerBytes {
		return false
	}
	switch string(head[4:8]) {
	case "ftyp", "moov", "mdat", "free", "skip", "wide", "pnot":
		return true
	}
	return false
}

// childStart returns where an atom's children begin, allowing for the version-and-flags word
// that meta carries ahead of them.
//
// meta is a FullBox: 4 bytes of version and flags precede its first child. Walking from the
// payload start reads those four zero bytes as a size of 0, which by the spec means "extends to
// the end of the file", so the whole tag block collapses into one atom named from the next
// atom's size field and every coordinate inside it is missed. The metadata extractor skips the
// same four bytes unconditionally (parseMetaBoxWithContext), so a coordinate it can REPORT is
// always behind them.
//
// Only meta is probed, and only when the four bytes really are a zero word. A size of 0 is
// legitimate for a trailing atom, so treating "does not decode" as "must be a FullBox prefix"
// on any atom would shift a valid walk by four bytes — and a walk shifted by four bytes
// overwrites the wrong bytes.
func childStart(r io.ReaderAt, name []byte, payloadStart, payloadEnd int64) int64 {
	const fullBoxPrefix = 4
	if !bytes.Equal(name, metaAtom) || payloadStart+fullBoxPrefix > payloadEnd {
		return payloadStart
	}
	var word [fullBoxPrefix]byte
	if _, err := r.ReadAt(word[:], payloadStart); err != nil {
		return payloadStart
	}
	if binary.BigEndian.Uint32(word[:]) != 0 {
		// A QuickTime writer that omits the prefix: the first child's size word is here.
		return payloadStart
	}
	return payloadStart + fullBoxPrefix
}

// walk decodes atom headers in r over [start, end) and calls visit for each. visit returns
// whether to descend into that atom's payload.
//
// The depth bound is belt-and-braces, and worth being honest about: termination is ALREADY
// guaranteed without it, because every level consumes at least an atom header out of a finite
// range and each child range is strictly inside its parent's. So a hostile file cannot drive
// unbounded recursion — only deep recursion, bounded by size/8. The explicit ceiling costs one
// comparison and keeps that reasoning from having to be re-derived by the next reader.
func walk(r io.ReaderAt, start, end int64, depth int, budget *int, visit func(name []byte, payloadStart, payloadEnd int64) bool) error {
	const maxDepth = 8
	if depth > maxDepth {
		return nil
	}

	var hdr [largeHeaderBytes]byte
	pos := start
	for pos+headerBytes <= end {
		if *budget <= 0 {
			return ErrAtomBudget
		}
		*budget--

		if _, err := r.ReadAt(hdr[:headerBytes], pos); err != nil {
			return nil // unreadable tail: stop rather than guess
		}
		size := int64(binary.BigEndian.Uint32(hdr[0:4]))
		name := hdr[4:8]
		header := int64(headerBytes)

		switch size {
		case 0:
			// Size 0 means "extends to the end of the file" (permitted for the last atom).
			size = end - pos
		case 1:
			// Size 1 means the real 64-bit size follows the name.
			if pos+largeHeaderBytes > end {
				return nil
			}
			if _, err := r.ReadAt(hdr[headerBytes:largeHeaderBytes], pos+headerBytes); err != nil {
				return nil
			}
			large := binary.BigEndian.Uint64(hdr[headerBytes:largeHeaderBytes])
			// Bound the declared size by what is actually there. #350's lesson: a declared
			// size may only ever be trusted after it has been checked against a real one.
			if large > uint64(end-pos) {
				return nil
			}
			size = int64(large)
			header = largeHeaderBytes
		}

		if size < header || pos+size > end {
			return nil // malformed or truncated: stop rather than guess
		}

		payloadStart := pos + header
		payloadEnd := pos + size

		if visit(name, payloadStart, payloadEnd) {
			if err := walk(r, childStart(r, name, payloadStart, payloadEnd), payloadEnd, depth+1, budget, visit); err != nil {
				return err
			}
		}

		pos = payloadEnd
	}
	return nil
}

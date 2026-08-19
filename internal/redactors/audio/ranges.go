// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package audio

import (
	"bytes"
	"encoding/binary"
)

// byteRange is a half-open [start, end) span of the file that holds metadata.
type byteRange struct {
	start int
	end   int
	label string // which container structure it came from, for the audit trail
}

// metadataRanges returns the spans of buf that hold tag metadata for the given format.
//
// # Why ranges rather than the whole file
//
// Redaction here is a same-length overwrite of the value's bytes (see redactor.go for why
// the length cannot change). A naive search over the whole file would also overwrite any
// coincidental occurrence of those bytes inside the AUDIO SAMPLES — silently corrupting the
// recording while reporting success. An 11-byte SSN is unlikely to appear in PCM by chance,
// but "Jane Doe" in a 40MB file is not, and a corrupted output that still looks redacted is
// worse than a refusal.
//
// Bounding the search to the tag structures also bounds the blast radius of a parsing
// mistake: getting an offset wrong can only damage metadata, never the audio stream.
//
// An empty result means "no metadata region found", which the caller must treat as a refusal
// rather than as success — a file whose tags could not be located is a file whose values were
// not removed.
func metadataRanges(buf []byte, format audioFormat) []byteRange {
	switch format {
	case formatWAV:
		return riffMetadataRanges(buf)
	case formatMP3:
		return id3MetadataRanges(buf)
	case formatFLAC:
		return flacMetadataRanges(buf)
	case formatM4A:
		return mp4MetadataRanges(buf)
	}
	return nil
}

// riffMetadataRanges finds LIST and id3 chunks in a RIFF/WAVE file.
//
// Deliberately NOT every non-audio chunk: only the two that carry free text. `fmt ` is
// numeric, and `data` is the audio itself — the one span that must never be touched.
//
// The odd-length pad byte is DETECTED rather than assumed, for the same reason the WAV
// extractor detects it (#312 and the INFO-walk follow-up): a non-compliant writer omits it,
// and seeking past a byte that is not there puts every subsequent offset one out. Here that
// would mean overwriting the wrong bytes, so the consequence is worse than a missed read.
func riffMetadataRanges(buf []byte) []byteRange {
	// "RIFF" + size(4) + "WAVE" = 12 bytes before the first chunk.
	const riffHeader = 12
	if len(buf) < riffHeader || !bytes.Equal(buf[0:4], []byte("RIFF")) || !bytes.Equal(buf[8:12], []byte("WAVE")) {
		return nil
	}

	var out []byteRange
	pos := riffHeader
	for pos+8 <= len(buf) {
		id := buf[pos : pos+4]
		size := int(binary.LittleEndian.Uint32(buf[pos+4 : pos+8]))
		if size < 0 {
			return out
		}
		dataStart := pos + 8
		dataEnd := dataStart + size
		if dataEnd > len(buf) {
			// A chunk declaring more than the file holds. Take what is present rather than
			// walking off the end; a truncated tag still deserves to be scrubbed.
			dataEnd = len(buf)
		}

		switch {
		case bytes.Equal(id, []byte("LIST")):
			out = append(out, byteRange{dataStart, dataEnd, "RIFF LIST"})
		case bytes.Equal(id, []byte("id3 ")), bytes.Equal(id, []byte("ID3 ")):
			// A WAV may carry an ID3 tag in its own chunk.
			out = append(out, byteRange{dataStart, dataEnd, "RIFF id3"})
		}

		next := dataEnd
		if size%2 == 1 {
			// Pad byte required by RIFF after an odd-length chunk — consumed only if it is
			// actually there. A pad is 0x00; a chunk ID's first byte is printable ASCII.
			if next < len(buf) && buf[next] == 0x00 {
				next++
			}
		}
		if next <= pos {
			return out // no forward progress: malformed, stop rather than spin
		}
		pos = next
	}
	return out
}

// id3MetadataRanges finds the ID3v2 tag at the head of an MP3 and the ID3v1 tag at its tail.
//
// ID3v2 sizes are SYNCHSAFE: seven bits per byte, high bit always clear, so that a size can
// never contain a byte sequence a decoder would mistake for a frame sync. Reading it as a
// plain big-endian uint32 gives a value that is too large and drifts further with every size —
// the classic ID3 parsing bug.
func id3MetadataRanges(buf []byte) []byteRange {
	var out []byteRange

	// ID3v2: "ID3" ver(2) flags(1) synchsafe-size(4), then size bytes of frames.
	const id3v2Header = 10
	if len(buf) >= id3v2Header && bytes.Equal(buf[0:3], []byte("ID3")) {
		size := synchsafe(buf[6:10])
		end := id3v2Header + size
		if end > len(buf) {
			end = len(buf)
		}
		if end > id3v2Header {
			out = append(out, byteRange{id3v2Header, end, "ID3v2"})
		}
	}

	// ID3v1: a fixed 128-byte trailer beginning "TAG".
	const id3v1Size = 128
	if len(buf) >= id3v1Size {
		tail := len(buf) - id3v1Size
		if bytes.Equal(buf[tail:tail+3], []byte("TAG")) {
			out = append(out, byteRange{tail + 3, len(buf), "ID3v1"})
		}
	}

	return out
}

// synchsafe decodes a 4-byte ID3v2 synchsafe integer (7 significant bits per byte).
func synchsafe(b []byte) int {
	if len(b) < 4 {
		return 0
	}
	return int(b[0]&0x7F)<<21 | int(b[1]&0x7F)<<14 | int(b[2]&0x7F)<<7 | int(b[3]&0x7F)
}

// flacMetadataRanges finds VORBIS_COMMENT blocks in a FLAC stream.
//
// Only type 4. STREAMINFO (0) is numeric and mandatory, SEEKTABLE (3) is offsets, and
// PICTURE (6) is binary image data whose bytes could coincidentally match a short value.
// Comments are where the text tags live.
func flacMetadataRanges(buf []byte) []byteRange {
	if len(buf) < 4 || !bytes.Equal(buf[0:4], []byte("fLaC")) {
		return nil
	}

	const (
		blockHeader        = 4
		vorbisCommentBlock = 4
	)
	var out []byteRange
	pos := 4
	for pos+blockHeader <= len(buf) {
		header := buf[pos]
		last := header&0x80 != 0
		blockType := header & 0x7F
		// 24-bit big-endian length.
		size := int(buf[pos+1])<<16 | int(buf[pos+2])<<8 | int(buf[pos+3])
		dataStart := pos + blockHeader
		dataEnd := dataStart + size
		if dataEnd > len(buf) {
			dataEnd = len(buf)
		}
		if blockType == vorbisCommentBlock && dataEnd > dataStart {
			out = append(out, byteRange{dataStart, dataEnd, "FLAC VORBIS_COMMENT"})
		}
		if last || dataEnd <= pos {
			break
		}
		pos = dataEnd
	}
	return out
}

// mp4MetadataRanges finds udta (user data) atoms in an MP4/M4A file, which is where the
// iTunes-style ilst tags live.
//
// Scoped to udta rather than to moov: moov also holds the sample tables (stbl/stco/stsz),
// which are offset and size arrays. Overwriting bytes there would desynchronise the decoder
// from the audio while the file still parsed as a container — a corrupt output that looks
// successful. udta is the only subtree that is purely descriptive.
func mp4MetadataRanges(buf []byte) []byteRange {
	var out []byteRange
	collectUdta(buf, 0, len(buf), 0, &out)
	return out
}

// collectUdta walks the atom tree in buf[start:end), appending every udta payload it finds.
//
// The depth bound is belt-and-braces, and worth being honest about: termination is ALREADY
// guaranteed without it, because every level consumes at least the 8 bytes of an atom header
// out of a finite buffer and the child range is strictly inside the parent's. So a hostile
// file cannot drive unbounded recursion — it can only drive deep recursion, bounded by
// filesize/8. The explicit ceiling costs one comparison and keeps that reasoning from having
// to be re-derived by the next reader; it is deliberately not covered by a test, because a
// fixture deep enough to distinguish its presence would have to be hundreds of thousands of
// levels deep and would be measuring Go's stack growth rather than this code.
func collectUdta(buf []byte, start, end, depth int, out *[]byteRange) {
	const maxDepth = 8
	if depth > maxDepth {
		return
	}

	pos := start
	for pos+8 <= end {
		size := int(binary.BigEndian.Uint32(buf[pos : pos+4]))
		name := buf[pos+4 : pos+8]
		header := 8

		switch size {
		case 0:
			// Size 0 means "extends to the end of the file" (permitted for the last atom).
			size = end - pos
		case 1:
			// Size 1 means the real 64-bit size follows the name.
			if pos+16 > end {
				return
			}
			large := binary.BigEndian.Uint64(buf[pos+8 : pos+16])
			// Bound the cast: a declared size beyond the buffer is malformed, and on a
			// 32-bit build the conversion would wrap.
			if large > uint64(end-pos) {
				return
			}
			size = int(large)
			header = 16
		}

		if size < header || pos+size > end {
			return // malformed or truncated: stop rather than guess
		}

		payloadStart := pos + header
		payloadEnd := pos + size

		if bytes.Equal(name, []byte("udta")) {
			*out = append(*out, byteRange{payloadStart, payloadEnd, "MP4 udta"})
		} else if isMP4Container(name) {
			collectUdta(buf, payloadStart, payloadEnd, depth+1, out)
		}

		pos = payloadEnd
	}
}

// isMP4Container reports whether an atom holds child atoms worth descending into on the way
// to udta. Listed explicitly rather than descending into everything, because descending into
// a leaf atom would interpret its payload bytes as atom headers and produce nonsense ranges.
func isMP4Container(name []byte) bool {
	switch string(name) {
	case "moov", "trak", "mdia", "minf", "stbl", "edts", "moof", "traf", "mvex":
		return true
	}
	return false
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractexiflib

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

// PNG keeps its descriptive text in chunks, not in EXIF, so an image carrying an author name or a
// description in the ordinary way was reported clean.
//
// Measured before this existed (#456): a 210-byte PNG holding tEXt "Author = Employee SSN
// 449-87-4100", iTXt "Description = Call 415-555-0132" and a DEFLATED zTXt "Comment = Card
// 4532-0151-1283-0366" produced 0 findings at exit 0, while exiftool read all three. Nothing in the
// tree parsed a PNG chunk — the four raw byte scans in exif-extractor.go look for JPEG, IPTC, XMP and
// Photoshop markers, and cannot see PNG text at all. zTXt is compressed, so no byte scan ever could.
//
// # Only headers and text payloads are read
//
// The walk reads the 8-byte header of each chunk and seeks past anything it does not want, so IDAT —
// which is the entire image — is never read. That keeps the cost proportional to the metadata rather
// than to the picture, and it is also why the reader takes an io.ReaderAt rather than a byte slice:
// the existing raw scans read only the first 1MB of the file, and a PNG may legally place tEXt AFTER
// a multi-megabyte IDAT, where that window cannot reach.
const (
	// maxPNGChunks bounds the walk. A real PNG has a handful of chunks; a 100MB file of nothing but
	// 12-byte empty chunks describes about 8.7 million, and each costs a read.
	maxPNGChunks = 1 << 16

	// maxPNGTextChunkBytes bounds ONE text payload, before and after decompression.
	//
	// zTXt and iTXt may be zlib-deflated, which is a decompression bomb with no other bound.
	// Measured: a 509.7KB PNG whose zTXt inflates to 512MB — 1029x, and zlib's ceiling is about
	// 1032x, so the ratio is not incidental. 1MB matches the window the existing raw scans already
	// use for a whole file, so a PNG text chunk cannot cost more attention than a JPEG's metadata.
	maxPNGTextChunkBytes = 1 << 20

	// maxPNGTextTotalBytes bounds the SUM across chunks, because the per-chunk cap alone does not:
	// a PNG may carry hundreds of tEXt chunks, each individually legal.
	maxPNGTextTotalBytes = 4 << 20
)

var pngSignature = []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'}

// IsPNG reports whether the bytes begin with the PNG signature.
//
// The SIGNATURE, never the extension: an extension is the producer's claim and a redactor that
// trusts it reads one format as another. This mirrors how the video path decides (isobmff.HasHeader).
func IsPNG(b []byte) bool { return bytes.HasPrefix(b, pngSignature) }

// extractPNGText reads tEXt, zTXt and iTXt chunks into tags, and returns the raw eXIf payload if the
// image carries one.
//
// Keys are prefixed "PNG_" so a PNG keyword cannot collide with an EXIF tag of the same name and
// silently overwrite it — the tag map is shared with the EXIF walker and the four raw scans.
//
// A malformed or truncated file yields the chunks found so far and no error, which is how the rest of
// this tool treats partial structure: a value that could be located is still worth reporting, and the
// caller decides what to do about the rest.
func extractPNGText(r io.ReaderAt, size int64, tags map[string]string) (exifPayload []byte) {
	var sig [8]byte
	if _, err := r.ReadAt(sig[:], 0); err != nil || !IsPNG(sig[:]) {
		return nil
	}

	pos := int64(len(pngSignature))
	total := 0
	for chunks := 0; chunks < maxPNGChunks; chunks++ {
		var hdr [8]byte
		if pos+8 > size {
			return exifPayload
		}
		if _, err := r.ReadAt(hdr[:], pos); err != nil {
			return exifPayload
		}
		declared := int64(binary.BigEndian.Uint32(hdr[0:4]))
		kind := string(hdr[4:8])

		// The declared length is a uint32 read out of the file, so its maximum is 4GiB. Bound it by
		// the bytes actually remaining before it is used for anything — #457 is this same class in
		// the audio extractors, where a 52-byte .m4a allocated 4096MB. Measured here: a 53-byte PNG
		// whose tEXt declares 4294967280.
		dataStart := pos + 8
		if declared < 0 || dataStart+declared > size {
			return exifPayload
		}

		switch kind {
		case "IEND":
			return exifPayload
		case "tEXt", "zTXt", "iTXt", "eXIf":
			want := declared
			if want > maxPNGTextChunkBytes {
				want = maxPNGTextChunkBytes
			}
			payload := make([]byte, want)
			if _, err := r.ReadAt(payload, dataStart); err != nil {
				return exifPayload
			}
			if kind == "eXIf" {
				// Handed back rather than parsed here: the EXIF decoder is the caller's, and a PNG
				// eXIf payload is exactly the TIFF stream it already knows how to read.
				exifPayload = payload
				break
			}
			key, text, ok := parsePNGText(kind, payload)
			if ok && total < maxPNGTextTotalBytes {
				if len(text) > maxPNGTextTotalBytes-total {
					text = text[:maxPNGTextTotalBytes-total]
				}
				total += len(text)
				tags["PNG_"+key] = text
			}
		}

		// length + type + data + CRC.
		next := dataStart + declared + 4
		if next <= pos {
			return exifPayload // no forward progress: refuse to spin
		}
		pos = next
	}
	return exifPayload
}

// parsePNGText decodes one text chunk's payload into a keyword and its text.
//
// The three layouts, from the PNG specification:
//
//	tEXt   keyword \0 text                                             (Latin-1, uncompressed)
//	zTXt   keyword \0 method text                                      (deflated when method == 0)
//	iTXt   keyword \0 flag method language \0 translated \0 text        (UTF-8, deflated when flag == 1)
func parsePNGText(kind string, payload []byte) (key, text string, ok bool) {
	sep := bytes.IndexByte(payload, 0)
	if sep <= 0 || sep >= len(payload)-1 {
		return "", "", false
	}
	key = decodeLatin1(payload[:sep])
	rest := payload[sep+1:]

	switch kind {
	case "tEXt":
		return key, decodeLatin1(rest), true

	case "zTXt":
		// One byte of compression method, then the deflated text. 0 is the only method the spec
		// defines; anything else is not something to guess at.
		if len(rest) < 1 || rest[0] != 0 {
			return "", "", false
		}
		out, err := inflateBounded(rest[1:])
		if err != nil {
			return "", "", false
		}
		return key, decodeLatin1(out), true

	case "iTXt":
		if len(rest) < 2 {
			return "", "", false
		}
		compressed, method := rest[0] == 1, rest[1]
		body := rest[2:]
		// Two NUL-terminated fields — language tag and translated keyword — precede the text.
		for i := 0; i < 2; i++ {
			j := bytes.IndexByte(body, 0)
			if j < 0 {
				return "", "", false
			}
			body = body[j+1:]
		}
		if !compressed {
			return key, string(body), true
		}
		if method != 0 {
			return "", "", false
		}
		out, err := inflateBounded(body)
		if err != nil {
			return "", "", false
		}
		return key, string(out), true
	}
	return "", "", false
}

// inflateBounded decompresses at most maxPNGTextChunkBytes.
//
// The bound is the whole point. A 509.7KB PNG can carry a zTXt that inflates to 512MB, and reading it
// into memory to look for a phone number would be a decompression bomb the tool handed itself. A
// truncated result is acceptable here in a way it is not on the redaction side: this is DETECTION, so
// reading the first megabyte of a value finds anything in it, and the alternative — refusing to read
// the chunk at all — reports the image clean.
func inflateBounded(compressed []byte) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	defer func() { _ = zr.Close() }()

	out, err := io.ReadAll(io.LimitReader(zr, maxPNGTextChunkBytes))
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("inflating png text: %w", err)
	}
	return out, nil
}

// decodeLatin1 converts Latin-1 bytes to UTF-8.
//
// tEXt and zTXt are Latin-1 by specification, not UTF-8. Passing those bytes through unconverted
// leaves a high byte as invalid UTF-8, and an accented name in a Copyright field then reaches the
// validators as replacement characters — a value altered before anything looked at it.
func decodeLatin1(b []byte) string {
	if isASCII(b) {
		return string(b)
	}
	var sb strings.Builder
	sb.Grow(len(b))
	for _, c := range b {
		sb.WriteRune(rune(c))
	}
	return sb.String()
}

func isASCII(b []byte) bool {
	for _, c := range b {
		if c >= 0x80 {
			return false
		}
	}
	return true
}

// isJPEG reports whether the bytes begin with the JPEG start-of-image marker.
//
// Used to confine the scans whose marker is short enough to occur by chance in compressed data. The
// SIGNATURE and not the extension, for the same reason IsPNG is: a `.jpg` that is really a PNG is a
// thing that happens, and the bytes are what the scan will actually be reading.
func isJPEG(b []byte) bool {
	return len(b) >= 2 && b[0] == 0xFF && b[1] == 0xD8
}

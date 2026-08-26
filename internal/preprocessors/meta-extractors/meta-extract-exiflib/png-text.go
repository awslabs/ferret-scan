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
			// The total budget is consulted FIRST, before this chunk is read or inflated.
			//
			// It used to be consulted after parsePNGText, which bounded the WORK by
			// maxPNGChunks * maxPNGTextChunkBytes -- 65,536 x 1MB, i.e. 64GB of decompression --
			// rather than by the 4MB of text actually kept. Both caps existed and were individually
			// correct; they simply did not compose in that order. Measured on a valid 69.4MB PNG of
			// 65,535 legal zTXt chunks each inflating to exactly the 1MB per-chunk cap: 81.27s and
			// 135MB RSS, against 0.09s and 30MB before this reader existed, and reported at rc 0 as
			// a fully scanned clean file. 2,000 chunks already cost 7.95s.
			//
			// eXIf is exempt because it is not text, does not draw on this budget, and is the one
			// chunk whose loss would be a coverage regression rather than a saving. Skipping is a
			// `break` out of the SWITCH, not the loop, so the walk continues header-only and cheaply
			// to find a later eXIf.
			if kind != "eXIf" && total >= maxPNGTextTotalBytes {
				break
			}

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
			if ok {
				// After inflation but before the cap below, so the budget counts what is actually
				// scanned -- an encoded payload is up to three times its decoded size -- and so a
				// truncation can never cut a `%XX` sequence in half.
				text = decodePercentEncoded(text)
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

// decodePercentEncoded resolves a percent-encoded chunk payload, and returns s unchanged when it is
// not one.
//
// A tool that stores a document inside a PNG text chunk commonly percent-encodes it. draw.io does:
// it writes the diagram source into a `tEXt` chunk keyed `mxfile`, run through
// encodeURIComponent. Scanning that as-is costs recall AND precision at the same time, which is
// unusual and is why decoding is the right fix rather than a trade:
//
//	stored in the chunk : Employee%20SSN%20449-87-4100     -> 0 findings
//	the same value      : Employee SSN 449-87-4100         -> SSN
//
// `%20` leaves characters glued to the value so no pattern matches, and only reported findings reach
// the redactor, so that is a silent miss. In the other direction, the encoded form is itself a
// false-positive generator: measured across 12 real draw.io PNGs on a macOS host, one 1.44MB payload
// produced 426 findings -- 425 RECOVERY_CODES at MEDIUM 65/75 from percent-encoded XML fragments
// (`%3C`, `%22`, hex-ish runs) read as codes, plus INTELLECTUAL_PROPERTY at HIGH. Those sit in the
// DEFAULT view, not the LOW band, so they crowd triage. Decoding removes that family because it is
// made of encoding artefacts, and reveals the hidden values at the same time.
//
// # Why the gate is "holds a valid escape", and not the keyword or `%3C`
//
// Three candidate gates were MEASURED across 5,989 real PNGs on this host, 1,645 of which carry a text
// chunk. Only 18 text chunks contain a `%` at all:
//
//	keyword                    has %3C     raw len   decoded len   changed by a lenient decode
//	mxfile  (x16)              yes         various   ~25% smaller  YES
//	XML:com.adobe.xmp (x2)     no          15544     15544         NO
//
// The narrowest gate -- keyword `mxfile` -- is keyed on one vendor's name and would not cover the next
// tool that does this. The middle gate -- the presence of `%3C`/`%3E`, an encoded '<' or '>' -- was the
// first version of this function, and it is wrong for a reason the measurement above does not show:
// it is derived from the XML population, so it misses a payload that is percent-encoded WITHOUT
// containing markup. `Employee%20SSN%20449-87-4100` is the exact recall example this issue was filed
// about, and a `%3C` gate leaves it encoded and therefore unreported.
//
// The wide gate -- does the text hold at least one VALID `%XX` escape -- fixes that, and the
// measurement says it is free: the two Adobe XMP packets are the only real chunks it newly considers,
// and a lenient decode leaves them **byte-identical**, because their `%` is not followed by two hex
// digits. So on real data the wide gate decodes exactly the 16 chunks that should be decoded.
//
// The residual risk is stated rather than hidden: prose containing a percent followed by two hex-ish
// characters -- "50%2B off" -> "50+ off" -- would be altered. Nothing like it appears in 5,989 real
// files, and the trade is deliberate: a mangled metadata string costs at most a false positive or a
// miss in ONE chunk, whereas not decoding costs a silent miss of PII, and only reported findings reach
// the redactor.
//
// # Why this is lenient rather than url.PathUnescape
//
// PathUnescape fails the WHOLE string on one malformed escape, and a payload that is only partly
// encoded -- `%3C` markup beside a literal "100% width" -- would then stay entirely encoded, turning
// a precision fix into a recall miss. This resolves every valid `%XX` and passes anything else through
// byte-for-byte, the same contract internal/xmlref uses for the same reason. `+` is deliberately NOT
// treated as a space: that is form encoding, not percent encoding, and a diagram's text may contain a
// literal plus.
//
// Decoding strictly SHRINKS the payload (three bytes become one), so it introduces no expansion bound
// to worry about, unlike the zlib paths above.
func decodePercentEncoded(s string) string {
	if !hasPercentEscape(s) {
		return s
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); {
		if s[i] == '%' && i+2 < len(s) {
			hi, hiOK := unhex(s[i+1])
			lo, loOK := unhex(s[i+2])
			if hiOK && loOK {
				out = append(out, hi<<4|lo)
				i += 3
				continue
			}
		}
		out = append(out, s[i])
		i++
	}
	return string(out)
}

// hasPercentEscape reports whether s holds at least one valid `%XX` escape.
//
// This is exactly the question "would decoding change anything", answered in a single pass with no
// allocation, so a chunk that is not percent-encoded never pays for a copy. Keeping the gate and the
// decoder in agreement is the point: a gate that admitted more than the decoder resolves would copy
// for nothing, and one that admitted less would leave a value encoded and unseen.
//
// Both hex cases are accepted because encoders differ: Go's url.QueryEscape emits upper case, and some
// JavaScript and Python paths emit lower.
func hasPercentEscape(s string) bool {
	for i := 0; i+2 < len(s); i++ {
		if s[i] != '%' {
			continue
		}
		if _, ok := unhex(s[i+1]); !ok {
			continue
		}
		if _, ok := unhex(s[i+2]); ok {
			return true
		}
	}
	return false
}

// unhex decodes one hexadecimal digit.
func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

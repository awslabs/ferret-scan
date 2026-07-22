// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// TextEncoding identifies the on-disk encoding of a text file, as detected
// from its leading bytes. Only encodings ferret-scan can transparently decode
// to UTF-8 (and re-encode on the redaction write path) are enumerated;
// everything else is EncodingUnknown and handled by the legacy byte-level
// heuristics.
type TextEncoding int

const (
	// EncodingUTF8 is plain UTF-8 / ASCII — no transform needed.
	EncodingUTF8 TextEncoding = iota
	// EncodingUTF8BOM is UTF-8 with a leading BOM (Windows Notepad default).
	// The BOM is stripped on decode and restored on encode.
	EncodingUTF8BOM
	// EncodingUTF16LE is UTF-16 little-endian with BOM (PowerShell 5
	// Out-File default, regedit .reg exports, many Windows logs).
	EncodingUTF16LE
	// EncodingUTF16BE is UTF-16 big-endian with BOM.
	EncodingUTF16BE
	// EncodingUTF16LENoBOM is BOM-less UTF-16 LE, detected by the
	// alternating-null heuristic.
	EncodingUTF16LENoBOM
	// EncodingUTF16BENoBOM is BOM-less UTF-16 BE.
	EncodingUTF16BENoBOM
	// EncodingUnknown means "not a transcodable encoding we recognize" —
	// callers fall back to treating the bytes as-is.
	EncodingUnknown
)

// String returns a short name for metadata/debug surfaces.
func (e TextEncoding) String() string {
	switch e {
	case EncodingUTF8:
		return "utf-8"
	case EncodingUTF8BOM:
		return "utf-8-bom"
	case EncodingUTF16LE:
		return "utf-16le-bom"
	case EncodingUTF16BE:
		return "utf-16be-bom"
	case EncodingUTF16LENoBOM:
		return "utf-16le"
	case EncodingUTF16BENoBOM:
		return "utf-16be"
	default:
		return "unknown"
	}
}

// hasNullByte reports whether b contains at least one 0x00 byte. Used to
// confirm a UTF-16 BOM: real UTF-16 text always carries nulls (the high half
// of every ASCII character, space, and newline), so a "BOM" followed by a
// null-free body is legacy single-byte text that happens to start with
// ÿþ/þÿ, not UTF-16.
func hasNullByte(b []byte) bool {
	for _, c := range b {
		if c == 0 {
			return true
		}
	}
	return false
}

// DetectTextEncoding inspects the leading bytes of buf (any prefix of the
// file, e.g. the 512-byte sniff window or the whole content) and identifies
// the encoding. Detection order matters: BOMs are unambiguous and checked
// first; the BOM-less UTF-16 heuristic runs only when the buffer contains
// null bytes in the tell-tale alternating pattern (UTF-16-encoded
// ASCII/Latin text has a 0x00 in every other byte, which is exactly why the
// legacy null-byte check classified such files as binary).
func DetectTextEncoding(buf []byte) TextEncoding {
	if len(buf) >= 3 && buf[0] == 0xEF && buf[1] == 0xBB && buf[2] == 0xBF {
		return EncodingUTF8BOM
	}
	if len(buf) >= 2 {
		if buf[0] == 0xFF && buf[1] == 0xFE {
			// Disambiguate from the UTF-32LE BOM (FF FE 00 00). A genuine
			// UTF-16LE file whose first character is NUL is not text anyway.
			if len(buf) >= 4 && buf[2] == 0x00 && buf[3] == 0x00 {
				return EncodingUnknown // UTF-32LE: rare; not supported
			}
			if hasNullByte(buf[2:]) {
				return EncodingUTF16LE
			}
			// FF FE with ZERO nulls after it is almost certainly NOT
			// UTF-16: every real UTF-16 document carries nulls (ASCII
			// chars, spaces U+0020, newlines U+000A all have a 0x00 half).
			// It IS what a legacy single-byte file looks like when its
			// text begins with 'ÿþ' (0xFF 0xFE in Latin-1/cp1252) —
			// adversarial verification proved decoding such a file as
			// UTF-16 turns it into mojibake and silently hides its PII.
			// Fall through to the non-BOM heuristics.
		} else if buf[0] == 0xFE && buf[1] == 0xFF {
			if hasNullByte(buf[2:]) {
				return EncodingUTF16BE
			}
			// Same rationale: 'þÿ'-leading legacy text, not a BOM.
		}
	}

	// BOM-less UTF-16 heuristic. Sample up to the first 512 bytes (even
	// length); require enough data to be meaningful.
	sample := buf
	if len(sample) > 512 {
		sample = sample[:512]
	}
	if len(sample)%2 == 1 {
		sample = sample[:len(sample)-1]
	}
	if len(sample) >= 16 {
		evenNulls, oddNulls := 0, 0
		pairs := len(sample) / 2
		for i := 0; i+1 < len(sample); i += 2 {
			if sample[i] == 0 {
				evenNulls++
			}
			if sample[i+1] == 0 {
				oddNulls++
			}
		}
		// ASCII-dominated UTF-16LE: high byte (odd index) is almost always
		// 0x00, low byte (even index) almost never. Thresholds are strict on
		// the "wrong side" nulls so UTF-32 (nulls on BOTH sides) and binary
		// blobs don't slip through.
		if float64(oddNulls)/float64(pairs) > 0.30 && float64(evenNulls)/float64(pairs) < 0.02 {
			return EncodingUTF16LENoBOM
		}
		if float64(evenNulls)/float64(pairs) > 0.30 && float64(oddNulls)/float64(pairs) < 0.02 {
			return EncodingUTF16BENoBOM
		}
	}

	return EncodingUTF8 // default: treat as UTF-8/unknown-single-byte; callers validate
}

// DecodeToUTF8 decodes raw file bytes to a UTF-8 string according to enc.
// Decoding is total: malformed sequences (lone surrogates, a truncated final
// code unit) decode to U+FFFD rather than failing — a corrupt tail must not
// hide the readable remainder of a file from scanning. The second return is
// false only when enc is not a transcodable encoding (caller keeps raw).
func DecodeToUTF8(raw []byte, enc TextEncoding) (string, bool) {
	switch enc {
	case EncodingUTF8:
		return string(raw), true
	case EncodingUTF8BOM:
		if len(raw) >= 3 {
			return string(raw[3:]), true
		}
		return "", true
	case EncodingUTF16LE:
		return decodeUTF16(raw[2:], false), true
	case EncodingUTF16BE:
		return decodeUTF16(raw[2:], true), true
	case EncodingUTF16LENoBOM:
		return decodeUTF16(raw, false), true
	case EncodingUTF16BENoBOM:
		return decodeUTF16(raw, true), true
	default:
		return "", false
	}
}

// EncodeFromUTF8 re-encodes a UTF-8 string back to enc, restoring the BOM
// where the source had one. Used by the redaction write path so a redacted
// copy of a UTF-16 file is still a valid UTF-16 file (a re-importable .reg
// export, a PowerShell transcript, ...) rather than silently becoming UTF-8.
func EncodeFromUTF8(s string, enc TextEncoding) []byte {
	switch enc {
	case EncodingUTF8BOM:
		return append([]byte{0xEF, 0xBB, 0xBF}, s...)
	case EncodingUTF16LE:
		return encodeUTF16(s, false, true)
	case EncodingUTF16BE:
		return encodeUTF16(s, true, true)
	case EncodingUTF16LENoBOM:
		return encodeUTF16(s, false, false)
	case EncodingUTF16BENoBOM:
		return encodeUTF16(s, true, false)
	default:
		return []byte(s)
	}
}

// decodeUTF16 converts UTF-16 bytes (without BOM) to a UTF-8 string. An odd
// trailing byte (truncated final code unit) is dropped; unpaired surrogates
// become U+FFFD via utf16.Decode.
func decodeUTF16(raw []byte, bigEndian bool) string {
	if len(raw)%2 == 1 {
		raw = raw[:len(raw)-1]
	}
	units := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		if bigEndian {
			units = append(units, uint16(raw[i])<<8|uint16(raw[i+1]))
		} else {
			units = append(units, uint16(raw[i])|uint16(raw[i+1])<<8)
		}
	}
	var b strings.Builder
	b.Grow(len(units)) // ASCII-dominated content: ~1 byte per unit
	for _, r := range utf16.Decode(units) {
		b.WriteRune(r)
	}
	return b.String()
}

// encodeUTF16 converts a UTF-8 string to UTF-16 bytes, optionally prefixed
// with the appropriate BOM. Invalid UTF-8 in s (which cannot occur on the
// redaction path — the decoded text is valid by construction) would encode
// as U+FFFD.
func encodeUTF16(s string, bigEndian, withBOM bool) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(units)*2+2)
	if withBOM {
		if bigEndian {
			out = append(out, 0xFE, 0xFF)
		} else {
			out = append(out, 0xFF, 0xFE)
		}
	}
	for _, u := range units {
		if bigEndian {
			out = append(out, byte(u>>8), byte(u))
		} else {
			out = append(out, byte(u), byte(u>>8))
		}
	}
	return out
}

// utf8OrDecoded is a convenience for sniffing: it returns the buffer's
// decoded text when buf is a recognized transcodable encoding, or "" and
// false when the buffer should be sniffed as raw bytes.
func utf8OrDecoded(buf []byte) (string, bool) {
	enc := DetectTextEncoding(buf)
	switch enc {
	case EncodingUTF16LE, EncodingUTF16BE, EncodingUTF16LENoBOM, EncodingUTF16BENoBOM:
		s, _ := DecodeToUTF8(buf, enc)
		return s, true
	case EncodingUTF8BOM:
		s, _ := DecodeToUTF8(buf, enc)
		return s, true
	default:
		return "", false
	}
}

// Silence unused warnings for utf8 import if build tags change.
var _ = utf8.RuneError

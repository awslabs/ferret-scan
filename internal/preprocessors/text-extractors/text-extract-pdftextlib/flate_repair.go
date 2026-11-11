// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package textextractpdftextlib

import "bytes"

// repairFlateHeaders overwrites, in place, the 2-byte zlib header of every stream whose dictionary
// names FlateDecode as its first filter and whose header bytes are not a valid zlib header, with
// 0x78 0x9C (deflate, 32 KiB window, no preset dictionary). It returns how many it rewrote.
//
// Why rewriting the header is a repair and not a guess: the zlib header (RFC 1950 §2.2) carries
// only the method, the window size and a check value over those two bytes; the deflate body and
// the Adler-32 trailer that follow do not depend on it. A stream whose header alone was damaged
// therefore decodes to exactly its original content once a valid header is in place, and one whose
// body is damaged too still fails in the deflate reader, as it did before. The byte length does
// not change, so every offset in the cross-reference data and every /Length stays correct.
//
// Candidates are the `stream` keywords (not `endstream`) followed by the EOL the spec requires
// (CRLF or LF, ISO 32000-1 §7.3.8.1; a lone CR is tolerated) and immediately preceded by a
// dictionary's closing `>>`. That last condition is what keeps a `stream` byte sequence inside some
// other stream's compressed body from being taken for a keyword.
//
// Linear in len(data): the dictionary of each candidate is looked for only between the end of the
// previous `stream`/`endstream` match and this one, so the windows never overlap and every byte is
// read a constant number of times however the keywords are spaced (measured 1/2/4 MiB of
// adversarial input: ratio ~2.0 per doubling).
func repairFlateHeaders(data []byte) int {
	keyword := []byte("stream")
	repaired := 0
	prevEnd := 0 // end of the previous keyword match; the next dictionary cannot start before it
	for i := 0; i < len(data); {
		j := bytes.Index(data[i:], keyword)
		if j < 0 {
			break
		}
		k := i + j
		i = k + len(keyword)
		windowStart := prevEnd
		prevEnd = i
		if k >= 3 && string(data[k-3:k]) == "end" {
			continue
		}
		p := i
		if p < len(data) && data[p] == '\r' {
			p++
		}
		if p < len(data) && data[p] == '\n' {
			p++
		}
		if p == i || p+2 > len(data) || validZlibHeader(data[p], data[p+1]) {
			continue
		}
		if !firstFilterIsFlate(data[windowStart:k]) {
			continue
		}
		data[p], data[p+1] = 0x78, 0x9c
		repaired++
	}
	return repaired
}

// validZlibHeader mirrors the checks compress/zlib.NewReader makes on the first two bytes: method 8
// (deflate), a window of at most 32 KiB, the FCHECK multiple of 31, and no preset dictionary (which
// the reader refuses with ErrDictionary, and which no PDF filter can supply).
func validZlibHeader(cmf, flg byte) bool {
	return cmf&0x0f == 8 && cmf>>4 <= 7 && (uint16(cmf)<<8|uint16(flg))%31 == 0 && flg&0x20 == 0
}

// firstFilterIsFlate reports whether before, the bytes ahead of a `stream` keyword, ends in a
// dictionary (`>>`, then optional whitespace) whose /Filter is /FlateDecode or an array whose FIRST
// entry is /FlateDecode. Only the first filter is applied to the raw bytes, so a later
// /FlateDecode in the array says nothing about the stream's first two bytes.
func firstFilterIsFlate(before []byte) bool {
	// Start at this object's own `obj` keyword, so a previous object's /Filter in the window is not
	// read as this stream's.
	if o := bytes.LastIndex(before, []byte("obj")); o >= 0 {
		before = before[o+len("obj"):]
	}
	d := bytes.TrimRight(before, " \t\r\n\f\x00")
	if !bytes.HasSuffix(d, []byte(">>")) {
		return false
	}
	f := bytes.LastIndex(d, []byte("/Filter"))
	if f < 0 {
		return false
	}
	rest := bytes.TrimLeft(d[f+len("/Filter"):], " \t\r\n\f\x00")
	if len(rest) > 0 && rest[0] == '[' {
		rest = bytes.TrimLeft(rest[1:], " \t\r\n\f\x00")
	}
	name := []byte("/FlateDecode")
	if !bytes.HasPrefix(rest, name) {
		return false
	}
	// The name must end there: /FlateDecodeX is a different (unknown) filter.
	if len(rest) == len(name) {
		return true
	}
	switch rest[len(name)] {
	case ' ', '\t', '\r', '\n', '\f', '\x00', '/', '[', ']', '<', '>', '(', '%':
		return true
	}
	return false
}

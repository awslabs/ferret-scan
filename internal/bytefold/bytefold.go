// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package bytefold provides case folding that PRESERVES BYTE LENGTH and byte
// positions, for the one job `strings.ToLower` cannot safely do: producing a
// case-insensitive copy of a line that will then be indexed with offsets taken
// from the ORIGINAL line.
//
// # Why strings.ToLower is wrong for that job
//
// Unicode case mapping is not length-preserving, and the exceptions are not
// obscure enough to ignore. Enumerating the entire code point space:
//
//	strings.ToLower   25 runes shrink,  2 grow
//	strings.ToUpper   13 runes shrink, 20 grow
//	strings.ToTitle   13 runes shrink, 20 grow
//
// U+212A KELVIN SIGN is the worst: 3 bytes in, 1 byte out. U+0130 LATIN CAPITAL
// LETTER I WITH DOT ABOVE goes 2 to 1, U+1E9E LATIN CAPITAL LETTER SHARP S 3 to
// 2, and U+023A / U+023E go the other way, 2 to 3.
//
// So `lower := strings.ToLower(line)` followed by `lower[start:end]`, where
// start and end came from a regex match on `line`, has two failure modes:
//
//	SHRINK: the offset points past the end of `lower` -> a slice-bounds panic.
//	GROW:   the offset points into the middle of a value -> a WRONG answer,
//	        silently, with no panic to notice.
//
// The panic is the one that got noticed (#656), and it is the less dangerous of
// the two.
//
// # Why ASCII-only folding is the right answer and not a compromise
//
// Every keyword these lines are searched for is ASCII: "routing", "account",
// "ssn", "vin", "passport". Folding non-ASCII therefore buys no matches while
// costing the position invariant that the caller depends on. Restricting the
// fold to A-Z/a-z makes byte-length preservation true BY CONSTRUCTION rather
// than true-in-practice: bytes >= 0x80 are copied verbatim, so a multi-byte rune
// cannot change width, and byte i of the result always corresponds to byte i of
// the input.
//
// # When NOT to use this
//
// If a caller genuinely needs full Unicode folding AND positions, it needs a
// mapping table, not this package — see upperWithOffsets in the bankaccount
// validator, which returns the offset slice alongside the folded string. Use
// bytefold when the search terms are ASCII, which is the common case; use an
// offset map when they are not.
package bytefold

// Lower returns s with ASCII A-Z folded to a-z and every other byte copied
// verbatim.
//
// len(Lower(s)) == len(s) for all s, and Lower(s)[i] corresponds to s[i]. That
// is the whole point: the result is safe to index with offsets derived from s.
// Bytes >= 0x80 are untouched, so invalid UTF-8 also passes through unchanged
// rather than being replaced (which would move every following byte).
func Lower(s string) string {
	// Scan first, allocate only if something actually changes. Most lines
	// contain no uppercase ASCII at all, and this runs once per line of every
	// scanned file.
	i := 0
	for ; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			break
		}
	}
	if i == len(s) {
		return s
	}
	b := []byte(s)
	for ; i < len(b); i++ {
		if c := b[i]; c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// Upper is Lower's counterpart: ASCII a-z folded to A-Z, every other byte
// verbatim, byte length and byte positions preserved.
func Upper(s string) string {
	i := 0
	for ; i < len(s); i++ {
		if c := s[i]; c >= 'a' && c <= 'z' {
			break
		}
	}
	if i == len(s) {
		return s
	}
	b := []byte(s)
	for ; i < len(b); i++ {
		if c := b[i]; c >= 'a' && c <= 'z' {
			b[i] = c - ('a' - 'A')
		}
	}
	return string(b)
}

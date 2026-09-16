// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package textnorm canonicalises the characters ordinary software substitutes into text, and maps
// every byte of the result back to the byte it came from.
//
// # The gap this closes
//
// Go's regexp is RE2, where `\d` is `[0-9]` and `\s` is `[\t\n\f\r ]` — both ASCII-only. Every
// structured pattern in this repository is therefore anchored on ASCII, while a word processor, a
// PDF extractor, or an HTML paste routinely produces something else. Measured at HEAD across 8
// structured types and 10 substitutions, **61 of 80 combinations lost the finding entirely**:
//
//	                 U+2010-2015 & U+2212 dashes   U+00A0/2007/202F spaces   U+00AD   U+200B   fullwidth
//	SSN                        LOST                          -                LOST     LOST      LOST
//	CREDIT_CARD (VISA)         LOST                        LOST               LOST     LOST      LOST
//	PHONE                      LOST                          -                LOST     LOST      LOST
//	DATE_OF_BIRTH              LOST                          -                LOST      -        LOST
//	MEDICARE_MBI               LOST                          -                LOST     LOST      LOST
//	IBAN                         -                         LOST                 -      LOST      LOST
//	ABA_ROUTING                  -                           -                  -      LOST      LOST
//	NPI                          -                           -                  -      LOST      LOST
//
// Not one of these is adversarial. A user who types an SSN into Word and lets autocorrect touch it
// gets a document this tool reports as clean, and under the sink rule a value that is never reported
// is a value that is never redacted — so each cell is a cleartext leak, not merely reduced coverage.
//
// # Why an offset map, and why the text is never rewritten downstream
//
// Redaction is TEXT-based: internal/redactors/plaintext locates a finding with
// strings.Index(text, match.Text) and asserts actualText == match.Text before writing. So a
// normalized Match.Text would not be found in the original file, and a detection fix would become a
// redaction failure — the one outcome the sink rule forbids.
//
// The answer is that normalization is used for MATCHING ONLY. A validator may run over the
// normalized copy, but the match reported downstream carries the ORIGINAL bytes, recovered through
// the offset table this package returns. That is the same pattern upperWithOffsets/origSpan
// established in the bankaccount validator for the identical problem, generalised so no validator
// needs its own table — twenty validators each solving this separately is how the current situation
// arose.
//
// Every mapping here SHRINKS or preserves byte length; none grows. That is not an accident of the
// table but a property worth stating, because a growing mapping would let a normalized offset run
// past the end of the original.
package textnorm

import (
	"strings"
	"unicode/utf8"
)

// canonical maps a rune ordinary software substitutes to its ASCII equivalent. A zero value means
// the rune is DROPPED — it carries no width and no meaning for pattern matching.
//
// Each entry names where it comes from, because the test of whether a rune belongs here is "does
// ordinary software produce this without anyone trying", not "could this be used to evade".
// Adversarial confusables are deliberately out of scope; see the package doc.
var canonical = map[rune]rune{
	// Dashes. Autocorrect in Word and Google Docs turns a typed hyphen into one of these, and PDF
	// extraction emits U+2212 for a minus sign in a form field.
	//
	// Written as \u escapes, not literal characters. A literal in this repository has already been
	// wrong once — two fixtures held an ASCII "K" where U+212A was intended and passed while testing
	// nothing — and several of the runes below are invisible or indistinguishable in an editor. An
	// escape is reviewable; a literal soft hyphen is not.
	'\u2010': '-', // HYPHEN
	'\u2011': '-', // NON-BREAKING HYPHEN
	'\u2012': '-', // FIGURE DASH
	'\u2013': '-', // EN DASH — the one autocorrect produces most
	'\u2014': '-', // EM DASH
	'\u2015': '-', // HORIZONTAL BAR
	'\u2212': '-', // MINUS SIGN
	'\uFF0D': '-', // FULLWIDTH HYPHEN-MINUS (CJK-locale forms)
	'\u2043': '-', // HYPHEN BULLET (list markup pasted from HTML)

	// Spaces. A non-breaking space is what HTML paste and justified text produce; the figure and
	// narrow forms come from spreadsheets and typesetting.
	'\u00A0': ' ', // NO-BREAK SPACE
	'\u1680': ' ', // OGHAM SPACE MARK
	'\u2000': ' ', // EN QUAD
	'\u2001': ' ', // EM QUAD
	'\u2002': ' ', // EN SPACE
	'\u2003': ' ', // EM SPACE
	'\u2004': ' ', // THREE-PER-EM SPACE
	'\u2005': ' ', // FOUR-PER-EM SPACE
	'\u2006': ' ', // SIX-PER-EM SPACE
	'\u2007': ' ', // FIGURE SPACE — used to align digits in tables
	'\u2008': ' ', // PUNCTUATION SPACE
	'\u2009': ' ', // THIN SPACE
	'\u200A': ' ', // HAIR SPACE
	'\u202F': ' ', // NARROW NO-BREAK SPACE
	'\u205F': ' ', // MEDIUM MATHEMATICAL SPACE
	'\u3000': ' ', // IDEOGRAPHIC SPACE

	// Dropped entirely: zero-width and formatting characters that carry no width.
	//
	// U+00AD SOFT HYPHEN is dropped rather than mapped to '-', because it is a hyphenation HINT and
	// not a visible dash: DOCX and PDF insert it where a word MAY break. Dropping it rejoins the
	// value, so "449<SHY>87<SHY>4100" normalizes to "449874100" — which the SSN pattern matches as
	// nine consecutive digits — and an ordinary hyphenated word rejoins correctly rather than
	// gaining a hyphen it never had.
	'\u00AD': 0, // SOFT HYPHEN
	'\u200B': 0, // ZERO WIDTH SPACE
	'\u200C': 0, // ZERO WIDTH NON-JOINER
	'\u200D': 0, // ZERO WIDTH JOINER
	'\u2060': 0, // WORD JOINER
	'\uFEFF': 0, // ZERO WIDTH NO-BREAK SPACE / a BOM appearing mid-document
}

// fullwidthDigitBase is U+FF10 FULLWIDTH DIGIT ZERO. CJK-locale forms and spreadsheets emit these,
// and RE2's \d does not match them.
const fullwidthDigitBase = '\uFF10'

// canonicalRune returns the ASCII replacement for r, whether r is replaced at all, and whether it is
// dropped.
func canonicalRune(r rune) (replacement rune, replaced, dropped bool) {
	if r >= fullwidthDigitBase && r <= fullwidthDigitBase+9 {
		return '0' + (r - fullwidthDigitBase), true, false
	}
	if c, ok := canonical[r]; ok {
		return c, true, c == 0
	}
	return r, false, false
}

// HasNormalizable reports whether s contains any character Normalize would change.
//
// The gate that keeps this package free on the common path. Content that is pure ASCII — the
// overwhelming majority of what is scanned — cannot contain any of these runes, so a single scan for
// a byte >= 0x80 answers the question without decoding anything. Callers use this to decide whether a
// second validation pass is worth running at all; without it, every scan would pay for a feature that
// applies to a small minority of documents.
func HasNormalizable(s string) bool {
	// Every rune in the table is non-ASCII, so no ASCII-only string can need normalization.
	hasHighByte := false
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			hasHighByte = true
			break
		}
	}
	if !hasHighByte {
		return false
	}
	for _, r := range s {
		if _, replaced, _ := canonicalRune(r); replaced {
			return true
		}
	}
	return false
}

// Normalize canonicalises s and returns a table translating each byte offset in the result back to an
// offset in s.
//
// A nil table means the identity mapping: s needed no change, and the returned string is s. That is
// the common case and it allocates nothing.
//
// The table has one entry per result byte plus one for the end, so a match's exclusive end offset
// maps too. The string and its table are built in the same loop, so they cannot disagree about a
// rune's width — the failure that made an earlier hand-rolled version drop the last digit of an IBAN
// and mask the preceding space instead.
func Normalize(s string) (string, []int) {
	if !HasNormalizable(s) {
		return s, nil
	}

	var b strings.Builder
	b.Grow(len(s))
	offsets := make([]int, 0, len(s)+1)

	for i, r := range s {
		replacement, replaced, dropped := canonicalRune(r)
		if dropped {
			continue // contributes no bytes, so no offsets either
		}
		if !replaced {
			replacement = r
		}
		before := b.Len()
		b.WriteRune(replacement)
		for j := before; j < b.Len(); j++ {
			offsets = append(offsets, i)
		}
	}
	offsets = append(offsets, len(s))
	return b.String(), offsets
}

// OrigSpan translates a [start,end) span in a normalized string back to the original.
//
// A nil table is the identity mapping. Out-of-range inputs are clamped rather than panicking: this
// runs on spans a validator produced, and a validator that reports a span past the end of the text it
// was given is a bug to be contained here, not a reason to crash a scan.
func OrigSpan(offsets []int, start, end int) (int, int) {
	if offsets == nil {
		return start, end
	}
	last := len(offsets) - 1
	if start < 0 {
		start = 0
	}
	if start > last {
		start = last
	}
	if end < start {
		end = start
	}
	if end > last {
		end = last
	}
	return offsets[start], offsets[end]
}

// Fold canonicalises s for COMPARISON, with no offset table.
//
// Used to verify that a span recovered from the original text is really the same value the validator
// matched in the normalized copy. That check is what makes the second pass safe to act on: if
// Fold(original span) does not equal the matched text, the mapping is wrong and the match is dropped
// rather than reported against bytes it may not describe. A dropped match costs a finding; a
// mis-mapped one costs a redaction that masks the wrong bytes and leaves the value in place.
func Fold(s string) string {
	out, _ := Normalize(s)
	return out
}

// ByteLengthNeverGrows is a documentation assertion, verified by the package tests: every mapping
// either shrinks the byte length or leaves it unchanged.
//
// It matters because the offset table is indexed by RESULT byte, so a mapping that grew would let a
// normalized offset exceed the original length and OrigSpan would clamp — silently reporting a
// shorter span than the value occupies. Stated as a function so a reader can find the property and
// the test that holds it.
func ByteLengthNeverGrows() bool {
	for r, c := range canonical {
		if c == 0 {
			continue // dropped: 0 bytes out, always a shrink
		}
		if utf8.RuneLen(c) > utf8.RuneLen(r) {
			return false
		}
	}
	for r := fullwidthDigitBase; r <= fullwidthDigitBase+9; r++ {
		if utf8.RuneLen('0'+(r-fullwidthDigitBase)) > utf8.RuneLen(r) {
			return false
		}
	}
	return true
}

// HasNormalizableNearDigit reports whether s contains a character Normalize would change that sits
// next to an ASCII digit — or that IS a digit, in the fullwidth case.
//
// # Why this and not HasNormalizable
//
// HasNormalizable is too broad to gate a second validation pass on. Measured over 1,497 real
// documents, 833 of them — 55% — contain at least one normalizable character, almost always a
// non-breaking space or an en dash in ordinary prose. Gating on that ran the whole validator set twice
// on more than half the corpus and cost **+59% wall clock (36.5s -> 58.2s) for 8 additional findings**,
// four of which were false positives. That is not a trade worth making.
//
// The narrower question matches what the pass is FOR. Every finding the pass recovers is a structured
// identifier whose separator or digits were substituted:
//
//	449<ENDASH>87<ENDASH>4100        the dash sits between digits
//	GB82<NBSP>WEST 1234 5698         the space follows a digit
//	449<SHY>87<SHY>4100              the soft hyphen sits between digits
//	4111<ZWSP>1111<ZWSP>1111         the zero-width space sits between digits
//	AKIAIOSFODNN<FW7>EXAMPLE         the fullwidth digit IS the substitution
//
// while prose that merely contains such a character — "long-term", "MACsec<NBHYPHEN>encrypted",
// "endpoints<EMDASH>dataplane", "Francisco,<NBSP>Contact" — has no digit beside it and is skipped.
// So the gate removes the cost on documents the pass could not have helped, and as a side effect it
// removes one of the false positives too.
//
// Adjacency is measured in RUNES, one either side, and a fullwidth digit qualifies on its own because
// it is itself the character RE2 cannot see.
func HasNormalizableNearDigit(s string) bool {
	// Same cheap pre-check as HasNormalizable: every rune in the table is non-ASCII.
	hasHighByte := false
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			hasHighByte = true
			break
		}
	}
	if !hasHighByte {
		return false
	}

	// A three-rune window: previous, current, next.
	var prev rune = -1
	runes := []rune(s)
	for i, r := range runes {
		_, replaced, _ := canonicalRune(r)
		if !replaced {
			prev = r
			continue
		}
		// A fullwidth digit is the substitution itself — no neighbour needed.
		if r >= fullwidthDigitBase && r <= fullwidthDigitBase+9 {
			return true
		}
		if isASCIIDigit(prev) {
			return true
		}
		if i+1 < len(runes) && isASCIIDigit(runes[i+1]) {
			return true
		}
		prev = r
	}
	return false
}

func isASCIIDigit(r rune) bool { return r >= '0' && r <= '9' }

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package detector

import "unicode/utf8"

// LineContextWindow is how many bytes of surrounding text LineContext keeps on
// each side of a match. It matches ContextExtractor's default (50), which is the
// wider of the two widths already in use across the validators.
const LineContextWindow = 50

// LineContext builds the ContextInfo for a match occupying [matchStart, matchEnd)
// of line.
//
// It exists so a validator that already has the line and the match offsets can
// record context without restating the window arithmetic, which is currently
// open-coded per validator at two different widths and, in the older copies, with
// a strings.Index rescan that resolves to the wrong occurrence when a value
// repeats on the line.
//
// The windows are clamped to the line and then pulled back to rune boundaries, so
// BeforeText and AfterText never begin or end inside a multi-byte character.
// (pkg/scan repairs that at its own boundary for the older validators; new
// callers get it right at the source instead.) Both exclude the match itself:
// BeforeText ends where the match starts and AfterText begins where it ends, so
// BeforeText+match+AfterText is always a contiguous span of the line.
//
// Offsets outside the line yield a ContextInfo carrying only FullLine, on the
// principle that a wrong window is worse than no window: the caller's offsets
// disagree with the caller's line, and guessing which is authoritative would
// attach text that never surrounded the match.
func LineContext(line string, matchStart, matchEnd int) ContextInfo {
	info := ContextInfo{FullLine: line}
	if matchStart < 0 || matchEnd > len(line) || matchStart > matchEnd {
		return info
	}

	before := line[max(0, matchStart-LineContextWindow):matchStart]
	after := line[matchEnd:min(len(line), matchEnd+LineContextWindow)]

	info.BeforeText = TrimLeadingRuneFragment(before)
	info.AfterText = TrimTrailingRuneFragment(after)
	return info
}

// TrimLeadingRuneFragment drops the tail of a rune the window's outer edge cut
// through. Only a leading run of continuation bytes can be such a tail, and a cut
// leaves at most utf8.UTFMax-1 of them, so the bound keeps this a boundary repair
// rather than a sanitizer: malformed bytes that were genuinely in the line are
// left for the caller to see.
func TrimLeadingRuneFragment(s string) string {
	i := 0
	for i < len(s) && i < utf8.UTFMax-1 && s[i]&0xC0 == 0x80 {
		i++
	}
	return s[i:]
}

// TrimTrailingRuneFragment is the mirror of TrimLeadingRuneFragment for the far
// edge of AfterText, where a cut leaves a rune's leading byte without its
// continuation bytes. A validly encoded U+FFFD decodes with a size greater than
// one and is kept; only an incomplete encoding is removed.
func TrimTrailingRuneFragment(s string) string {
	for i := 0; i < utf8.UTFMax-1 && s != ""; i++ {
		r, size := utf8.DecodeLastRuneInString(s)
		if r != utf8.RuneError || size > 1 {
			break
		}
		s = s[:len(s)-size]
	}
	return s
}

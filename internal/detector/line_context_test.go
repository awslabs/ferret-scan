// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package detector

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestLineContextBracketsTheMatch(t *testing.T) {
	const line = "Bucket arn:aws:s3:::prod-customer-exports listed here"
	const match = "arn:aws:s3:::prod-customer-exports"
	start := strings.Index(line, match)

	got := LineContext(line, start, start+len(match))

	if got.FullLine != line {
		t.Errorf("FullLine = %q, want %q", got.FullLine, line)
	}
	if want := "Bucket "; got.BeforeText != want {
		t.Errorf("BeforeText = %q, want %q", got.BeforeText, want)
	}
	if want := " listed here"; got.AfterText != want {
		t.Errorf("AfterText = %q, want %q", got.AfterText, want)
	}
	// The defining property callers rely on: before+match+after reconstructs a
	// contiguous span of the line, so the match is bracketed and never restated.
	if rebuilt := got.BeforeText + match + got.AfterText; !strings.Contains(line, rebuilt) {
		t.Errorf("before+match+after = %q is not a span of %q", rebuilt, line)
	}
	if strings.Contains(got.BeforeText, match) || strings.Contains(got.AfterText, match) {
		t.Errorf("context must exclude the match (before=%q after=%q)", got.BeforeText, got.AfterText)
	}
}

func TestLineContextClampsToWindowAndLine(t *testing.T) {
	match := "SECRET"
	long := strings.Repeat("a", 300) + match + strings.Repeat("b", 300)

	got := LineContext(long, 300, 300+len(match))

	if len(got.BeforeText) != LineContextWindow {
		t.Errorf("len(BeforeText) = %d, want the window %d", len(got.BeforeText), LineContextWindow)
	}
	if len(got.AfterText) != LineContextWindow {
		t.Errorf("len(AfterText) = %d, want the window %d", len(got.AfterText), LineContextWindow)
	}

	// At the very start and end of a line the window clamps rather than
	// underflowing the slice bounds.
	short := match + "!"
	got = LineContext(short, 0, len(match))
	if got.BeforeText != "" {
		t.Errorf("BeforeText = %q, want empty at line start", got.BeforeText)
	}
	if got.AfterText != "!" {
		t.Errorf("AfterText = %q, want %q", got.AfterText, "!")
	}
}

// TestLineContextIsRuneAligned is the reason this helper exists rather than each
// caller slicing for itself: a fixed byte window lands mid-rune on non-ASCII
// text, and a public consumer converts these to a platform string.
func TestLineContextIsRuneAligned(t *testing.T) {
	const match = "4111-1111-1111-1111"
	// Runs of 3-byte runes on both sides, long enough that a 50-byte window
	// cannot land on a rune boundary by luck.
	cjk := strings.Repeat("機密資料", 12)
	line := cjk + " " + match + " " + cjk
	start := strings.Index(line, match)

	got := LineContext(line, start, start+len(match))

	if !utf8.ValidString(got.BeforeText) {
		t.Errorf("BeforeText is not valid UTF-8: %q", got.BeforeText)
	}
	if !utf8.ValidString(got.AfterText) {
		t.Errorf("AfterText is not valid UTF-8: %q", got.AfterText)
	}
	// Trimming only ever removes bytes, so both remain spans of the line.
	if !strings.Contains(line, got.BeforeText) || !strings.Contains(line, got.AfterText) {
		t.Error("trimming produced text that is not a span of the input line")
	}
}

// TestLineContextRejectsInconsistentOffsets covers the deliberate choice to
// return FullLine only rather than guess. Offsets that do not fit the line mean
// the caller passed a mismatched pair, and inventing a window would attach text
// that never surrounded the match.
func TestLineContextRejectsInconsistentOffsets(t *testing.T) {
	const line = "short line"
	cases := []struct {
		name       string
		start, end int
	}{
		{"end past line", 0, len(line) + 5},
		{"negative start", -1, 4},
		{"inverted", 6, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := LineContext(line, tc.start, tc.end)
			if got.FullLine != line {
				t.Errorf("FullLine = %q, want it preserved", got.FullLine)
			}
			if got.BeforeText != "" || got.AfterText != "" {
				t.Errorf("want no window for inconsistent offsets, got before=%q after=%q",
					got.BeforeText, got.AfterText)
			}
		})
	}
}

func TestTrimRuneFragments(t *testing.T) {
	const cjk = "資料" // 3 bytes per rune

	cases := []struct {
		name         string
		in, wantHead string
		wantTail     string
	}{
		{"empty", "", "", ""},
		{"ascii untouched", "abc", "abc", "abc"},
		{"clean multibyte untouched", cjk, cjk, cjk},
		{"encoded replacement char kept", "�", "�", "�"},
		// A window cut one byte into a 3-byte rune leaves two continuation
		// bytes at the head; cut two bytes in, one leading byte at the tail.
		{"head fragment trimmed", cjk[1:], cjk[3:], cjk[1:]},
		{"tail fragment trimmed", cjk[:4], cjk[:4], cjk[:3]},
		{"tail lead byte trimmed", cjk[:5], cjk[:5], cjk[:3]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := TrimLeadingRuneFragment(tc.in); got != tc.wantHead {
				t.Errorf("TrimLeadingRuneFragment(%q) = %q, want %q", tc.in, got, tc.wantHead)
			}
			if got := TrimTrailingRuneFragment(tc.in); got != tc.wantTail {
				t.Errorf("TrimTrailingRuneFragment(%q) = %q, want %q", tc.in, got, tc.wantTail)
			}
		})
	}
}

// TestTrimIsBoundedNotSanitizing pins the deliberate limit on the repair: it
// fixes a cut edge, it does not scrub malformed input. Content that was genuinely
// mis-encoded in the source still reaches the caller.
func TestTrimIsBoundedNotSanitizing(t *testing.T) {
	const inner = "ok\xff\xfe more text"
	if got := TrimLeadingRuneFragment(inner); got != inner {
		t.Errorf("TrimLeadingRuneFragment(%q) = %q, want it unchanged", inner, got)
	}
	longRun := strings.Repeat("\x80", 16)
	if got := TrimLeadingRuneFragment(longRun); len(longRun)-len(got) > utf8.UTFMax-1 {
		t.Errorf("trimmed %d bytes from the head, want at most %d", len(longRun)-len(got), utf8.UTFMax-1)
	}
	if got := TrimTrailingRuneFragment(longRun); len(longRun)-len(got) > utf8.UTFMax-1 {
		t.Errorf("trimmed %d bytes from the tail, want at most %d", len(longRun)-len(got), utf8.UTFMax-1)
	}
}

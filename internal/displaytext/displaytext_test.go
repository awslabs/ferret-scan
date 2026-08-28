// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package displaytext

import (
	"strings"
	"testing"
)

// TestSanitizeDisplayTextEscapesEveryControlByte.
//
// Escaping is an allowlist: everything outside the printable set goes, rather than a
// denylist of sequences known to be dangerous. BSC1 Output Encoding is explicit that a
// denylist is always incomplete, and the payloads here show why — "\x1b[2K\r" and a bare
// "\n" do completely different damage and neither would appear on a list drawn up for the
// other.
func TestSanitizeDisplayTextEscapesEveryControlByte(t *testing.T) {
	for b := 0; b < 0x20; b++ {
		in := "a" + string(rune(b)) + "b"
		got := SanitizeDisplayText(in)
		if strings.ContainsRune(got, rune(b)) {
			t.Errorf("byte 0x%02x survived: %q -> %q", b, in, got)
		}
	}
	if got := SanitizeDisplayText("a\x7fb"); strings.ContainsRune(got, 0x7f) {
		t.Errorf("DEL survived: %q", got)
	}
	// C1. A terminal in 8-bit mode reads U+009B as CSI and U+0085 as NEL, so they are
	// commands exactly as the C0 range is.
	for _, r := range []rune{0x80, 0x85, 0x9b, 0x9f} {
		in := "a" + string(r) + "b"
		if got := SanitizeDisplayText(in); strings.ContainsRune(got, r) {
			t.Errorf("C1 U+%04X survived: %q -> %q", r, in, got)
		}
	}
}

// TestSanitizeDisplayTextLeavesOrdinaryPathsAlone is the half that keeps this from being a
// mangling function. A report that escaped legitimate names would be worse than one that
// passed control bytes, because operators would stop trusting the filenames.
func TestSanitizeDisplayTextLeavesOrdinaryPathsAlone(t *testing.T) {
	for _, s := range []string{
		"",
		"report.txt",
		"/home/user/Documents/quarterly-report.txt",
		`C:\Users\alice\report.txt`,
		"rapport-café.txt",
		"報告書.txt",
		"файл.txt",
		"emoji-🙂.txt",
		"weird but printable !@#$%^&*()[]{}|;:'\",.<>/?`~.txt",
		"spaces are fine.txt",
	} {
		if got := SanitizeDisplayText(s); got != s {
			t.Errorf("SanitizeDisplayText(%q) = %q, want it unchanged", s, got)
		}
	}
}

// TestSanitizeDisplayTextKeepsInvalidUTF8Distinguishable.
//
// Unix paths are byte strings, so a filename need not be valid UTF-8. Writing U+FFFD would
// collapse two different invalid bytes to the same displayed name, and two different files
// would then be indistinguishable in the report. Escaping keeps them apart.
func TestSanitizeDisplayTextKeepsInvalidUTF8Distinguishable(t *testing.T) {
	a := SanitizeDisplayText("f\xffle.txt")
	b := SanitizeDisplayText("f\xfele.txt")
	if a == b {
		t.Errorf("two different invalid bytes produced the same output %q; a report cannot "+
			"then tell the two files apart", a)
	}
	for _, got := range []string{a, b} {
		if strings.ContainsRune(got, 0xFFFD) {
			t.Errorf("%q contains U+FFFD; escaping must be byte-faithful", got)
		}
		if !strings.Contains(got, `\x`) {
			t.Errorf("%q carries no escape, so the invalid byte passed through", got)
		}
	}
}

// TestSanitizeDisplayTextIsIdempotentlySafe: running it twice must not re-escape the
// backslashes it produced, or repeated application would corrupt the name. It is not
// required to be a fixed point in the strict sense, only to stop introducing control bytes.
func TestSanitizeDisplayTextIsIdempotentlySafe(t *testing.T) {
	once := SanitizeDisplayText("a\x1b[2K\rb.txt")
	twice := SanitizeDisplayText(once)
	if once != twice {
		t.Errorf("not idempotent: %q -> %q. The output contains only printable bytes, so a "+
			"second pass must be a no-op.", once, twice)
	}
}

// TestSanitizeDisplayTextEscapesTabAndNewlineDeliberately.
//
// These are the two an author might be tempted to treat as harmless whitespace. A newline
// in a filename is what fabricates a report line; a tab is a formula trigger in the CSV
// sink. A formatter that wants its own newline writes its own.
func TestSanitizeDisplayTextEscapesTabAndNewlineDeliberately(t *testing.T) {
	got := SanitizeDisplayText("a\tb\nc\r\nd")
	for _, bad := range []string{"\t", "\n", "\r"} {
		if strings.Contains(got, bad) {
			t.Errorf("%q survived in %q. It is not this function's own whitespace — it came "+
				"from borrowed data.", bad, got)
		}
	}
}

// TestMarkdownFenceForOutrunsItsContent covers #381 item 5.
//
// CommonMark §4.5 closes a fenced block at the first run of AT LEAST the opening length, so
// a hardcoded three-backtick fence is closed by any three-backtick line in the content.
func TestMarkdownFenceForOutrunsItsContent(t *testing.T) {
	cases := []struct {
		name, content string
		wantLen       int
	}{
		{"no backticks", "hello", 3},
		{"one backtick", "a `b` c", 3},
		{"two backticks", "a ``b`` c", 3},
		{"three backticks", "a\n```\nb", 4},
		{"four backticks", "a\n````\nb", 5},
		{"run split across lines stays a run of one", "`\n`\n`", 3},
		{"longest run wins", "``\n`````\n```", 6},
		{"empty", "", 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fence := MarkdownFenceFor(tc.content)
			if len(fence) != tc.wantLen {
				t.Errorf("MarkdownFenceFor(%q) = %d backticks, want %d", tc.content, len(fence), tc.wantLen)
			}
			if strings.Trim(fence, "`") != "" {
				t.Errorf("fence %q contains something other than backticks", fence)
			}
			// The property that matters, stated directly: no run in the content can close
			// this fence.
			if longest := longestBacktickRun(tc.content); longest >= len(fence) {
				t.Errorf("content's longest run is %d and the fence is %d; the fence must be "+
					"strictly longer or the content closes it", longest, len(fence))
			}
		})
	}
}

func longestBacktickRun(s string) int {
	longest, run := 0, 0
	for i := 0; i < len(s); i++ {
		if s[i] == '`' {
			run++
			if run > longest {
				longest = run
			}
			continue
		}
		run = 0
	}
	return longest
}

// TestMarkdownFenceForNeverGoesBelowThree: CommonMark requires at least three.
func TestMarkdownFenceForNeverGoesBelowThree(t *testing.T) {
	for _, content := range []string{"", "x", "`", "``"} {
		if n := len(MarkdownFenceFor(content)); n < 3 {
			t.Errorf("MarkdownFenceFor(%q) = %d backticks; CommonMark requires >= 3", content, n)
		}
	}
}

// TestTheFastPathIsNarrowButComplete pins needsSanitizing.
//
// It is an optimisation, so a bug here is either a wasted allocation (harmless) or a MISSED
// control byte (not harmless). Both directions are asserted. The C1 half rests on one fact:
// in valid UTF-8, U+0080-U+009F encodes as 0xC2 followed by 0x80-0x9F, so 0xC2 is the only
// lead byte that can introduce a C1 control.
func TestTheFastPathIsNarrowButComplete(t *testing.T) {
	mustSanitize := []string{
		"a\x00b", "a\x1bb", "a\x0ab", "a\x7fb",
		"a\u0085b",   // C1 NEL, encoded 0xC2 0x85
		"a\u009bb",   // C1 CSI, encoded 0xC2 0x9b
		"f\xffle",    // invalid UTF-8
		"\xc2",       // truncated lead byte
		"a\xc0\x80b", // overlong NUL: invalid UTF-8
	}
	for _, s := range mustSanitize {
		if !needsSanitizing(s) {
			t.Errorf("needsSanitizing(%q) = false, so the full pass is skipped and the byte "+
				"reaches the report", s)
		}
	}

	fastPath := []string{
		"", "plain.txt", "a b c", "rapport-café.txt", "報告書.txt", "файл.txt",
		"emoji-🙂.txt", "e\u00e9\u00fc.txt",
		// These live in the 0xC2 lead-byte block alongside the C1 controls, so a fast path
		// that stopped at the lead byte sent all of them down the full pass. Testing the
		// continuation byte separates them.
		"price-\u00a340.txt", "\u00a9-notice.txt", "45\u00b0-turn.txt", "\u00bd-share.txt",
		"\u00b5-service.txt", "caf\u00e9-\u00a3\u00a9.txt",
	}
	for _, s := range fastPath {
		if needsSanitizing(s) {
			t.Errorf("needsSanitizing(%q) = true; an ordinary path must take the "+
				"allocation-free path", s)
		}
		if got := SanitizeDisplayText(s); got != s {
			t.Errorf("SanitizeDisplayText(%q) = %q, want unchanged", s, got)
		}
	}
}

// TestTheCleanPathDoesNotAllocate states the property the fast path exists for, so it cannot
// silently regress into the full pass for every non-ASCII filename — which is exactly what
// the first version did.
func TestTheCleanPathDoesNotAllocate(t *testing.T) {
	paths := []string{"/home/user/Documents/quarterly-report.txt", "rapport-café.txt", "報告書.txt"}
	allocs := testing.AllocsPerRun(200, func() {
		for _, p := range paths {
			_ = SanitizeDisplayText(p)
		}
	})
	if allocs != 0 {
		t.Errorf("the clean path allocated %.1f times per run, want 0. A non-ASCII filename "+
			"is not an edge case, and treating every byte >= 0x80 as suspicious sent all of "+
			"them through the Builder.", allocs)
	}
}

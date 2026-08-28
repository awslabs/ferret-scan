// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package displaytext escapes borrowed text before it reaches a display sink.
//
// A LEAF package, deliberately: it imports nothing from this repository. That is the whole
// reason it exists separately from internal/formatters/shared, where these functions used to
// live. shared imports internal/formatters, so internal/formatters could not import shared
// back — which left the coverage/redaction disclosure emitters in internal/formatters and cmd
// with no way to reach the escaping at all, and that is exactly where the control bytes were
// still landing (#544). Escaping "at every sink" is only possible if every sink can import the
// escaper.
//
// Keep it dependency-free. Anything added here that imports another internal package
// reintroduces the cycle for some future emitter.
package displaytext

import (
	"strings"
	"unicode/utf8"
)

// A filename comes from the scanned tree, so its bytes are chosen by whoever created the
// file — a contributor to a repository, an upload directory, an extracted archive. The
// report writes it out. Any control byte in that name is therefore attacker-supplied
// terminal or markup input arriving at a display sink.
//
// Measured on HEAD before this existed, scanning a directory of three such files:
//
//	format        raw control bytes in the report
//	text                                        6
//	csv                                         6
//	json / yaml / junit / sarif                 0
//
// so the raw-byte sinks are exactly text and csv. json, yaml and sarif escape them;
// encoding/xml substitutes U+FFFD for 0x1B, which covers junit.
//
// What that buys an attacker, each reproduced end to end:
//
//   - A name containing "\x1b[2K\r" (erase line, carriage return) makes the operator's
//     terminal blank the finding row and return to its start. Replayed through a CSI
//     interpreter the report shows the header, the rule, an EMPTY line where a HIGH SSN
//     finding was, and then "Files: 1 scanned | Findings: 1 (1 high...)". The finding is
//     gone from the screen while the summary still counts it.
//   - A name containing "\n\nNo sensitive information found. Scan complete: 0 findings."
//     adds that sentence to the report as its own line, between the last finding and the
//     summary block.
//
// Exit codes are unaffected, so machine gates are not fooled; the damage is to the human
// reading the report, which is the artefact most likely to be trusted at a glance.
//
// This is an ALLOWLIST encoding rather than a denylist strip, per BSC1 Output Encoding:
// a denylist of "dangerous" sequences is always incomplete, so everything outside the
// printable set is escaped and nothing is removed. Nothing is lost either — the escaped
// form still identifies the file, and it is reversible by eye.

// SanitizeDisplayText replaces every byte a terminal or markup renderer would treat as a
// command with a visible \xNN escape.
//
// Escaped: C0 (U+0000–U+001F), DEL (U+007F), C1 (U+0080–U+009F), and any byte that is not
// valid UTF-8. Everything else passes through untouched, so an ordinary path — including a
// non-ASCII one like "rapport-café.txt" or "報告書.txt" — is unchanged.
//
// TAB and NEWLINE are escaped too, deliberately. They are not styling here: a newline in a
// filename is what fabricates a report line, and a tab is a formula trigger in the CSV
// sink. A formatter that wants its OWN newline writes its own; this function only ever sees
// borrowed data.
//
// Applied UNCONDITIONALLY, not gated on NoColor. These bytes are not ferret's styling, so
// "the operator asked for colour" is not a reason to pass an attacker's escape sequence
// through. Colour is applied by wrapping the sanitized string, which is why this must run
// before any colouring.
func SanitizeDisplayText(s string) string {
	if !needsSanitizing(s) {
		return s
	}

	var b strings.Builder
	// Every escape is 4 bytes for a 1-byte input, so this is a safe lower bound that
	// avoids the first few grows without over-allocating for a mostly-clean string.
	b.Grow(len(s) + 8)

	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			// One-byte range: decide from the byte directly.
			if isDangerousASCII(c) {
				writeHexEscape(&b, c)
			} else {
				b.WriteByte(c)
			}
			i++
			continue
		}

		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			// Invalid UTF-8. Escaping the byte rather than writing U+FFFD keeps the
			// output byte-faithful: two different invalid bytes stay distinguishable, so
			// two different files cannot collapse to the same displayed name.
			writeHexEscape(&b, c)
			i++
			continue
		}
		if r >= 0x80 && r <= 0x9F {
			// C1 controls. A terminal in 8-bit mode treats U+0085 as NEL and U+009B as
			// CSI, so these are commands exactly as the C0 range is.
			writeUnicodeEscape(&b, r)
			i += size
			continue
		}
		b.WriteString(s[i : i+size])
		i += size
	}
	return b.String()
}

// needsSanitizing is the fast path. Nearly every real filename is clean, and this keeps those
// allocation-free.
//
// The multi-byte case is narrowed to exactly the C1 range rather than waved through. In valid
// UTF-8, U+0080–U+009F encodes as 0xC2 followed by 0x80–0x9F, so 0xC2 is the only lead byte
// that can introduce a C1 control — and it is not sufficient on its own, because 0xC2 also
// leads U+00A0–U+00BF, which is where £ © ° µ ½ ¿ live. Testing the continuation byte too
// makes this exact for any valid UTF-8 string. Anything else is only interesting if the string
// is not valid UTF-8 at all, which utf8.ValidString answers directly.
//
// Both narrowings came from the benchmark rather than from reading the code. A first version
// treated any byte >= 0x80 as a maybe, so an ordinary non-ASCII path allocated 32 B for
// nothing; a second stopped at the 0xC2 lead byte, which still sent "price-£40.txt" down the
// full pass. Non-ASCII filenames are not an edge case.
func needsSanitizing(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7F {
			return true
		}
		if c == 0xC2 && i+1 < len(s) && s[i+1] >= 0x80 && s[i+1] <= 0x9F {
			return true
		}
	}
	return !utf8.ValidString(s)
}

// isDangerousASCII reports whether a single-byte value is a control character.
//
// Written as an explicit range rather than unicode.IsControl so the set is visible at the
// call site and cannot widen under a Unicode table update.
func isDangerousASCII(c byte) bool {
	return c < 0x20 || c == 0x7F
}

const hexDigits = "0123456789abcdef"

func writeHexEscape(b *strings.Builder, c byte) {
	b.WriteString(`\x`)
	b.WriteByte(hexDigits[c>>4])
	b.WriteByte(hexDigits[c&0x0F])
}

func writeUnicodeEscape(b *strings.Builder, r rune) {
	b.WriteString(`\u`)
	for shift := 12; shift >= 0; shift -= 4 {
		b.WriteByte(hexDigits[(r>>uint(shift))&0x0F])
	}
}

// MarkdownFenceFor returns a backtick fence long enough to enclose content.
//
// CommonMark closes a fenced code block at the first fence of AT LEAST the opening length,
// so a hardcoded three-backtick fence is closed early by any three-backtick line inside the
// content. Measured on a real SSH private key whose body carried one such line, emitted
// through --show-match --format gitlab-sast: the description contained THREE fence lines
// rather than two, so the opener paired with the injected line, the key's END marker
// rendered as prose, and the trailing fence opened a block that was never closed —
// swallowing the "**Remediation:**" section that follows it.
//
// An even number of injected fences is not safe either, only less obviously broken: two
// injected lines re-pair into balanced blocks, and the key body between them still leaks
// out of the code block as ordinary prose.
//
// CommonMark §4.5 permits a fence of three or more backticks, so the fix is to outrun the
// content: one longer than the longest run in it, never fewer than three.
func MarkdownFenceFor(content string) string {
	longest, run := 0, 0
	for i := 0; i < len(content); i++ {
		if content[i] == '`' {
			run++
			if run > longest {
				longest = run
			}
			continue
		}
		run = 0
	}

	n := longest + 1
	if n < 3 {
		n = 3
	}
	return strings.Repeat("`", n)
}

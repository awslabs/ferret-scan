// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package passport

import "strings"

// A UK-shaped candidate, nine bare digits, followed by a byte unit is a quantity, not a passport
// number (#939). Measured on main @ 2fb4719: docs/COVERAGE_DISCLOSURE.md's row "would exceed the
// <9 digits>-byte total embedded extraction budget for this document" read PASSPORT 90 HIGH, the
// form-context arm accepting "document" as the travel word.
//
// The candidate is not reported as a passport. That is this validator's ordinary outcome for weak
// evidence (scoreCandidate reports nothing at 60 or below, or without strong context), and the
// digits are not left unreported: the SSN validator still reports the bare nine-digit form, at its
// quantity ceiling, so the redactor still covers them. internal/validators/ssn/other_meaning.go holds
// the twin of this test.

// byteWordUnits are matched case-insensitively; byteSymbolUnits exactly, because a lower-case "b"
// is a bit in the unit conventions that use it.
var (
	byteWordUnits   = []string{"bytes", "byte"}
	byteSymbolUnits = []string{"KiB", "MiB", "GiB", "TiB", "kB", "KB", "MB", "GB", "TB", "B"}
)

// isByteQuantityAt reports whether the candidate ending at line[end] is directly followed by a unit
// of bytes, with at most one space or hyphen between, ending at a word boundary. It reads a fixed
// number of bytes, so the per-candidate cost does not grow with the line.
func isByteQuantityAt(line string, end int) bool {
	rest := line[end:]
	if len(rest) > 0 && (rest[0] == ' ' || rest[0] == '-') {
		rest = rest[1:]
	}
	unitEnds := func(n int) bool {
		return len(rest) == n || !isASCIIWordByte(rest[n])
	}
	for _, u := range byteWordUnits {
		if len(rest) >= len(u) && strings.EqualFold(rest[:len(u)], u) && unitEnds(len(u)) {
			return true
		}
	}
	for _, u := range byteSymbolUnits {
		if strings.HasPrefix(rest, u) && unitEnds(len(u)) {
			return true
		}
	}
	return false
}

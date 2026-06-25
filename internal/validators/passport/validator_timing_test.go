// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package passport

import (
	"strings"
	"testing"
	"time"
)

// buildWorstCaseSingleLine builds the worst-case input shape for this
// validator: a SINGLE very long line (no newlines) densely packed with
// passport-shaped tokens. Each token is separated by a space so the regex \b
// word boundaries fire on every one, maximizing the number of regex hits the
// per-match logic must process.
//
// Before the O(n^2) fix, ValidateContent on this shape re-scanned and
// re-lower-cased the entire (growing) line once per match, so a ~1MB line took
// on the order of an hour. The fix hoists per-line work out of the per-match
// loop, uses match byte offsets instead of strings.Index rescans, and caps the
// number of matches processed per (line, pattern), making the same input
// complete in well under a second.
func buildWorstCaseSingleLine(targetBytes int) string {
	// A mix of US (C12345678), Canada (CA654321 / GB123456), UK (987654321),
	// EU (FR1234567 / DEABCDE12) shaped tokens so multiple patterns hit.
	tokens := []string{"C12345678", "CA654321", "987654321", "FR1234567", "B98765432", "DEABCDE12"}
	var sb strings.Builder
	sb.Grow(targetBytes + 16)
	i := 0
	for sb.Len() < targetBytes {
		sb.WriteString(tokens[i%len(tokens)])
		sb.WriteByte(' ')
		i++
	}
	return sb.String()
}

// TestPassportValidator_NoQuadraticBlowup is a performance regression guard. It
// feeds a ~1MB single-line worst-case input to ValidateContent and asserts it
// returns within a generous ceiling. The ceiling is deliberately loose (5s) so
// the test is not flaky on slow/loaded CI hosts; it still catches a
// reintroduction of the O(n^2) behavior, which made this same input take
// minutes-to-hours.
func TestPassportValidator_NoQuadraticBlowup(t *testing.T) {
	v := NewValidator()
	line := buildWorstCaseSingleLine(1 << 20) // ~1 MiB, single line, no newlines

	start := time.Now()
	matches, err := v.ValidateContent(line, "worstcase.txt")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ValidateContent returned error: %v", err)
	}

	t.Logf("worst-case single line: len=%d bytes, matches=%d, elapsed=%s", len(line), len(matches), elapsed)

	const ceiling = 5 * time.Second
	if elapsed > ceiling {
		t.Fatalf("ValidateContent on %d-byte single line took %s, exceeds %s ceiling (possible O(n^2) regression)", len(line), elapsed, ceiling)
	}
}

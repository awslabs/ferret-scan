// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ipaddress

import (
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/internal/detector"
)

// buildWorstCaseLine constructs a single ~targetBytes line packed with distinct
// public IPv4 addresses separated by spaces (no newlines). This is the DoS
// shape: one very long line dense with matches, which made any per-match
// whole-line operation (strings.Index rescans, ToLower, keyword scans) quadratic.
func buildWorstCaseLine(targetBytes int) string {
	var sb strings.Builder
	a, b, c, d := 13, 0, 0, 1
	for sb.Len() < targetBytes {
		sb.WriteByte(' ')
		sb.WriteString(itoa(a))
		sb.WriteByte('.')
		sb.WriteString(itoa(b))
		sb.WriteByte('.')
		sb.WriteString(itoa(c))
		sb.WriteByte('.')
		sb.WriteString(itoa(d))
		d++
		if d > 254 {
			d = 1
			c++
		}
		if c > 254 {
			c = 0
			b++
		}
		if b > 254 {
			b = 0
			a++
			// Skip first octets that fall into private/reserved/test ranges so
			// every generated address is a routable public IP (a real match).
			for a == 127 || a == 169 || a == 172 || a == 192 ||
				a == 198 || a == 203 || a == 100 || a == 10 {
				a++
			}
			if a > 223 {
				a = 13
			}
		}
	}
	return sb.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [3]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// TestIPAddressValidator_WorstCaseSingleLineTiming is a performance regression
// guard for the O(n^2) DoS: a single ~1MB line packed with distinct public IPv4
// addresses. Before the fix this shape did not complete within 600s even at
// 256KB (each match re-lowercased and re-scanned the whole line). After the fix
// the per-line work is hoisted and offsets come from the regex, so it must
// finish well within a generous ceiling. The ceiling is intentionally loose to
// avoid flakiness on slow/loaded CI while still catching a quadratic regression.
func TestIPAddressValidator_WorstCaseSingleLineTiming(t *testing.T) {
	v := NewValidator()
	line := buildWorstCaseLine(1 << 20) // ~1MB single line, no newlines

	start := time.Now()
	matches, err := v.ValidateContent(line, "worst.txt")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ValidateContent returned error: %v", err)
	}
	t.Logf("worst-case single line: len=%d bytes, matches=%d, elapsed=%s",
		len(line), len(matches), elapsed)

	const ceiling = 5 * time.Second
	if raceEnabled {
		// -race inflates wall-clock 5-20x; the scan ran above (so -race checks
		// for data races), but the timing ceiling is meaningless and skipped.
		t.Logf("timing assertion skipped under -race")
		return
	}
	if elapsed > ceiling {
		t.Fatalf("ValidateContent on a ~1MB single line took %s, exceeding %s "+
			"(possible reintroduction of the O(n^2) per-match line rescan)",
			elapsed, ceiling)
	}
	if len(matches) == 0 {
		t.Fatalf("expected matches on a line full of public IPs, got 0")
	}
}

// TestIPAddressValidator_HotPathEquivalence locks the claim that the hoisted
// hot-path helpers (analyzeContextLower / findKeywordsLower) return exactly what
// the original per-match helpers (AnalyzeContext / findKeywords) return for the
// ValidateContent call site, where BeforeText/AfterText are the ±50 window
// around the match and are substrings of FullLine.
func TestIPAddressValidator_HotPathEquivalence(t *testing.T) {
	v := NewValidator()
	lines := []string{
		"connection to server 172.217.14.206 established",
		"network endpoint 54.239.28.85 configured",
		"release version 4.12.0.1 is available",
		"the nullable server 13.52.11.22 responded",
		"plain text with no keywords and 13.52.11.22 here",
		"host server router gateway dns 13.52.11.22 test example fake",
	}
	for _, line := range lines {
		// Build a context shaped like the ValidateContent call site: BeforeText
		// and AfterText are substrings of FullLine (the ±50 window). The hot-path
		// helpers only ever see the line, so equivalence must hold.
		mid := len(line) / 2
		ctx := detector.ContextInfo{
			BeforeText: line[max0(mid-10):mid],
			FullLine:   line,
			AfterText:  line[mid:min(mid+10, len(line))],
		}
		want := v.AnalyzeContext("13.52.11.22", ctx)
		got := v.analyzeContextLower(strings.ToLower(line))
		if want != got {
			t.Errorf("analyzeContextLower mismatch for %q: AnalyzeContext=%f hotpath=%f", line, want, got)
		}

		wantPos := v.findKeywords(ctx, v.positiveKeywords)
		gotPos := v.findKeywordsLower(strings.ToLower(line), v.positiveKeywords)
		if !eqSlice(wantPos, gotPos) {
			t.Errorf("findKeywordsLower positive mismatch for %q: %v vs %v", line, wantPos, gotPos)
		}
		wantNeg := v.findKeywords(ctx, v.negativeKeywords)
		gotNeg := v.findKeywordsLower(strings.ToLower(line), v.negativeKeywords)
		if !eqSlice(wantNeg, gotNeg) {
			t.Errorf("findKeywordsLower negative mismatch for %q: %v vs %v", line, wantNeg, gotNeg)
		}
	}
}

func max0(n int) int {
	if n < 0 {
		return 0
	}
	return n
}

func eqSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

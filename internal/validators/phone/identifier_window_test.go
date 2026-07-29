// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phone

import (
	"strings"
	"testing"
)

// TestPunctuatedPhoneSurvivesIdentifierWindow is the leak this file exists for.
//
// isEmbeddedInIdentifierAt looks for words like "session", "hash", "token" and
// "build" within 10 bytes of the match and, on a hit, drops the finding
// entirely. Those words are ordinary English, so the window also fires on prose
// that merely mentions them near a real phone number.
//
// Dropping the finding is not a scoring nit. Only reported findings are handed
// to the redactor, and a file that yields no findings has no redacted output
// written at all — so the phone number stays in cleartext in the file a
// redaction pipeline was supposed to sanitize.
func TestPunctuatedPhoneSurvivesIdentifierWindow(t *testing.T) {
	v := NewValidator()

	// Each of these contains a real, punctuated phone number and an innocent use
	// of an identifier word close enough to land inside the window.
	lines := []string{
		"Callback 212-555-0142 (session token expired)",
		"Reached customer at 212-555-0142, build 4.2 confirmed",
		"Customer 212-555-0142 hash mismatch reported",
		"Reached her at 415-555-0123 -- hash noted",
		"Reached her at 415-555-0123 -- token noted",
		"Reached her at 415-555-0123 -- uuid noted",
		"Reached her at 415-555-0123 -- guid noted",
		"Reached her at 415-555-0123 -- build noted",
	}

	for _, line := range lines {
		t.Run(line, func(t *testing.T) {
			matches, err := v.ValidateContent(line, "records.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) == 0 {
				t.Fatalf("a real punctuated phone next to an identifier word was dropped;\n"+
					"an unreported value is never redacted, so it survives in cleartext.\nline: %s", line)
			}
		})
	}
}

// TestBareDigitRunsStaySuppressed is the other half of the contract, and the
// reason the fix keys on punctuation rather than deleting the keyword list.
//
// Every word in identifierPatterns was measured to be load-bearing against a
// BARE digit run: with the keyword the finding is suppressed, without it the
// same digits are reported. For those the keyword really is the only available
// signal, so it must keep working.
func TestBareDigitRunsStaySuppressed(t *testing.T) {
	v := NewValidator()

	lines := []string{
		"instance i-057034242931 running",
		"image ami-050451375729 available",
		"timestamp 1735689600 recorded",
		"session 4155550123 opened",
		"build 20260714093012 shipped",
		"uuid 5501234567 assigned",
		"token 4155550123 issued",
		"hash 4155550123 mismatch",
	}

	for _, line := range lines {
		t.Run(line, func(t *testing.T) {
			matches, err := v.ValidateContent(line, "infra.log")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) != 0 {
				t.Errorf("a bare identifier digit run was reported as a phone number: %s\ngot %d match(es)",
					line, len(matches))
			}
		})
	}
}

// TestHasPhonePunctuation pins the shape rule directly, including the cases the
// callers depend on but do not exercise obviously.
func TestHasPhonePunctuation(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		// Human phone formats.
		{"212-555-0142", true},
		{"(415) 555-0123", true},
		{"415.555.0123", true},
		{"415 555 0123", true},
		{"+14155550123", true}, // leading plus alone qualifies
		{"+1 415 555 0123", true},

		// Digit runs: identifiers, epochs, build numbers.
		{"4155550123", false},
		{"1735689600", false},
		{"20260714093012", false},
		{"057034242931", false},

		// Degenerate inputs must not panic or claim punctuation.
		{"", false},
		{"-", false},
		{"()", false},
		{"abc", false},
	}

	for _, c := range cases {
		if got := hasPhonePunctuation(c.in); got != c.want {
			t.Errorf("hasPhonePunctuation(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestIdentifierWindowIsStillBounded guards the reason the window exists at all:
// it must remain a fixed-size read around the match, not a scan of the line. A
// per-match full-line scan is the single-long-line CPU-exhaustion shape this
// package has had to fix before.
//
// The assertion is on match COUNT growth rather than wall-clock, so it cannot
// pass by being fast on a fast machine: with a linear implementation the number
// of findings tracks the number of phone numbers, and a non-vacuity floor
// asserts that number is actually growing.
func TestIdentifierWindowIsStillBounded(t *testing.T) {
	v := NewValidator()

	build := func(n int) string {
		var sb strings.Builder
		for i := 0; i < n; i++ {
			if i > 0 {
				sb.WriteString(" ; ")
			}
			// Distinct numbers: identical repeats would let a quadratic
			// implementation measure as linear via dedup.
			sb.WriteString("call 212-555-")
			sb.WriteString(pad4(i))
		}
		return sb.String()
	}

	var prev int
	for _, n := range []int{100, 200, 400} {
		matches, err := v.ValidateContent(build(n), "big.txt")
		if err != nil {
			t.Fatalf("ValidateContent at n=%d: %v", n, err)
		}
		if len(matches) == 0 {
			t.Fatalf("non-vacuity floor: zero findings at n=%d, so this test would "+
				"pass no matter how the window behaved", n)
		}
		if len(matches) <= prev {
			t.Errorf("findings did not grow with input at n=%d: got %d, previous %d",
				n, len(matches), prev)
		}
		prev = len(matches)
	}
}

func pad4(i int) string {
	s := "0000" + itoa(i)
	return s[len(s)-4:]
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [8]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}

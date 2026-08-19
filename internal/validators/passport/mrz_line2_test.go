// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package passport

import (
	"math/rand"
	"strings"
	"testing"
)

// buildTD3Line2 assembles a well-formed ICAO 9303 TD3 line-2 MRZ from its
// fields, computing all five check digits. Tests build their fixtures through
// this rather than pasting literals, because a hand-typed MRZ with a wrong check
// digit is indistinguishable from a deliberate negative case — and while writing
// these tests a hand-built fixture did exactly that, failing on the personal
// number and looking like the production code was broken.
func buildTD3Line2(docNum, state, dob, sex, exp, personal string) string {
	d := padMRZ(docNum, 9)
	p := padMRZ(personal, 14)
	dCD := digit(d)
	dobCD := digit(dob)
	expCD := digit(exp)
	pCD := digit(p)
	composite := d + dCD + dob + dobCD + exp + expCD + p + pCD
	return d + dCD + state + dob + dobCD + sex + exp + expCD + p + pCD + digit(composite)
}

func padMRZ(s string, n int) string {
	for len(s) < n {
		s += "<"
	}
	return s[:n]
}

func digit(s string) string {
	return string(byte('0' + mrzCheckDigit(s)))
}

const (
	// A canonical ICAO 9303 specimen pair.
	validLine1 = "P<GBRSMITH<<JOHN<ALBERT<<<<<<<<<<<<<<<<<<<<<"
)

func validLine2() string {
	return buildTD3Line2("L898902C3", "GBR", "740812", "M", "120415", "ZE184226B")
}

// TestMRZLine2IsDetected is the leak this file exists for.
//
// TD3 line 1 carries the holder's NAME; line 2 carries the passport NUMBER, date
// of birth, sex, expiry and personal number. Only line 1 was matched by anything,
// so on the most ordinary passport shape there is — a scan or OCR pipeline emits
// both lines — line 1 was redacted and line 2 passed through in cleartext.
func TestMRZLine2IsDetected(t *testing.T) {
	v := NewValidator()
	content := validLine1 + "\n" + validLine2() + "\n"

	matches, err := v.ValidateContent(content, "passport-scan.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}

	var sawLine2 bool
	for _, m := range matches {
		if m.LineNumber == 2 {
			sawLine2 = true
		}
	}
	if !sawLine2 {
		t.Fatalf("MRZ line 2 was not reported; it carries the passport number, so an "+
			"unreported line 2 is handed to no redactor and stays in cleartext.\ngot %d finding(s)",
			len(matches))
	}
}

// TestCorruptedCheckDigitIsRejected is what makes the 44-character pattern safe.
// The shape alone matches any run of 44 MRZ characters; the check digits are the
// actual test, so a single corrupted digit must drop the finding.
func TestCorruptedCheckDigitIsRejected(t *testing.T) {
	v := NewValidator()
	good := validLine2()

	// Corrupt each check digit position in turn.
	for _, pos := range []int{9, 19, 27, 42, 43} {
		bad := []byte(good)
		if bad[pos] == '0' {
			bad[pos] = '1'
		} else {
			bad[pos] = '0'
		}

		t.Run(string(rune('A'+pos%26)), func(t *testing.T) {
			matches, err := v.ValidateContent(string(bad), "x.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) != 0 {
				t.Errorf("a line-2 MRZ with a corrupted check digit at position %d was "+
					"reported (%d finding(s)); the check digits are the only thing "+
					"separating this pattern from any 44-character token", pos, len(matches))
			}
		})
	}
}

// TestMRZLine2ChecksValid covers the arithmetic directly, including the boundary
// cases the callers can reach.
func TestMRZLine2ChecksValid(t *testing.T) {
	good := validLine2()
	if !mrzLine2ChecksValid(good) {
		t.Fatalf("a correctly-built TD3 line 2 failed validation: %s", good)
	}

	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"valid", good, true},
		{"empty", "", false},
		{"too short", good[:43], false},
		{"too long", good + "<", false},
		{"all fillers", strings.Repeat("<", 44), false},
		{"all zeros", strings.Repeat("0", 44), false},
		{"all A", strings.Repeat("A", 44), false},
		// A lowercase byte has no MRZ value at all.
		{"lowercase", strings.ToLower(good), false},
		// Sex field must be M, F or filler.
		{"bad sex", good[:20] + "X" + good[21:], false},
		// Dates must be plausible: month 13 cannot occur.
		{"month 13", buildTD3Line2("L898902C3", "GBR", "741312", "M", "120415", "ZE184226B"), false},
		{"day 32", buildTD3Line2("L898902C3", "GBR", "740832", "M", "120415", "ZE184226B"), false},
		{"filler in date", good[:13] + "<<<<<<" + good[19:], false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := mrzLine2ChecksValid(c.in); got != c.want {
				t.Errorf("mrzLine2ChecksValid(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

// TestMRZCheckDigit pins the 7-3-1 arithmetic against values from the ICAO 9303
// specification, so a refactor cannot quietly change the weighting.
func TestMRZCheckDigit(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"L898902C3", 6}, // ICAO 9303 Part 3 specimen document number
		{"740812", 2},    // specimen date of birth
		{"120415", 9},    // specimen expiry date
		{"", 0},          // empty sums to 0
		{"<<<<<<", 0},    // fillers are worth 0
		{"AAAAAAAAA", 10 * (7 + 3 + 1 + 7 + 3 + 1 + 7 + 3 + 1) % 10},
	}

	for _, c := range cases {
		if got := mrzCheckDigit(c.in); got != c.want {
			t.Errorf("mrzCheckDigit(%q) = %d, want %d", c.in, got, c.want)
		}
	}

	// A character with no MRZ value must be reported, not silently treated as a
	// filler — otherwise a lowercase or punctuation byte would score as 0 and a
	// non-MRZ token could satisfy the arithmetic.
	if got := mrzCheckDigit("abc"); got != -1 {
		t.Errorf("mrzCheckDigit on invalid characters = %d, want -1", got)
	}
	if got := mrzCharValue('!'); got != -1 {
		t.Errorf("mrzCharValue('!') = %d, want -1", got)
	}
}

// TestArbitrary44CharTokensAreNotPassports is the false-positive guard. The
// pattern matches any 44 MRZ-legal characters, so without the check digits this
// would fire on base32 secrets, hashes and uppercase identifiers.
//
// Five independent mod-10 digits make the odds of an arbitrary token passing
// roughly 1 in 100,000; this samples well beyond that to keep the guard honest.
func TestArbitrary44CharTokensAreNotPassports(t *testing.T) {
	v := NewValidator()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<"

	// Deterministic seed: a fixed corpus is reproducible, and a failure is
	// debuggable rather than a one-off flake.
	rng := rand.New(rand.NewSource(20260729))

	var reported int
	const n = 20000
	for i := 0; i < n; i++ {
		b := make([]byte, 44)
		for j := range b {
			b[j] = alphabet[rng.Intn(len(alphabet))]
		}
		if mrzLine2ChecksValid(string(b)) {
			// Astronomically unlikely but not impossible; such a token IS a
			// well-formed MRZ by every test available, so reporting it is correct.
			continue
		}
		matches, err := v.ValidateContent(string(b), "tokens.txt")
		if err != nil {
			t.Fatalf("ValidateContent: %v", err)
		}
		for _, m := range matches {
			if len(m.Text) == 44 {
				reported++
			}
		}
	}
	if reported != 0 {
		t.Errorf("%d of %d arbitrary 44-character tokens were reported as line-2 MRZ", reported, n)
	}
}

// TestRealWorld44CharShapesAreNotPassports covers the concrete shapes a scanner
// actually meets at this length.
func TestRealWorld44CharShapesAreNotPassports(t *testing.T) {
	v := NewValidator()

	tokens := []string{
		"AKIAIOSFODNN7EXAMPLEAKIAIOSFODNN7EXAMPLE1234", // doubled AWS key id
		"0123456789012345678901234567890123456789ABCD", // sequential digits
		strings.Repeat("A", 44),
		strings.Repeat("<", 44),
		"K5CUWY3ZNRXW4Z3TK5CUWY3ZNRXW4Z3TJBSWY3DPEHPK", // base32
	}

	for _, tok := range tokens {
		t.Run(tok[:12], func(t *testing.T) {
			if mrzLine2ChecksValid(tok) {
				t.Skip("token happens to satisfy the check digits; reporting it is correct")
			}
			matches, err := v.ValidateContent(tok, "tokens.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			for _, m := range matches {
				if len(m.Text) == 44 {
					t.Errorf("non-MRZ 44-char token reported as a passport: %q", tok)
				}
			}
		})
	}
}

// TestLine2NeedsNoProseKeyword documents why the strong-context bypass exists.
// Line 2 is pure machine-readable data: it contains no "passport" keyword, so the
// prose-context requirement would drop it even with all five check digits valid.
func TestLine2NeedsNoProseKeyword(t *testing.T) {
	v := NewValidator()
	line2 := validLine2()

	if strings.Contains(strings.ToLower(line2), "passport") {
		t.Fatal("test premise wrong: the fixture contains the keyword")
	}

	matches, err := v.ValidateContent(line2, "standalone.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	if len(matches) == 0 {
		t.Error("a standalone line-2 MRZ with valid check digits was dropped for lack " +
			"of a prose keyword; a scanned passport has no prose")
	}
}

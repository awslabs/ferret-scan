// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package bankaccount

import (
	"strings"
	"testing"
)

// Offsets found in an uppercased copy of a line must be translated before they are
// used to slice the original.
//
// scanIBAN, the spaced-IBAN pass and scanSWIFT all matched against
// strings.ToUpper(line) and then sliced `line` with the resulting offsets.
// Uppercasing is per-rune and not length-preserving: U+017F LATIN SMALL LETTER LONG
// S is 2 bytes and uppercases to "S", 1 byte, so every offset after it is shifted
// by one.
//
// Measured on the shipped binary:
//
//	input:    Payment ref ſ IBAN GB82WEST12345698765432 end
//	reported: " GB82WEST1234569876543"   (leading space, final digit missing)
//	redacted: Payment ref ſ IBAN**********************2 end
//
// The last digit of the IBAN stayed in cleartext and the mask consumed the
// preceding space instead, at rc=0.
func TestIBANOffsetsSurviveNonLengthPreservingUppercase(t *testing.T) {
	const iban = "GB82WEST12345698765432"
	v := NewValidator()

	cases := []struct {
		name string
		line string
	}{
		// The long s appears BEFORE the IBAN, so it shifts the IBAN's offsets.
		{"long s earlier in the line", "Payment ref ſ IBAN " + iban + " end"},
		// Control: identical line with an ASCII 's'. Must behave the same.
		{"ascii control", "Payment ref s IBAN " + iban + " end"},
		// Two shifting runes, to catch a fix that only handles a single-byte delta.
		{"two long s", "ſ ref ſ IBAN " + iban + " end"},
		// Dotless i is also 2 bytes and uppercases to 1.
		{"dotless i earlier", "ınvoice IBAN " + iban + " end"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			matches, err := v.ValidateContent(c.line, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			var got []string
			for _, m := range matches {
				if m.Type == "IBAN" {
					got = append(got, m.Text)
				}
			}
			if len(got) != 1 {
				t.Fatalf("got %d IBAN matches %q, want 1", len(got), got)
			}
			if got[0] != iban {
				t.Errorf("reported text = %q, want %q.\n"+
					"A shifted offset reports a truncated value, and redaction masks the "+
					"reported span — so the bytes left over stay in cleartext.", got[0], iban)
			}
			// The reported text must actually occur in the line at that text, or
			// downstream redaction cannot locate it.
			if !strings.Contains(c.line, got[0]) {
				t.Errorf("reported text %q does not occur in the line %q", got[0], c.line)
			}
		})
	}
}

// Uppercasing must not be replaced by a case-insensitive match on the original
// line: (?i)[A-Z] does not fold U+017F, so an IBAN whose own text contains a long s
// would stop being detected at all. That is a strictly worse outcome than the
// mis-slice being fixed — the whole value would pass through in cleartext.
func TestIBANWithFoldingRuneInsideTheValueStillDetected(t *testing.T) {
	v := NewValidator()
	// Swedish IBAN with its leading S written as a long s.
	line := "IBAN ſE3550000000054910000003 end"

	matches, err := v.ValidateContent(line, "test.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	var got []string
	for _, m := range matches {
		if m.Type == "IBAN" {
			got = append(got, m.Text)
		}
	}
	if len(got) != 1 {
		t.Fatalf("got %d IBAN matches %q, want 1 — an obfuscating rune inside the value "+
			"must not make the IBAN invisible", len(got), got)
	}
	if !strings.Contains(line, got[0]) {
		t.Errorf("reported text %q does not occur in the line", got[0])
	}
	if !strings.HasPrefix(got[0], "ſ") {
		t.Errorf("reported text = %q, want it to start at the long s so redaction masks the "+
			"whole token", got[0])
	}
}

// upperWithOffsets is the primitive, so its contract is pinned directly.
func TestUpperWithOffsets(t *testing.T) {
	t.Run("ascii returns no table", func(t *testing.T) {
		up, off := upperWithOffsets("plain ascii 123")
		if up != "PLAIN ASCII 123" {
			t.Errorf("upper = %q", up)
		}
		if off != nil {
			t.Errorf("offsets = %v, want nil (identity) so the common path allocates nothing", off)
		}
	})

	t.Run("table maps every byte back", func(t *testing.T) {
		line := "aſb" // 'a', long s (2 bytes), 'b' => "ASB" (3 bytes)
		up, off := upperWithOffsets(line)
		if up != "ASB" {
			t.Fatalf("upper = %q, want %q", up, "ASB")
		}
		if len(off) != len(up)+1 {
			t.Fatalf("offsets has %d entries, want %d (one past the end)", len(off), len(up)+1)
		}
		// 'A' at upper[0] came from line[0]; 'S' at upper[1] from line[1] (the long
		// s); 'B' at upper[2] from line[3]; and one past the end maps to len(line).
		want := []int{0, 1, 3, len(line)}
		for i := range want {
			if off[i] != want[i] {
				t.Errorf("offsets = %v, want %v", off, want)
				break
			}
		}
	})

	t.Run("every mapped span slices the original safely", func(t *testing.T) {
		// Invalid UTF-8 must not panic or produce an out-of-range offset.
		for _, line := range []string{
			"", "a", "ſ", "\xff\xfe bad bytes ſ x", "ıſı",
			"mixed ASCII ſ and ı runes",
		} {
			up, off := upperWithOffsets(line)
			for start := 0; start <= len(up); start++ {
				for end := start; end <= len(up); end++ {
					s, e := origSpan(off, start, end)
					if s < 0 || e < s || e > len(line) {
						t.Fatalf("origSpan(%q, %d, %d) = (%d,%d), out of range for a %d-byte line",
							line, start, end, s, e, len(line))
					}
					_ = line[s:e] // must not panic
				}
			}
		}
	})

	t.Run("nil table is the identity", func(t *testing.T) {
		if s, e := origSpan(nil, 3, 7); s != 3 || e != 7 {
			t.Errorf("origSpan(nil,3,7) = (%d,%d), want (3,7)", s, e)
		}
	})
}

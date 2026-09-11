// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package bytefold

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// TestLengthPreservedOverTheWholeCodePointSpace is the contract, asserted
// exhaustively rather than sampled.
//
// Every valid rune is folded on its own and inside a surrounding line, and the
// byte length must be identical. This is a whole-space enumeration on purpose:
// the bug this package exists to prevent (#656) survived because the affected
// characters -- U+212A KELVIN SIGN, U+0130, U+1E9E and 24 others -- are exactly
// the ones nobody thinks to put in a fixture. A hand-written table of "tricky
// characters" is how the gap got there; only enumeration closes it.
func TestLengthPreservedOverTheWholeCodePointSpace(t *testing.T) {
	checked := 0
	for r := rune(0); r <= 0x10FFFF; r++ {
		if !utf8.ValidRune(r) {
			continue
		}
		checked++
		in := string(r)
		for _, fn := range []struct {
			name string
			f    func(string) string
		}{{"Lower", Lower}, {"Upper", Upper}} {
			if got := fn.f(in); len(got) != len(in) {
				t.Fatalf("%s(U+%04X) changed length %d -> %d", fn.name, r, len(in), len(got))
			}
			// And in context, where a real caller would index it.
			line := "routing number: " + in + " account 1234567890"
			if got := fn.f(line); len(got) != len(line) {
				t.Fatalf("%s(line containing U+%04X) changed length %d -> %d",
					fn.name, r, len(line), len(got))
			}
		}
	}
	if checked < 1_000_000 {
		t.Fatalf("only %d runes checked -- the enumeration is not covering the code point space", checked)
	}
}

// TestTheRunesStringsToLowerGetsWrong names the population this package exists
// for, and proves both that stdlib really does change length on them and that we
// really do not.
//
// The list is not hand-picked: it is the COMPLETE set of runes for which
// strings.ToLower changes byte length, derived by enumerating the code point
// space. Two of them GROW rather than shrink, which is the failure mode that
// produces a wrong answer instead of a panic -- no crash, no log, just an offset
// pointing into the middle of a value.
func TestTheRunesStringsToLowerGetsWrong(t *testing.T) {
	shrink := []rune{
		0x0130, 0x1E9E, 0x2126, 0x212A, 0x212B, 0x2C62, 0x2C64, 0x2C6D, 0x2C6E,
		0x2C6F, 0x2C70, 0x2C7E, 0x2C7F, 0xA78D, 0xA7AA, 0xA7AB, 0xA7AC, 0xA7AD,
		0xA7AE, 0xA7B0, 0xA7B1, 0xA7B2, 0xA7C5, 0xA7CB, 0xA7DC,
	}
	grow := []rune{0x023A, 0x023E}

	for _, r := range append(append([]rune{}, shrink...), grow...) {
		in := string(r)
		// Precondition: if stdlib ever became length-preserving here, this test
		// would be measuring nothing, and it must say so rather than pass quietly.
		if len(strings.ToLower(in)) == len(in) {
			t.Errorf("U+%04X: strings.ToLower no longer changes length -- this test's premise is stale", r)
		}
		if got := Lower(in); got != in {
			t.Errorf("Lower(U+%04X) = %q, want the input unchanged", r, got)
		}
	}
	// The DIRECTION matters: shrink panics, grow corrupts silently.
	for _, r := range shrink {
		if len(strings.ToLower(string(r))) >= len(string(r)) {
			t.Errorf("U+%04X was classified as shrinking but does not shrink", r)
		}
	}
	for _, r := range grow {
		if len(strings.ToLower(string(r))) <= len(string(r)) {
			t.Errorf("U+%04X was classified as growing but does not grow", r)
		}
	}
}

// TestOffsetsRemainValid is the invariant stated the way callers use it: a span
// found in the original line is the same span in the folded copy.
//
// The hostile runes are written as \u escapes on purpose. U+212A KELVIN SIGN is
// visually indistinguishable from an ASCII "K", so a fixture that silently holds
// the ASCII letter tests nothing -- which is what the first draft of this test
// did, and it passed.
func TestOffsetsRemainValid(t *testing.T) {
	// Twelve of them, not three. The overshoot is a THRESHOLD, not a switch: with
	// n Kelvin signs the keyword starts at 3n+1 and the folded copy is only n+25
	// bytes, so the span runs past the end only once 2n > 17, i.e. n >= 9. A
	// three-rune fixture indexes safely and proves nothing -- which is exactly
	// why the shipped bug needed a long run of the character to show itself.
	line := "KKKKKKKKKKKK ROUTING number 021000021"
	want := "ROUTING"
	start := strings.Index(line, want)
	if start < 0 {
		t.Fatal("fixture does not contain the keyword")
	}
	if got := Lower(line)[start : start+len(want)]; got != "routing" {
		t.Errorf("Lower(line)[%d:%d] = %q, want %q", start, start+len(want), got, "routing")
	}

	// The same indexing against stdlib is the bug. Asserted, so this test
	// documents WHY the package exists instead of restating a tautology.
	std := strings.ToLower(line)
	if len(std) >= len(line) {
		t.Fatal("premise stale: strings.ToLower did not shrink this line")
	}
	if start+len(want) <= len(std) {
		t.Errorf("premise stale: the span %d:%d still fits in the %d-byte stdlib result, "+
			"so this fixture no longer reproduces the overshoot", start, start+len(want), len(std))
	}
}

// TestFoldsASCIIAndOnlyASCII pins the mapping itself.
func TestFoldsASCIIAndOnlyASCII(t *testing.T) {
	cases := []struct{ in, lower, upper string }{
		{"Routing Number", "routing number", "ROUTING NUMBER"},
		{"already lower", "already lower", "ALREADY LOWER"},
		{"MiXeD123-_/", "mixed123-_/", "MIXED123-_/"},
		{"", "", ""},
		// Non-ASCII letters are left alone in BOTH directions, deliberately:
		// U+00EF does not become U+00CF and U+1E9E does not become U+00DF.
		// Folding them is exactly what breaks the position invariant, and it buys
		// no keyword matches because every keyword searched for is ASCII. The "K"
		// here IS a real ASCII K and folds normally.
		{"Ünïcode ẞ K", "Ünïcode ẞ k", "ÜNïCODE ẞ K"},
		// ...and U+212A, its lookalike, does not fold in either direction.
		{"K", "K", "K"},
		{"\xff\xfe invalid utf8 A", "\xff\xfe invalid utf8 a", "\xff\xfe INVALID UTF8 A"},
	}
	for _, c := range cases {
		if got := Lower(c.in); got != c.lower {
			t.Errorf("Lower(%q) = %q, want %q", c.in, got, c.lower)
		}
		if got := Upper(c.in); got != c.upper {
			t.Errorf("Upper(%q) = %q, want %q", c.in, got, c.upper)
		}
	}
}

// TestNoAllocationWhenNothingChanges guards the fast path, since this runs once
// per line of every scanned file.
func TestNoAllocationWhenNothingChanges(t *testing.T) {
	s := "already all lowercase with digits 021000021 and punctuation."
	if n := testing.AllocsPerRun(50, func() { _ = Lower(s) }); n != 0 {
		t.Errorf("Lower allocated %v times on an input needing no change, want 0", n)
	}
	u := "ALREADY ALL UPPERCASE WITH DIGITS 021000021"
	if n := testing.AllocsPerRun(50, func() { _ = Upper(u) }); n != 0 {
		t.Errorf("Upper allocated %v times on an input needing no change, want 0", n)
	}
}

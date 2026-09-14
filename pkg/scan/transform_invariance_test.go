// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scan_test

import (
	"strings"
	"testing"
)

// This file generalises the guard in lengthchanging_runes_test.go from ONE
// transformation to the family, because case folding was never the whole class.
//
// # The class, stated once
//
//	Indexing a transformed string with offsets measured on the untransformed original.
//
// Case folding is the member that got noticed, because a SHRINKING fold makes the
// offset overshoot and panic. It is not the only member. Measured, one representative
// input each:
//
//	html.UnescapeString  "a&amp;b"     7 -> 3      strconv.Unquote    6 -> 3
//	url.QueryUnescape    "a%20b"       5 -> 3      base64 decode     24 -> 17
//	strings.TrimSpace    "  a b  "     7 -> 3      strip non-digits  11 -> 9
//	strings.ReplaceAll   spaces       19 -> 16     ToLower U+212A     5 -> 3
//
// Thirteen of fourteen probed transformations change byte length. So the invariant has
// to be stated over the family, not over one member:
//
//	Two inputs with the SAME sensitive content must produce the same findings, even
//	when they differ in a way that changes how much a transformation shrinks them.
//
// # Why this is the gate rather than static analysis
//
// An interprocedural SSA taint analysis was tried first and cannot decide this. Run
// against main it classified 267 index sites: 0 provable bugs, 45 safe, 222
// undecidable — with dob:591, a CONFIRMED bug, sitting in the undecidable bucket. And
// the personname instance is invisible to it entirely, because that bug compares two
// coordinate spaces as INTEGERS and contains no slice expression for a slice-based
// analysis to flag.
//
// A behavioural oracle has neither limitation: it does not care whether the mechanism
// is a slice, a comparison, or something nobody has thought of yet.
//
// # Why the other members currently pass
//
// They do, and that is a measured result rather than an assumption — see the table
// below. The reason is structural: case folding is applied to a whole LINE whose
// offsets are then reused for keyword proximity, whereas stripping, unescaping and
// trimming are applied to a short candidate VALUE that is consumed whole. Searching
// specifically for "transform a whole-input variable, then index it" finds 7 sites in
// the module and all 7 bound by the transformed value's own length.
//
// These rows are therefore PREVENTIVE. They cost one scan each and they mean the next
// validator that folds a line, unescapes a line, or trims a line and keeps offsets
// into it is caught here rather than by someone pasting Kelvin signs into a document.

// transformVariants is a semantically-neutral variation per transformation family.
//
// "Semantically neutral" is the whole design constraint: both strings must carry the
// SAME sensitive value, so any difference in findings is attributable to the
// transformation and not to the content. That is why the case-folding row pads with a
// rune that is not part of any value, and why the entity row uses two spellings of one
// character rather than two different characters.
var transformVariants = []struct {
	name string
	// why records what the variation changes about the transformation, so a future
	// reader can tell whether a new row belongs in this table.
	why      string
	variants []string
}{
	{
		name: "strings.TrimSpace (25 runes shrink)",
		why:  "leading and trailing whitespace is not part of any value, and TrimSpace removes a variable number of bytes",
		variants: []string{
			"Employee SSN 219-09-9999 on the W-2 form.",
			"   \t  Employee SSN 219-09-9999 on the W-2 form.   \t  ",
			"\t\t\t\t\t\t\t\t Employee SSN 219-09-9999 on the W-2 form.\t\t\t\t\t\t\t\t",
		},
	},
	{
		name: "separator stripping (strings.Map / ReplaceAll)",
		why:  "every validator normalises a candidate before validating it; these three spellings are the same card",
		variants: []string{
			"Card 4111-1111-1111-1111 exp 12/28.",
			"Card 4111 1111 1111 1111 exp 12/28.",
			"Card 4111111111111111 exp 12/28.",
		},
	},
	{
		name: "case folding (27 runes change length under ToLower)",
		// Deliberately a PERSON_NAME fixture, not an SSN one, so this row OVERLAPS a
		// confirmed bug and the table is demonstrably non-vacuous. Verified by mutation:
		// reverting personname to strings.ToLower makes this row fail. Without an overlap
		// like that, a table of all-passing preventive rows cannot be told apart from a
		// table that asserts nothing — which is what the first draft of this file was.
		why: "the member with the confirmed bugs; the padding runes are not part of any value",
		variants: []string{
			"Jonathan Whitfield qqqqqq street",
			"Jonathan Whitfield \u212a\u212a street",
			"Jonathan Whitfield \u0130\u0130\u0130 street",
		},
	},
	{
		name: "whitespace collapsing inside a line",
		why:  "the office text extractor collapses runs of spaces, which shortens the line the validators then see",
		variants: []string{
			"Employee SSN 219-09-9999 on the W-2 form.",
			"Employee  SSN  219-09-9999  on  the  W-2  form.",
			"Employee      SSN      219-09-9999      on the W-2 form.",
		},
	},
}

// TestOutputDoesNotDependOnTransformationLength asserts the family invariant.
//
// Each row's variants carry identical sensitive content, so their finding signatures
// must match. A difference means some transformation's length behaviour is leaking into
// a decision — which is the class, whatever the mechanism turns out to be.
func TestOutputDoesNotDependOnTransformationLength(t *testing.T) {
	for _, row := range transformVariants {
		t.Run(row.name, func(t *testing.T) {
			if len(row.variants) < 2 {
				t.Fatalf("row %q needs at least two variants to compare", row.name)
			}

			base := signature(t, row.variants[0]+"\n")
			// Non-vacuity: the first variant must find something, or every comparison
			// below is satisfied by all variants finding nothing.
			total := 0
			for _, n := range base {
				total += n
			}
			if total == 0 {
				t.Fatalf("the first variant of %q produced no findings, so this row asserts "+
					"nothing. (%s)", row.name, row.why)
			}

			for i, v := range row.variants[1:] {
				got := signature(t, v+"\n")
				if d := diffSignature(base, got); len(d) > 0 {
					t.Errorf("variant %d differs from variant 0 despite carrying the same value.\n"+
						"  %s\n\n  variant 0: %q\n  variant %d: %q\n\n"+
						"Why these are comparable: %s.\n"+
						"A difference means a transformation's LENGTH behaviour reached a decision. "+
						"The usual cause is indexing a transformed string with an offset measured on "+
						"the original — see internal/bytefold for the case-folding case, and prefer an "+
						"offset map (upperWithOffsets/origSpan in the bankaccount validator) when the "+
						"transformation genuinely cannot preserve length.",
						i+1, strings.Join(d, "\n  "), row.variants[0], i+1, v, row.why)
				}
			}
		})
	}
}

// TestEveryVariantRowIsSemanticallyNeutral keeps the table honest.
//
// The rows are only meaningful if the variants really do carry the same value. A row
// whose variants differed in content would fail TestOutputDoesNotDependOnTransformationLength
// for a reason that has nothing to do with transformations, and the failure message
// would send the next reader hunting for a bug that is not there.
func TestEveryVariantRowIsSemanticallyNeutral(t *testing.T) {
	// The sensitive token each row's variants must all contain, after removing the
	// characters that row varies.
	strip := func(s string) string {
		s = strings.ReplaceAll(s, " ", "")
		s = strings.ReplaceAll(s, "\t", "")
		s = strings.ReplaceAll(s, "-", "")
		s = strings.ReplaceAll(s, "q", "")
		s = strings.ReplaceAll(s, "K", "")
		s = strings.ReplaceAll(s, "İ", "")
		return s
	}
	for _, row := range transformVariants {
		t.Run(row.name, func(t *testing.T) {
			want := strip(row.variants[0])
			for i, v := range row.variants[1:] {
				if got := strip(v); got != want {
					t.Errorf("variant %d is not a neutral variation of variant 0:\n  0: %q\n  %d: %q\n"+
						"After removing the characters this row varies they must be identical, or a "+
						"failure in the invariance test would not mean what it says.",
						i+1, want, i+1, got)
				}
			}
			if strings.TrimSpace(row.why) == "" {
				t.Errorf("row %q has no `why`; a reader cannot tell whether a new row belongs "+
					"beside it", row.name)
			}
		})
	}
}

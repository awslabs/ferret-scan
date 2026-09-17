// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package driverslicense

import (
	"strings"
	"testing"
)

// markerModifiesLabel took its offset from strings.ToLower(line) and handed it to
// markerOpensAsideAfter, which indexes the ORIGINAL line. A length-changing rune before the value
// shifted the window. Measured before the fix, on "Driver License<rune> D1234567 (see note)", the bytes
// the aside check actually inspected:
//
//	ascii                        " (see note)"     correct — the aside marker is found
//	one U+0130 dotted capital I  "7 (see note)"    one byte early, reading INTO the value
//	forty U+0130                 "\xb0İİİİİ "       far off, and not valid UTF-8
//
// The same shape as the dob site #660 fixed, where the misread produced a silent false positive at
// confidence 90. It is the silent half of the class: nothing errors, the window simply lands somewhere
// else and the verdict flips.
//
// MEASURED, with the fold reverted: on "Driver Licenseİ D1234567 (test record)" the verdict goes
// true -> false for U+0130, U+023A, U+023E and U+1E9E. True here means "an aside marks this value as a
// test or example, so suppress it"; false means it is reported.
//
// REACHABILITY IS NOT DEMONSTRATED, and saying so matters more than the fix. Driven through the CLI the
// same line is suppressed on BOTH builds, because strongSuppressKeywords (provenanceMarkers plus
// identifierTypeMarkers, validator.go:616-619) suppresses on "test" anywhere on the line "regardless of
// how strong" the positive signal is — independently of this offset path. So the misalignment produces a
// wrong ANSWER from this function without changing what the tool reports, for every input tried.
//
// The fix stands on the function being correct, and on the class: an offset applied to a string it was
// not computed from is a defect whatever currently masks it, and the next site may have nothing masking
// it. Two of the four earlier instances of this class were panics that took a whole file to 0 findings.
//
// The assertion is INVARIANCE rather than a fixed verdict. What the aside rule decides for a given line
// is that rule's business; what must not happen is the answer depending on a rune elsewhere in the line
// that the rule is not about.
func TestTheAsideWindowDoesNotMoveWithALengthChangingRune(t *testing.T) {
	const match = "D1234567"
	labels := []string{"driver", "license", "licence", "dl"}

	var lengthChanging []rune
	for r := rune(1); r < 0x3000; r++ {
		if lower := strings.ToLower(string(r)); len(lower) != len(string(r)) {
			lengthChanging = append(lengthChanging, r)
		}
	}
	if len(lengthChanging) < 10 {
		t.Fatalf("only %d length-changing rune(s); the table is empty and this test asserts nothing",
			len(lengthChanging))
	}

	// Two line shapes, one where an aside marker follows the value and one where it does not, so the
	// invariance is asserted for both verdicts rather than only the one that happens to be false.
	// Both VERDICTS must be represented. "test" is one of provenanceMarkers, so as the first word of an
	// aside immediately after the value it makes the rule fire; "on file" does not. Without a true case
	// this test would also pass on a rule that always returned false — which is the shape of vacuity
	// this repository has shipped before.
	shapes := []struct {
		name   string
		before string
		after  string
	}{
		{"an aside marker follows the value", "Driver License", " (test record)"},
		{"no aside marker follows", "Driver License", " on file"},
	}

	// NON-VACUITY on the pair: the two shapes must produce DIFFERENT verdicts, or the invariance below
	// is being asserted about a constant.
	seen := map[bool]string{}
	for _, sh := range shapes {
		seen[markerModifiesLabel(sh.before+" "+match+sh.after, match, labels)] = sh.name
	}
	if len(seen) < 2 {
		t.Fatalf("both shapes give the same verdict (%v), so this test would pass on a rule that "+
			"always returns that value. Pick an `after` that makes the aside rule fire.", seen)
	}

	for _, sh := range shapes {
		// The ASCII reading is the reference. A control that cannot be established makes the rest moot.
		reference := markerModifiesLabel(sh.before+" "+match+sh.after, match, labels)
		t.Logf("%-34s ascii verdict = %v", sh.name, reference)

		for _, r := range lengthChanging {
			for _, n := range []int{1, 20} {
				line := sh.before + strings.Repeat(string(r), n) + " " + match + sh.after
				got := func() (out bool) {
					defer func() {
						if rec := recover(); rec != nil {
							t.Errorf("%s U+%04X x%d: PANIC %v", sh.name, r, n, rec)
						}
					}()
					return markerModifiesLabel(line, match, labels)
				}()
				if got != reference {
					t.Errorf("%s: U+%04X x%d changed the verdict %v -> %v.\n"+
						"The aside rule is about what follows the VALUE; a rune inserted before it must "+
						"not move the window. This is the shape that produced a silent false positive "+
						"at confidence 90 in #660.", sh.name, r, n, reference, got)
				}
			}
		}
	}
}

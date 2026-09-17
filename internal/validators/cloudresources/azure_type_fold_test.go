// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cloudresources

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// extractAzureResourceType took its offset from strings.ToLower(resourcePath) and applied it to
// resourcePath. strings.ToLower is not length-preserving — 25 runes shrink and 2 grow — so a
// length-changing rune anywhere before "/providers/" shifted the slice. Measured before the fix:
//
//	ascii                        "Microsoft.Compute/virtualMachines"   correct
//	one U+212A KELVIN SIGN       "s/Microsoft.Compute"                 shifted by 2 bytes
//	one U+0130 dotted capital I  ""                                    the type is LOST
//	forty U+0130                 "\xb0İİİİ…/providers"                  mojibake, invalid UTF-8
//
// The fourth confirmed site of the class #659 tracks. The AST guard in internal/bytefold now refuses
// the shape repo-wide; this pins the behaviour, because a guard on the shape cannot tell whether the
// replacement is correct — only that the dangerous call is gone.
//
// REACHABILITY IS NOT DEMONSTRATED. Driven through the CLI, an Azure resource ID whose subscription
// segment holds one of these runes produces ZERO findings on both builds: the upstream matcher rejects
// the path before this helper is reached, because such a segment is not a valid subscription GUID. So
// the wrong answer measured above is a wrong answer from this function, not a change in what the tool
// reports, for every input tried. The fix stands on the function being correct and on the class — an
// offset applied to a string it was not computed from is a defect whatever currently masks it.
func TestAzureResourceTypeSurvivesLengthChangingRunes(t *testing.T) {
	const want = "Microsoft.Compute/virtualMachines"

	// Every rune whose lowercase differs in byte length, placed before "/providers/".
	var lengthChanging []rune
	for r := rune(1); r < 0x3000; r++ {
		if lower := strings.ToLower(string(r)); len(lower) != len(string(r)) {
			lengthChanging = append(lengthChanging, r)
		}
	}
	// NON-VACUITY: if this set is empty the loop below asserts nothing at all.
	if len(lengthChanging) < 10 {
		t.Fatalf("only %d length-changing rune(s) found; the table this test is built on is empty and "+
			"every case below would be an ASCII control", len(lengthChanging))
	}
	t.Logf("exercising %d length-changing rune(s)", len(lengthChanging))

	// The ASCII control first: if this is wrong the fixture is wrong, not the fold.
	control := "/subscriptions/s/resourceGroups/rg/providers/" + want + "/vm"
	if got := extractAzureResourceType(control); got != want {
		t.Fatalf("the ASCII control returned %q, want %q — the fixture is wrong", got, want)
	}

	for _, r := range lengthChanging {
		for _, n := range []int{1, 40} {
			path := "/subscriptions/" + strings.Repeat(string(r), n) +
				"/resourceGroups/rg/providers/" + want + "/vm"
			got := func() (out string) {
				defer func() {
					if rec := recover(); rec != nil {
						t.Errorf("U+%04X x%d: PANIC %v — the slice overran, which is how this class "+
							"took a whole file to 0 findings in #658", r, n, rec)
					}
				}()
				return extractAzureResourceType(path)
			}()
			if got != want {
				t.Errorf("U+%04X x%d: got %q, want %q", r, n, got, want)
			}
			if !utf8.ValidString(got) {
				t.Errorf("U+%04X x%d: result is not valid UTF-8 (%q); a misaligned slice cuts a "+
					"multi-byte rune in half and the broken bytes reach the report", r, n, got)
			}
		}
	}
}

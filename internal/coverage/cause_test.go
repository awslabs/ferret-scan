// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package coverage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCauseZeroValueIsUnsetNotUnreadable is the one that would matter if it broke.
//
// The cmd-side enum starts its iota at causeUnreadable. If this one did the same, every producer not
// yet updated would carry Cause == CauseUnreadable by default, and the tool would assert that a file
// could not be READ when in fact nothing had been said about it — the most misleading of the six
// causes, and invisible because it needs no code to be wrong.
func TestCauseZeroValueIsUnsetNotUnreadable(t *testing.T) {
	var zero Cause
	if zero != CauseUnset {
		t.Fatalf("zero-value Cause is %v (%q), want CauseUnset", zero, zero)
	}
	if zero.Known() {
		t.Error("the zero value reports itself as a known cause, so a consumer would trust it instead " +
			"of falling back to the prose it used to classify")
	}
	if CauseUnset.String() == CauseUnreadable.String() {
		t.Error("unset and unreadable render identically; a producer that says nothing would be " +
			"indistinguishable from one reporting a read failure")
	}
}

// TestEveryCauseRendersDistinctly guards the taxonomy's purpose: an operator acts differently on each.
//
// A duplicate rendering would collapse two causes with different remedies — "fix permissions" versus
// "scan the link's target directly" — into one line, and no other test would notice, because each
// cause's own assertion would still pass.
func TestEveryCauseRendersDistinctly(t *testing.T) {
	all := []Cause{
		CauseUnreadable, CauseUnparseable, CauseNoText,
		CauseCutShort, CauseNotFollowed, CauseTooLarge,
	}
	seen := map[string]Cause{}
	for _, c := range all {
		s := c.String()
		if s == "unknown" {
			t.Errorf("cause %d renders as \"unknown\"; String() is missing a case", int(c))
		}
		if prev, dup := seen[s]; dup {
			t.Errorf("causes %d and %d both render as %q", int(prev), int(c), s)
		}
		seen[s] = c
		if !c.Known() {
			t.Errorf("%q reports Known() == false", s)
		}
	}
}

// TestCauseStringsAreTheDocumentedOnes is the decay guard, computed rather than fixtured.
//
// These strings are a contract, not a label: docs/COVERAGE_DISCLOSURE.md tabulates them for operators
// and the test suite asserts them — "cannot read" alone appears in ten test files. Rewording one here
// would silently diverge the code from the document that tells people what it means, and the
// divergence would show up only as a confused operator.
//
// Reading the doc rather than restating its contents, so this cannot pass by having the same typo
// twice.
func TestCauseStringsAreTheDocumentedOnes(t *testing.T) {
	// internal/parallel -> repo root.
	docPath := filepath.Join("..", "..", "docs", "COVERAGE_DISCLOSURE.md")
	raw, err := os.ReadFile(docPath) // #nosec G304 -- a fixed path inside the repo
	if err != nil {
		t.Skipf("cannot read %s: %v", docPath, err)
	}
	doc := string(raw)

	// Non-vacuity: if the file were not the disclosure document, every Contains below would be
	// meaningless and the test would pass by accident.
	if !strings.Contains(doc, "not examined") {
		t.Fatalf("%s does not look like the coverage disclosure document, so this proves nothing", docPath)
	}

	for _, c := range []Cause{
		CauseUnreadable, CauseUnparseable, CauseNoText,
		CauseCutShort, CauseNotFollowed, CauseTooLarge, CauseNotRegular,
	} {
		if !strings.Contains(doc, c.String()) {
			t.Errorf("cause %q is not in %s. Either the string was reworded without updating the "+
				"document operators read, or a new cause needs documenting.", c.String(), docPath)
		}
	}
}

// TestReduceMatchesTheRuleItReplaces pins the combination rule, including the case that made it
// necessary: two readers of one container disagreeing.
func TestReduceMatchesTheRuleItReplaces(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []Cause
		want Cause
	}{
		{"nothing stated keeps the fallback reachable", nil, CauseUnset},
		{"only unset values", []Cause{CauseUnset, CauseUnset}, CauseUnset},
		{"a single cause is exact", []Cause{CauseNoText}, CauseNoText},
		{"agreement is exact", []Cause{CauseNoText, CauseNoText}, CauseNoText},
		{"unset alongside a real one is ignored", []Cause{CauseUnset, CauseUnparseable}, CauseUnparseable},
		{"disagreement means partial", []Cause{CauseNoText, CauseCutShort}, CauseCutShort},
		{"disagreement, neither being cut-short", []Cause{CauseNoText, CauseUnparseable}, CauseCutShort},
		{"three-way disagreement", []Cause{CauseUnreadable, CauseNoText, CauseTooLarge}, CauseCutShort},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Reduce(tc.in); got != tc.want {
				t.Errorf("Reduce(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

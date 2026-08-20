// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kwmatch

import (
	"strings"
	"testing"
	"time"
)

// A multi-word keyword must match the separator forms the same label takes in
// real files. Config keys, EDI field names and column headers write the same
// label as "member id", "member_id", "member-id" or with padded alignment; a
// keyword list cannot enumerate every spelling, and when the keyword gates a
// shape suppressor rather than a confidence boost, missing one form drops the
// finding entirely.
func TestContainsLower_SeparatorForms(t *testing.T) {
	const kw = "member id"
	for _, tc := range []struct {
		text string
		want bool
		why  string
	}{
		{"member id: X9876543210", true, "canonical space"},
		{"member_id: X9876543210", true, "snake_case"},
		{"member-id: X9876543210", true, "kebab-case"},
		{"member\tid: X9876543210", true, "tab separated"},
		{"member  id: X9876543210", true, "padded alignment"},
		{"member \t _ id: X9876543210", true, "mixed separator run"},

		// A space in the keyword means "zero or more separators". This line was
		// asserted false until #372, on the theory that "memberid" is "a different
		// token" -- but text is lowercased before matching, so this is also the
		// camelCase "memberId" that JSON, REST payloads and ORM exports emit by
		// default. Excluding it left one member ID in cleartext beside its
		// redacted twin in the same object. Unlike the '.' and '/' exclusions
		// below, the zero-separator exclusion carried no measurement; admitting it
		// changed nothing across 184 real documents and payloads.
		{"memberid: X9876543210", true, "concatenated/camelCase"},

		// '.' and '/' are excluded on purpose: they cross sentence and URL
		// boundaries, where the two words are unrelated.
		{"member.id: X9876543210", false, "dot excluded"},
		{"member/id: X9876543210", false, "slash excluded"},

		// The outer whole-word rule still applies at both ends.
		{"remember id: X9876543210", false, "left boundary"},
		{"member idx: X9876543210", false, "right boundary"},
		{"xmember_id", false, "left boundary with separator form"},
		{"member_idx", false, "right boundary with separator form"},
	} {
		if got := ContainsLower(tc.text, kw); got != tc.want {
			t.Errorf("ContainsLower(%q, %q) = %v, want %v (%s)", tc.text, kw, got, tc.want, tc.why)
		}
	}
}

// Separator flexibility must not leak into single-word keywords, which take the
// original scan path untouched.
func TestContainsLower_SingleWordUnchanged(t *testing.T) {
	for _, tc := range []struct {
		text, kw string
		want     bool
	}{
		{"customer_ssn", "ssn", true},
		{"account_number_test", "test", true},
		{"Christopher", "hr", false},
		{"Einstein", "ein", false},
		{"parking", "park", false},
		{"learn", "arn", false},
		{"w-2 wages", "w-2", true},
	} {
		if got := Contains(tc.text, tc.kw); got != tc.want {
			t.Errorf("Contains(%q, %q) = %v, want %v", tc.text, tc.kw, got, tc.want)
		}
	}
}

// Keywords of three or more words must match with independent separators
// between each pair, since real labels mix them.
func TestContainsLower_MultiWordSeparatorsAreIndependent(t *testing.T) {
	const kw = "social security number"
	for _, text := range []string{
		"social security number: 078-05-1120",
		"social_security_number: 078-05-1120",
		"social-security-number: 078-05-1120",
		"social_security number: 078-05-1120",
		"social security-number: 078-05-1120",
		"social\tsecurity_number: 078-05-1120",
	} {
		if !ContainsLower(text, kw) {
			t.Errorf("ContainsLower(%q, %q) = false, want true", text, kw)
		}
	}
	// Independent separators includes independently ZERO of them, so a fully or
	// partially concatenated label matches too (#372).
	for _, text := range []string{
		"socialsecuritynumber: 078-05-1120",
		"social_securitynumber: 078-05-1120",
	} {
		if !ContainsLower(text, kw) {
			t.Errorf("ContainsLower(%q, %q) = false, want true", text, kw)
		}
	}
	// The camelCase spelling this admits reaches ContainsLower already folded, so
	// pin it through Contains, which is the entry point that folds. Asserting the
	// mixed-case form against ContainsLower would test the fold, not the fix.
	for _, text := range []string{
		"socialSecurityNumber: 078-05-1120",
		"social_securityNumber: 078-05-1120",
		"SocialSecurityNumber: 078-05-1120",
	} {
		if !Contains(text, kw) {
			t.Errorf("Contains(%q, %q) = false, want true", text, kw)
		}
	}
	for _, text := range []string{
		"social security numbers_are_fine", // right boundary
		"antisocial security number",       // left boundary
	} {
		if ContainsLower(text, kw) {
			t.Errorf("ContainsLower(%q, %q) = true, want false", text, kw)
		}
	}
}

// An empty keyword must never match, so a stray "" in a keyword list cannot
// score every line. Guarded here because the separator path adds a second
// early return that could bypass the original check.
func TestContainsLower_EmptyKeyword(t *testing.T) {
	if ContainsLower("member id", "") {
		t.Error(`ContainsLower(text, "") = true, want false`)
	}
	if ContainsLower("", "member id") {
		t.Error(`ContainsLower("", kw) = true, want false`)
	}
}

// ContainsFunc's accept callback must receive the span of the whole
// separator-flexible match, not just the anchor word — callers use it to reject
// occurrences that do not touch a window junction, and an anchor-only span
// would let a match be accepted on the wrong side of the boundary.
func TestContainsFunc_SpanCoversWholeMatch(t *testing.T) {
	text := "x member_id y"
	var gotStart, gotEnd int
	var calls int
	ok := ContainsFunc(text, "member id", func(start, end int) bool {
		calls++
		gotStart, gotEnd = start, end
		return true
	})
	if !ok {
		t.Fatal("ContainsFunc = false, want true")
	}
	if calls != 1 {
		t.Errorf("accept called %d times, want 1", calls)
	}
	if got := text[gotStart:gotEnd]; got != "member_id" {
		t.Errorf("accepted span = %q, want %q", got, "member_id")
	}
}

// A rejecting accept must not stop the scan at the first occurrence.
func TestContainsFunc_ContinuesPastRejectedMatch(t *testing.T) {
	text := "member_id first, member-id second"
	var spans []string
	ok := ContainsFunc(text, "member id", func(start, end int) bool {
		spans = append(spans, text[start:end])
		return len(spans) == 2 // reject the first, accept the second
	})
	if !ok {
		t.Fatal("ContainsFunc = false, want true")
	}
	if len(spans) != 2 || spans[0] != "member_id" || spans[1] != "member-id" {
		t.Errorf("accepted spans = %v, want [member_id member-id]", spans)
	}
}

// The separator path anchors on the keyword's first word and rescans from the
// next byte on every failure. On input that repeats the anchor without ever
// completing a match, that is the classic quadratic shape — and the prefilter
// cannot help when every keyword word IS present somewhere. Cost must stay
// linear in input size.
//
// Wall-clock ratios are compared with generous slack because CI machines are
// noisy; the failure this guards against is quadratic (ratio ~4 per doubling,
// growing), not a 2.5x blip.
func TestContainsLower_NoQuadraticBlowup(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	const kw = "member id"

	// Anchor repeated with a separator that never leads to "id", plus one "id"
	// far away so allWordsPresent cannot short-circuit the scan.
	build := func(n int) string { return strings.Repeat("member_x ", n) + " id" }

	measure := func(text string) time.Duration {
		ContainsLower(text, kw) // warm caches
		const iters = 5
		best := time.Duration(1) << 62
		for i := 0; i < iters; i++ {
			start := time.Now()
			ContainsLower(text, kw)
			if d := time.Since(start); d < best {
				best = d
			}
		}
		return best
	}

	small := measure(build(8000))
	large := measure(build(32000)) // 4x the input

	// Linear would be ~4x; quadratic would be ~16x. Allow a wide band for noise
	// but still fail unambiguously on quadratic growth.
	if small > 0 && float64(large)/float64(small) > 9 {
		t.Errorf("scaling looks super-linear: 4x input cost %v vs %v (ratio %.1f)",
			large, small, float64(large)/float64(small))
	}
}

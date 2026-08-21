// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kwmatch

import "testing"

// labelKeywords is the insurance vocabulary the cross-line window is opened with, so these assertions
// are about the list that actually reaches this code.
var labelKeywords = []string{
	"member id", "member number", "subscriber id", "policy number",
	"insurance id", "group number", "enrollee id",
	"member identification", "subscriber identification",
}

// A label written without separators is still that label.
//
// #396 opens a cross-line window when the previous line looks like a field label; #407 taught the
// matcher that "member id" also finds "memberId". The two did not compose: a camelCase label alone on
// its own line still opened no window, so the value on the next line was never reported and therefore
// never redacted.
//
// TWO independent gates rejected it, and the ORDER matters for anyone fixing this again. Measured at
// HEAD: for "memberId:" the vocabulary gate (ContainsAny, now ContainsAnyLabel) returned false and
// returned early, so the per-word loop below never ran. Teaching only keywordWord — which is what the
// issue proposed — would have been a measured no-op.
func TestConcatenatedLabelIsAFieldLabel(t *testing.T) {
	for _, line := range []string{
		"member id:", // already worked
		"member_id:", // already worked
		"memberId:",  // camelCase, the JSON/ORM default
		"MemberId:",  // PascalCase
		"memberID:",  // initialism
		"memberid:",  // fully concatenated
		"Member ID (primary)",
		"policyNumber:",
		"groupNumber:",
		"memberIdentification:",
	} {
		if !LooksLikeFieldLabel(line, labelKeywords) {
			t.Errorf("LooksLikeFieldLabel(%q) = false: no cross-line window opens, so a value on the "+
				"next line is never reported and never redacted", line)
		}
	}
}

// The per-word loop is the false-positive gate that keeps a non-label line from vouching for whatever
// follows it, and widening the vocabulary must not weaken it. Every line here names no field.
func TestNonLabelLinesStillOpenNoWindow(t *testing.T) {
	for _, line := range []string{
		"itemCount:",
		"orderNumber:",
		"lineTotal:",
		"rowCount:",
		"batchSize:",
		"requestId:",
		"sessionId:",
		"buildNumber:",
		"errorCode:",
		"invoiceTotal:",
		"Please renew your membership soon.",
		"the member said the policy was fine",
		// A line that already carries its own value must not vouch for the next one.
		"member 449871234567",
		"memberId 449871234567",
	} {
		if LooksLikeFieldLabel(line, labelKeywords) {
			t.Errorf("LooksLikeFieldLabel(%q) = true: a line that names no field must not open a "+
				"cross-line window, or it vouches for whatever number follows it", line)
		}
	}
}

// Only the FULL concatenation of a keyword counts. Accepting an arbitrary run of its words would admit
// "licensenumber" from "driver's license number" and turn the vocabulary check into a substring
// search.
func TestOnlyTheWholeKeywordConcatenationCounts(t *testing.T) {
	licence := []string{"driver's license", "driver's license number", "license number", "dl number"}

	if !keywordWord("licensenumber", licence) {
		t.Error("\"licensenumber\" is the full concatenation of the keyword \"license number\", " +
			"which is in this list, so it must be accepted")
	}
	if !keywordWord("dlnumber", licence) {
		t.Error("\"dlnumber\" is the full concatenation of \"dl number\"")
	}
	if keywordWord("licensenumberextra", licence) {
		t.Error("a token longer than any keyword concatenation was accepted")
	}
	if keywordWord("driversnumber", licence) {
		t.Error("\"driversnumber\" skips a word of the keyword; accepting a non-contiguous run would " +
			"make the check a loose substring match")
	}

	// A PREFIX of the keyword's words is not the keyword. This is the case that distinguishes "the
	// whole concatenation" from "as many words as happen to line up", and it is the one a mutation
	// removing the alignment guard survives on every other input: for
	// "patient identification number", the guard is what rejects "patientidentification" after
	// "number" fails to fit.
	threeWord := []string{"patient identification number"}
	if !keywordWord("patientidentificationnumber", threeWord) {
		t.Error("the full three-word concatenation was rejected")
	}
	for _, partial := range []string{"patientidentification", "identificationnumber", "patientnumber"} {
		if keywordWord(partial, threeWord) {
			t.Errorf("%q is only part of \"patient identification number\" and must not count as that "+
				"keyword's word. Accepting a prefix or a skipped word widens the false-positive gate "+
				"that keeps a non-label line from opening a cross-line window", partial)
		}
	}
}

// A keyword containing an APOSTROPHE is a known, separate gap, and it is pinned here so the boundary
// of this change is explicit rather than accidental.
//
// "driver's license number" concatenates to "driver'slicensenumber", keeping the apostrophe, so the
// camelCase field name a JSON export actually writes — "driversLicenseNumber" — matches neither this
// per-word check nor the vocabulary gate before it. Measured: ContainsAnyLabel is false for
// "driverslicensenumber" and true for "driver'slicensenumber".
//
// That is a different mechanism from the one this change fixes — a LITERAL character requirement in
// the keyword, not a separator one — and closing it means changing what an apostrophe means to the
// shared matcher, for every caller. Filed on its own rather than folded in here.
func TestApostropheInAKeywordIsAKnownGap(t *testing.T) {
	licence := []string{"driver's license number"}

	if keywordWord("driverslicensenumber", licence) {
		t.Log("the apostrophe gap now closes; fold this case into " +
			"TestOnlyTheWholeKeywordConcatenationCounts and drop this test")
	}
	// The apostrophe-preserving spelling is what matches today. If this stops holding, the matcher's
	// treatment of an apostrophe changed and every caller is affected.
	if !keywordWord("driver'slicensenumber", licence) {
		t.Error("the apostrophe-preserving concatenation no longer matches, so the shared matcher's " +
			"handling of a literal apostrophe has changed — check every caller, not just this one")
	}
}

// The whole-word boundary must survive, or the widening becomes a substring search.
func TestConcatenatedLabelRespectsWordBoundaries(t *testing.T) {
	for _, line := range []string{
		"teammemberid:",
		"xmemberidx:",
		"memberidentifiers:",
		"remembering:",
	} {
		if LooksLikeFieldLabel(line, labelKeywords) {
			t.Errorf("LooksLikeFieldLabel(%q) = true: a longer word that merely CONTAINS the label "+
				"is not the label", line)
		}
	}
}

// ContainsAnyLabel is the vocabulary gate's new matcher; assert it directly so a failure says which
// layer broke rather than only that the composite verdict changed.
func TestContainsAnyLabel(t *testing.T) {
	for _, text := range []string{"memberid:", "memberid: w999", "the memberid field"} {
		if !ContainsAnyLabel(text, labelKeywords) {
			t.Errorf("ContainsAnyLabel(%q) = false", text)
		}
	}
	for _, text := range []string{"itemcount:", "teammemberid:", "remembering", ""} {
		if ContainsAnyLabel(text, labelKeywords) {
			t.Errorf("ContainsAnyLabel(%q) = true", text)
		}
	}
	// It must agree with ContainsAny wherever ContainsAny already matched: this is a widening, and a
	// widening that loses a previously-matching case is a regression.
	for _, text := range []string{"member id:", "member_id:", "policy number: 1"} {
		if ContainsAny(text, labelKeywords) && !ContainsAnyLabel(text, labelKeywords) {
			t.Errorf("ContainsAnyLabel(%q) = false while ContainsAny = true: the label form must be "+
				"a superset, never a replacement", text)
		}
	}
}

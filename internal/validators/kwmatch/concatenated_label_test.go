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

// An APOSTROPHE in a keyword is part of a word here, not a separator, so "driver's license number"
// concatenates to "driver'slicensenumber". That asymmetry with isWordByte — which treats an
// apostrophe as a word BOUNDARY — is pinned below because both behaviours are load-bearing.
//
// #438 was filed on the theory that this asymmetry is what hid the camelCase licence label
// `driversLicenseNumber`, and **that theory is wrong**. Two measurements refute it:
//
//   - the apostrophe SPELLINGS already worked end to end. `driver's license number: D1234567`
//     reported at 95, as did `Drivers License Number:` and `drivers_license_number:`. The two
//     spellings that reported nothing — `driversLicenseNumber:` and `driverslicensenumber:` —
//     contain no apostrophe at all.
//   - making the apostrophe a separator here, on the unchanged vocabulary, is a **measured no-op**:
//     `driversLicenseNumber: D1234567` still reported 0 findings. The vocabulary's longest DL
//     keyword was two words ("drivers license" -> "driverslicense"), so no concatenation could
//     reach "driverslicensenumber" however the apostrophe is treated.
//
// The real cause was vocabulary: a keyword's concatenation must equal the WHOLE word, and no
// three-word DL keyword existed. #438 was closed by adding them to driverslicense's
// positiveKeywords, leaving the shared matcher's apostrophe semantics untouched — which is the
// right outcome, because changing them reaches every caller for no measured gain.
func TestApostropheIsPartOfAWordHereAndABoundaryInIsWordByte(t *testing.T) {
	licence := []string{"driver's license number"}

	// The apostrophe-preserving spelling is what matches. If this stops holding, the matcher's
	// treatment of an apostrophe changed and every caller is affected.
	if !keywordWord("driver'slicensenumber", licence) {
		t.Error("the apostrophe-preserving concatenation no longer matches, so the shared matcher's " +
			"handling of a literal apostrophe has changed — check every caller, not just this one")
	}
	// And the apostrophe-free spelling does NOT, which is what makes the doc comment on keywordWord
	// correct as now written. It said the opposite until #438, and that false example is what made
	// the camelCase gap look already-closed.
	if keywordWord("driverslicensenumber", licence) {
		t.Error("an apostrophe is now dropped from a keyword's concatenation. That is a change to " +
			"shared matcher semantics for every caller of ContainsLabel/LooksLikeFieldLabel — if it " +
			"is deliberate, update the keywordWord doc comment, which states the opposite, and " +
			"re-measure the label-gated validators (driverslicense, passport, medicalid)")
	}
	// The other half of the asymmetry: isWordByte excludes the apostrophe, so a bare "driver"
	// whole-word-matches inside "driver'slicensenumber" but not inside "driverslicensenumber".
	// This is why the two functions must be read together and neither changed alone.
	if !ContainsLabelLower("driver'slicensenumber:", "driver") {
		t.Error(`ContainsLabelLower no longer treats "'" as a word boundary, so a bare keyword ` +
			`stopped matching before an apostrophe`)
	}
	if ContainsLabelLower("driverslicensenumber:", "driver") {
		t.Error(`ContainsLabelLower now matches "driver" inside "driverslicensenumber", so the ` +
			`whole-word rule has been weakened into a prefix search`)
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

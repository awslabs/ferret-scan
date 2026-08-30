// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package driverslicense

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// #553: the same licence label scored 95, 75 or 65 depending only on how whoever produced the file
// chose to spell it.
//
// AnalyzeContext awards the label boost (+75, taking a finding from the base of 20 to 95) by matching
// exact substrings — "drivers license:", "dl:", "license number:" and eight more. Every one of those
// literals carries a space and a colon, so a label written in any other convention missed all of them
// and fell through to the generic keyword arm at +45/+55. Measured at HEAD, one label per line, the
// identical value:
//
//	drivers license: D1234567      95 HIGH
//	Drivers License: D1234567      95 HIGH
//	drivers_license: D1234567      75 MEDIUM
//	drivers-license: D1234567      75 MEDIUM
//	driversLicense: D1234567       65 MEDIUM
//	DriversLicense: D1234567       65 MEDIUM
//	dlNumber: D1234567             65 MEDIUM
//
// camelCase and snake_case are the default key styles of JSON, REST payloads and ORM exports, so the
// conventions that lost are the two a machine-generated export uses. A consumer gated on HIGH saw the
// spaced form and missed the rest.
//
// Worth knowing: the COLUMN-header path was already convention-insensitive — the same label as a CSV
// header scored 100 for all three spellings, before and after this change. It was the INLINE label
// path that lagged behind it.

const dlValue = "D1234567"

// confidenceFor returns the confidence of the first finding, or -1 when nothing is reported.
func confidenceFor(t *testing.T, content string) float64 {
	t.Helper()
	matches, err := NewValidator().ValidateContent(content, "export.json")
	if err != nil {
		t.Fatalf("ValidateContent(%q): %v", content, err)
	}
	if len(matches) == 0 {
		return -1
	}
	return matches[0].Confidence
}

// TestOneLabelScoresTheSameInEveryConvention is the regression test for #553.
//
// The assertion is EQUALITY across spellings rather than a particular number, because the defect is
// the spread, not the value. Pinning 95 would also pass if every spelling regressed to 65 together.
func TestOneLabelScoresTheSameInEveryConvention(t *testing.T) {
	spellings := []string{
		"drivers license",
		"Drivers License",
		"DRIVERS LICENSE",
		"drivers_license",
		"drivers-license",
		"driversLicense",
		"DriversLicense",
		"driverslicense",
	}

	got := map[string]float64{}
	for _, s := range spellings {
		got[s] = confidenceFor(t, s+": "+dlValue+"\n")
	}

	// Non-vacuity: every spelling must actually produce a finding, or "all equal" would hold
	// trivially at -1.
	for s, c := range got {
		if c < 0 {
			t.Fatalf("spelling %q reported nothing, so an equality assertion over the set proves "+
				"nothing", s)
		}
	}

	want := got["drivers license"]
	for _, s := range spellings {
		if got[s] != want {
			t.Errorf("%q scores %.0f but %q scores %.0f. The two lines carry the same label and the "+
				"same value; the only difference is the writing convention of whoever produced the "+
				"file, which must not decide the confidence band.",
				s, got[s], "drivers license", want)
		}
	}

	// And the shared value must be the HIGH band, not a low number they happen to agree on.
	if want < 90 {
		t.Errorf("every spelling agrees at %.0f, but a labelled licence field should reach the HIGH "+
			"band — an equal-but-demoted set is the other way to fail this", want)
	}
}

// TestTheAbbreviatedLabelIsAlsoConventionIndependent.
//
// "dl" and "dl number" are separate entries in the literal list ("dl:" is there, "dl number:" is
// not), so the abbreviated label had its own spread: `DL:` scored 95 while `dlNumber:` scored 65 and
// `dl number:` scored 75 — three values for one abbreviation.
func TestTheAbbreviatedLabelIsAlsoConventionIndependent(t *testing.T) {
	got := map[string]float64{}
	for _, s := range []string{"DL", "dl", "dl number", "dlNumber", "dl_number", "DLNumber"} {
		got[s] = confidenceFor(t, s+": "+dlValue+"\n")
		if got[s] < 0 {
			t.Fatalf("spelling %q reported nothing", s)
		}
	}
	want := got["DL"]
	for s, c := range got {
		if c != want {
			t.Errorf("%q scores %.0f but %q scores %.0f — same abbreviation, different convention",
				s, c, "DL", want)
		}
	}
}

// TestTheLabelBoostStillNeedsALabel is the false-positive guard, and it is the half that keeps this
// change from being a confidence giveaway.
//
// Each of these lines mentions licence vocabulary. None of them is a driver's-licence field, and each
// must score exactly what it scored before the change. The values are the measured pre-fix numbers.
func TestTheLabelBoostStillNeedsALabel(t *testing.T) {
	for _, tc := range []struct {
		line string
		want float64
		why  string
	}{
		{`"license": "MIT"`, -1, "a package manifest's license field: not a DL, and no DL-shaped value"},
		{"Software license: ABC12345", -1, `"software" is a negative keyword`},
		{"Business license: 12345678", 30, `"business" is a negative keyword; must not gain the label boost`},
		{"License: " + dlValue, 65, `bare "license" is deliberately NOT a prefix label — it could be software, fishing, or gun`},
		{"Fishing license: " + dlValue, 45, `"fishing" is a negative keyword`},
		{"licenseKey: " + dlValue, -1, `a config key, not a licence label`},
	} {
		t.Run(strings.SplitN(tc.line, ":", 2)[0], func(t *testing.T) {
			if got := confidenceFor(t, tc.line+"\n"); got != tc.want {
				t.Errorf("%q scores %.0f, want %.0f — %s.\nWidening the label boost must not promote "+
					"a line that does not carry a driver's-licence label.", tc.line, got, tc.want, tc.why)
			}
		})
	}
}

// TestProseEndingInAColonDoesNotEarnTheLabelBoost.
//
// This is the control for the length bound, and without it the whole change would be unsafe. The new
// arm reads the text before the first separator, so a SENTENCE that happens to mention a licence and
// end in a colon would occupy the label position — and a sentence is exactly what the separator
// requirement was supposed to exclude.
func TestProseEndingInAColonDoesNotEarnTheLabelBoost(t *testing.T) {
	prose := "A very long sentence that eventually mentions a drivers license and then ends with a colon"
	if len(prose) <= maxLabelPrefixLen {
		t.Fatalf("the fixture is %d bytes, which is within maxLabelPrefixLen (%d) — it cannot "+
			"exercise the bound it exists to test", len(prose), maxLabelPrefixLen)
	}

	got := confidenceFor(t, prose+": "+dlValue+"\n")
	if got < 0 {
		t.Fatal("the prose line reported nothing, so this proves nothing about the boost")
	}
	if got >= 90 {
		t.Errorf("prose in the label position scored %.0f. A label is short; a long run of text "+
			"before a colon is a sentence, and admitting it readmits exactly the prose the separator "+
			"requirement exists to exclude.", got)
	}

	// And the direct check, so a failure names the predicate rather than a confidence number.
	v := NewValidator()
	if v.labelledFieldPrefix(strings.ToLower(prose + ": " + dlValue)) {
		t.Error("labelledFieldPrefix accepted a label position longer than maxLabelPrefixLen")
	}
}

// TestLabelledFieldPrefixRequiresTheLabelPosition.
//
// The new arm is NARROWER than the literals in one way worth pinning: the literal list is a raw
// strings.Contains over the whole line, so it fires wherever the text appears. This arm requires the
// label to sit before the first separator.
func TestLabelledFieldPrefixRequiresTheLabelPosition(t *testing.T) {
	v := NewValidator()
	for _, tc := range []struct {
		line string
		want bool
		why  string
	}{
		{"drivers license: d1234567", true, "the canonical shape"},
		{"driverslicense: d1234567", true, "concatenated"},
		{"drivers_license: d1234567", true, "snake_case"},
		{"employee record, dl: d1234567", true, "a label after other short fields still occupies the position before the first separator"},
		{"d1234567 was the drivers license", false, "no separator at all"},
		{"d1234567: issued under a drivers license", false, "the licence words are AFTER the separator, so they are the value, not the label"},
		{"", false, "empty"},
		{":d1234567", false, "a separator at position 0 leaves no label"},
	} {
		t.Run(tc.line, func(t *testing.T) {
			if got := v.labelledFieldPrefix(tc.line); got != tc.want {
				t.Errorf("labelledFieldPrefix(%q) = %v, want %v — %s", tc.line, got, tc.want, tc.why)
			}
		})
	}
}

// TestACamelCaseLabelIsReportedAsSupportingEvidence covers the second half of #553.
//
// findKeywordsOnLine used the STRICT matcher for positives, so Context.PositiveKeywords was empty for
// a camelCase label. That list is consumed only by the formatters — the text report's "Supporting
// keywords:" line and SARIF's positiveKeywords property — so a reviewer saw a finding with no stated
// supporting evidence, even though the validator had matched a label to raise its confidence.
//
// Confidence is NOT affected by this half: it comes from AnalyzeContext, which already used the
// label-flexible matcher.
func TestACamelCaseLabelIsReportedAsSupportingEvidence(t *testing.T) {
	for _, label := range []string{"driversLicense", "drivers_license", "drivers license"} {
		t.Run(label, func(t *testing.T) {
			matches, err := NewValidator().ValidateContent(label+": "+dlValue+"\n", "export.json")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) == 0 {
				t.Fatalf("no finding for %q", label)
			}
			if len(matches[0].Context.PositiveKeywords) == 0 {
				t.Errorf("Context.PositiveKeywords is empty for %q, so the text report's "+
					"\"Supporting keywords\" line and SARIF's positiveKeywords property state no "+
					"evidence for a finding the validator raised on exactly that evidence", label)
			}
		})
	}
}

// TestTheNegativeKeywordListIsStillMatchedStrictly.
//
// The asymmetry is the point: positives may reach further because that can only add evidence, while
// widening a suppressor silences real values. findLabelsOnLine is therefore used for positives ONLY,
// and findKeywordsOnLine still serves the negative call site.
//
// One fact bounds how much this matters, and it is worth stating because it was not obvious: the
// label-flexible matcher differs from the strict one ONLY for MULTI-WORD keywords. Its widening is
// "each space may match zero separators", so a single-word keyword has no space to widen and the two
// matchers are identical for it. `test`, `fishing`, `software` and every other one-word suppressor
// therefore cannot be reached into a longer token by either matcher — the difference is confined to
// the two multi-word negatives (`social security`, `work permit`) and to the multi-word positives.
func TestTheNegativeKeywordListIsStillMatchedStrictly(t *testing.T) {
	v := NewValidator()

	// A MULTI-word negative is where the two matchers genuinely diverge, so this is the pair that
	// demonstrates the asymmetry rather than merely asserting it.
	const camel = "socialSecurity: " + dlValue
	const multi = "social security"

	if got := v.findKeywordsOnLine(camel, []string{multi}); len(got) > 0 {
		t.Errorf("findKeywordsOnLine(%q, [%q]) = %v — the STRICT matcher must not see a concatenated "+
			"suppressor. If it does, the negative call site has been widened and a real licence "+
			"beside a camelCase field name can be silenced.", camel, multi, got)
	}
	if got := v.findLabelsOnLine(camel, []string{multi}); len(got) == 0 {
		t.Errorf("findLabelsOnLine(%q, [%q]) found nothing, so the two matchers no longer differ on a "+
			"multi-word keyword and this test cannot detect the negative call site being widened",
			camel, multi)
	}

	// And the real negative list, through the real call site, must still not fire on a longer word.
	for _, line := range []string{"latestLicense: " + dlValue, "socialSecurityLicense: " + dlValue} {
		if got := v.findKeywordsOnLine(line, v.negativeKeywords); len(got) > 0 {
			t.Errorf("findKeywordsOnLine(%q, negatives) = %v — a suppressor matched inside a longer "+
				"word", line, got)
		}
	}

	// Single-word keywords: identical under both, which is what confines the change's blast radius.
	for _, kw := range []string{"test", "software", "fishing"} {
		strict := len(v.findKeywordsOnLine("latestLicense: "+dlValue, []string{kw}))
		flex := len(v.findLabelsOnLine("latestLicense: "+dlValue, []string{kw}))
		if strict != flex {
			t.Errorf("single-word keyword %q behaves differently under the two matchers (strict=%d "+
				"flexible=%d). The flexible matcher only widens SPACES, so a one-word keyword must "+
				"be identical under both; if that changed, the risk assessment for this change no "+
				"longer holds.", kw, strict, flex)
		}
	}
}

// TestTheNEGATIVECallSiteIsStrict_ThroughTheRealPath.
//
// The test above compares the two matchers directly, and that is NOT enough: it passes whichever one
// the production call site actually uses. Swapping the negative call site to findLabelsOnLine — the
// forbidden direction — survived it. This test drives ValidateContent instead, so it observes which
// matcher the caller chose.
//
// The fixture carries a real DL label (so a finding exists at all) plus a camelCase multi-word
// suppressor. Measured: the camelCase spelling reports no negative keyword, while the underscored
// spelling of the same words reports one — which is what makes the first half of this test
// non-vacuous.
//
// Getting the fixture right took two attempts, and the reason is worth recording. `socialSecurityNumber`
// does NOT work: the flexible matcher still applies the outer whole-word rule, and the concatenation
// `socialsecurity` sits inside the longer word `socialsecuritynumber`, so neither matcher finds it and
// the mutation survived a test that looked correct. The suppressor has to be a COMPLETE word for the
// two matchers to differ at all.
func TestTheNEGATIVECallSiteIsStrict_ThroughTheRealPath(t *testing.T) {
	const camel = "drivers license: " + dlValue + " (socialSecurity withheld)"
	const spaced = "drivers license: " + dlValue + " (social_security withheld)"

	report := func(content string) []string {
		matches, err := NewValidator().ValidateContent(content+"\n", "f.txt")
		if err != nil {
			t.Fatalf("ValidateContent(%q): %v", content, err)
		}
		if len(matches) == 0 {
			t.Fatalf("no finding for %q, so nothing can be observed about the negative list", content)
		}
		return matches[0].Context.NegativeKeywords
	}

	// Non-vacuity FIRST: the spaced spelling must report the suppressor, or the emptiness asserted
	// below would prove nothing (an always-empty list would pass).
	if got := report(spaced); len(got) == 0 {
		t.Fatalf("the SPACED suppressor was not reported either (%v). Either the fixture stopped "+
			"reaching the negative list or nothing populates it, and the assertion below is vacuous.",
			got)
	}

	if got := report(camel); len(got) != 0 {
		t.Errorf("Context.NegativeKeywords = %v for a camelCase suppressor. The negative call site "+
			"has been widened to the label-flexible matcher, which is the forbidden direction: a "+
			"suppressor that reaches into concatenated field names silences real licences. Positives "+
			"may widen because that only adds evidence; suppressors may not.", got)
	}
}

// TestContextInfoIsPopulatedForTheFormattersNotForScoring.
//
// Guards the boundary this change relies on: if Context.PositiveKeywords ever starts feeding
// confidence, widening it becomes a scoring change and needs its own false-positive measurement.
func TestContextInfoIsPopulatedForTheFormattersNotForScoring(t *testing.T) {
	v := NewValidator()

	// AnalyzeContext is the scoring entry point and takes only the line — it cannot read a keyword
	// list a caller assembled, which is what makes the reporting half safe.
	spaced := v.AnalyzeContext("", detector.ContextInfo{FullLine: "drivers license: " + dlValue})
	camel := v.AnalyzeContext("", detector.ContextInfo{FullLine: "driversLicense: " + dlValue})
	if spaced != camel {
		t.Errorf("AnalyzeContext gives %.0f for the spaced label and %.0f for the camelCase one; "+
			"the scoring path must not depend on the convention", spaced, camel)
	}

	// And populating PositiveKeywords must not change the score.
	withKeywords := v.AnalyzeContext("", detector.ContextInfo{
		FullLine:         "driversLicense: " + dlValue,
		PositiveKeywords: []string{"drivers license", "driver", "license"},
	})
	if withKeywords != camel {
		t.Errorf("AnalyzeContext returned %.0f with PositiveKeywords set and %.0f without. That list "+
			"is meant to be reporting only — if it now feeds confidence, findLabelsOnLine is a "+
			"scoring change and needs a false-positive measurement across a real corpus.",
			withKeywords, camel)
	}
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metadata

import "testing"

// A sensitivity MARKING must rank below an actual disclosure.
//
// Two scorers were charging a custom property for the same classification word.
// CalculateConfidence's containsEnhancedCopyright matches a bare substring —
// "confidential", "proprietary", "trade secret", "(c)" — anywhere in the line, and
// analyzeCustomPropertyRisk's classification branch then scored the SAME word again.
// Measured, holding the property NAME constant and varying only the value:
//
//	Custom_Notice: Quarterly summary                            ->  60
//	Custom_Notice: Confidential                                 -> 100
//	Custom_Notice: Confidential - Project Nightjar acquisition  -> 100
//
// The bare marking saturated the score, so a document that merely CARRIES a Purview
// label ranked identically to one carrying the label AND naming a live acquisition
// project. That ordering failure is the defect. A label is standard enterprise plumbing
// on a large fraction of real documents — measured, CUSTOM_PROPERTY was the largest HIGH
// population of any metadata type on a 304-file corpus — so treating the marking as
// CRITICAL crowds the band operators triage first.
//
// This is deliberately NOT a veto: a marking is still worth reporting, just not at HIGH.
// See #307.

// TestBareMarkingIsNotHigh is the reported defect.
func TestBareMarkingIsNotHigh(t *testing.T) {
	for _, line := range []string{
		// The Purview/MSIP shape, which is what showed up in the real corpus.
		`Custom_MSIP_Label_a1b2c3d4-e5f6-7890-abcd-ef1234567890_Name: Confidential`,
		// The same statement, undressed.
		`Custom_Notice: Confidential`,
		`Custom_Sensitivity: Internal Only`,
		`Custom_Handling: Restricted`,
	} {
		got := confidenceFor(t, PreprocessorTypeOfficeMetadata, line, "CUSTOM_PROPERTY")
		if got < 0 {
			t.Errorf("%q produced NO finding; a marking should still be reported, just not "+
				"at HIGH — suppressing it entirely would be a different bug", line)
			continue
		}
		if got >= 90 {
			t.Errorf("%q scored %.0f (HIGH). A sensitivity marking states the document's "+
				"handling class; it discloses nothing by itself, and at HIGH it crowds out "+
				"the findings that do.", line, got)
		}
	}
}

// TestMarkingPlusDisclosureOutranksMarkingAlone is the ordering the fix exists to
// restore, and the assertion that keeps the fix from becoming a blanket demotion.
//
// Asserted as a RELATIONSHIP rather than against fixed numbers, so it survives future
// re-weighting: what must hold is that adding a project codename to a classification
// property raises it above the bare label.
func TestMarkingPlusDisclosureOutranksMarkingAlone(t *testing.T) {
	marking := confidenceFor(t, PreprocessorTypeOfficeMetadata,
		`Custom_Notice: Confidential`, "CUSTOM_PROPERTY")
	disclosure := confidenceFor(t, PreprocessorTypeOfficeMetadata,
		`Custom_Notice: Confidential - Project Nightjar acquisition`, "CUSTOM_PROPERTY")

	if marking < 0 || disclosure < 0 {
		t.Fatalf("fixture produced no finding (marking=%.0f disclosure=%.0f)", marking, disclosure)
	}
	if disclosure <= marking {
		t.Errorf("a classification property naming a project scored %.0f, no higher than the "+
			"bare marking at %.0f. The tool cannot then rank a disclosure above a label, "+
			"which is the whole point.", disclosure, marking)
	}
	if disclosure < 90 {
		t.Errorf("marking + project codename scored %.0f, want >= 90 (HIGH): the fix must not "+
			"demote real disclosures along with the labels", disclosure)
	}
}

// TestClassificationWithContentStaysHigh pins the pre-existing requirement.
//
// value_shape_risk_test.go already demands this one be >= 90. It is restated here
// because it is the case that ruled OUT the simpler design: making a marking never
// promote at all dropped this to 70, since the project branch requires a literal
// "project-" (with hyphen) in the value and "Project Nightjar" does not match it. The
// simpler rule was measured and rejected on this evidence, not on taste.
func TestClassificationWithContentStaysHigh(t *testing.T) {
	got := confidenceFor(t, PreprocessorTypeOfficeMetadata,
		`Custom_Classification: SECRET - Project Nightjar`, "CUSTOM_PROPERTY")
	if got < 90 {
		t.Errorf("Custom_Classification 'SECRET - Project Nightjar' scored %.0f, want >= 90. "+
			"A classification property that also names a codename IS a disclosure.", got)
	}
}

// TestCopyrightHeuristicStillAppliesToOtherMetadataTypes bounds the blast radius.
//
// The double-count was withdrawn for CUSTOM_PROPERTY only. For an image's Copyright
// field the IP heuristic is the RIGHT signal and there is no second scorer doubling it,
// so removing it there would be a recall loss. This asserts the withdrawal did not leak
// into other types.
func TestCopyrightHeuristicStillAppliesToOtherMetadataTypes(t *testing.T) {
	v := NewValidator()

	// Same field name both times, so only the VALUE differs: the control must contain
	// no copyright pattern at all. A first attempt compared "Copyright: (c) ..." against
	// "Copyright: 2026 ...", and both scored identically — because the field NAME itself
	// contains "copyright" and fires the same check. The control has to be marker-free.
	withMarker, _ := v.CalculateConfidence("Artist: (c) 2026 Acme Corporation")
	without, _ := v.CalculateConfidence("Artist: 2026 Acme Corporation")

	if withMarker <= without {
		t.Errorf("the enhanced-copyright signal no longer raises confidence (%.2f vs %.2f). "+
			"CalculateConfidence is shared by every metadata type; the CUSTOM_PROPERTY fix "+
			"must not disarm it globally.", withMarker, without)
	}
}

// TestClassificationIsBareMarkingRecognisesRealLabelSpellings.
//
// Real labels arrive dressed — bracketed, punctuated, slash-separated — and all of those
// are the same statement.
//
// The rationale here originally said that what must NOT count as bare is "a value carrying
// content alongside the label". That was the rule when this test was written, and #320 replaced
// it: harmless decoration ("- Draft", "FY25", "(Rev 3)", an org prefix) is content by that
// definition, and treating it as a disclosure put thousands of ordinary labels into HIGH. The rule
// is now about the SHAPE of what remains once the marking phrases are removed — see
// classificationIsBareMarking and classification_decoration_test.go.
//
// Every assertion below still holds under the new rule, which is why they are unchanged. The
// four notBare values each leave two or more words behind. The narrower consequence, recorded so
// this comment does not overclaim: a ONE-word remainder now counts as bare, so
// "confidential - nightjar" is bare here where it once was not.
func TestClassificationIsBareMarkingRecognisesRealLabelSpellings(t *testing.T) {
	bare := []string{
		"confidential",
		"  confidential  ",
		"[confidential]",
		"confidential.",
		"confidential / internal",
		"highly confidential",
		"internal use only",
		"restricted",
		"",
	}
	for _, v := range bare {
		if !classificationIsBareMarking(v) {
			t.Errorf("classificationIsBareMarking(%q) = false; this is a label spelling with "+
				"no content, so it must not be promoted to CRITICAL", v)
		}
	}

	notBare := []string{
		"confidential - project nightjar acquisition",
		"secret - project nightjar",
		"confidential: jane.doe@example.com",
		"restricted to the acme merger team",
	}
	for _, v := range notBare {
		if classificationIsBareMarking(v) {
			t.Errorf("classificationIsBareMarking(%q) = true; this value carries content "+
				"beyond the label and must keep the full classification weight", v)
		}
	}
}

// TestIsClassifiedIsUnchangedInSubstance — the predicate was extracted from an inline
// condition, so it must still recognise exactly what that condition did. A narrower
// predicate would silently stop treating some properties as classified at all.
func TestIsClassifiedIsUnchangedInSubstance(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"classification", "anything"},
		{"clearance", "anything"},
		{"notice", "secret"},
		{"notice", "confidential"},
		{"notice", "restricted"},
	} {
		if !isClassified(tc.name, tc.value) {
			t.Errorf("isClassified(%q, %q) = false, want true", tc.name, tc.value)
		}
	}
	if isClassified("documentpurpose", "quarterly summary") {
		t.Error("isClassified fired on a property with no classification signal")
	}
}

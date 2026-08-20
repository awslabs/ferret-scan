// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/router"
)

// confidenceFor returns the confidence of the first match of the given type, or
// -1 when no such match was emitted.
func confidenceFor(t *testing.T, pt, line, wantType string) float64 {
	t.Helper()
	v := NewValidator()
	body := "--- " + pt + " ---\n" + line
	matches, err := v.ValidateMetadataContent(router.MetadataContent{
		Content:          body,
		SourceFile:       "probe.docx",
		PreprocessorType: pt,
	})
	if err != nil {
		t.Fatalf("ValidateMetadataContent(%q): %v", pt, err)
	}
	for _, m := range matches {
		if m.Type == wantType {
			return m.Confidence
		}
	}
	return -1
}

// TestLivePathAppliesTemplateValueShapeRisk is the regression guard for the
// scoring loss. validateWithPreprocessorRules is the path every REGISTERED
// preprocessor type takes; the per-field blocks in checkOfficeMetadataFields are
// only a fallback for unregistered types. The registered path labelled a finding
// TEMPLATE_INFO but never called analyzeTemplatePathRisk, so the risk analysis
// was dead for real documents: a template disclosing an internal fileserver
// ranked BELOW a mundane company name.
func TestLivePathAppliesTemplateValueShapeRisk(t *testing.T) {
	const (
		sensitive = `Template: \\corp-fs01\confidential\nightjar\t.dotx`
		mundane   = `Template: Normal.dotm`
	)

	got := confidenceFor(t, PreprocessorTypeOfficeMetadata, sensitive, "TEMPLATE_INFO")
	base := confidenceFor(t, PreprocessorTypeOfficeMetadata, mundane, "TEMPLATE_INFO")

	if got < 0 || base < 0 {
		t.Fatalf("expected a TEMPLATE_INFO match for both inputs, got sensitive=%.0f mundane=%.0f", got, base)
	}

	// The whole point of the fix: a UNC path into a share named "confidential"
	// must outrank boilerplate by a band, not by a rounding error.
	if got < 90 {
		t.Errorf("a UNC template path into a share named 'confidential' scored %.0f, want >= 90 (HIGH): the value-shape risk analysis is not being applied on the live path", got)
	}
	if got-base < 40 {
		t.Errorf("sensitive template scored %.0f vs mundane %.0f (gap %.0f): the gap must be large enough to rank one above the other, not a flat offset", got, base, got-base)
	}
}

// TestLivePathEmitsCustomProperties guards the harder half: custom document
// properties were extracted and printed by --preprocess-only but produced ZERO
// findings, because office_metadata's SensitiveFields had no custom_ entry and
// validateWithPreprocessorRules filters on that list. A Classification property
// reading "SECRET - <codename>" was visible in the preprocessed text and never
// reported.
func TestLivePathEmitsCustomProperties(t *testing.T) {
	got := confidenceFor(t, PreprocessorTypeOfficeMetadata,
		`Custom_Classification: SECRET - Project Nightjar`, "CUSTOM_PROPERTY")
	if got < 0 {
		t.Fatalf("a Custom_Classification property produced NO CUSTOM_PROPERTY finding: it is extracted and printed by --preprocess-only, so failing to report it is a silent disclosure gap")
	}
	if got < 90 {
		t.Errorf("Custom_Classification 'SECRET - ...' scored %.0f, want >= 90 (HIGH)", got)
	}
}

// TestCustomPropertyTypeWinsOverSubstringMatch pins the ordering in
// determineMatchType. Custom property names are author-chosen, so a name like
// Custom_ProjectManager contains "manager" and would be typed MANAGER_INFO by
// the substring checks — which would route it away from the custom-property risk
// analysis entirely.
func TestCustomPropertyTypeWinsOverSubstringMatch(t *testing.T) {
	v := NewValidator()
	for _, line := range []string{
		"Custom_ProjectManager: Jane Analyst",
		"Custom_DeviceOwner: Jane Analyst",
		"Custom_AuthorNotes: internal",
		"Custom_CameraSerial: SN-1",
	} {
		if got := v.determineMatchType(line, PreprocessorTypeOfficeMetadata); got != "CUSTOM_PROPERTY" {
			t.Errorf("determineMatchType(%q) = %q, want CUSTOM_PROPERTY: a substring in an author-chosen property name must not steal the type and bypass custom-property risk analysis", line, got)
		}
	}
}

// TestValuelessPropertiesAreSkipped is the false-positive guard, and the numbers
// in it are measured rather than assumed. Enabling custom properties on a corpus
// of 119 real documents emitted 1,228 findings; 488 were Microsoft Purview
// MSIP_Label_<guid>_* bookkeeping. Filtering on the VALUE (not the property
// name) brought the delta to 186 while keeping every human-readable
// classification label.
func TestValuelessPropertiesAreSkipped(t *testing.T) {
	// Values measured from real documents that disclose nothing.
	valueless := []string{
		"true", "false", "0", "Standard", "None", "n/a", "",
		"50, 3, 0, 1",                          // MSIP_Label _Tag
		"5280104a-472d-4538-9ccf-1e1d0efe8b1b", // _SiteId GUID
		"2026-01-14T21:22:37Z",                 // _SetDate
		"0x010100D3F06DC058215A4D90BF",         // SharePoint ContentTypeId

		// Letterless values that must STAY unreported after #373 admitted
		// identifier-length digit runs. Every one of these was measured in the
		// 150-document corpus that sized that rule, and each is the reason for one
		// clause of it.
		"1234",        // a counter: below the 7-digit floor
		"999999",      // 6 digits, still below the floor
		"11, 2, 1, 0", // MSIP_Label _Tag, the commonest shape in the corpus (89 rows)
		"2026-01-14",  // a plain date: 8 digits with hyphens, which the grouped form
		// would otherwise admit
		"2026-01-14.0002", // measured under db_template_version: a dot means a version
		"1.2.3.4567",      // a version, not an identifier
		"12:34:56",        // a time
		"2026/01/14",      // a date with slashes
	}
	for _, v := range valueless {
		if !isValuelessProperty(v) {
			t.Errorf("isValuelessProperty(%q) = false, want true: machine bookkeeping must not be reported, it buries the values that matter", v)
		}
	}

	// Values measured from real documents that DO disclose something. These are
	// the reason the field is surfaced at all, so a filter that drops any of
	// them has defeated its own purpose.
	meaningful := []string{
		"Amazon Confidential",
		"Amazon Pending_Classification",
		"Privileged",
		"Not Classified",
		"Nasdaq - Internal Use: Distribution limited to personnel",
		"SECRET - Project Nightjar",
		"CC-99213-NIGHTJAR",

		// Identifier-length digit runs (#373). These carry no ASCII letter and were
		// therefore never scored, which is how a case number, a billing reference and an
		// SSN under a property named SubscriberSSN reached no validator at all. The
		// sharpest pair measured: "Ledger 8291746350284" scored CUSTOM_PROPERTY 60 while
		// the bare "8291746350284" scored nothing — one English word was the whole
		// difference.
		"923456781",     // a 9-digit member id that no other validator claims
		"8291746350284", // a 13-digit billing reference
		"9999999",       // exactly at the 7-digit floor
		"449-87-4100",   // measured under a property named SubscriberSSN
		"415 892 4471",  // space-separated groups are how a phone-shaped id is written
	}
	for _, v := range meaningful {
		if isValuelessProperty(v) {
			t.Errorf("isValuelessProperty(%q) = true, want false: this is a real classification/disclosure value and dropping it defeats the point of surfacing custom properties", v)
		}
	}
}

// TestValueShapeRiskIsAdditiveOnly is a security invariant, not a behaviour
// test. Metadata values are entirely attacker-controlled: anyone can set
// dc:title or a custom property to any string. A subtractive rule here would let
// an attacker append a token to demote a real finding below the reporting
// threshold, and a finding that is not reported is never redacted (the TM-11
// suppression-oracle shape). applyValueShapeRisk must therefore never return a
// negative boost, for any input.
func TestValueShapeRiskIsAdditiveOnly(t *testing.T) {
	v := NewValidator()
	adversarial := []string{
		"Template: Normal.dotm",
		"Template: ",
		`Template: \\host\share\x.dotx test sample example dummy fake`,
		"Custom_Classification: test sample example dummy ignore",
		"Custom_X: " + strings.Repeat("a", 4096),
		"Custom_: ",
		"Template: ../../../etc/passwd",
		"Custom_Budget: not-a-number",
	}
	for _, line := range adversarial {
		for _, mt := range []string{"TEMPLATE_INFO", "CUSTOM_PROPERTY", "COMPANY_INFO", "UNKNOWN_TYPE"} {
			boost, _ := v.applyValueShapeRisk(mt, line, strings.TrimSpace(strings.TrimPrefix(line, "Template:")))
			if boost < 0 {
				t.Errorf("applyValueShapeRisk(%q, %q) returned %.2f: a negative boost is an attacker-controllable suppression oracle", mt, line, boost)
			}
		}
	}
}

// TestValueShapeRiskIgnoresUnknownTypes keeps the switch honest: a metadata type
// whose risk shape is not understood must get exactly zero, so adding a new type
// later cannot silently inherit another type's scoring.
func TestValueShapeRiskIgnoresUnknownTypes(t *testing.T) {
	v := NewValidator()
	for _, mt := range []string{"COMPANY_INFO", "APPLICATION_INFO", "AUTHOR_INFO", "GPS", ""} {
		boost, meta := v.applyValueShapeRisk(mt, `Template: \\host\confidential\x`, `\\host\confidential\x`)
		if boost != 0 || meta != nil {
			t.Errorf("applyValueShapeRisk(%q, ...) = (%.2f, %v), want (0, nil)", mt, boost, meta)
		}
	}
}

// TestCustomPropertyIDIsWholeWord is the measured false-positive fix. A plain
// strings.Contains on "id" fired inside the SharePoint plumbing that dominates
// real custom properties — ContentTypeId, ComplianceAssetId, _dlc_DocIdItemGuid
// — promoting 45 corpus occurrences of pure boilerplate to HIGH.
func TestCustomPropertyIDIsWholeWord(t *testing.T) {
	v := NewValidator()

	// Must NOT be flagged as containing an id.
	for _, name := range []string{"ContentTypeId", "ComplianceAssetId", "_dlc_DocIdItemGuid", "GrammarlyDocumentId"} {
		risk := v.analyzeCustomPropertyRisk("Custom_" + name + ": someValue")
		for _, f := range risk.RiskFactors {
			if strings.Contains(f, "PII: id") {
				t.Errorf("property %q was flagged %q: 'id' must match on a word boundary, not as a substring of machine plumbing", name, f)
			}
		}
	}

	// Must still be flagged: '_' is a boundary in kwmatch, and compound names
	// are caught by their own keyword in the PII list.
	for _, name := range []string{"employee_id", "user_id", "EmployeeID", "BadgeId"} {
		risk := v.analyzeCustomPropertyRisk("Custom_" + name + ": 88213")
		if len(risk.RiskFactors) == 0 {
			t.Errorf("property %q produced no risk factors: an employee/badge identifier must still be recognised", name)
		}
	}
}

// The digit-run rule is sized against a corpus, so the corpus's own distribution is what
// the test asserts — not a handful of invented strings.
//
// 150 real Office documents from this machine, 117 carrying docProps/custom.xml, 908 custom
// properties, 193 of whose values contain no ASCII letter and were therefore invisible:
//
//	98  bare integers of 4 digits or fewer   <- Purview MSIP_Label ContentBits
//	89  integer tuples ("11, 2, 1, 0")       <- Purview MSIP_Label Tag
//	 2  unbroken runs of 7-8 digits
//	 4  one 5-6 digit run, one date-ish, two bracket literals
//
// The rule admits 2 of 193 and 0 of the 187 Purview rows. End to end over the same 150
// documents the finding count went 1956 -> 1958. That is the false-positive budget, and this
// test pins the two properties that keep it: the floor, and the exclusions.
func TestIdentifierDigitRunFloorAndExclusions(t *testing.T) {
	// The floor is what keeps the 187 Purview bookkeeping rows out. A rule that admitted
	// 4-digit values would report one finding per label per document.
	if identifierDigitFloor != 7 {
		t.Errorf("identifierDigitFloor = %d; the corpus measurement that sized this rule "+
			"assumed 7, and every bare integer it found was 4 digits or fewer",
			identifierDigitFloor)
	}
	// The pattern and the constant have to agree, or the floor is decorative.
	for _, below := range []string{"1", "12", "123456"} {
		if unbrokenDigitRunPattern.MatchString(below) {
			t.Errorf("unbrokenDigitRunPattern matched %q, shorter than identifierDigitFloor=%d",
				below, identifierDigitFloor)
		}
	}
	if !unbrokenDigitRunPattern.MatchString("1234567") {
		t.Errorf("unbrokenDigitRunPattern rejects a %d-digit run, so the floor is wrong",
			identifierDigitFloor)
	}

	// Each exclusion, asserted through the function an operator's findings depend on.
	for _, c := range []struct {
		value  string
		reason string
	}{
		{"11, 2, 1, 0", "a comma makes it an integer tuple, the commonest bookkeeping shape measured"},
		{"2026-01-14", "a plain date is 8 digits with hyphens and would otherwise be admitted"},
		{"2026-01-14.0002", "a dot means a version; measured under db_template_version"},
		{"1.2.3.4567", "a version"},
		{"12:34:56", "a time"},
		{"2026/01/14", "a slash-separated date"},
		{"123456", "below the floor"},
	} {
		if isIdentifierDigitRun(c.value) {
			t.Errorf("isIdentifierDigitRun(%q) = true, want false: %s", c.value, c.reason)
		}
	}

	for _, c := range []struct {
		value  string
		reason string
	}{
		{"1234567", "exactly at the floor"},
		{"923456781", "a 9-digit member id that no other validator claims"},
		{"8291746350284", "a 13-digit billing reference"},
		{"449-87-4100", "hyphen-grouped, measured under a property named SubscriberSSN"},
		{"415 892 4471", "space-grouped groups, how a phone-shaped id is written"},
	} {
		if !isIdentifierDigitRun(c.value) {
			t.Errorf("isIdentifierDigitRun(%q) = false, want true: %s", c.value, c.reason)
		}
	}
}

// A letterless value that IS admitted must be admitted for the right reason: the shape of the
// VALUE, never the property's name.
//
// A name vocabulary would have to be maintained, and it would still miss a digit run under
// "Ref" or "Field3" — while the corpus shows the value shape alone costs 2 findings in 150
// documents. This pins that the decision does not consult a name, so nobody later "improves"
// the rule into a keyword list without noticing it changes what the measurement covered.
func TestIdentifierAdmissionDoesNotDependOnThePropertyName(t *testing.T) {
	const value = "923456781"
	if isValuelessProperty(value) {
		t.Fatalf("isValuelessProperty(%q) = true; the rest of this test would be vacuous", value)
	}
	// isValuelessProperty takes only the value — there is no name parameter to consult.
	// This compiles as an assertion of that fact; if a name is ever threaded through, this
	// call fails to build and the author has to come and read the comment above.
	var _ func(string) bool = isValuelessProperty
}

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

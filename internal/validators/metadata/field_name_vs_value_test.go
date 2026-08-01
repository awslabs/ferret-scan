// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/router"
)

// These tests cover one root cause with two symptoms: the validator used to score
// a metadata field's NAME as if it were the field's content. The name is chosen by
// the file format, so it says what KIND of thing the field holds and nothing about
// whether the value is real or sensitive.
//
// Symptom 1 (AnalyzeContext): a line beginning "Template:" matched the word
// "template" in the validator's own test-data denylist and penalized its own
// value 0.15.
//
// Symptom 2 (determineMatchType + applyPreprocessorConfidenceBoosts): a VALUE
// containing another field's name stole that field's TYPE and its confidence
// boost, so a company genuinely named "Manager Tools LLC" was reported as
// MANAGER_INFO at 95 while "Company: Acme Corp" sat at 55.
//
// Both directions are asserted throughout: the sensitive case must be scored
// correctly AND the legitimate test-data suppression must still fire. A test that
// only checked the first would pass on code that simply deleted the suppression.

// ctxImpactOf returns AnalyzeContext's adjustment for a whole metadata line.
func ctxImpactOf(line string) float64 {
	v := NewValidator()
	return v.AnalyzeContext(line, detector.ContextInfo{FullLine: line})
}

// TestAnalyzeContext_FieldNameIsNotTestData pins the fix for symptom 1: only the
// VALUE can be evidence that content is test/sample data.
func TestAnalyzeContext_FieldNameIsNotTestData(t *testing.T) {
	// The value is byte-identical in both; only the field's label differs. Any
	// difference between these two is the field name scoring itself.
	const sensitiveValue = `\\corp-fs01\confidential\nightjar\t.dotx`

	underTemplate := ctxImpactOf("Template: " + sensitiveValue)
	underNeutral := ctxImpactOf("Tmpl: " + sensitiveValue)

	if underTemplate != underNeutral {
		t.Errorf("field name changed the context score for an identical value:\n"+
			"  %-10s -> %+.2f\n  %-10s -> %+.2f\n"+
			"the label must not be scored as content (a UNC path disclosing an "+
			"internal fileserver lost %.2f for being stored under a field called "+
			"\"Template\")",
			"Template:", underTemplate, "Tmpl:", underNeutral,
			underNeutral-underTemplate)
	}

	// Not merely equal — equal and NOT penalized. Pins the direction, so a
	// mutation that penalized BOTH lines cannot satisfy the assertion above.
	if underTemplate < 0 {
		t.Errorf("a field named \"Template\" still penalizes its own value: got %+.2f, want >= 0", underTemplate)
	}
}

// TestAnalyzeContext_TestDataInValueStillSuppressed is the vacuity guard for the
// test above: the suppression this validator needs must still work. Deleting the
// nonPiiIndicators loop entirely would satisfy the previous test and fail this one.
func TestAnalyzeContext_TestDataInValueStillSuppressed(t *testing.T) {
	// Each value genuinely contains a test-data marker, so each must be demoted.
	suppressed := []string{
		"Author: test user",
		"Author: Example Person",
		"Company: Sample Solutions Ltd",
		"Manager: demo account",
		"Creator: placeholder",
		"LastModifiedBy: dummy",
		"Company: Anonymous",
		"Manager: unknown",
		"Application: default",
		// The denylist word is in the VALUE here, not the label, so a template
		// whose value names a stock template is still demoted.
		"Tmpl: sample.dotx",
	}
	for _, line := range suppressed {
		if got := ctxImpactOf(line); got >= 0 {
			t.Errorf("value-borne test-data marker was NOT suppressed for %q: got %+.2f, want < 0", line, got)
		}
	}

	// A field name alone must never trigger it, for every word on the list that
	// can plausibly appear as a real field name.
	notSuppressed := []string{
		"Template: Normal.dotm",
		"BitsPerSample: 8",
		"Custom_db_template_reference: 1033 Amendment to Professional Services SOW",
		"TestPlanOwner: Dana Reyes",
	}
	for _, line := range notSuppressed {
		if got := ctxImpactOf(line); got < 0 {
			t.Errorf("field name was scored as test data for %q: got %+.2f, want >= 0", line, got)
		}
	}
}

// officeFinding scans one metadata line and returns its single finding.
func officeFinding(t *testing.T, preprocessorType, line string) detector.Match {
	t.Helper()
	v := NewValidator()
	ms, err := v.ValidateMetadataContent(router.MetadataContent{
		Content:          line,
		SourceFile:       "probe.docx",
		PreprocessorType: preprocessorType,
	})
	if err != nil {
		t.Fatalf("ValidateMetadataContent(%q): %v", line, err)
	}
	if len(ms) != 1 {
		t.Fatalf("ValidateMetadataContent(%q): got %d findings, want exactly 1", line, len(ms))
	}
	return ms[0]
}

// boostsOf returns the field-name boosts recorded on a finding.
func boostsOf(m detector.Match) map[string]float64 {
	out := map[string]float64{}
	for k, v := range m.Metadata {
		if len(k) > len("_boost") && k[len(k)-len("_boost"):] == "_boost" {
			if f, ok := v.(float64); ok {
				out[k] = f
			}
		}
	}
	return out
}

// TestValueContainingFieldNameKeepsItsOwnFieldsIdentity pins symptom 2. Each case
// is a "Company:" line, so every one must be COMPANY_INFO at the same confidence
// as the control no matter what its value says.
func TestValueContainingFieldNameKeepsItsOwnFieldsIdentity(t *testing.T) {
	control := officeFinding(t, PreprocessorTypeOfficeMetadata, "Company: Acme Corp")
	if control.Type != "COMPANY_INFO" {
		t.Fatalf("control: got type %s, want COMPANY_INFO", control.Type)
	}

	// Real companies carry these names, so this is ordinary input.
	//
	// Deliberately excludes values like "GPS Insight": CalculateConfidence has
	// its own value-shape rules (a "gps" token is worth +0.25 wherever it
	// appears), which are a separate question from this bug and are unchanged
	// here. These values collide only with the field-NAME vocabularies —
	// determineMatchType's type table and the ConfidenceBoosts table — so any
	// difference from the control is attributable to the defect under test.
	for _, value := range []string{
		"Manager Tools LLC",
		"Author Solutions Inc",
		"Creator Labs",
		"Comments Media Group",
	} {
		line := "Company: " + value
		got := officeFinding(t, PreprocessorTypeOfficeMetadata, line)

		if got.Type != "COMPANY_INFO" {
			t.Errorf("%q: value stole another field's TYPE: got %s, want COMPANY_INFO "+
				"(the wrong type reaches the report, the redaction path and the suppression hash)",
				line, got.Type)
		}
		if got.Confidence != control.Confidence {
			t.Errorf("%q: value changed the confidence of its own field: got %.0f, want %.0f (control %q)",
				line, got.Confidence, control.Confidence, "Company: Acme Corp")
		}
		if b := boostsOf(got); len(b) != 0 {
			t.Errorf("%q: value collected another field's confidence boost: %v", line, b)
		}
	}
}

// TestFieldNameDecidesTypeAcrossFields is the broader form: for each field, the
// name decides the type even when the value names a different field.
func TestFieldNameDecidesTypeAcrossFields(t *testing.T) {
	cases := []struct {
		line     string
		wantType string
	}{
		// name wins over a colliding value
		{"Company: Manager Tools LLC", "COMPANY_INFO"},
		{"Manager: Company Secretary", "MANAGER_INFO"},
		{"Comments: see author notes", "DOCUMENT_COMMENTS"},
		{"Description: camera setup", "DOCUMENT_DESCRIPTION"},
		{"Template: authored by hand", "TEMPLATE_INFO"},
		{"Application: Creator Suite", "APPLICATION_INFO"},
		// each field still resolves to its own type on ordinary values
		{"Author: Jane Q Smith", "AUTHOR_INFO"},
		{"LastModifiedBy: Ops Reviewer", "LAST_MODIFIED_BY"},
		{"Manager: Dana Reyes", "MANAGER_INFO"},
		{"Company: Acme Corp", "COMPANY_INFO"},
		// an @-address in the value is a real value-shape signal, but a
		// recognized field name still wins over it
		{"Author: john.doe@example.com", "AUTHOR_INFO"},
		{"Subject: reach me at ops@example.com", "EMAIL"},
	}
	for _, c := range cases {
		if got := officeFinding(t, PreprocessorTypeOfficeMetadata, c.line).Type; got != c.wantType {
			t.Errorf("%q: got type %s, want %s", c.line, got, c.wantType)
		}
	}
}

// TestBoostRequiresTheFieldNameToAgree pins the boost half of symptom 2 directly.
//
// The boost table is keyed by field type ("contact", "manager", "author"), so a
// key found only in the VALUE is not evidence about that value. This is the exact
// shape that put a WAV Comment field at 100: its value began "contact ...", so it
// collected audio metadata's contact boost of 50.
func TestBoostRequiresTheFieldNameToAgree(t *testing.T) {
	// Field is named "Comment"; only the VALUE says "contact".
	got := officeFinding(t, PreprocessorTypeAudioMetadata, "Comment: contact 212-555-0142")
	if b := boostsOf(got); len(b) != 0 {
		t.Errorf("a boost key found only in the VALUE was credited: %v (field is named \"Comment\", not \"contact\")", b)
	}

	// Same validator, same boost table: a field actually named "Artist" whose
	// value also carries the word is still eligible, so the guard narrows the
	// match rather than disabling the table. Without this, deleting the boost
	// loop outright would satisfy the assertion above.
	//
	// "Artist" rather than "Contact" because a bare phone value already scores
	// 0.90 on its own, and a +0.50 boost on top is clamped at 1.0 — which is
	// indistinguishable from no boost at the confidence level, though the
	// recorded key would still differ.
	withName := officeFinding(t, PreprocessorTypeAudioMetadata, "Artist: artist collective")
	if b := boostsOf(withName); len(b) == 0 {
		t.Errorf("a field genuinely named \"Artist\" lost its boost entirely: %v", b)
	}
}

// TestSplitMetadataField covers the shared helper's contract, including the cases
// the callers depend on: ":" wins over "=", only the first separator splits, and a
// separator-less line reports ok=false so callers can keep prose behaviour.
func TestSplitMetadataField(t *testing.T) {
	cases := []struct {
		in        string
		name      string
		value     string
		ok        bool
		rationale string
	}{
		{"Author: Jane Smith", "Author", "Jane Smith", true, "ordinary field"},
		{"Author = Jane Smith", "Author", "Jane Smith", true, "= separator"},
		{"Author:Jane", "Author", "Jane", true, "no space after colon"},
		{"  Author :  Jane  ", "Author", "Jane", true, "surrounding whitespace trimmed"},
		{"Author:", "Author", "", true, "empty value"},
		{": Jane", "", "Jane", true, "empty name"},
		// A value containing the separator must stay whole: this is a real
		// corpus value (a classification footer) and splitting it twice would
		// truncate the disclosure.
		{"Custom_Marking: Nasdaq - Internal Use: Distribution limited", "Custom_Marking",
			"Nasdaq - Internal Use: Distribution limited", true, "only first separator splits"},
		{"Template: C:\\Users\\jsmith\\Normal.dotm", "Template", `C:\Users\jsmith\Normal.dotm`, true,
			"windows path value keeps its drive colon"},
		{"a=b:c", "a=b", "c", true, "colon wins over equals"},
		{"Just some prose", "", "Just some prose", false, "no separator"},
		{"", "", "", false, "empty line"},
	}
	for _, c := range cases {
		name, value, ok := splitMetadataField(c.in)
		if name != c.name || value != c.value || ok != c.ok {
			t.Errorf("splitMetadataField(%q) [%s]\n got  (%q, %q, %v)\n want (%q, %q, %v)",
				c.in, c.rationale, name, value, ok, c.name, c.value, c.ok)
		}
	}
}

// TestTemplatePathDisclosureOutranksBoilerplate is the end-to-end statement of
// why symptom 1 mattered: a template path that discloses an internal fileserver
// must rank above stock boilerplate. Before the fix both were dragged down by the
// field's own name, and the disclosure landed at 75 while a mundane company name
// sat at 55.
func TestTemplatePathDisclosureOutranksBoilerplate(t *testing.T) {
	disclosure := officeFinding(t, PreprocessorTypeOfficeMetadata,
		`Template: \\corp-fs01\confidential\nightjar\t.dotx`)
	boilerplate := officeFinding(t, PreprocessorTypeOfficeMetadata, "Template: Normal.dotm")
	mundane := officeFinding(t, PreprocessorTypeOfficeMetadata, "Company: Acme Corp")

	if disclosure.Confidence <= boilerplate.Confidence {
		t.Errorf("UNC path disclosure (%.0f) does not outrank stock boilerplate (%.0f)",
			disclosure.Confidence, boilerplate.Confidence)
	}
	if disclosure.Confidence <= mundane.Confidence {
		t.Errorf("UNC path disclosure (%.0f) does not outrank a mundane company name (%.0f)",
			disclosure.Confidence, mundane.Confidence)
	}
}

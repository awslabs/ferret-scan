// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package medicalid

import (
	"fmt"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// The tests in this file pin #858: two MEDICAL_ID subtypes accepted only part of the alphabet their
// public specification defines, so a value outside it got no finding and --enable-redaction left it
// in cleartext at exit 0.
//
//   - DEA_NUMBER accepted 7 of the 18 registrant letters and no '9' business-address form.
//   - MEDICARE_MBI was uppercase-only, although CMS converts a lowercase MBI to uppercase.
//   - The provider, DEA and Medicare context helpers missed camelCase keys and column headers.
//
// Confidences below are the validator's own numbers. The CLI applies a document-level adjustment
// on top (a CSV file gains +20, for example), so they differ from a CLI run on the same text.

// findingsFor runs the validator over content and returns every finding.
func findingsFor(t *testing.T, content string) []detector.Match {
	t.Helper()
	matches, err := NewValidator().ValidateContent(content, "test.txt")
	if err != nil {
		t.Fatalf("ValidateContent(%q): %v", content, err)
	}
	return matches
}

// only returns the single finding of type typ whose Text is text, failing when there is not exactly
// one.
func only(t *testing.T, matches []detector.Match, typ, text string) detector.Match {
	t.Helper()
	var hits []detector.Match
	for _, m := range matches {
		if m.Type == typ && m.Text == text {
			hits = append(hits, m)
		}
	}
	if len(hits) != 1 {
		t.Fatalf("want exactly one %s %q, got %d; all findings: %v", typ, text, len(hits), describe(matches))
	}
	return hits[0]
}

// noneOf fails when any finding has type typ.
func noneOf(t *testing.T, matches []detector.Match, typ string) {
	t.Helper()
	for _, m := range matches {
		if m.Type == typ {
			t.Fatalf("want no %s, got %q at %.0f; all findings: %v", typ, m.Text, m.Confidence, describe(matches))
		}
	}
}

func describe(matches []detector.Match) []string {
	var out []string
	for _, m := range matches {
		out = append(out, fmt.Sprintf("%s %.0f %q", m.Type, m.Confidence, m.Text))
	}
	return out
}

func checkOf(t *testing.T, m detector.Match, key string) bool {
	t.Helper()
	checks, ok := m.Metadata["validation_checks"].(map[string]bool)
	if !ok {
		t.Fatalf("%s %q has no validation_checks map: %v", m.Type, m.Text, m.Metadata)
	}
	v, ok := checks[key]
	if !ok {
		t.Fatalf("%s %q records no %q check: %v", m.Type, m.Text, key, checks)
	}
	return v
}

// TestEveryRegistrantLetterReportsBesideADEALabel is the recall half for DEA_NUMBER. On main 11 of
// the 18 registrant letters (E, H, J, K, L, P, R, S, T, U, X) and every '9' form reported nothing
// beside "DEA registration number:"; each now reports at the score the seven legacy letters have.
func TestEveryRegistrantLetterReportsBesideADEALabel(t *testing.T) {
	for _, first := range "ABCDEFGHJKLMPRSTUX" {
		for _, value := range []string{string(first) + "R1234563", string(first) + "97654329"} {
			t.Run(value, func(t *testing.T) {
				m := only(t, findingsFor(t, "DEA registration number: "+value), "DEA_NUMBER", value)
				if m.Confidence != 95 {
					t.Errorf("confidence %.0f, want 95 (85 base + 10 for \"dea\"), the legacy letters' score", m.Confidence)
				}
				if !checkOf(t, m, "prescriber_context") {
					t.Error("prescriber_context = false beside a DEA label")
				}
			})
		}
	}
}

// TestExtendedDEAFormsReportInEveryLabelledLayout covers the layouts the issue lists: a prescriber
// label, a camelCase key, and every row of a dea_number column, not only the first one.
func TestExtendedDEAFormsReportInEveryLabelledLayout(t *testing.T) {
	t.Run("prescriber label", func(t *testing.T) {
		m := only(t, findingsFor(t, "Prescriber DEA #: XR7654329"), "DEA_NUMBER", "XR7654329")
		if m.Confidence != 100 {
			t.Errorf("confidence %.0f, want 100", m.Confidence)
		}
	})
	t.Run("lowercase new letter", func(t *testing.T) {
		only(t, findingsFor(t, "DEA registration number: xr1234563"), "DEA_NUMBER", "xr1234563")
	})
	t.Run("lowercase 9 form", func(t *testing.T) {
		only(t, findingsFor(t, "DEA registration number: b97654329"), "DEA_NUMBER", "b97654329")
	})
	t.Run("camelCase key", func(t *testing.T) {
		m := only(t, findingsFor(t, `{"deaNumber": "XR1234563"}`), "DEA_NUMBER", "XR1234563")
		if m.Confidence != 85 {
			t.Errorf("confidence %.0f, want 85", m.Confidence)
		}
	})
	t.Run("every row of a dea_number column", func(t *testing.T) {
		csv := "prescriber,dea_number,state\n" +
			"Alpha Bravo,XR1234563,WA\n" +
			"Charlie Delta,BR1234563,OR\n" +
			"Echo Foxtrot,XR7654329,CA\n" +
			"Golf Hotel,BR7654329,NV\n"
		got := findingsFor(t, csv)
		// The first data row also reads the header as a field label on the line above, which
		// adds +20 for "prescriber" and "dea". Every later row has only its column header.
		for value, want := range map[string]float64{
			"XR1234563": 100, "BR1234563": 85, "XR7654329": 85, "BR7654329": 85,
		} {
			m := only(t, got, "DEA_NUMBER", value)
			if m.Confidence != want {
				t.Errorf("%s: confidence %.0f, want %.0f", value, m.Confidence, want)
			}
			if !checkOf(t, m, "prescriber_context") {
				t.Errorf("%s: prescriber_context = false in a dea_number column", value)
			}
		}
	})
}

// TestExtendedDEAFormsNeedDEAContext is the precision half. A newer registrant letter or a '9'
// second character with no DEA context on the line, the label line above or the column header
// reports no DEA_NUMBER: ungated, patent and passport numbers turned into DEA findings.
func TestExtendedDEAFormsNeedDEAContext(t *testing.T) {
	for _, line := range []string{
		"Patent EP1234563 was granted in 2019",
		"US patent US7654329 cites it",
		"Passport number: X91234563",
		"Ticket A97654329 closed",
		"XR1234563",
		"Passport number: XX0000000",
		"name,ticket,state\nAlpha Bravo,XR1234563,WA\nCharlie Delta,KR7654329,OR\n",
	} {
		t.Run(line, func(t *testing.T) {
			noneOf(t, findingsFor(t, line), "DEA_NUMBER")
		})
	}
}

// TestDEANegativesAreUnchanged pins what must still report nothing beside a DEA label, and the
// legacy controls that must keep their main scores.
func TestDEANegativesAreUnchanged(t *testing.T) {
	for _, first := range "INOQVWYZ" {
		value := string(first) + "R1234563"
		t.Run("not a registrant letter "+value, func(t *testing.T) {
			noneOf(t, findingsFor(t, "DEA registration number: "+value), "DEA_NUMBER")
		})
	}
	for _, value := range []string{"BR1234564", "XR1234564", "B97654320"} {
		t.Run("bad check digit "+value, func(t *testing.T) {
			noneOf(t, findingsFor(t, "DEA registration number: "+value), "DEA_NUMBER")
		})
	}
	for _, tc := range []struct {
		line, value string
		want        float64
	}{
		{"BR1234563", "BR1234563", 55},
		{"DEA registration number: br1234563", "br1234563", 95},
		{"DEA number: AA0000000", "AA0000000", 95},
		{`{"dea_number": "BR1234563"}`, "BR1234563", 95},
	} {
		t.Run("control "+tc.line, func(t *testing.T) {
			m := only(t, findingsFor(t, tc.line), "DEA_NUMBER", tc.value)
			if m.Confidence != tc.want {
				t.Errorf("confidence %.0f, want %.0f (main's score)", m.Confidence, tc.want)
			}
		})
	}
}

// TestBusinessAddressFormIsRecordedAsSuch: a '9' in second place is not a last-name initial.
func TestBusinessAddressFormIsRecordedAsSuch(t *testing.T) {
	m := only(t, findingsFor(t, "DEA registration number: B97654329"), "DEA_NUMBER", "B97654329")
	if m.Metadata["business_address"] != true {
		t.Errorf("business_address = %v, want true", m.Metadata["business_address"])
	}
	if _, ok := m.Metadata["last_name_initial"]; ok {
		t.Errorf("a '9' form recorded last_name_initial %v", m.Metadata["last_name_initial"])
	}

	m = only(t, findingsFor(t, "DEA registration number: BR1234563"), "DEA_NUMBER", "BR1234563")
	if m.Metadata["last_name_initial"] != "R" {
		t.Errorf("last_name_initial = %v, want R", m.Metadata["last_name_initial"])
	}
	if _, ok := m.Metadata["business_address"]; ok {
		t.Error("a last-name form recorded business_address; the legacy metadata must not change")
	}
}

// TestLowercaseMBIReportsBesideAMedicareLabel is the recall half for MEDICARE_MBI: every layout
// that reports an uppercase MBI now reports the lowercase or mixed-case one, with Text the original
// span and Metadata["normalized"] the canonical uppercase form.
func TestLowercaseMBIReportsBesideAMedicareLabel(t *testing.T) {
	for _, tc := range []struct {
		name, content, span string
		want                float64
	}{
		{"compact", "Medicare MBI: 1ac2de3fg45", "1ac2de3fg45", 85},
		{"mixed case", "Medicare MBI: 1Ac2dE3fG45", "1Ac2dE3fG45", 85},
		{"dashed", "Medicare MBI: 1ac2-de3-fg45", "1ac2-de3-fg45", 85},
		{"spaced", "Medicare MBI: 1ac2 de3 fg45", "1ac2 de3 fg45", 85},
		{"snake_case JSON key", `{"medicare_beneficiary_identifier": "1ac2de3fg45"}`, "1ac2de3fg45", 95},
		{"camelCase JSON key", `{"medicareBeneficiaryIdentifier": "1ac2de3fg45"}`, "1ac2de3fg45", 75},
		{"query parameter", "GET /eligibility?mbi=9aa9aa9aa99&plan=B", "9aa9aa9aa99", 75},
		{"label line above", "Medicare Beneficiary Identifier\n1ac2de3fg45", "1ac2de3fg45", 95},
		{"ASCII k", "Medicare MBI: 1ak2de3fg45", "1ak2de3fg45", 85},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := only(t, findingsFor(t, tc.content), "MEDICARE_MBI", tc.span)
			if m.Confidence != tc.want {
				t.Errorf("confidence %.0f, want %.0f", m.Confidence, tc.want)
			}
			wantNorm := strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(tc.span))
			if m.Metadata["normalized"] != wantNorm {
				t.Errorf("normalized = %v, want %s", m.Metadata["normalized"], wantNorm)
			}
			if !checkOf(t, m, "medicare_context") {
				t.Error("medicare_context = false for a value a Medicare label admitted")
			}
		})
	}

	t.Run("scores exactly as the uppercase sibling", func(t *testing.T) {
		upper := only(t, findingsFor(t, "Medicare MBI: 1AC2DE3FG45"), "MEDICARE_MBI", "1AC2DE3FG45")
		lower := only(t, findingsFor(t, "Medicare MBI: 1ac2de3fg45"), "MEDICARE_MBI", "1ac2de3fg45")
		if upper.Confidence != lower.Confidence {
			t.Errorf("upper %.0f, lower %.0f", upper.Confidence, lower.Confidence)
		}
		if _, ok := upper.Metadata["normalized"]; ok {
			t.Error("an uppercase compact MBI gained a normalized key; its metadata must not change")
		}
	})

	t.Run("a line holding both cases reports both copies", func(t *testing.T) {
		got := findingsFor(t, "Medicare MBI 1AC2DE3FG45 (re-keyed by intake as 1ac2de3fg45)")
		only(t, got, "MEDICARE_MBI", "1AC2DE3FG45")
		only(t, got, "MEDICARE_MBI", "1ac2de3fg45")
	})

	t.Run("every row of an mbi column", func(t *testing.T) {
		got := findingsFor(t, "patient_name,mbi,ward\nAlpha Bravo,1ac2de3fg45,West\nCharlie Delta,9aa9aa9aa99,East\nEcho Foxtrot,1AC2DE3FG45,North\n")
		for _, value := range []string{"1ac2de3fg45", "9aa9aa9aa99", "1AC2DE3FG45"} {
			m := only(t, got, "MEDICARE_MBI", value)
			if !checkOf(t, m, "medicare_context") {
				t.Errorf("%s: medicare_context = false in an mbi column", value)
			}
		}
	})
}

// TestLowercaseMBINeedsAMedicareSpecificLabel is the precision half: the wider Medicare-adjacent
// words score an uppercase MBI but never admit a lowercase one, because lowercase 11-character
// alphanumerics (hex digests, base36 keys) are common and these words are not specific.
func TestLowercaseMBINeedsAMedicareSpecificLabel(t *testing.T) {
	for _, line := range []string{
		"coverage report keys 9ad4ce7fa21",
		"cms asset keys 9ad4ce7fa21",
		"cache keys 9ad4ce7fa21",
		"enrollment batch 9ad4ce7fa21",
		"beneficiary record 9ad4ce7fa21",
		"medicaid file 9ad4ce7fa21",
		"Part A file 9ad4ce7fa21",
		"Part B file 9ad4ce7fa21",
		"Part D file 9ad4ce7fa21",
		"9ad4ce7fa21",
		"1ac2de3fg45",
		// U+212A KELVIN SIGN in the K position: an explicit ASCII class, not (?i), so it is not
		// an MBI however it is labelled.
		"Medicare MBI: 1A\u212a2DE3FG45",
		"Medicare MBI: 1a\u212a2de3fg45",
		// A neighbouring column's header does not vouch for this column.
		"patient_name,mbi,notes\nAlpha Bravo,1AC2DE3FG45,9ad4ce7fa21\n",
	} {
		t.Run(line, func(t *testing.T) {
			for _, m := range findingsFor(t, line) {
				if m.Type == "MEDICARE_MBI" && m.Text != strings.ToUpper(m.Text) {
					t.Fatalf("lowercase %q reported as MEDICARE_MBI at %.0f", m.Text, m.Confidence)
				}
				if m.Type == "MEDICARE_MBI" && strings.ContainsRune(line, '\u212a') {
					t.Fatalf("a KELVIN SIGN value reported as MEDICARE_MBI: %q", m.Text)
				}
			}
		})
	}

	t.Run("the generic words still score an uppercase MBI", func(t *testing.T) {
		m := only(t, findingsFor(t, "coverage report keys 9AD4CE7FA21"), "MEDICARE_MBI", "9AD4CE7FA21")
		if m.Confidence != 75 {
			t.Errorf("confidence %.0f, want 75 (main's score)", m.Confidence)
		}
	})
}

// TestVetoesFollowTheSubtypeDecision is the veto-agreement test (#858 mechanism C). For every value
// on every line below, exactly one finding covers it: the specific subtype when that subtype
// reports it, and INSURANCE_MEMBER_ID otherwise. Zero would be a value the veto dropped although no
// subtype claims it, which is what the widened patterns did to `Member ID: XR1234563` with the old
// shape-based veto. Two would be a duplicate the veto failed to suppress.
func TestVetoesFollowTheSubtypeDecision(t *testing.T) {
	values := []string{
		"XR1234563",   // newer registrant letter: DEA only with DEA context
		"HR7654329",   // newer registrant letter
		"BR1234563",   // legacy form: DEA on the value alone
		"B97654329",   // business-address form: DEA only with DEA context
		"1ac2de3fg45", // lowercase MBI: MBI only with a Medicare label
		"1AC2DE3FG45", // uppercase MBI: MBI on the value alone
	}
	lines := []string{
		"Member ID: %s",
		"member id: %s",
		`{"memberId": "%s"}`,
		"Subscriber ID %s for the pharmacy",
		"Prescriber DEA and member id: %s",
		"Medicare member ID: %s",
		"Member Identification Number: %s",
	}
	for _, format := range lines {
		for _, value := range values {
			line := fmt.Sprintf(format, value)
			t.Run(line, func(t *testing.T) {
				var covering []string
				for _, m := range findingsFor(t, line) {
					if m.Text == value {
						covering = append(covering, m.Type)
					}
				}
				if len(covering) != 1 {
					t.Fatalf("%d findings cover %q, want exactly 1: %v", len(covering), value, covering)
				}
			})
		}
	}

	// The specific rows the issue measured on main, which the agreement above must not move.
	for _, tc := range []struct{ line, value, typ string }{
		{"Member ID: XR1234563", "XR1234563", "INSURANCE_MEMBER_ID"},
		{"Member ID: HR7654329", "HR7654329", "INSURANCE_MEMBER_ID"},
		{"Member ID: 1ac2de3fg45", "1ac2de3fg45", "INSURANCE_MEMBER_ID"},
		{`{"memberId": "1ac2de3fg45"}`, "1ac2de3fg45", "INSURANCE_MEMBER_ID"},
		{"Member Identification Number: 1ac2de3fg45", "1ac2de3fg45", "INSURANCE_MEMBER_ID"},
		{"Member Identification Number: 1AC2DE3FG45", "1AC2DE3FG45", "MEDICARE_MBI"},
		// The one narrow retype, the arbitration the uppercase and legacy siblings already get.
		{"Medicare member ID: 1ac2de3fg45", "1ac2de3fg45", "MEDICARE_MBI"},
		{"Prescriber DEA and member id: XR1234563", "XR1234563", "DEA_NUMBER"},
		{"Medicare member ID: 1AC2DE3FG45", "1AC2DE3FG45", "MEDICARE_MBI"},
		{"Prescriber DEA and member id: BR1234563", "BR1234563", "DEA_NUMBER"},
	} {
		t.Run("type of "+tc.line, func(t *testing.T) {
			only(t, findingsFor(t, tc.line), tc.typ, tc.value)
		})
	}
}

// TestCamelCaseKeysSetTheContextChecks: a JSON or ORM export writes the label as one camelCase
// token, which a one-word keyword cannot match. Each now sets its *_context check and scores as the
// separator-free spelling allows; the snake_case spellings keep their main scores.
func TestCamelCaseKeysSetTheContextChecks(t *testing.T) {
	for _, tc := range []struct {
		line, typ, value, check string
		want                    float64
	}{
		{`{"medicareBeneficiaryIdentifier": "1AC2DE3FG45"}`, "MEDICARE_MBI", "1AC2DE3FG45", "medicare_context", 75},
		{`{"medicareNumber": "1AC2DE3FG45"}`, "MEDICARE_MBI", "1AC2DE3FG45", "medicare_context", 75},
		{`{"mbiNumber": "1AC2DE3FG45"}`, "MEDICARE_MBI", "1AC2DE3FG45", "medicare_context", 75},
		{`{"medicare_number": "1AC2DE3FG45"}`, "MEDICARE_MBI", "1AC2DE3FG45", "medicare_context", 85},
		{`{"deaNumber": "BR1234563"}`, "DEA_NUMBER", "BR1234563", "prescriber_context", 85},
		{`{"deaRegistrationNumber": "BR1234563"}`, "DEA_NUMBER", "BR1234563", "prescriber_context", 85},
		{`{"dea_number": "BR1234563"}`, "DEA_NUMBER", "BR1234563", "prescriber_context", 95},
		{`{"providerNpi": "1000000004"}`, "NPI", "1000000004", "provider_context", 80},
		{`{"npiNumber": "1000000004"}`, "NPI", "1000000004", "provider_context", 80},
		{`{"provider_npi": "1000000004"}`, "NPI", "1000000004", "provider_context", 100},
	} {
		t.Run(tc.line, func(t *testing.T) {
			m := only(t, findingsFor(t, tc.line), tc.typ, tc.value)
			if !checkOf(t, m, tc.check) {
				t.Errorf("%s = false", tc.check)
			}
			if m.Confidence != tc.want {
				t.Errorf("confidence %.0f, want %.0f", m.Confidence, tc.want)
			}
		})
	}
}

// TestColumnHeadersCountAsContext: a header vouches for its own column, as insuranceContextFor's
// does, and only raises a score. The first data row is not used for the header-only rows, because
// it also reads the header as a label line above.
func TestColumnHeadersCountAsContext(t *testing.T) {
	t.Run("mbi column", func(t *testing.T) {
		got := findingsFor(t, "patient_name,mbi,ward\nAlpha Bravo,1AC2DE3FG45,West\nCharlie Delta,9AA9AA9AA99,East\n")
		m := only(t, got, "MEDICARE_MBI", "9AA9AA9AA99")
		if m.Confidence != 75 {
			t.Errorf("confidence %.0f, want 75 (40 on main, which read only the row)", m.Confidence)
		}
	})
	t.Run("a neighbouring column is not vouched for", func(t *testing.T) {
		got := findingsFor(t, "patient_name,mbi,notes\nAlpha Bravo,1AC2DE3FG45,9AA9AA9AA99\nCharlie Delta,4AA9AA9AA99,7AA9AA9AA99\n")
		m := only(t, got, "MEDICARE_MBI", "7AA9AA9AA99")
		if m.Confidence != 40 || checkOf(t, m, "medicare_context") {
			t.Errorf("notes column: confidence %.0f medicare_context %v, want 40 and false",
				m.Confidence, checkOf(t, m, "medicare_context"))
		}
	})
	t.Run("provider_npi column", func(t *testing.T) {
		got := findingsFor(t, "name,provider_npi,state\nAlpha Bravo,1000000004,WA\nCharlie Delta,1104332188,OR\n")
		m := only(t, got, "NPI", "1104332188")
		if m.Confidence != 80 || !checkOf(t, m, "provider_context") {
			t.Errorf("confidence %.0f provider_context %v, want 80 and true", m.Confidence, checkOf(t, m, "provider_context"))
		}
	})
}

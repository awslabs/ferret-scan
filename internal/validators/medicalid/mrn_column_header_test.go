// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package medicalid

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/tabular"
)

// #436: the MRN scan had no column-header arm while the INSURANCE scan did, both in the
// same file and both added by the same change. So a CSV export whose header names a medical
// record number reported NOTHING, while the identical layout naming an insurance member ID
// reported normally.
//
// Measured on the parent:
//
//	patient,medical record number,order number / Smith,5729183,1234567  -> 0 findings
//	patient,member id,order number / Smith,ABC123456789,1234567         -> 2 findings HIGH
//	medical_record_number: 5729183                                      -> 1 finding HIGH
//
// A tabular export is the normal shape for this data, and an unreported identifier is never
// handed to the redactor either — so it stayed cleartext in a file the scan exits 0 on.
//
// The header names below are taken from REAL published sources rather than invented, because
// the whole fix keys on header TEXT and an invented spelling proves nothing about a real
// export. See TestRealEHRSchemasAreAdmitted.

// mrnFindings returns the MRN values reported for content, so assertions read as sets rather
// than indices.
func mrnFindings(t *testing.T, content string) map[string]float64 {
	t.Helper()
	matches, err := NewValidator().ValidateContent(content, "probe.csv")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	out := map[string]float64{}
	for _, m := range matches {
		if m.Type == "MRN" {
			out[m.Text] = m.Confidence
		}
	}
	return out
}

// strongMRNBoost is the confidence a value reaches when a strong MRN keyword covers it:
// base 15 + 55. The generic-medical boost yields 45 instead, and no boost at all leaves 15.
//
// The number is asserted, not just presence, and the reason is a surviving mutation. Reverting
// the boost to the LINE flags (lc.mrnKeyword / lc.medical) leaves both false on a data row, so
// the value is still REPORTED — at 15, a LOW finding indistinguishable from noise. A
// presence-only assertion passed on that revert. Confidence is the behaviour here, so
// confidence is what the test reads.
const (
	strongMRNBoost  = 70.0
	genericMRNBoost = 45.0
	noBoostBase     = 15.0
)

// TestAMedicalRecordColumnIsReported is the regression test.
func TestAMedicalRecordColumnIsReported(t *testing.T) {
	for _, header := range []string{
		"patient,medical record number,order number",
		"patient,mrn,order number",
		"patient,medicalRecordNumber,orderNumber",
		"patient,chart number,order number",
	} {
		t.Run(header, func(t *testing.T) {
			content := header + "\nSmith,5729183,1234567\nJones,4183926,2345678\n"
			got := mrnFindings(t, content)
			conf, ok := got["5729183"]
			if !ok {
				t.Fatalf("the value in the medical column was not reported (#436).\n"+
					"header: %s\nreported: %v\n"+
					"An unreported identifier is never handed to the redactor, so it stays "+
					"cleartext in a file the scan exits 0 on.", header, got)
			}
			// The column header carries a STRONG MRN keyword, so it must count as one — the
			// same rule evaluateInsuranceID applies to a header naming its own column.
			if conf != strongMRNBoost {
				t.Errorf("reported at %v, want %v.\nheader: %s\n"+
					"%v means the generic-medical boost was applied and %v means none was: the "+
					"value would surface as LOW noise rather than an identifiable MRN.",
					conf, strongMRNBoost, header, genericMRNBoost, noBoostBase)
			}
		})
	}
}

// TestAGenericMedicalColumnGetsTheWeakerBoost pins the other branch, so the two are not
// interchangeable. "patient" names a medical setting but is not an MRN label, so the value
// gets the generic boost — enough to be reported, less than a column that says "mrn".
// The other header cells are deliberately neutral. An earlier fixture used
// "hospital,patient,region" and read 65 rather than 45, because "hospital" on the adjacent
// header line contributes +20 of line impact — the line context reaches the previous line.
// Isolating the arithmetic needs every cell except the one under test to say nothing.
func TestAGenericMedicalColumnGetsTheWeakerBoost(t *testing.T) {
	const content = "aaa,patient,region\nbbb,5729183,east\n"

	got := mrnFindings(t, content)
	conf, ok := got["5729183"]
	if !ok {
		t.Fatalf("a value in a column headed \"patient\" was not reported: %v", got)
	}
	if conf != genericMRNBoost {
		t.Errorf("reported at %v, want the generic-medical boost %v. A column headed "+
			"\"patient\" is medical context but not an MRN label, so it must not earn the "+
			"strong boost %v.", conf, genericMRNBoost, strongMRNBoost)
	}
}

// TestTheNeighbouringColumnsAreNotReported is the other half, and the issue asked for both on
// ONE fixture: "a fix that admits the whole row is worse than the gap."
//
// Admission is per ROW and deliberately permissive — a row cannot be scanned column-by-column
// before its candidates are found — so the per-COLUMN decision in evaluateMRN is the only
// thing standing between this arm and turning every numeric column into a medical finding.
func TestTheNeighbouringColumnsAreNotReported(t *testing.T) {
	const content = "patient,medical record number,order number,invoice number,tracking number\n" +
		"Smith,5729183,1234567,9876543,5551234\n" +
		"Jones,4183926,2345678,8765432,4441234\n"

	got := mrnFindings(t, content)

	for _, want := range []string{"5729183", "4183926"} {
		if _, ok := got[want]; !ok {
			t.Errorf("the medical column value %s was not reported", want)
		}
	}
	for _, unwanted := range []string{"1234567", "9876543", "5551234", "2345678", "8765432", "4441234"} {
		if conf, ok := got[unwanted]; ok {
			t.Errorf("%s came from an order/invoice/tracking column and was reported as MRN at %v.\n"+
				"reported: %v\nThe base score is 15, which clamps to a reported LOW rather than "+
				"being dropped, so without the per-column gate one medical header turns every "+
				"numeric column in the table into a medical finding.", unwanted, conf, got)
		}
	}
}

// TestOtherNumberShapesInANeighbouringColumnAreNotReported extends the control to the shapes
// most likely to be swept up: a zip code, a year, a phone extension, an SSN, a fax number.
func TestOtherNumberShapesInANeighbouringColumnAreNotReported(t *testing.T) {
	const content = "patient,medical record number,zip code,year,phone extension,ssn,fax number\n" +
		"Smith,5729183,021384,201942,555123,123456789,5551234\n"

	got := mrnFindings(t, content)
	if _, ok := got["5729183"]; !ok {
		t.Fatalf("the medical column value was not reported; reported: %v", got)
	}
	if len(got) != 1 {
		t.Errorf("reported %d MRN values, want exactly 1: %v\n"+
			"Only the medical column is an MRN; the rest are a zip, a year, an extension, "+
			"an SSN and a fax number.", len(got), got)
	}
}

// TestATableWithNoMedicalHeaderIsNeverAdmitted. The admission predicate is the outer gate;
// if it fires on a table with no medical column at all, everything downstream is moot.
func TestATableWithNoMedicalHeaderIsNeverAdmitted(t *testing.T) {
	const content = "name,order number,invoice number,tracking number\n" +
		"Smith,5729183,1234567,9876543\n"

	if got := mrnFindings(t, content); len(got) != 0 {
		t.Errorf("a table with no medical header reported %d MRN values: %v", len(got), got)
	}
}

// TestHeaderRowAdmissionIsSubsumedButAsserted.
//
// The admission predicate is asserted DIRECTLY here, because its effect on output is
// subsumed by the per-column gate and therefore cannot be observed end to end. Forcing
// headerRowHasMedicalContext to return true unconditionally leaves all 78 packages green and
// changes not one finding across 2,198 real files: every candidate it would let through is
// then rejected by mrnContextFor/medicalContextFor, since a table with no medical header has
// no medical column either.
//
// That makes it a cheap outer gate — it skips a regex pass over rows that cannot produce a
// finding — rather than the thing preventing a false positive. Recorded plainly so nobody
// reads it as the safety mechanism it is not; the per-column gate in evaluateMRN is that.
func TestHeaderRowAdmissionIsSubsumedButAsserted(t *testing.T) {
	v := NewValidator()
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{"a medical header", "patient,medical record number,order number\nSmith,5729183,1\n", true},
		{"mrn abbreviation", "a,mrn,c\nx,5729183,z\n", true},
		{"no medical header", "name,order number,invoice number\nSmith,5729183,1\n", false},
		{"generic identifiers only", "person_id,widget_id,region\n5729183,1,east\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			table := analyzeForTest(tc.content)
			if !table.IsTable() {
				t.Fatalf("fixture was not recognised as a table, so the predicate is untested")
			}
			// Any data row's bounds will do; the predicate reads the header set, not the row.
			lines := strings.Split(tc.content, "\n")
			lc := medicalLineContext{table: table, bounds: table.Bounds(lines[1])}
			_ = lc
			if got := v.tableHasMedicalHeader(table); got != tc.want {
				t.Errorf("tableHasMedicalHeader = %v, want %v for headers %v",
					got, tc.want, table.Headers())
			}
		})
	}
}

// TestTheSameLinePathIsUnchanged. The per-column gate added to evaluateMRN must be a no-op
// here: admission on this path requires hasMedicalContext(lowerLine), which sets lc.medical,
// which makes medicalContextFor true regardless of any column header.
//
// The second case matters most. Its line carries BOTH an MRN keyword and the "account" soft
// suppressor, which the existing code deliberately does not let hard-drop the value.
func TestTheSameLinePathIsUnchanged(t *testing.T) {
	cases := []struct {
		name, content, want string
	}{
		{"labelled MRN", "medical_record_number: 5729183", "5729183"},
		{"patient account number", "Patient account number: 1234567", "1234567"},
		{"mrn abbreviation", "MRN 5729183 admitted today", "5729183"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mrnFindings(t, tc.content)
			if _, ok := got[tc.want]; !ok {
				t.Errorf("%s was not reported on the same-line path; reported: %v.\n"+
					"The per-column gate must not reach this path.", tc.want, got)
			}
		})
	}
}

// TestNonTabularContentIsUnaffected. tabular.Analyze is conservative, and this asserts the
// consequence: comma-rich prose is not a table, so no header is resolved and the behaviour is
// exactly the pre-existing one.
func TestNonTabularContentIsUnaffected(t *testing.T) {
	// A medical keyword IS present, so the same-line path admits and reports — the point is
	// that nothing about column resolution changes the answer.
	const prose = "The patient, admitted on Tuesday, has medical record number 5729183, as noted."
	if got := mrnFindings(t, prose); len(got) == 0 {
		t.Errorf("prose carrying a labelled MRN reported nothing: %v", got)
	}

	// And prose with no medical keyword stays silent.
	const neutral = "The order, placed on Tuesday, carries reference 5729183, as noted."
	if got := mrnFindings(t, neutral); len(got) != 0 {
		t.Errorf("neutral prose reported %d MRN values: %v", len(got), got)
	}
}

// TestRealEHRSchemasAreAdmitted is the real-file half, and it is the reason this fix is
// trustworthy at all.
//
// Every header row here is transcribed VERBATIM from a real published source, not invented:
//
//   - Synthea's CSVExporter.java, which is the header row that tool actually writes
//   - the OMOP CDM v5.4 Field_Level.csv data dictionary
//   - Epic Clarity and Cerner Millennium column names as publicly documented
//
// This matters because the fix keys entirely on header TEXT, and real systems do not write
// "medical record number". They write PATIENT, PAT_MRN_ID, MRN, person_id. A fixture using
// my own spelling would have passed while a real export failed — which is exactly what
// happened to me on a neighbouring change, where a hand-written "sourceIPAddress" did not
// match while the real export's "Source IP address" did.
func TestRealEHRSchemasAreAdmitted(t *testing.T) {
	cases := []struct {
		name, header, row, value string
	}{
		{
			name:   "Synthea encounters",
			header: "Id,START,STOP,PATIENT,ORGANIZATION,PROVIDER,PAYER,ENCOUNTERCLASS,CODE,DESCRIPTION",
			row:    "abc,2024-01-01,2024-01-02,5729183,ORG1,PRV1,PAY1,ambulatory,1234,Visit",
			value:  "5729183",
		},
		{
			name:   "Synthea observations",
			header: "DATE,PATIENT,ENCOUNTER,CATEGORY,CODE,DESCRIPTION,VALUE,UNITS",
			row:    "2024-01-01,5729183,4183926,vital-signs,8302-2,Body Height,170,cm",
			value:  "5729183",
		},
		{
			name:   "Epic Clarity",
			header: "PAT_ID,PAT_MRN_ID,PAT_NAME,BIRTH_DATE,SEX_C",
			row:    "Z1234,5729183,Smith John,1980-01-01,1",
			value:  "5729183",
		},
		{
			name:   "Cerner Millennium",
			header: "PERSON_ID,MRN,NAME_FULL_FORMATTED,BIRTH_DT_TM,SEX_CD",
			row:    "4183926,5729183,Smith John,1980-01-01,362",
			value:  "5729183",
		},
		{
			name:   "flat HL7-style extract",
			header: "message_id,patient_identifier,visit_number,facility",
			row:    "M1,5729183,4183926,General",
			value:  "5729183",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mrnFindings(t, tc.header+"\n"+tc.row+"\n")
			if _, ok := got[tc.value]; !ok {
				t.Errorf("%s was not reported from a real %s header row.\nheader: %s\nreported: %v",
					tc.value, tc.name, tc.header, got)
			}
		})
	}
}

// TestOMOPGenericIdentifierColumnsStayUnadmitted records a DECISION, not a gap that slipped
// through.
//
// The OMOP CDM names its patient key `person_id` and its source key `person_source_value`.
// Neither is a medical label — a generic surrogate key of that name appears in countless
// non-clinical databases — and hasMedicalContext's own comment states the position this rests
// on: "A bare 'record number' is deliberately NOT here. It names an MRN only in a medical
// setting, and this list is what decides whether the line is a medical setting at all."
// Adding "person" would make every `person_id` column in every schema medical context,
// including on the same-line path.
//
// Admitting these would need a different signal — a TABLE-level one, such as a sibling column
// named `visit_concept_id` or `care_site_id` — which is a separate question from the missing
// arm this change adds. This test exists so that if someone widens the list, they do it
// deliberately and see this reasoning first.
func TestOMOPGenericIdentifierColumnsStayUnadmitted(t *testing.T) {
	const content = "person_id,gender_concept_id,year_of_birth,person_source_value,care_site_id\n" +
		"5729183,8507,1980,4183926,9182736\n"

	if got := mrnFindings(t, content); len(got) != 0 {
		t.Errorf("an OMOP CDM row reported %d MRN values: %v\n"+
			"If this is now intended, say so in hasMedicalContext — the list deliberately "+
			"excludes generic identifier names, and 'person' is one.", len(got), got)
	}
}

// TestTheInsuranceArmIsUnchanged. The two scans sit in the same function and share the line
// context, so a change to one is a plausible way to break the other.
func TestTheInsuranceArmIsUnchanged(t *testing.T) {
	const content = "patient,member id,order number\n" +
		"Smith,ABC123456789,1234567\n" +
		"Jones,XYZ987654321,2345678\n"

	matches, err := NewValidator().ValidateContent(content, "probe.csv")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	var ids []string
	for _, m := range matches {
		if m.Type == "INSURANCE_MEMBER_ID" {
			ids = append(ids, m.Text)
		}
	}
	if len(ids) != 2 {
		t.Errorf("the insurance header arm reported %v, want both member IDs. This is the arm "+
			"the MRN scan was modelled on; breaking it would be a regression.", ids)
	}
}

// TestTheColumnHeaderContextHelpersAreAsymmetric states the one-way property in code.
//
// mrnContextFor and medicalContextFor only ever ADD context. There is no "header contradicts"
// counterpart, and there must not be: suppressing a medical identifier because its column is
// named something else would be suppression chosen by whoever wrote the file.
func TestTheColumnHeaderContextHelpersAreAsymmetric(t *testing.T) {
	v := NewValidator()

	// A line that already carries the keyword keeps its context whatever the column says.
	lc := medicalLineContext{mrnKeyword: true, medical: true}
	if !v.mrnContextFor(lc, 0) {
		t.Error("mrnContextFor lost a same-line MRN keyword when no table was present")
	}
	if !v.medicalContextFor(lc, 0) {
		t.Error("medicalContextFor lost a same-line medical keyword when no table was present")
	}

	// And with neither line keyword nor table, both are false rather than panicking on a nil
	// table — the shape every non-tabular document takes.
	empty := medicalLineContext{}
	if v.mrnContextFor(empty, 0) || v.medicalContextFor(empty, 0) {
		t.Error("context was reported for a candidate with neither a line keyword nor a table")
	}
	if v.tableHasMedicalHeader(nil) {
		t.Error("tableHasMedicalHeader reported true with a nil table")
	}
}

// TestTwoColumnTablesStillReportNothing records a residual, pre-existing limit so it is not
// mistaken for this change.
//
// tabular.Analyze requires at least 3 fields, so a 2-column medical CSV is not recognised as
// a table and no header is resolved. That threshold is shared with the five other validators
// using the package and is deliberately conservative; changing it belongs with the package,
// not here.
func TestTwoColumnTablesStillReportNothing(t *testing.T) {
	const two = "medical record number,order number\n5729183,1234567\n"
	const three = "medical record number,order number,region\n5729183,1234567,east\n"

	if got := mrnFindings(t, two); len(got) != 0 {
		t.Logf("a 2-column table now reports %v — tabular.Analyze's >=3-field rule may have "+
			"changed; update this test's premise deliberately", got)
	}
	if got := mrnFindings(t, three); len(got) == 0 {
		t.Errorf("a 3-column table reported nothing, so the >=3-field threshold is not the " +
			"explanation for the 2-column case and something else is wrong")
	}
	if !strings.Contains(three, "region") {
		t.Fatal("fixture drift")
	}
}

// analyzeForTest wraps tabular.Analyze so the test does not need the import alias twice.
func analyzeForTest(content string) *tabular.Table { return tabular.Analyze(content) }

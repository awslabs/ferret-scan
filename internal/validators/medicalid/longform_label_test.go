// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package medicalid

import (
	"strings"
	"testing"
)

// A label's concatenated spelling must reach the MRN scan.
//
// A keyword list holding only the SUB-PHRASES of a label cannot match the label itself: the
// whole-word rule correctly refuses "medical record" inside "medicalrecordnumber", because "number"
// continues the word, and equally refuses "record number", because "medical" precedes it. So
// `medicalRecordNumber: 4839271` carried no medical context at all, hasMedicalContext returned false,
// and the MRN regex never ran — while `medical_record_number: 5729183` reported MRN at HIGH 90.
// Measured, both at HEAD (#408).
//
// evaluateMRN accepted the value all along; it was simply never reached, which is why this is a gate
// bug rather than a scoring one.
func TestConcatenatedMedicalLabelsReachTheMRNScan(t *testing.T) {
	// Every separator spelling of the same label, plus the sibling labels an EHR or ORM export
	// writes. A JSON or ORM field name has no spaces to match.
	for _, line := range []string{
		"medicalRecordNumber: 4839271",
		"MedicalRecordNumber: 4839272",
		"medicalrecordnumber: 4839274",
		"medical_record_number: 5729183",
		"medical-record-number: 5729184",
		"medical record number: 5729185",
		"patientIdentificationNumber: 4839275",
		"healthRecordNumber: 4839276",
		"hospitalRecordNumber: 4839281",
		"patientId: 4839277",
		"patientNumber: 4839280",
		"chartNumber: 4839278",
		"admissionNumber: 4839279",
	} {
		t.Run(line, func(t *testing.T) {
			v := NewValidator()
			matches, err := v.ValidateContent(line, "record.json")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) == 0 {
				t.Errorf("no finding: the label carries no recognised medical context, so the MRN "+
					"regex never ran. An unreported identifier is never redacted either, so it stays "+
					"cleartext in a file the scan exits 0 on.\n  line: %q", line)
			}
		})
	}
}

// The gate decides whether a line is a MEDICAL setting, so a generic record identifier must not
// enter it. This is the direction that would cost precision, and it is the reason a bare
// "record number" is deliberately absent from hasMedicalContext even though it IS in the MRN
// keyword list — that list only applies once the line is already medical.
func TestGenericIdentifierLabelsAreNotMedicalContext(t *testing.T) {
	for _, line := range []string{
		"record number: 1234567",
		"recordNumber: 1234567",
		"orderNumber: 1234567",
		"invoiceNumber: 1234567",
		"trackingNumber: 1234567",
		"serialNumber: 1234567",
		"accountNumber: 1234567",
		"referenceNumber: 1234567",
		"confirmationNumber: 1234567",
		"ticketNumber: 1234567",
	} {
		t.Run(line, func(t *testing.T) {
			v := NewValidator()
			matches, err := v.ValidateContent(line, "orders.csv")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) > 0 {
				var got []string
				for _, m := range matches {
					got = append(got, m.Type+"="+m.Text)
				}
				t.Errorf("reported %v on a line with no medical context. hasMedicalContext is what "+
					"decides whether the line is medical at all, so a generic identifier label must "+
					"not be in it.\n  line: %q", got, line)
			}
		})
	}
}

// The whole-token boundary must survive the widening. A longer word that merely CONTAINS the label
// is not the label, and this is what stops the flexible-separator matching from becoming a
// substring search.
func TestConcatenatedLabelStillRespectsWordBoundaries(t *testing.T) {
	for _, kw := range []string{"medical record number", "patient id", "chart number"} {
		for _, text := range []string{
			"nonmedicalrecordnumbers: 1",
			"medicalrecordnumbering: 1",
			"xpatientidx: 1",
			"chartnumbering: 1",
		} {
			if containsLabel(text, kw) && strings.Contains(text, "ing") {
				t.Errorf("containsLabel(%q, %q) = true: a longer word that contains the label is "+
					"not the label, and matching it would turn every keyword into a substring "+
					"search", text, kw)
			}
		}
	}

	// And the two-word form must still refuse the three-word concatenation, which is the asymmetry
	// that makes the explicit long-form entries necessary rather than redundant.
	if containsLabel("medicalrecordnumber: 1", "medical record") {
		t.Error("containsLabel matched the two-word \"medical record\" against " +
			"\"medicalrecordnumber\". If that ever becomes true, the long-form keywords added for " +
			"#408 are redundant — but so is the whole-word rule, and \"medical\" would match " +
			"\"medicalrecordnumbering\" too")
	}
}

// hasMedicalContext is the gate, and it must recognise each added spelling directly. Asserted at the
// gate as well as end to end, so a failure says which layer broke.
func TestHasMedicalContextRecognisesConcatenatedLabels(t *testing.T) {
	v := NewValidator()

	for _, line := range []string{
		"medicalrecordnumber: 4839271",
		"patientidentificationnumber: 1",
		"healthrecordnumber: 1",
		"hospitalrecordnumber: 1",
		"patientid: 1",
		"patientnumber: 1",
		"chartnumber: 1",
		"admissionnumber: 1",
	} {
		if !v.hasMedicalContext(line) {
			t.Errorf("hasMedicalContext(%q) = false: the MRN scan is gated on this, so the regex "+
				"never runs and no value is reported", line)
		}
	}

	for _, line := range []string{
		"recordnumber: 1",
		"ordernumber: 1",
		"serialnumber: 1",
	} {
		if v.hasMedicalContext(line) {
			t.Errorf("hasMedicalContext(%q) = true: a generic identifier label must not make a "+
				"line medical", line)
		}
	}
}

// The MRN keyword flag boosts confidence and cancels the soft non-medical suppressor, so widening it
// can only admit findings. This pins that it recognises the long forms too — the same asymmetry the
// package already documented for "patient identification".
func TestMRNKeywordRecognisesTheLongForms(t *testing.T) {
	v := NewValidator()
	for _, line := range []string{
		"patientidentificationnumber: 1",
		"medicalrecordnumber: 1",
		"patientid: 1",
		"chartnumber: 1",
		"recordnumber: 1", // in the MRN list, unlike hasMedicalContext
	} {
		if !v.hasMRNKeyword(line) {
			t.Errorf("hasMRNKeyword(%q) = false", line)
		}
	}
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package office

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// #627: a value Word split across two adjacent runs was reported at confidence 100 and then written
// out in cleartext, at exit 0 with an empty stderr, because all three layers held a per-node view of
// the part. This file covers the fail-closed guard's half: it must SEE such a value, so the miss is a
// disclosed refusal rather than a silent leak.
//
// Measured on the parent commit, the docx below:
//
//	rc=0, stderr 0 bytes, a file written into the redaction directory
//	textutil -convert txt -stdout -> "Employee SSN: 449-87-4100 | Contact: [EMAIL-REDACTED]"
//
// The email being masked in the same part is the positive control: the redactor ran.

// splitAcrossRuns is the shape Word produces routinely — a run boundary at a formatting change. The
// xml:space attribute is present ON PURPOSE; see TestRunTextExcludesAttributes.
const splitAcrossRuns = `<?xml version="1.0" encoding="UTF-8"?>` +
	`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>` +
	`<w:p><w:r><w:t xml:space="preserve">Employee SSN: 449-87-</w:t></w:r>` +
	`<w:r><w:rPr><w:b/></w:rPr><w:t xml:space="preserve">4100</w:t></w:r></w:p>` +
	`</w:body></w:document>`

// wholeInOneRun is the control: the identical value, not split. It redacted correctly all along, and
// must keep doing so.
const wholeInOneRun = `<?xml version="1.0" encoding="UTF-8"?>` +
	`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>` +
	`<w:p><w:r><w:t xml:space="preserve">Employee SSN: 449-87-4100</w:t></w:r></w:p>` +
	`</w:body></w:document>`

func TestDecodedPartTextSeesASplitValueInRunText(t *testing.T) {
	separated, runText, ok := decodedPartText([]byte(splitAcrossRuns))
	if !ok {
		t.Fatal("decodedPartText refused to tokenize a well-formed part")
	}

	// The separated view cannot see it, and that is not a bug in it: its newline exists to stop two
	// adjacent runs concatenating into a value that is in neither. This assertion records WHY a
	// second view was needed, so nobody "simplifies" it back to one.
	if strings.Contains(separated, "449-87-4100") {
		t.Errorf("the separated view now contains the split value: %q. If a separator is no longer "+
			"written, the run-text view below is redundant — but so is the protection the separator "+
			"gave against a value that appears in neither run", separated)
	}

	// The run-text view must see it, because the SCANNER does: its extractor strips tags with a regex
	// and inserts nothing between runs, which is why the value was reported in the first place.
	if !strings.Contains(runText, "449-87-4100") {
		t.Errorf("run text does not contain the split value, so the guard is still blind to the shape "+
			"#627 is about: %q", runText)
	}
}

// TestRunTextExcludesAttributes pins the mistake that made the first attempt at this fix silently do
// nothing.
//
// encoding/xml delivers tokens in document order, so a w:t element carrying xml:space="preserve"
// contributes "preserve" BETWEEN the two runs. A view built from every token therefore reads
// "449-87-" + "preserve" + "4100" and still cannot find the value — the fix appeared to change
// nothing and gave no reason why. Attributes are covered by the separated view; this one must not
// carry them.
func TestRunTextExcludesAttributes(t *testing.T) {
	separated, runText, ok := decodedPartText([]byte(splitAcrossRuns))
	if !ok {
		t.Fatal("decodedPartText refused to tokenize a well-formed part")
	}

	if strings.Contains(runText, "preserve") {
		t.Errorf("run text contains the xml:space attribute value, so attribute text is being "+
			"interleaved between runs and a split value spanning them cannot be found: %q", runText)
	}
	// Non-vacuity: the attribute must really be in the part, or the assertion above is about nothing.
	if !strings.Contains(separated, "preserve") {
		t.Fatalf("the separated view has no attribute text, so this fixture is not exercising the "+
			"interleaving case at all: %q", separated)
	}
	// And attributes must still be covered SOMEWHERE, since the raw replacer rewrites them and a
	// value can live in one.
	if !strings.Contains(separated, "http://schemas.openxmlformats.org") {
		t.Errorf("the separated view dropped namespace/attribute text, which is the view responsible "+
			"for covering a value that lives in an attribute: %q", separated)
	}
}

func TestParentPartResidueCatchesASplitValue(t *testing.T) {
	for _, tc := range []struct {
		name        string
		part        string
		match       string
		wantResidue int
	}{
		{"split across adjacent runs", splitAcrossRuns, "449-87-4100", 1},
		{"whole inside one run", wholeInOneRun, "449-87-4100", 1},
		// Must NOT fire: a reported value that genuinely is not in the part.
		{"value absent from the part", splitAcrossRuns, "111-22-3333", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			contents := &OfficeZipContents{Files: map[string][]byte{"word/document.xml": []byte(tc.part)}}
			got := parentPartResidue(contents, []detector.Match{{Text: tc.match, Type: "SSN"}})
			if len(got) != tc.wantResidue {
				t.Errorf("parentPartResidue = %d residue, want %d. A miss here means the value is "+
					"written out in cleartext with nothing said; a false hit here means refusing to "+
					"write a document that was correctly redacted", len(got), tc.wantResidue)
			}
		})
	}
}

// TestASecondViewCannotManufactureAFalseRefusal is the must-NOT-fire half at the level that matters.
//
// The run-text view concatenates adjacent runs, so it can contain strings that appear in neither run
// — which is exactly what the separator was protecting against. That is harmless here for a specific
// reason worth pinning: only REPORTED values are ever probed, so a string the concatenation invents
// is never looked for unless some extraction actually produced it and a validator reported it.
func TestASecondViewCannotManufactureAFalseRefusal(t *testing.T) {
	// "123" and "456" in adjacent runs concatenate to "123456", which is in neither.
	part := `<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://x"><w:body>` +
		`<w:p><w:r><w:t>123</w:t></w:r><w:r><w:t>456</w:t></w:r></w:p></w:body></w:document>`

	_, runText, ok := decodedPartText([]byte(part))
	if !ok {
		t.Fatal("decodedPartText refused to tokenize a well-formed part")
	}
	// Non-vacuity: the concatenation really does invent the string, or this test proves nothing.
	if !strings.Contains(runText, "123456") {
		t.Fatalf("the run-text view does not concatenate these runs, so the invented-string case is "+
			"not being exercised: %q", runText)
	}

	// With nothing reported, there is nothing to refuse over.
	contents := &OfficeZipContents{Files: map[string][]byte{"word/document.xml": []byte(part)}}
	if got := parentPartResidue(contents, nil); len(got) != 0 {
		t.Errorf("parentPartResidue = %d residue for a document with no reported values, want 0", len(got))
	}

	// And a value that WAS reported is legitimately residue even if it only exists across the join —
	// that is the whole point, not a false positive: something extracted and reported it.
	if got := parentPartResidue(contents, []detector.Match{{Text: "123456", Type: "TEST"}}); len(got) != 1 {
		t.Errorf("parentPartResidue = %d for a reported value present only across the run join, want "+
			"1. If a validator reported it, an extractor produced it, and writing the file would ship "+
			"it in cleartext", len(got))
	}
}

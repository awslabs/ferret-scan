// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package office

import "testing"

// The redactor's part selection has to agree with the extractor's.
//
// The extractor finds the text and the redactor rewrites it, so a part that only one of
// them recognizes produces the worst possible outcome: a finding is reported, the user
// is handed a file that looks redacted, and the value is still in it. Measured on a
// .docx whose body part was named word/Document.xml — 4 findings detected, and both the
// SSN and the card survived --enable-redaction in cleartext inside the rewritten
// archive, because this predicate matched the entry name case-sensitively.
//
// A zip entry name is producer-controlled data and nothing makes the conventional
// spelling normative, so matching is case-insensitive.

func TestIsTextContainingFileIgnoresPartNameCase(t *testing.T) {
	or := &OfficeRedactor{}

	cases := []struct {
		name    string
		file    string
		docType OfficeDocumentType
		want    bool
	}{
		// Word: the conventional name, and the variants that used to be missed.
		{"docx conventional", "word/document.xml", DocumentTypeDOCX, true},
		{"docx capital D", "word/Document.xml", DocumentTypeDOCX, true},
		{"docx all caps", "WORD/DOCUMENT.XML", DocumentTypeDOCX, true},
		{"docx capital ext", "word/document.XML", DocumentTypeDOCX, true},
		{"docx named main", "word/main.xml", DocumentTypeDOCX, true},
		{"docx header", "word/header1.xml", DocumentTypeDOCX, true},
		{"docx Header caps", "word/Header1.xml", DocumentTypeDOCX, true},
		{"docx comments", "word/comments.xml", DocumentTypeDOCX, true},

		// Word negatives: still not everything under word/ is prose.
		{"docx styles", "word/styles.xml", DocumentTypeDOCX, false},
		{"docx settings", "word/settings.xml", DocumentTypeDOCX, false},
		{"docx rels", "word/_rels/document.xml.rels", DocumentTypeDOCX, false},
		{"docx not xml", "word/document.bin", DocumentTypeDOCX, false},

		// Excel.
		{"xlsx sheet", "xl/worksheets/sheet1.xml", DocumentTypeXLSX, true},
		{"xlsx Sheet caps", "xl/Worksheets/Sheet1.xml", DocumentTypeXLSX, true},
		{"xlsx shared strings", "xl/sharedStrings.xml", DocumentTypeXLSX, true},
		{"xlsx shared strings lower", "xl/sharedstrings.xml", DocumentTypeXLSX, true},
		{"xlsx workbook is not text", "xl/workbook.xml", DocumentTypeXLSX, false},

		// PowerPoint.
		{"pptx slide", "ppt/slides/slide1.xml", DocumentTypePPTX, true},
		{"pptx Slide caps", "ppt/Slides/Slide1.xml", DocumentTypePPTX, true},
		{"pptx layout", "ppt/slideLayouts/slideLayout1.xml", DocumentTypePPTX, true},
		{"pptx master", "ppt/slideMasters/slideMaster1.xml", DocumentTypePPTX, true},
		{"pptx presentation is not a slide", "ppt/presentation.xml", DocumentTypePPTX, false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := or.isTextContainingFile(tc.file, tc.docType)
			if got != tc.want {
				verb := "was not selected for redaction"
				why := "\nA part the extractor reads but the redactor skips yields a finding that " +
					"cannot be redacted: the user gets a file that looks sanitized with the value " +
					"still inside it."
				if !tc.want {
					verb = "was selected for redaction but should not be"
					why = ""
				}
				t.Errorf("isTextContainingFile(%q, %v) = %v, want %v — %s%s",
					tc.file, tc.docType, got, tc.want, verb, why)
			}
		})
	}
}

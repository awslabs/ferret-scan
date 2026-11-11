// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractofficelib

import (
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/olefixture"
)

// A property whose value is nothing but '*' is what a redacted copy holds where a value was: the
// legacy redactor overwrites in place with that byte. Collecting it made every masked field a finding
// on the re-scan of a redacted .doc ("Author: *****" as AUTHOR_INFO, "Company: *****" as
// COMPANY_INFO), six of the seven findings on the redacted copy of govdocs1--000696.doc: a field name
// with no value (#915). It is not collected now, mapped or custom.
//
// The control matters as much: a value that merely CONTAINS '*' is content and is still collected,
// or the rule would hide "Pa**word" or a format-preserving rendering that keeps part of a value.
func TestLegacyExtraction_AValueThatIsOnlyTheMaskIsNotCollected(t *testing.T) {
	path := writeLegacyFixture(t, "masked.doc", []legacyCFBStream{
		{Name: "WordDocument", Data: []byte("Body text long enough to be recovered.\r")},
		{Name: "\x05SummaryInformation", Data: BuildSummaryInformation(map[uint32]string{
			SummaryPropAuthor: "************",
			SummaryPropTitle:  "j*******@example.com",
		})},
		{Name: "\x05DocumentSummaryInformation", Data: olefixture.DocSummaryInformationWithCustom(
			map[uint32]string{olefixture.PropCompany: "******************"},
			map[string]string{"_AuthorEmail": "************************", "Note": "Pa**word"},
			nil,
		)},
	})

	md, err := ExtractMetadata(path)
	if err != nil {
		t.Fatalf("ExtractMetadata: %v", err)
	}
	if md.Author != "" || md.Creator != "" || md.Company != "" {
		t.Errorf("a mask-only value was collected: Author %q, Creator %q, Company %q", md.Author, md.Creator, md.Company)
	}
	if v, ok := md.CustomProps["_AuthorEmail"]; ok {
		t.Errorf("a mask-only custom property was collected: %q", v)
	}
	if md.Title != "j*******@example.com" {
		t.Errorf("Title = %q: a value that keeps part of its content must still be collected", md.Title)
	}
	if md.CustomProps["Note"] != "Pa**word" {
		t.Errorf("custom Note = %q: a value containing '*' is content and must still be collected", md.CustomProps["Note"])
	}
}

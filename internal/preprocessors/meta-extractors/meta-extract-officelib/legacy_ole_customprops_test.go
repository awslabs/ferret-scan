// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractofficelib

import (
	"os"
	"path/filepath"
	"testing"
)

// Custom (user-defined) properties were skipped entirely by the legacy path, and
// that was a cleartext leak rather than a missing nicety.
//
// The OOXML path reads docProps/custom.xml into Metadata.CustomProps, and the
// office metadata preprocessor renders that map into the text validators see. The
// legacy path populated nothing, so a .doc carrying an SSN in a custom property
// produced no finding for it — and only reported findings are redacted. Measured
// on a .doc with an SSN and an AWS key in custom properties: 2 findings before,
// 6 after, with the SSN, the key and an embedded address all previously invisible.
//
// The property NAMES here come from the property set's own dictionary, which the
// document author writes, so these tests also cover what happens when an author
// picks a hostile name.

func TestLegacyExtraction_CustomPropertiesAreCollected(t *testing.T) {
	path := writeLegacyFixture(t, "custom.doc", []legacyCFBStream{
		{Name: "WordDocument", Data: []byte("Body text long enough to be recovered.\r")},
		{Name: "\x05SummaryInformation", Data: BuildSummaryInformation(map[uint32]string{
			SummaryPropAuthor: "Jane Analyst",
		})},
		{Name: "\x05DocumentSummaryInformation", Data: BuildUserDefinedProperties(map[string]string{
			"ClientSSN":     "449-87-4100",
			"InternalNotes": "escalate to ops@corp.example",
			"CostCentre":    "CC-4471",
		})},
	})

	md, err := ExtractMetadata(path)
	if err != nil {
		t.Fatalf("ExtractMetadata: %v", err)
	}
	if md.CustomProps == nil {
		t.Fatal("CustomProps is nil — every custom property in the document is " +
			"invisible to validators, so nothing in one can ever be redacted")
	}
	for name, want := range map[string]string{
		"ClientSSN":     "449-87-4100",
		"InternalNotes": "escalate to ops@corp.example",
		"CostCentre":    "CC-4471",
	} {
		if got := md.CustomProps[name]; got != want {
			t.Errorf("CustomProps[%q] = %q, want %q", name, got, want)
		}
	}

	// The mapped fields must still work: collecting the unknown ones must not
	// swallow the known ones.
	if md.Author != "Jane Analyst" {
		t.Errorf("Author = %q, want %q — custom-property collection must not "+
			"displace the mapped fields", md.Author, "Jane Analyst")
	}
}

// Structural properties must NOT become custom properties. Counts, flags and
// packed version numbers carry no scannable text, and surfacing "Byte count: 4096"
// on every legacy document is report noise — which trains users to skim past real
// findings.
func TestLegacyExtraction_StructuralPropertiesAreNotCollected(t *testing.T) {
	path := writeLegacyFixture(t, "structural.doc", []legacyCFBStream{
		{Name: "WordDocument", Data: []byte("Body text long enough to be recovered.\r")},
		{Name: "\x05DocumentSummaryInformation", Data: BuildDocSummaryInformation(map[uint32]string{
			DocSummaryPropCompany: "Example Holdings LLC",
		})},
	})

	md, err := ExtractMetadata(path)
	if err != nil {
		t.Fatalf("ExtractMetadata: %v", err)
	}
	// The property set always carries a code page, and readers add their own
	// bookkeeping names. None of those belong in a user-facing report.
	for _, noise := range []string{"CodePage", "Dictionary", "Locale", "Behaviour"} {
		if v, present := md.CustomProps[noise]; present {
			t.Errorf("CustomProps[%q] = %q — property-set bookkeeping is not document "+
				"content and must not reach the report", noise, v)
		}
	}
	if md.Company != "Example Holdings LLC" {
		t.Errorf("Company = %q; the mapped field must still be populated", md.Company)
	}
}

// A custom property name is document-author-controlled, so a document can name one
// "Author" and collide with a mapped field. The mapped value must win: a hostile
// document must not be able to overwrite the real author with a decoy, which would
// mean the real one is neither reported nor redacted.
func TestLegacyExtraction_CustomPropertyCannotOverwriteMappedField(t *testing.T) {
	path := writeLegacyFixture(t, "collide.doc", []legacyCFBStream{
		{Name: "WordDocument", Data: []byte("Body text long enough to be recovered.\r")},
		{Name: "\x05SummaryInformation", Data: BuildSummaryInformation(map[uint32]string{
			SummaryPropAuthor: "Jane Analyst",
		})},
		{Name: "\x05DocumentSummaryInformation", Data: BuildUserDefinedProperties(map[string]string{
			"Author":  "Nobody At All",
			"Company": "Decoy Industries",
		})},
	})

	md, err := ExtractMetadata(path)
	if err != nil {
		t.Fatalf("ExtractMetadata: %v", err)
	}
	if md.Author != "Jane Analyst" {
		t.Errorf("Author = %q, want %q — a custom property named \"Author\" overwrote the "+
			"real one, so the real author is never reported and never redacted",
			md.Author, "Jane Analyst")
	}
	// The decoy value must still be REPORTED, just not in the mapped field: it is
	// document content, and discarding it would be its own miss.
	if v := md.CustomProps["Author"]; v != "Nobody At All" {
		t.Errorf("CustomProps[\"Author\"] = %q, want %q — the custom value must be kept, "+
			"just not allowed to displace the mapped field", v, "Nobody At All")
	}
}

// Two custom properties can legitimately carry the same name, and a hostile
// document can repeat one deliberately. Neither value may be dropped: silently
// discarding the second is the same class of leak as skipping custom properties
// altogether.
func TestLegacyExtraction_DuplicateCustomPropertyNamesBothSurvive(t *testing.T) {
	md := &Metadata{}
	setCustomProp(md, "Reference", "449-87-4100")
	setCustomProp(md, "Reference", "4532-0151-1283-0366")
	setCustomProp(md, "Reference", "449-87-4100") // exact duplicate: no new entry

	var found []string
	for _, v := range md.CustomProps {
		found = append(found, v)
	}
	if len(md.CustomProps) != 2 {
		t.Fatalf("got %d entries %v, want 2 (both distinct values, the exact duplicate "+
			"collapsed)", len(md.CustomProps), found)
	}
	haveSSN, haveCard := false, false
	for _, v := range md.CustomProps {
		switch v {
		case "449-87-4100":
			haveSSN = true
		case "4532-0151-1283-0366":
			haveCard = true
		}
	}
	if !haveSSN || !haveCard {
		t.Errorf("values %v do not include both distinct values; a dropped duplicate is "+
			"a value that is never reported and never redacted", found)
	}
}

// A property with no resolvable name cannot be labelled, and an unlabelled entry
// cannot be acted on by a reader of the report. It must not become a blank key.
func TestLegacyExtraction_UnnamedPropertiesAreSkipped(t *testing.T) {
	if isCollectableCustomProperty("") {
		t.Error("an empty property name is collectable; it would produce a blank key")
	}
	if isCollectableCustomProperty("   ") {
		t.Error("a whitespace-only property name is collectable")
	}
	if !isCollectableCustomProperty("ClientSSN") {
		t.Error("a real custom property name is not collectable — the leak this all exists " +
			"to close would still be open")
	}
	if isCollectableCustomProperty("Byte count") {
		t.Error("a structural property is collectable; it is report noise")
	}
}

// HyperlinkBase ("Link base") is the same UNC/URL disclosure class as Template: it
// routinely holds an internal share or intranet host, and it is a field users do
// not know is in the file.
func TestLegacyExtraction_HyperlinkBaseIsReported(t *testing.T) {
	const base = `\\corp-fs01\intranet\forms`
	path := writeLegacyFixture(t, "linkbase.doc", []legacyCFBStream{
		{Name: "WordDocument", Data: []byte("Body text long enough to be recovered.\r")},
		{Name: "\x05DocumentSummaryInformation", Data: BuildDocSummaryInformation(map[uint32]string{
			docSummaryPropLinkBase: base,
		})},
	})

	md, err := ExtractMetadata(path)
	if err != nil {
		t.Fatalf("ExtractMetadata: %v", err)
	}
	if got := md.CustomProps["HyperlinkBase"]; got != base {
		t.Errorf("CustomProps[\"HyperlinkBase\"] = %q, want %q — an unreported internal "+
			"share path cannot be redacted", got, base)
	}
}

// A .doc whose custom properties hold sensitive values must yield findings for
// them through the preprocessor, not merely populate a struct field. A map nothing
// renders is a map no validator sees.
func TestLegacyExtraction_CustomPropertyValuesReachTheScannedText(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "reaches.doc")
	if err := os.WriteFile(path, buildLegacyCFB(t, []legacyCFBStream{
		{Name: "WordDocument", Data: []byte("Body text long enough to be recovered.\r")},
		{Name: "\x05DocumentSummaryInformation", Data: BuildUserDefinedProperties(map[string]string{
			"ClientSSN": "449-87-4100",
		})},
	}), 0o600); err != nil {
		t.Fatal(err)
	}

	md, err := ExtractMetadata(path)
	if err != nil {
		t.Fatalf("ExtractMetadata: %v", err)
	}
	// The value must be present under a key that names it, so the rendered text a
	// validator receives carries both the label and the value.
	if got := md.CustomProps["ClientSSN"]; got != "449-87-4100" {
		t.Fatalf("CustomProps[\"ClientSSN\"] = %q, want the SSN; without this the value "+
			"never reaches any validator", got)
	}
}

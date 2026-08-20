// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractofficelib

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/olefixture"
)

// Vector-valued properties are where a legacy workbook keeps its SHEET NAMES and a legacy
// deck its SLIDE TITLES, and none of it was reaching any validator. See #267 and the
// package comment in legacy-ole-vectors.go for why msoleps cannot read one.
//
// Measured on 19 real .xls/.doc/.ppt files from the Apache POI corpus: 14 of them carry a
// property whose type word is 0x101E, so this is what real Office writes, not an exotic
// shape. Those files decode 40 elements between them — sheet names, slide titles, theme
// and font names.

// vectorStream builds a property-set stream by hand, so a test can control the exact type
// word and element layout. The type word is the whole subject: an encoder that "helpfully"
// wrote it the way msoleps expects would make a broken reader look correct.
func vectorStream(t *testing.T, id uint32, typeWord uint32, payload []byte, extraScalars map[uint32]string) []byte {
	return vectorStreamWithDict(t, id, typeWord, payload, extraScalars, false)
}

// vectorStreamWithDict optionally includes a DICTIONARY entry at property id 0, which is what
// a user-defined property set carries. msoleps creates a Property for that entry too — filled
// with a Null rather than evaluated — so it occupies an index in the slice this decoder pairs
// against. Getting that wrong shifts every value onto the neighbouring property.
func vectorStreamWithDict(t *testing.T, id uint32, typeWord uint32, payload []byte, extraScalars map[uint32]string, dict bool) []byte {
	t.Helper()

	type entry struct {
		id  uint32
		val []byte
	}
	vec := make([]byte, 4)
	binary.LittleEndian.PutUint32(vec, typeWord)
	vec = append(vec, payload...)

	entries := []entry{{id: id, val: vec}}
	if dict {
		// A minimal dictionary blob: one entry naming a property.
		d := make([]byte, 4)
		binary.LittleEndian.PutUint32(d, 1)
		idBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(idBytes, 2)
		nameBytes := append([]byte("CustomThing"), 0)
		for len(nameBytes)%4 != 0 {
			nameBytes = append(nameBytes, 0)
		}
		nlen := make([]byte, 4)
		binary.LittleEndian.PutUint32(nlen, uint32(len("CustomThing")+1))
		d = append(d, idBytes...)
		d = append(d, nlen...)
		d = append(d, nameBytes...)
		entries = append(entries, entry{id: 0, val: d})
	}
	for sid, s := range extraScalars {
		body := append([]byte(s), 0)
		for len(body)%4 != 0 {
			body = append(body, 0)
		}
		v := make([]byte, 8+len(body))
		binary.LittleEndian.PutUint16(v[0:], 0x001E)
		binary.LittleEndian.PutUint32(v[4:], uint32(len(s)+1))
		copy(v[8:], body)
		entries = append(entries, entry{id: sid, val: v})
	}
	// Ascending id, as a property table is written.
	for i := 1; i < len(entries); i++ {
		for j := i; j > 0 && entries[j].id < entries[j-1].id; j-- {
			entries[j], entries[j-1] = entries[j-1], entries[j]
		}
	}

	table := 8 + len(entries)*8
	offs := make([]uint32, len(entries))
	cur := uint32(table)
	for i, e := range entries {
		offs[i] = cur
		cur += uint32(len(e.val))
	}

	set := new(bytes.Buffer)
	_ = binary.Write(set, binary.LittleEndian, cur)
	_ = binary.Write(set, binary.LittleEndian, uint32(len(entries)))
	for i, e := range entries {
		_ = binary.Write(set, binary.LittleEndian, e.id)
		_ = binary.Write(set, binary.LittleEndian, offs[i])
	}
	for _, e := range entries {
		set.Write(e.val)
	}

	hdr := make([]byte, 48)
	binary.LittleEndian.PutUint16(hdr[0:], 0xFFFE)
	binary.LittleEndian.PutUint32(hdr[4:], 0x00020006)
	binary.LittleEndian.PutUint32(hdr[24:], 1)
	// DocumentSummaryInformation FMTID, so msoleps names the properties from its own table.
	copy(hdr[28:44], []byte{
		0x02, 0xD5, 0xCD, 0xD5, 0x9C, 0x2E, 0x1B, 0x10,
		0x93, 0x97, 0x08, 0x00, 0x2B, 0x2C, 0xF9, 0xAE,
	})
	binary.LittleEndian.PutUint32(hdr[44:], 48)
	return append(hdr, set.Bytes()...)
}

// lpstrElements packs count + (length, bytes) elements with NO padding between them, which
// is how a real file stores them. See TestVectorElementsAreNotPadded.
func lpstrElements(vals []string) []byte {
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out, uint32(len(vals)))
	for _, v := range vals {
		body := append([]byte(v), 0)
		n := make([]byte, 4)
		binary.LittleEndian.PutUint32(n, uint32(len(body)))
		out = append(out, n...)
		out = append(out, body...)
	}
	return out
}

func lpwstrElements(vals []string) []byte {
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out, uint32(len(vals)))
	for _, v := range vals {
		units := append([]rune(v), 0)
		n := make([]byte, 4)
		binary.LittleEndian.PutUint32(n, uint32(len(units)))
		out = append(out, n...)
		for _, r := range units {
			b := make([]byte, 2)
			binary.LittleEndian.PutUint16(b, uint16(r))
			out = append(out, b...)
		}
	}
	return out
}

// TestVectorElementsAreNotPadded is the bug REAL files found and no hand-built fixture did.
//
// A standalone CodePageString property value is padded to a multiple of 4; the elements
// inside a vector are packed end to end. Padding each element desyncs the walk after the
// first element whose length is not a multiple of 4 — measured on poi_sampless.xls, which
// decoded 2 of 3 sheet names, and on a workbook whose first sheet is "Sheet1" (7 bytes with
// its terminator), which decoded 1 of 3. Every fixture written before that used lengths
// that happened to be multiples of 4, so all of them passed.
//
// The lengths here are 12, 15 and 7 — the exact ones from that real file.
func TestVectorElementsAreNotPadded(t *testing.T) {
	want := []string{"First Sheet", "Sheet Number 2", "Sheet3"}
	for i, w := range want {
		if got := len(w) + 1; got != []int{12, 15, 7}[i] {
			t.Fatalf("fixture drift: %q is %d bytes with its terminator, want %d — this test is "+
				"only meaningful if at least one length is NOT a multiple of 4", w, got, []int{12, 15, 7}[i])
		}
	}

	stream := vectorStream(t, olefixture.PropDocumentParts, 0x0000101E, lpstrElements(want), nil)
	got := legacyVectorStrings(stream)
	if len(got) != 1 {
		t.Fatalf("decoded %d vector properties, want 1: %+v", len(got), got)
	}
	for _, v := range got {
		if len(v.Elements) != len(want) {
			t.Fatalf("decoded %d elements, want %d: %q (truncated=%d)",
				len(v.Elements), len(want), v.Elements, v.Truncated)
		}
		for i := range want {
			if v.Elements[i] != want[i] {
				t.Errorf("element %d = %q, want %q", i, v.Elements[i], want[i])
			}
		}
		if v.Truncated != 0 {
			t.Errorf("Truncated = %d on a complete 3-element vector; a spurious truncation note "+
				"tells an operator the scan was cut short when it was not", v.Truncated)
		}
	}
}

// TestEveryStringVectorTypeDecodes covers the three base types that carry text.
func TestEveryStringVectorTypeDecodes(t *testing.T) {
	cases := []struct {
		name     string
		typeWord uint32
		payload  []byte
		want     []string
	}{
		{"VT_LPSTR", 0x0000101E, lpstrElements([]string{"Payroll", "Q3 Forecast"}), []string{"Payroll", "Q3 Forecast"}},
		{"VT_LPWSTR", 0x0000101F, lpwstrElements([]string{"Zusammenfassung", "Données"}), []string{"Zusammenfassung", "Données"}},
		{"VT_BSTR", 0x00001008, lpstrElements([]string{"Summary", "Detail"}), []string{"Summary", "Detail"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := legacyVectorStrings(vectorStream(t, olefixture.PropDocumentParts, c.typeWord, c.payload, nil))
			if len(got) != 1 {
				t.Fatalf("decoded %d properties, want 1", len(got))
			}
			for _, v := range got {
				if strings.Join(v.Elements, "|") != strings.Join(c.want, "|") {
					t.Errorf("elements = %q, want %q", v.Elements, c.want)
				}
			}
		})
	}
}

// TestANonTextVectorIsIgnored is the precision floor for the type filter. A vector of
// counts or of VT_VARIANT pairs (Heading pair) is structure, not content; decoding it would
// put "Worksheets 3" in every workbook's report for no detection value.
func TestANonTextVectorIsIgnored(t *testing.T) {
	// VT_VECTOR|VT_I4: a count vector.
	payload := make([]byte, 4)
	binary.LittleEndian.PutUint32(payload, 2)
	payload = append(payload, 1, 0, 0, 0, 2, 0, 0, 0)

	if got := legacyVectorStrings(vectorStream(t, olefixture.PropDocumentParts, 0x00001003, payload, nil)); len(got) != 0 {
		t.Errorf("a VT_I4 vector was decoded as text: %+v", got)
	}
}

// TestVectorPairsWithTheRightProperty is the subtle one: the decoded values are keyed by
// INDEX into msoleps's Property slice, so anything that shifts that slice — most obviously
// the dictionary entry at id 0, which msoleps keeps as a Null rather than skipping — puts
// every value on the wrong property.
//
// A wrong pairing is worse than no fix at all: a sheet-name list would be reported as a
// company name, or a company name silently replaced by a list.
func TestVectorPairsWithTheRightProperty(t *testing.T) {
	path := writeLegacyFixture(t, "pairing.xls", []legacyCFBStream{
		{Name: "Workbook", Data: []byte("Body text long enough to be recovered.")},
		{Name: "\x05DocumentSummaryInformation", Data: olefixture.DocSummaryInformationWithVectors(
			// Scalars on BOTH sides of the vector's id, so an off-by-one in either
			// direction lands on a mapped field and is visible.
			map[uint32]string{
				olefixture.PropCategory: "Quarterly",          // id 0x02
				olefixture.PropManager:  "Dana Whitfield",     // id 0x0E
				olefixture.PropCompany:  "Fairbanks Holdings", // id 0x0F
			},
			map[uint32][]string{
				olefixture.PropDocumentParts: {"Sheet1", "Payroll SSN 452-11-9384"}, // id 0x0D
			},
		)},
	})

	md, err := ExtractMetadata(path)
	if err != nil {
		t.Fatalf("ExtractMetadata: %v", err)
	}
	if md.Category != "Quarterly" {
		t.Errorf("Category = %q, want %q — a scalar before the vector was corrupted", md.Category, "Quarterly")
	}
	if md.Manager != "Dana Whitfield" {
		t.Errorf("Manager = %q, want %q — a scalar after the vector was corrupted", md.Manager, "Dana Whitfield")
	}
	if md.Company != "Fairbanks Holdings" {
		t.Errorf("Company = %q, want %q", md.Company, "Fairbanks Holdings")
	}
	if got := md.Properties["DocumentParts_2"]; got != "Payroll SSN 452-11-9384" {
		t.Errorf("DocumentParts_2 = %q, want the second sheet name; the vector paired with the "+
			"wrong property or was not decoded at all.\nProperties: %#v", got, md.Properties)
	}
}

// TestVectorPairsPastADictionaryEntry is the other half of the pairing, and it is the one a
// fixture without a dictionary cannot see.
//
// A user-defined property set carries its DICTIONARY at property id 0. msoleps still creates a
// Property for it — a Null, not a skip — so the index this decoder pairs against advances for
// it. A decoder that skipped id 0 without advancing would hand every value to the property
// before it: the sheet-name list would be reported as whatever the next property is, and that
// property's real value would be replaced. Measured as a surviving mutation before this test
// existed.
func TestVectorPairsPastADictionaryEntry(t *testing.T) {
	want := []string{"First Sheet", "Payroll SSN 452-11-9384"}
	stream := vectorStreamWithDict(t, olefixture.PropDocumentParts, 0x0000101E,
		lpstrElements(want), map[uint32]string{olefixture.PropCompany: "Fairbanks Holdings"}, true)

	md := &Metadata{}
	applyLegacyProperties(stream, md)

	if md.Company != "Fairbanks Holdings" {
		t.Errorf("Company = %q, want %q — the value landed on the wrong property, which means "+
			"the dictionary entry shifted the pairing", md.Company, "Fairbanks Holdings")
	}
	if got := md.Properties["DocumentParts_2"]; got != want[1] {
		t.Errorf("DocumentParts_2 = %q, want %q.\nProperties: %#v", got, want[1], md.Properties)
	}
}

// TestSheetNamesDoNotBecomeCustomProperties is the PRECISION floor, and it exists because
// the obvious implementation fails it.
//
// The metadata validator types any field named "Custom_*" as CUSTOM_PROPERTY and reports
// it — by design, since a custom property is an author-named leak channel. A sheet-name
// list is not that. Measured with the elements routed through CustomProps: an ordinary
// 12-sheet workbook went from 1 finding to 13, twelve of them CUSTOM_PROPERTY at MEDIUM on
// values like "Sheet1", "Q4" and "Chart1", all at the default confidence. A finding per
// sheet in every legacy workbook is what teaches an operator to stop reading findings.
func TestSheetNamesDoNotBecomeCustomProperties(t *testing.T) {
	path := writeLegacyFixture(t, "ordinary.xls", []legacyCFBStream{
		{Name: "Workbook", Data: []byte("Body text long enough to be recovered.")},
		{Name: "\x05DocumentSummaryInformation", Data: olefixture.DocSummaryInformationWithVectors(
			map[uint32]string{olefixture.PropCompany: "Contoso Ltd"},
			map[uint32][]string{olefixture.PropDocumentParts: {
				"Sheet1", "Sheet2", "Sheet3", "Summary", "Data", "Pivot",
			}},
		)},
	})

	md, err := ExtractMetadata(path)
	if err != nil {
		t.Fatalf("ExtractMetadata: %v", err)
	}
	for name := range md.CustomProps {
		if strings.Contains(strings.ToLower(name), "document") || strings.Contains(name, "Sheet") {
			t.Errorf("CustomProps[%q] exists; a part-name list routed through custom properties "+
				"makes the metadata validator report one CUSTOM_PROPERTY finding per sheet",
				name)
		}
	}
	// ...and it must still be SCANNABLE, or the fix removes the leak by hiding the values.
	if md.Properties["DocumentParts_1"] != "Sheet1" {
		t.Errorf("DocumentParts_1 = %q, want %q: the values still have to reach the validators "+
			"as text", md.Properties["DocumentParts_1"], "Sheet1")
	}
}

// TestVectorValuedKeywordsLandInTheMappedField covers the other arm: a property that maps
// to a single scalar field has nowhere to put a list, so those are joined.
func TestVectorValuedKeywordsLandInTheMappedField(t *testing.T) {
	const propKeywords = 0x00000005
	path := writeLegacyFixture(t, "keywords.doc", []legacyCFBStream{
		{Name: "WordDocument", Data: []byte("Body text long enough to be recovered.")},
		{Name: "\x05SummaryInformation", Data: olefixture.SummaryInformationWithVectors(
			map[uint32]string{olefixture.PropAuthor: "Dana Whitfield"},
			map[uint32][]string{propKeywords: {"confidential", "acme-project", "SSN 452-11-9384"}},
		)},
	})

	md, err := ExtractMetadata(path)
	if err != nil {
		t.Fatalf("ExtractMetadata: %v", err)
	}
	for _, want := range []string{"confidential", "acme-project", "452-11-9384"} {
		if !strings.Contains(md.Keywords, want) {
			t.Errorf("Keywords = %q, want it to contain %q", md.Keywords, want)
		}
	}
	if md.Author != "Dana Whitfield" {
		t.Errorf("Author = %q; the scalar sibling was corrupted", md.Author)
	}
}

// TestHostileVectorInputIsBounded covers the shapes a crafted container takes. None may
// panic, and none may produce a value outside the buffer it came from.
func TestHostileVectorInputIsBounded(t *testing.T) {
	huge := make([]byte, 4)
	binary.LittleEndian.PutUint32(huge, 0xFFFFFFF0) // a count larger than any real file

	truncated := lpstrElements([]string{"Sheet1", "Sheet2"})
	truncated = truncated[:len(truncated)-4] // cut the last element short

	lying := make([]byte, 4)
	binary.LittleEndian.PutUint32(lying, 1)
	lyingLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(lyingLen, 0x7FFFFFFF) // one element claiming 2GB
	lying = append(lying, lyingLen...)
	lying = append(lying, []byte("Sheet1\x00")...)

	// A lying count must be REJECTED against the bytes present before it is used, not walked
	// until a bounds check happens to trip. The difference is observable at this level:
	// rejecting it reports nothing truncated, while walking it reports the whole capped run
	// as truncated — and a truncation note on a stream that never held an element is a false
	// statement about coverage.
	//
	// Called on the payload directly so the count sits at offset 0. An earlier version of
	// this assertion computed an offset by hand, got it wrong, and passed whether the bound
	// was present or not.
	if elems, trunc := decodeStringVector(huge, 0, vtLPSTR); len(elems) != 0 || trunc != 0 {
		t.Errorf("a count of 0xFFFFFFF0 over a 4-byte payload produced %d elements and "+
			"truncated=%d, want 0 and 0", len(elems), trunc)
	}

	cases := map[string][]byte{
		"count larger than the buffer":  huge,
		"declared 2GB element":          lying,
		"element cut short":             truncated,
		"zero elements":                 {0, 0, 0, 0},
		"empty payload":                 {},
		"one byte":                      {0},
		"count with no elements at all": {9, 0, 0, 0},
	}
	for name, payload := range cases {
		stream := vectorStream(t, olefixture.PropDocumentParts, 0x0000101E, payload, nil)
		got := legacyVectorStrings(stream)
		for _, v := range got {
			for _, e := range v.Elements {
				if len(e) > len(stream) {
					t.Errorf("%s: decoded a %d-byte element from a %d-byte stream",
						name, len(e), len(stream))
				}
			}
			if v.Truncated < 0 {
				t.Errorf("%s: Truncated = %d", name, v.Truncated)
			}
		}
	}

	// And a malformed HEADER must not walk off the end either.
	for name, stream := range map[string][]byte{
		"short header":      {0xFE, 0xFF},
		"set count of 2^32": append(make([]byte, 24), 0xFF, 0xFF, 0xFF, 0xFF),
		"set offset past end": func() []byte {
			s := make([]byte, 48)
			binary.LittleEndian.PutUint32(s[24:], 1)
			binary.LittleEndian.PutUint32(s[44:], 0xFFFFFF00)
			return s
		}(),
	} {
		if got := legacyVectorStrings(stream); len(got) != 0 {
			t.Errorf("%s: decoded %d properties from a malformed stream", name, len(got))
		}
	}
}

// TestVectorElementCapIsDisclosed pins that a truncation says so. A reader who cannot tell
// a short list from a truncated one cannot tell whether the scan covered the document —
// the same reasoning as every other cap in this tool.
func TestVectorElementCapIsDisclosed(t *testing.T) {
	many := make([]string, maxVectorElements+7)
	for i := range many {
		many[i] = "Sheet" + itoa(i+1)
	}
	got := legacyVectorStrings(vectorStream(t, olefixture.PropDocumentParts, 0x0000101E, lpstrElements(many), nil))
	if len(got) != 1 {
		t.Fatalf("decoded %d properties, want 1", len(got))
	}
	for _, v := range got {
		if len(v.Elements) != maxVectorElements {
			t.Errorf("decoded %d elements, want the cap of %d", len(v.Elements), maxVectorElements)
		}
		if v.Truncated != 7 {
			t.Errorf("Truncated = %d, want 7 — the count of what was dropped is what makes the "+
				"cap honest", v.Truncated)
		}
	}

	md := &Metadata{}
	handleVectorProperty(md, "Document parts", vectorProperty{Elements: []string{"Sheet1"}, Truncated: 7})
	note := md.Properties["DocumentParts_truncated"]
	if !strings.Contains(note, "7 further value") {
		t.Errorf("truncation note = %q, want it to state how many values were dropped", note)
	}
}

// TestMsolepsStillCannotReadARealVector documents WHY this decoder exists, so a future
// dependency bump does not leave dead code nobody dares delete.
//
// If msoleps ever reads the vector flag from the correct half of the type word, this test
// fails and the decoder can be reconsidered. Until then, a real vector reaches our code as
// the scalar I1(0) whose String() is "0" — which is also why #267's proposed
// types.Vector type switch could never have worked.
func TestMsolepsStillCannotReadARealVector(t *testing.T) {
	stream := vectorStream(t, olefixture.PropDocumentParts, 0x0000101E,
		lpstrElements([]string{"Sheet1", "Payroll SSN 452-11-9384"}), nil)

	md := &Metadata{}
	applyLegacyProperties(stream, md)
	// The decoder is what recovers it; this asserts the recovery happened rather than the
	// dependency having started to work.
	if md.Properties["DocumentParts_2"] != "Payroll SSN 452-11-9384" {
		t.Fatalf("DocumentParts_2 = %q, want the decoded element", md.Properties["DocumentParts_2"])
	}
	// And the literal "0" msoleps produces must never reach a field.
	for k, v := range md.Properties {
		if v == "0" {
			t.Errorf("Properties[%q] == \"0\": that is msoleps's I1(0) for a type it could not "+
				"read, not a value from the document", k)
		}
	}
	for k, v := range md.CustomProps {
		if v == "0" {
			t.Errorf("CustomProps[%q] == \"0\": see above", k)
		}
	}
}

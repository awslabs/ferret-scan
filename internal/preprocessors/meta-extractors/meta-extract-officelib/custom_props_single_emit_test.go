// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractofficelib

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A custom property must be recorded ONCE.
//
// extractOfficeMetadata used to store every custom property in CustomProps AND mirror it
// into Properties under a "Custom_" prefix, described as "for easy scanning". The office
// preprocessor renders both maps — the dedicated "--- Custom Properties ---" block from
// CustomProps, then FormatPropertiesMap over Properties — and both lines carry the
// custom_ prefix the validator types on, so every custom property was reported TWICE.
//
// Measured on a real corpus of 304 .docx files: 506 CUSTOM_PROPERTY findings across 202
// files, ZERO files with an odd count, every (file, confidence) bucket even. A synthetic
// one-property fixture produced 2 findings.
//
// The existing dedup cannot catch this: per #202 its key is the BYTE SPAN, and the two
// rendered lines occupy genuinely different spans, so they are correctly treated as two
// occurrences of duplicated input. The fix belongs at the point the value was written
// into two maps. See #308.

func TestCustomPropertyIsRecordedOnce(t *testing.T) {
	path := writeDocxWithCustomProps(t, map[string]string{
		"ProjectCode": "PROJECT-ALPHA-7",
	})

	got, err := ExtractMetadata(path)
	if err != nil {
		t.Fatalf("extraction failed: %v", err)
	}

	if len(got.CustomProps) != 1 {
		t.Errorf("CustomProps has %d entries, want 1: %v", len(got.CustomProps), got.CustomProps)
	}
	if got.CustomProps["ProjectCode"] != "PROJECT-ALPHA-7" {
		t.Errorf("CustomProps[ProjectCode] = %q, want the extracted value",
			got.CustomProps["ProjectCode"])
	}

	// The mirror must be gone. Counting Custom_-prefixed keys rather than asserting a
	// specific one, so a differently-named mirror is caught too.
	var mirrored []string
	for k := range got.Properties {
		if strings.HasPrefix(k, "Custom_") {
			mirrored = append(mirrored, k)
		}
	}
	if len(mirrored) != 0 {
		t.Errorf("Properties still mirrors %d custom propert(ies) under a Custom_ prefix: %v\n"+
			"The office preprocessor renders BOTH maps, so each mirrored entry becomes a "+
			"second identical finding.", len(mirrored), mirrored)
	}
}

// TestManyCustomPropertiesAreEachRecordedOnce — the count is what matters.
//
// An existence-only assertion ("a finding was produced") passes just as well when every
// property is duplicated, which is exactly how this shipped.
func TestManyCustomPropertiesAreEachRecordedOnce(t *testing.T) {
	props := map[string]string{
		"ProjectCode":       "PROJECT-ALPHA-7",
		"EmployeeSSN":       "452-11-9384",
		"ContentTypeId":     "0x0101002A3B4C",
		"ComplianceAssetId": "abc-123",
		"Classification":    "CONFIDENTIAL",
	}
	path := writeDocxWithCustomProps(t, props)

	got, err := ExtractMetadata(path)
	if err != nil {
		t.Fatalf("extraction failed: %v", err)
	}

	if len(got.CustomProps) != len(props) {
		t.Errorf("CustomProps has %d entries, want %d", len(got.CustomProps), len(props))
	}
	for k, want := range props {
		if got.CustomProps[k] != want {
			t.Errorf("CustomProps[%q] = %q, want %q", k, got.CustomProps[k], want)
		}
	}

	// Total renderable custom entries across BOTH maps must equal the property count.
	// This is the assertion that actually fails on the duplicated shape: it would be
	// 2 * len(props).
	total := len(got.CustomProps)
	for k := range got.Properties {
		if strings.HasPrefix(k, "Custom_") {
			total++
		}
	}
	if total != len(props) {
		t.Errorf("%d renderable custom entries across CustomProps+Properties, want %d. "+
			"Each surplus entry becomes a duplicate finding.", total, len(props))
	}
}

// writeDocxWithCustomProps builds a minimal OOXML package carrying docProps/custom.xml.
func writeDocxWithCustomProps(t *testing.T, props map[string]string) string {
	t.Helper()

	const contentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
		`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
		`<Default Extension="xml" ContentType="application/xml"/>` +
		`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
		`<Override PartName="/docProps/custom.xml" ContentType="application/vnd.openxmlformats-officedocument.custom-properties+xml"/>` +
		`</Types>`

	const rels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
		`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>` +
		`<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/custom-properties" Target="docProps/custom.xml"/>` +
		`</Relationships>`

	const doc = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` +
		`<w:body><w:p><w:r><w:t>Body text.</w:t></w:r></w:p></w:body></w:document>`

	// Sorted keys so the fixture bytes are reproducible regardless of map order.
	names := make([]string, 0, len(props))
	for k := range props {
		names = append(names, k)
	}
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j] < names[j-1]; j-- {
			names[j], names[j-1] = names[j-1], names[j]
		}
	}

	var custom strings.Builder
	custom.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties" ` +
		`xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">`)
	for i, name := range names {
		custom.WriteString(`<property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="`)
		custom.WriteString(itoaSmall(i + 2))
		custom.WriteString(`" name="` + name + `"><vt:lpwstr>` + props[name] + `</vt:lpwstr></property>`)
	}
	custom.WriteString(`</Properties>`)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range []struct{ name, body string }{
		{"[Content_Types].xml", contentTypes},
		{"_rels/.rels", rels},
		{"word/document.xml", doc},
		{"docProps/custom.xml", custom.String()},
	} {
		w, err := zw.Create(e.name)
		if err != nil {
			t.Fatalf("creating %s: %v", e.name, err)
		}
		if _, err := w.Write([]byte(e.body)); err != nil {
			t.Fatalf("writing %s: %v", e.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "customprops.docx")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func itoaSmall(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

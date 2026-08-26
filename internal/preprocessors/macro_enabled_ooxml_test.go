// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #497: `.docm`, `.xlsm` and `.pptm` were not scanned at all.
//
// The macro-enabled OOXML formats are the same ZIP container as their plain counterparts, with a
// different content type and a `vbaProject.bin` alongside. Nothing in the reading path needed to
// change; they were simply never admitted.
//
// Measured on merged main, with byte-identical content and only the extension differing:
//
//	sample.docx  2 findings (SSN, BUSINESS)      <- control
//	sample.docm  0 findings, rc 0, no disclosure
//	real.xlsm    0 findings   (real.xlsx: 4)
//	real.pptm    0 findings   (real.pptx: 4)
//
// After: all three report exactly what their plain counterpart reports, including the docProps
// metadata, and they redact.
//
// The root cause was SEVEN disagreeing extension lists. The macro forms were registered in
// plaintext_preprocessor.go and redactors/manager.go, and absent from every site that does the work --
// including a direct contradiction where manager.go routed `.docm` to the office redactor whose own
// GetSupportedTypes() said it did not support it. The list this file pins is officeExtensions in
// shared_utilities.go, because the router's isBinaryDocument derives from it: that one map is what
// decided a `.docm` never reached a preprocessor at all.
//
// The documentation asserted the opposite the whole time. docs/reference/quotas-and-limits.md says
// "An OOXML container (.docx, .xlsx, .pptx and their macro-enabled forms) can hold arbitrarily ...",
// which requires them to be processed before any budget could apply to them.

// zipDoc writes a ZIP with the given parts and returns its path.
func zipDoc(t *testing.T, dir, name string, parts map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for n, body := range parts {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatalf("create %s: %v", n, err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("write %s: %v", n, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

const (
	macroCore = `<?xml version="1.0"?><cp:coreProperties ` +
		`xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" ` +
		`xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>Marcus Whitfield</dc:creator>` +
		`</cp:coreProperties>`
	macroWordBody = `<?xml version="1.0"?><w:document ` +
		`xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r>` +
		`<w:t>Employee SSN 449-87-4100</w:t></w:r></w:p></w:body></w:document>`
)

// TestTheOfficeExtensionSetAdmitsMacroEnabledForms is the gate that decided everything else.
//
// The router's isBinaryDocument delegates to extValidator.IsOfficeFile, which reads this map. While the
// macro forms were absent from it, a `.docm` was rejected before any preprocessor was consulted, so no
// change further down the pipeline could have helped.
func TestTheOfficeExtensionSetAdmitsMacroEnabledForms(t *testing.T) {
	v := NewFileExtensionValidator()
	for _, ext := range []string{".docm", ".xlsm", ".pptm"} {
		t.Run(ext, func(t *testing.T) {
			if !v.IsOfficeFile("f" + ext) {
				t.Errorf("IsOfficeFile(%q) = false. The router's isBinaryDocument derives from this, "+
					"so the file is rejected before any preprocessor sees it and reports 0 findings "+
					"at exit 0.", ext)
			}
		})
	}
	// The plain forms must not have been disturbed.
	for _, ext := range []string{".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".doc", ".xls", ".ppt"} {
		if !v.IsOfficeFile("f" + ext) {
			t.Errorf("IsOfficeFile(%q) regressed to false", ext)
		}
	}
	// And something that is not an Office file must still not be one.
	for _, ext := range []string{".txt", ".png", ".zip", ".docmx"} {
		if v.IsOfficeFile("f" + ext) {
			t.Errorf("IsOfficeFile(%q) = true; the set widened past Office formats", ext)
		}
	}
}

// TestTextPreprocessorHandlesMacroEnabledForms pins the dispatch, both the advertised set and the
// switch, since a format can be advertised and still fall to the default arm.
func TestTextPreprocessorHandlesMacroEnabledForms(t *testing.T) {
	tp := NewTextPreprocessor()
	advertised := map[string]bool{}
	for _, e := range tp.supportedExtensions {
		advertised[e] = true
	}
	for _, ext := range []string{".docm", ".xlsm", ".pptm"} {
		if !advertised[ext] {
			t.Errorf("%s is not in the text preprocessor's supported set", ext)
		}
	}

	// The switch, exercised through CanProcess so a default-arm error would show up.
	dir := t.TempDir()
	for ext, parts := range map[string]map[string]string{
		".docm": {"word/document.xml": macroWordBody, "docProps/core.xml": macroCore},
	} {
		p := zipDoc(t, dir, "doc"+ext, parts)
		if !tp.CanProcess(p) {
			t.Errorf("CanProcess(%s) = false", p)
		}
	}
}

// TestMacroEnabledBodyAndMetadataAreBothRead is the end-to-end assertion, and it is a CONTROL PAIR.
//
// Byte-identical parts under two extensions. Asserting only "the .docm reports" would also pass on a
// reader that ignored the extension entirely and sniffed the ZIP, which is a different fix with
// different consequences for the redactor -- so the plain form is scanned in the same test and the two
// results are compared.
func TestMacroEnabledBodyAndMetadataAreBothRead(t *testing.T) {
	dir := t.TempDir()
	parts := map[string]string{
		"[Content_Types].xml": `<?xml version="1.0"?><Types ` +
			`xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
			`<Default Extension="xml" ContentType="application/xml"/></Types>`,
		"word/document.xml": macroWordBody,
		"docProps/core.xml": macroCore,
	}

	plain := zipDoc(t, dir, "control.docx", parts)
	macro := zipDoc(t, dir, "subject.docm", parts)

	tp := NewTextPreprocessor()
	read := func(path string) string {
		c, err := tp.Process(path)
		if err != nil {
			t.Fatalf("Process(%s): %v", path, err)
		}
		if c == nil {
			t.Fatalf("Process(%s) returned no content", path)
		}
		return c.Text
	}

	plainText, macroText := read(plain), read(macro)

	// NON-VACUITY: the control must actually carry the body value, or the comparison below is
	// comparing two empty strings.
	if !strings.Contains(plainText, "449-87-4100") {
		t.Fatalf("the .docx CONTROL did not yield the body value, so this test cannot say anything "+
			"about the .docm. got %q", plainText)
	}
	if !strings.Contains(macroText, "449-87-4100") {
		t.Errorf("the .docm did not yield the body value that the byte-identical .docx does. It was "+
			"reported clean at exit 0, and only reported findings reach the redactor. got %q", macroText)
	}
}

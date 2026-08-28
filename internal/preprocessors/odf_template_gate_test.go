// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"os"
	"strings"
	"testing"
)

// #528: the defect was the EXTENSION GATE, not the extractor.
//
// `.ott`/`.ots`/`.otp` were absent from officeExtensions, and the router's isBinaryDocument derives
// from IsOfficeFile, so a template was refused before any preprocessor was consulted. Every synthetic
// ODF test was green while all 118 real templates on this host reported 0 findings, because no
// synthetic test crossed the gate. That is why this test exists separately from the extractor's.

// odfTemplateExts are the extensions #528 adds.
var odfTemplateExts = []string{".ott", ".ots", ".otp"}

// TestTheOfficeExtensionSetAdmitsODFTemplates.
func TestTheOfficeExtensionSetAdmitsODFTemplates(t *testing.T) {
	v := NewFileExtensionValidator()
	for _, ext := range odfTemplateExts {
		t.Run(ext, func(t *testing.T) {
			if !v.IsOfficeFile("f" + ext) {
				t.Errorf("IsOfficeFile(%q) = false. The router's isBinaryDocument derives from this, so "+
					"the file is refused before any preprocessor sees it and reports 0 findings at "+
					"exit 0 — while the identical meta.xml in a .odt is reported.", ext)
			}
		})
	}
	// Nothing already admitted may regress.
	for _, ext := range []string{".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm",
		".odt", ".ods", ".odp", ".doc", ".xls", ".ppt"} {
		if !v.IsOfficeFile("f" + ext) {
			t.Errorf("IsOfficeFile(%q) regressed to false", ext)
		}
	}
	// And the set must not have widened past Office formats. `.otf` is the trap: one letter from
	// `.otp` and a FONT, which carries no ODF package at all.
	for _, ext := range []string{".txt", ".png", ".zip", ".otf", ".ottx", ".ot"} {
		if v.IsOfficeFile("f" + ext) {
			t.Errorf("IsOfficeFile(%q) = true; the set widened past Office formats", ext)
		}
	}
}

// TestTextPreprocessorHandlesODFTemplates pins BOTH halves of the dispatch.
//
// A format can be advertised in supportedExtensions and still fall to the switch's default arm, which
// returns "unsupported file extension" — claimed and then unhandled, which looks exactly like a clean
// file. That is the shape the `.3gp` work produced twice.
func TestTextPreprocessorHandlesODFTemplates(t *testing.T) {
	tp := NewTextPreprocessor()

	advertised := map[string]bool{}
	for _, e := range tp.GetSupportedExtensions() {
		advertised[strings.ToLower(e)] = true
	}
	for _, ext := range odfTemplateExts {
		if !advertised[ext] {
			t.Errorf("%s is not advertised by the text preprocessor, so the router will not select it", ext)
		}
	}

	// The switch: a template must not reach the default arm. Driven through Process on a file that
	// is not a valid package, so the error distinguishes "unsupported extension" (the default arm)
	// from any parse failure (the handled arm doing its job).
	for _, ext := range odfTemplateExts {
		t.Run(ext, func(t *testing.T) {
			dir := t.TempDir()
			path := dir + "/f" + ext
			if err := os.WriteFile(path, []byte("not a real package"), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			_, err := tp.Process(path)
			if err != nil && strings.Contains(err.Error(), "unsupported file extension") {
				t.Errorf("%s fell through to the default arm: %v. It is advertised, so the router "+
					"hands it over and then nothing handles it.", ext, err)
			}
		})
	}
}

// TestODFTemplatesAreTreatedAsContainersNotText.
//
// containerExtensions is what stops a zip-based package being sniffed as plain text. A template
// omitted there could be handed to the plain-text path, which would scan compressed bytes and report
// nothing useful while looking like a successful scan.
func TestODFTemplatesAreTreatedAsContainersNotText(t *testing.T) {
	for _, ext := range odfTemplateExts {
		if !containerExtensions[ext] {
			t.Errorf("containerExtensions[%q] = false; the package would be sniffed as plain text", ext)
		}
	}
	// The document forms must still be there too.
	for _, ext := range []string{".odt", ".ods", ".odp"} {
		if !containerExtensions[ext] {
			t.Errorf("containerExtensions[%q] regressed to false", ext)
		}
	}
}

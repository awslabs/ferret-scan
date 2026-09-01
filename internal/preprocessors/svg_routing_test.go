// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #314: THREE PLACES MUST AGREE before .svg is really handled.
//
// The rule comes from #400, where adding a video extension made the file REACH the
// preprocessor and still extract nothing, so "Status: Success, 0 findings" was
// indistinguishable from a clean file. For .svg the three are:
//
//  1. WHO CLAIMS THE EXTENSION. The router runs EVERY preprocessor that claims a file
//     and concatenates the successes, so an SVG-aware extractor is not enough on its
//     own -- the plaintext preprocessor claimed .svg on a byte sniff, and both texts
//     would have been scanned. vectorExtensions/IsVectorFile is what withdraws that
//     claim; TextPreprocessor.supportedExtensions is what takes it up.
//  2. THE PARSER. textextractsvgtextlib, reached through the `case ".svg"` in
//     TextPreprocessor.Process. Pinned in that package's own tests.
//  3. THE REDACTOR. internal/redactors/svg, pinned there.
//
// This file covers (1) and the handoff to (2). Measured before the change, on a
// 479-byte drawing carrying an SSN, an email, a name and a phone in
// <text>/<title>/<desc>: 4 findings standalone through the plaintext path, 0 when the
// same drawing was an embedded part -- and 943 findings on a 64KB SVG of pure glyph
// geometry.

const svgRoutingProse = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="600" height="200" viewBox="0 0 600 200">
  <title>Onboarding diagram for Renee Vasquez</title>
  <desc>Contact renee.vasquez@examplecorp.com before editing.</desc>
  <path d="m24 136-191v-63h-136zm587-260v401c0 41 465 0 863 76 1012 109"/>
  <text x="10" y="40">Employee SSN: 452-11-9384</text>
</svg>
`

// svgRoutingWrite drops body at dir/name and returns the path.
func svgRoutingWrite(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

// TestSVGIsClaimedByExactlyOnePreprocessor is place (1), stated as a property.
//
// EXACTLY one, not at least one. Two claimants means the router concatenates both
// texts, so the prose-only extraction would be appended to the whole raw document and
// the flood would come back with the recall fix on top of it -- the worst of both.
func TestSVGIsClaimedByExactlyOnePreprocessor(t *testing.T) {
	dir := t.TempDir()
	p := svgRoutingWrite(t, dir, "diagram.svg", svgRoutingProse)

	text := NewTextPreprocessor()
	plain := NewPlainTextPreprocessorWithConfig(false)

	if !text.CanProcess(p) {
		t.Error("the text preprocessor does not claim .svg, so nothing SVG-aware runs on it")
	}
	if plain.CanProcess(p) {
		t.Error("the plaintext preprocessor still claims .svg.\n" +
			"The router runs every claiming preprocessor and concatenates the successes, so the raw " +
			"document -- path coordinates included -- would be scanned alongside the prose. Measured " +
			"at a0e983c: 943 findings on a 64KB glyph-path SVG, 817 of them PHONE.")
	}

	// The withdrawal must come from the SHARED validator, not from a second list in
	// the plaintext preprocessor: one map decides both who owns .svg and who must not.
	if !NewFileExtensionValidator().IsVectorFile("f.svg") {
		t.Error("IsVectorFile(.svg) is false, so claimedByAnotherPreprocessor cannot withdraw the claim")
	}
	// The binary metafiles must NOT be claimed here. They have no text reader anywhere
	// in this tool, so claiming them would promise an extraction that cannot happen.
	for _, ext := range []string{".emf", ".wmf", ".wdp"} {
		if NewFileExtensionValidator().IsVectorFile("f" + ext) {
			t.Errorf("%s is claimed as a vector TEXT type; it is a binary metafile with no extractor", ext)
		}
	}
}

// TestSVGProseIsExtractedAndGeometryIsNot is the handoff to place (2), through the
// preprocessor rather than the library.
func TestSVGProseIsExtractedAndGeometryIsNot(t *testing.T) {
	dir := t.TempDir()
	p := svgRoutingWrite(t, dir, "diagram.svg", svgRoutingProse)

	got, err := NewTextPreprocessor().Process(p)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if got == nil || !got.Success {
		t.Fatalf("preprocessing did not succeed: %+v", got)
	}
	if strings.TrimSpace(got.Text) == "" {
		t.Fatal("no text extracted, so the assertions below prove nothing")
	}

	for _, prose := range []string{
		"Onboarding diagram for Renee Vasquez",
		"renee.vasquez@examplecorp.com",
		"Employee SSN: 452-11-9384",
	} {
		if !strings.Contains(got.Text, prose) {
			t.Errorf("prose %q was not extracted.\ngot:\n%s", prose, got.Text)
		}
	}
	for _, geom := range []string{"863 76 1012", "136-191", "0 0 600 200"} {
		if strings.Contains(got.Text, geom) {
			t.Errorf("geometry %q reached the extracted text; only prose may.\ngot:\n%s", geom, got.Text)
		}
	}
	if got.Format != "SVG Image" {
		t.Errorf("Format = %q, want %q", got.Format, "SVG Image")
	}
	// Position tracking must be on, or a finding has no line to point at.
	if len(got.PositionMappings) == 0 {
		t.Error("no position mappings were created, so findings would carry no locations")
	}
}

// TestGeometryOnlySVGIsCleanNotUnexamined is the disclosure polarity.
//
// A prose-less drawing is an ICON: nothing was missed, so nothing is claimed. Measured
// before the router learned to accept a parsed-but-textless result, on a well-formed
// 64KB SVG of pure path geometry:
//
//	NOT FULLY EXAMINED: 1 of 1 file - findings may be missing
//	  cannot parse (1)
//	    icon.svg  contents do not match the .svg format
//
// and exit 3 under --fail-on-incomplete. Every word of that is false, and 88 of 90 real
// .svg files measured would have produced it.
func TestGeometryOnlySVGIsCleanNotUnexamined(t *testing.T) {
	dir := t.TempDir()
	body := `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">` +
		`<path d="m24 136-191v-63h-136zm587-260v401c0 41 465 0 863 76 1012 109"/></svg>`
	p := svgRoutingWrite(t, dir, "icon.svg", body)

	got, err := NewTextPreprocessor().Process(p)
	if err != nil {
		t.Fatalf("a well-formed geometry-only SVG errored: %v", err)
	}
	if got == nil || !got.Success {
		t.Fatalf("a well-formed geometry-only SVG did not succeed: %+v", got)
	}
	if strings.TrimSpace(got.Text) != "" {
		t.Errorf("geometry reached the extracted text: %q", got.Text)
	}
	if got.ExtractionWarning != "" {
		t.Errorf("a fully-read icon claimed lost coverage: %q.\n"+
			"88 of 90 real .svg files carry no prose; a line each is how the warning that matters "+
			"becomes noise an operator filters out.", got.ExtractionWarning)
	}
	if got.ExtractionCause.Known() {
		t.Errorf("a fully-read icon stated cause %v", got.ExtractionCause)
	}
}

// TestMislabelledSVGStillScans: the withdrawal in place (1) has no fallback, so the SVG
// branch has to carry the mislabelled case itself.
//
// Measured: 2 findings for a plain text file named .svg through the plaintext
// preprocessor, and 0 once .svg routed to prose-only extraction. Losing them is a leak
// wearing a precision win.
func TestMislabelledSVGStillScans(t *testing.T) {
	dir := t.TempDir()
	raw := "Employee SSN: 452-11-9384\nrenee.vasquez@examplecorp.com\n"
	p := svgRoutingWrite(t, dir, "notreally.svg", raw)

	got, err := NewTextPreprocessor().Process(p)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if got == nil || !got.Success {
		t.Fatalf("a mislabelled .svg did not succeed: %+v", got)
	}
	if got.Text != raw {
		t.Errorf("a file named .svg that is not an SVG must be scanned as its raw bytes.\ngot:\n%q\nwant:\n%q",
			got.Text, raw)
	}
	if !strings.Contains(got.Format, "not an SVG") {
		t.Errorf("Format = %q; it must say the file is not an SVG, or an operator cannot tell "+
			"which reading was taken", got.Format)
	}
}

// TestSVGWithNoExtensionIsNotHijacked keeps the claim keyed on the extension.
//
// A .txt whose CONTENT happens to start with <svg is still a .txt, and must keep going
// to the plaintext preprocessor: prose-only extraction of it would drop everything
// outside a text node.
func TestSVGWithNoExtensionIsNotHijacked(t *testing.T) {
	dir := t.TempDir()
	p := svgRoutingWrite(t, dir, "drawing.txt", svgRoutingProse)

	if NewTextPreprocessor().CanProcess(p) {
		t.Error("the text preprocessor claimed a .txt file because its bytes look like SVG")
	}
	if !NewPlainTextPreprocessorWithConfig(false).CanProcess(p) {
		t.Error("the plaintext preprocessor stopped claiming .txt")
	}
}

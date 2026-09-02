// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package svg

import (
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// #314, the redaction half. Detection without redaction is the state #305 fixed and
// #311's policy forbids: a value REPORTED and left in the file, with the report saying
// it was handled.
//
// The bug this package exists for is subtle enough to be worth restating. The plaintext
// redactor implements RedactContent, which the worker pool PREFERS over RedactDocument,
// and RedactContent writes the PREPROCESSOR'S EXTRACTED TEXT. For a .txt that is the
// whole file. For an .svg it is prose nodes only. Measured on a 479-byte drawing routed
// to the plaintext redactor, all three strategies:
//
//	Onboarding diagram for [PERSON-NAME-REDACTED]
//	Contact the owner at [EMAIL-REDACTED] before editing.
//	Employee SSN: [SSN-REDACTED]
//	Desk phone:
//	+1 [PHONE-REDACTED]
//
// No <svg> element, no geometry, 5 lines where the file had 8. Every value gone and so
// was the drawing. This redactor writes the FILE.

const svgRedactBody = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="600" height="200" viewBox="0 0 600 200">
  <title>Onboarding diagram for Renee Vasquez</title>
  <desc>Contact the owner at renee.vasquez@examplecorp.com before editing.</desc>
  <path d="M32.6982,23.9008 C33.0592,24.3698 32.0078 31.3992 43.5968 15.4721"/>
  <text x="10" y="40">Employee SSN: 452-11-9384</text>
  <text x="10" y="70">Desk phone: <tspan>+1 (202) 555-0143</tspan></text>
</svg>
`

// svgRedactValues are the reported values that must not survive.
var svgRedactValues = []struct{ typ, text string }{
	{"SSN", "452-11-9384"},
	{"BUSINESS", "renee.vasquez@examplecorp.com"},
	{"PERSON_NAME", "Renee Vasquez"},
	{"PHONE", "(202) 555-0143"},
}

// svgRedactKeep is the POSITIVE CONTROL: strings that must SURVIVE.
//
// Without it "no leak" is satisfied by an empty file, by a deleted file, and by the
// prose-only output this package exists to prevent -- all three of which are worse
// than the leak.
var svgRedactKeep = []string{
	`<svg`,
	`viewBox="0 0 600 200"`,
	"Onboarding diagram for",
	`M32.6982,23.9008`,
	"Desk phone:",
	`</svg>`,
}

func svgRedactMatches() []detector.Match {
	var out []detector.Match
	for _, v := range svgRedactValues {
		out = append(out, detector.Match{
			Type:       v.typ,
			Text:       v.text,
			Confidence: 90,
			LineNumber: 1,
		})
	}
	return out
}

// svgRedactFixture writes body and returns (inputPath, outputPath).
func svgRedactFixture(t *testing.T, body string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	in := filepath.Join(dir, "diagram.svg")
	if err := os.WriteFile(in, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return in, filepath.Join(dir, "out", "diagram.svg")
}

// svgRedactWellFormed reports whether data parses as XML end to end.
func svgRedactWellFormed(t *testing.T, data []byte) error {
	t.Helper()
	dec := xml.NewDecoder(strings.NewReader(string(data)))
	for {
		if _, err := dec.Token(); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// TestAllThreeStrategiesRemoveEveryValueAndKeepTheDrawing is the sink assertion.
func TestAllThreeStrategiesRemoveEveryValueAndKeepTheDrawing(t *testing.T) {
	for _, strategy := range []redactors.RedactionStrategy{
		redactors.RedactionSimple,
		redactors.RedactionFormatPreserving,
		redactors.RedactionSynthetic,
	} {
		t.Run(strategy.String(), func(t *testing.T) {
			in, out := svgRedactFixture(t, svgRedactBody)
			if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
				t.Fatalf("mkdir: %v", err)
			}

			res, err := NewSVGRedactor(nil, nil).RedactDocument(in, out, svgRedactMatches(), strategy)
			if err != nil {
				t.Fatalf("redaction failed: %v", err)
			}
			if res == nil || !res.Success {
				t.Fatalf("redaction reported failure: %+v", res)
			}

			// ASSERT THE FILE EXISTS before grepping it. A missing file greps clean.
			data, err := os.ReadFile(out)
			if err != nil {
				t.Fatalf("no output file to check: %v", err)
			}
			if len(data) == 0 {
				t.Fatal("the output file is empty, so every leak check below is vacuous")
			}

			// POSITIVE CONTROL first.
			for _, keep := range svgRedactKeep {
				if !strings.Contains(string(data), keep) {
					t.Errorf("the drawing was destroyed: %q is gone.\n"+
						"An output with no <svg> element passes the leak check and is still data loss.\ngot:\n%s",
						keep, data)
				}
			}
			// Then the leaks.
			for _, v := range svgRedactValues {
				if strings.Contains(string(data), v.text) {
					t.Errorf("%s survived redaction in cleartext.\ngot:\n%s", v.typ, data)
				}
			}
			if err := svgRedactWellFormed(t, data); err != nil {
				t.Errorf("the redacted drawing no longer parses as XML: %v\ngot:\n%s", err, data)
			}
			// The geometry must be BYTE-IDENTICAL: a redactor that touches a part
			// holding none of the reported values is vandalising the document.
			if !strings.Contains(string(data), `<path d="M32.6982,23.9008 C33.0592,24.3698 32.0078 31.3992 43.5968 15.4721"/>`) {
				t.Errorf("the path element was modified; nothing in it was ever reported.\ngot:\n%s", data)
			}
		})
	}
}

// TestSyntheticIsRandomPerRun is the positive control for the byte-comparison method
// itself.
//
// synthetic picks fresh fake values every run, so a byte A/B of two synthetic outputs
// proves nothing about correctness -- and equally, a test that ASSERTED byte equality
// would be asserting the randomness away. Both halves are checked: the outputs differ,
// and both are leak-free.
func TestSyntheticIsRandomPerRun(t *testing.T) {
	var outputs [][]byte
	for i := 0; i < 2; i++ {
		in, out := svgRedactFixture(t, svgRedactBody)
		if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if _, err := NewSVGRedactor(nil, nil).RedactDocument(
			in, out, svgRedactMatches(), redactors.RedactionSynthetic); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("run %d: no output: %v", i, err)
		}
		for _, v := range svgRedactValues {
			if strings.Contains(string(data), v.text) {
				t.Errorf("run %d: %s survived", i, v.typ)
			}
		}
		outputs = append(outputs, data)
	}
	if string(outputs[0]) == string(outputs[1]) {
		t.Error("two synthetic runs produced identical bytes.\n" +
			"If that is now true, a byte A/B is a valid method here and the comment in this " +
			"package explaining why it is not must be corrected.")
	}
}

// TestXMLEscapedValueIsRemoved: a value stored in XML character data is escaped, so the
// literal from a Match need not occur in the file.
//
// Without escapedForFile the inner redactor searches for the literal, finds nothing,
// skips the match and reports success -- the value stays in cleartext with the run
// exiting 0. Same leak class as the OOXML one.
func TestXMLEscapedValueIsRemoved(t *testing.T) {
	const secret = "wJalrXUtnFEMI/K7MDENG&bPxRfiCYEXAMPLEKEY"
	body := `<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 600 120">` + "\n" +
		`  <path d="M32.6982,23.9008"/>` + "\n" +
		`  <text x="10" y="40">aws_secret_access_key = wJalrXUtnFEMI/K7MDENG&amp;bPxRfiCYEXAMPLEKEY</text>` + "\n" +
		`</svg>` + "\n"

	in, out := svgRedactFixture(t, body)
	if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	matches := []detector.Match{{Type: "API_KEY_OR_SECRET", Text: secret, Confidence: 75, LineNumber: 1}}

	if _, err := NewSVGRedactor(nil, nil).RedactDocument(
		in, out, matches, redactors.RedactionSimple); err != nil {
		t.Fatalf("redaction failed: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("no output file: %v", err)
	}
	// POSITIVE CONTROL.
	if !strings.Contains(string(data), "<svg") || !strings.Contains(string(data), "aws_secret_access_key") {
		t.Fatalf("the drawing was destroyed, so the leak check is vacuous:\n%s", data)
	}
	// The ESCAPED spelling is what is actually in the file, so that is what must be gone.
	if strings.Contains(string(data), "wJalrXUtnFEMI/K7MDENG&amp;bPxRfiCYEXAMPLEKEY") {
		t.Errorf("the escaped spelling of the value survived.\ngot:\n%s", data)
	}
	if strings.Contains(string(data), secret) {
		t.Errorf("the literal value survived.\ngot:\n%s", data)
	}
	if err := svgRedactWellFormed(t, data); err != nil {
		t.Errorf("output does not parse: %v\n%s", err, data)
	}
}

// TestNumericCharacterReferenceIsRefusedNotShipped is the loud-refusal half.
//
// A value written with numeric character references is REPORTED (the extractor decodes
// it, so the validator sees the real SSN) and occurs literally nowhere in the file, so
// no byte substitution can remove it. The spellings are unbounded (&#56; &#x38;
// &#0056;) so they cannot be enumerated the way the five predefined entities can.
//
// Measured before the decoded residue check, on `<text>Employee SSN: 452-11-93&#56;4</text>`:
// 1 SSN at HIGH 100, a redacted copy written, byte-identical to the input, exit 0. That
// is the worst outcome available. It is now a refusal, disclosed as
// "VALUES LEFT IN CLEARTEXT" with exit 3 under --fail-on-incomplete.
func TestNumericCharacterReferenceIsRefusedNotShipped(t *testing.T) {
	body := `<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		`<svg xmlns="http://www.w3.org/2000/svg"><text>Employee SSN: 452-11-93&#56;4</text></svg>` + "\n"
	in, out := svgRedactFixture(t, body)
	if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	matches := []detector.Match{{Type: "SSN", Text: "452-11-9384", Confidence: 100, LineNumber: 1}}

	res, err := NewSVGRedactor(nil, nil).RedactDocument(in, out, matches, redactors.RedactionSimple)
	if err == nil {
		data, _ := os.ReadFile(out)
		t.Fatalf("redaction reported SUCCESS over a value it did not remove: %+v\noutput:\n%s", res, data)
	}
	if !strings.Contains(err.Error(), "SSN") {
		t.Errorf("the refusal does not name the TYPE that survived: %v", err)
	}
	// BSC4: the message reaches the operator, so it must not republish the value.
	if strings.Contains(err.Error(), "452-11-9384") {
		t.Errorf("the refusal message leaks the value it is refusing to leak: %v", err)
	}
	// No file, rather than a file an operator will read as redacted.
	if _, statErr := os.Stat(out); statErr == nil {
		t.Error("a file was left behind that still holds the reported value")
	}
}

// TestRegisteredSupportedTypes is place (3) of the three-places rule.
func TestRegisteredSupportedTypes(t *testing.T) {
	r := NewSVGRedactor(nil, nil)

	types := r.GetSupportedTypes()
	if len(types) != 1 || types[0] != ".svg" {
		t.Errorf("GetSupportedTypes() = %v, want exactly [.svg]", types)
	}
	// .emf/.wmf/.wdp must NOT be claimed: they have no text extractor, so nothing
	// reports a value in them and claiming them would promise a redaction that
	// cannot happen. See embedded.SkipTextPipeline.
	for _, ext := range types {
		for _, bad := range []string{".emf", ".wmf", ".wdp"} {
			if ext == bad {
				t.Errorf("%s is claimed; it is a binary metafile with no extractor", bad)
			}
		}
	}

	if got := len(r.GetSupportedStrategies()); got != 3 {
		t.Errorf("GetSupportedStrategies() returned %d strategies, want 3", got)
	}
	if r.GetName() != "svg_redactor" {
		t.Errorf("GetName() = %q", r.GetName())
	}

	// The whole reason this type exists: it must NOT satisfy the content-redaction
	// interface, because the worker pool prefers it and it would write the lossy
	// extracted text.
	if _, ok := interface{}(r).(redactors.ContentRedactor); ok {
		t.Error("SVGRedactor implements ContentRedactor.\n" +
			"parallel/worker_pool.go performInlineRedaction prefers RedactContent, which writes the " +
			"PREPROCESSOR'S extracted text -- prose nodes only for an SVG. That is how a 479-byte " +
			"drawing came back as 5 lines of prose with no <svg> element.")
	}
	// And it must satisfy the plain one, or nothing dispatches to it at all.
	if _, ok := interface{}(r).(redactors.Redactor); !ok {
		t.Error("SVGRedactor does not satisfy redactors.Redactor, so it cannot be registered")
	}
}

// TestNoMatchesLeavesTheFileAlone: a drawing holding nothing reported must come back
// unchanged. Every redactor here is lossy in some way, and degrading content that was
// never implicated is the failure the office redactor's dispatch gate exists to avoid.
func TestNoMatchesLeavesTheFileAlone(t *testing.T) {
	in, out := svgRedactFixture(t, svgRedactBody)
	if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := NewSVGRedactor(nil, nil).RedactDocument(
		in, out, nil, redactors.RedactionSimple); err != nil {
		t.Fatalf("redaction with no matches failed: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("no output: %v", err)
	}
	if string(got) != svgRedactBody {
		t.Errorf("a drawing with nothing reported was modified.\ngot:\n%s\nwant:\n%s", got, svgRedactBody)
	}
}

// TestMalformedInputIsStillRedactable: the well-formedness gate is conditioned on the
// INPUT having parsed, so a malformed source drawing is not refused for a defect it
// arrived with.
func TestMalformedInputIsStillRedactable(t *testing.T) {
	body := `<svg xmlns="http://www.w3.org/2000/svg"><text>Employee SSN: 452-11-9384</text><g><text>x`
	in, out := svgRedactFixture(t, body)
	if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	matches := []detector.Match{{Type: "SSN", Text: "452-11-9384", Confidence: 100, LineNumber: 1}}

	if _, err := NewSVGRedactor(nil, nil).RedactDocument(
		in, out, matches, redactors.RedactionSimple); err != nil {
		t.Fatalf("a malformed but redactable drawing was refused: %v", err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("no output: %v", err)
	}
	if strings.Contains(string(data), "452-11-9384") {
		t.Errorf("the value survived:\n%s", data)
	}
	if !strings.Contains(string(data), "<svg") {
		t.Errorf("the drawing was destroyed:\n%s", data)
	}
}

// TestDecodedRenderingSeesThroughEscapes pins the helper the residue check depends on.
func TestDecodedRenderingSeesThroughEscapes(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"numeric decimal", `<svg><text>452-11-93&#56;4</text></svg>`, "452-11-9384"},
		{"numeric hex", `<svg><text>452-11-93&#x38;4</text></svg>`, "452-11-9384"},
		{"predefined entity", `<svg><text>a&amp;b</text></svg>`, "a&b"},
		{"attribute value", `<svg><g aria-label="452-11-93&#56;4"/></svg>`, "452-11-9384"},
		{"comment", `<svg><!-- 452-11-9384 --></svg>`, "452-11-9384"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := decodedRendering([]byte(tc.body)); !strings.Contains(got, tc.want) {
				t.Errorf("decodedRendering did not surface %q; residue would go unseen.\ngot: %q", tc.want, got)
			}
		})
	}
}

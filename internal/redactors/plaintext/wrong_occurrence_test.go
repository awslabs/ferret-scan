// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package plaintext

import (
	"bytes"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// The value used throughout: a Luhn-valid VISA test number whose trailing groups also parse as a
// phone number, which is what makes one reported value a substring of another.
const (
	wrongOccCard  = "4532 0151 1283 0366"
	wrongOccPhone = "0151 1283 0366" // a substring of wrongOccCard
)

func allStrategies() []redactors.RedactionStrategy {
	return []redactors.RedactionStrategy{
		redactors.RedactionSimple,
		redactors.RedactionFormatPreserving,
		redactors.RedactionSynthetic,
	}
}

// wrongOccMatches builds the match set the scanner really produces for the two-line fixture.
//
// Context.FullLine MUST be populated. detector.ResolveLineSpans keys on (line number, FullLine) to
// assign each match to a concrete occurrence within its line, and redactors.ResolveOverlaps uses those
// spans to drop a match contained in a wider one. With FullLine empty nothing is dropped, all three
// matches survive, and a third replacement then covers the line the leak is on BY ACCIDENT — so the
// test passes against the unfixed code and proves nothing. That is how the first version of this test
// was written, and reverting the production change is what exposed it.
func wrongOccMatches(content string) []detector.Match {
	lines := strings.Split(content, "\n")
	return []detector.Match{
		{
			Text: wrongOccCard, Type: "VISA", LineNumber: 1, Confidence: 100, Validator: "creditcard",
			Context: detector.ContextInfo{FullLine: lines[0]},
		},
		{
			// The occurrence INSIDE the card: contained, so ResolveOverlaps drops it.
			Text: wrongOccPhone, Type: "PHONE", LineNumber: 1, Confidence: 25, Validator: "phone",
			Context: detector.ContextInfo{FullLine: lines[0]},
		},
		{
			// The standalone occurrence, reported at the highest confidence in the file.
			Text: wrongOccPhone, Type: "PHONE", LineNumber: 2, Confidence: 100, Validator: "phone",
			Context: detector.ContextInfo{FullLine: lines[1]},
		},
	}
}

// TestReportedValueOnALaterLineIsRedacted is the regression test for #519.
//
// A value reported at two positions, where the FIRST position sits inside a longer reported match,
// was resolved by a document-wide search that always returns the first occurrence. So both reports
// redacted the same occurrence and the second one — reported at HIGH confidence — was never
// rewritten. Measured before the fix on exactly this shape: line 2 came back byte-identical to the
// input, at exit 0, with Success true and no disclosure.
//
// Only reported findings reach the redactor, so a value it skips is left in cleartext with nothing
// saying so. That makes this a leak rather than a cosmetic mistake.
func TestReportedValueOnALaterLineIsRedacted(t *testing.T) {
	content := strings.Join([]string{
		"creditcard VISA " + wrongOccCard,
		"Call " + wrongOccPhone + " for support.",
	}, "\n")

	matches := wrongOccMatches(content)

	for _, strategy := range allStrategies() {
		t.Run(strategy.String(), func(t *testing.T) {
			ptr := NewPlainTextRedactor(nil, nil)

			redacted, mappings, err := ptr.RedactString(content, matches, strategy)
			if err != nil {
				t.Fatalf("RedactString: %v", err)
			}

			// Non-vacuity: redaction must have done something, or the assertions below would hold
			// for a function that returned its input unchanged.
			if len(mappings) == 0 {
				t.Fatal("no replacements were recorded, so this test is not exercising redaction")
			}
			if redacted == content {
				t.Fatal("the output is byte-identical to the input")
			}

			lines := strings.Split(redacted, "\n")
			if len(lines) != 2 {
				t.Fatalf("expected 2 output lines, got %d: %q", len(lines), redacted)
			}

			// The whole point. Line 2 carries a PHONE reported at confidence 100.
			if strings.Contains(lines[1], wrongOccPhone) {
				t.Errorf("the value reported at HIGH confidence on line 2 survived in cleartext.\n"+
					"  line 2 in : %q\n  line 2 out: %q\n"+
					"Both PHONE reports resolved to the occurrence on line 1, so line 2 was never "+
					"rewritten (#519).", "Call "+wrongOccPhone+" for support.", lines[1])
			}

			// And line 1's card must still be redacted — fixing the second occurrence must not cost
			// the first.
			if strings.Contains(lines[0], wrongOccCard) {
				t.Errorf("the card on line 1 was left unredacted: %q", lines[0])
			}
		})
	}
}

// TestTheEnclosingMatchIsStillApplied covers the second harm the wrong offset caused.
//
// Resolving the line-2 report onto line 1 rewrote the bytes the VISA replacement was about to
// rewrite, so when the VISA's turn came the text there no longer matched and its replacement was
// SILENTLY SKIPPED — the debug log recorded text_mismatch_warning for the VISA instead of
// redaction_applied. So the card was left partly exposed as well: measured on the parent, line 1 read
// "4532 **** **** 0366", which is the PHONE's mask landing in the wrong place rather than the card
// being redacted.
//
// The assertion is that the LONGEST match is applied. Note that a contained match mismatching AFTER
// its enclosing match has masked those bytes is expected and harmless — the value is already gone —
// so asserting "no text_mismatch_warning at all" would be asserting a non-defect. An earlier version
// of this test did exactly that and failed on correct output.
func TestTheEnclosingMatchIsStillApplied(t *testing.T) {
	content := strings.Join([]string{
		"creditcard VISA " + wrongOccCard,
		"Call " + wrongOccPhone + " for support.",
	}, "\n")
	matches := wrongOccMatches(content)

	var log bytes.Buffer
	debugObs := observability.NewDebugObserver(&log)
	observer := debugObs.StandardObserver
	observer.DebugObserver = debugObs

	ptr := NewPlainTextRedactor(nil, observer)
	redacted, _, err := ptr.RedactString(content, matches, redactors.RedactionFormatPreserving)
	if err != nil {
		t.Fatalf("RedactString: %v", err)
	}

	got := log.String()
	// Non-vacuity: the log must be populated, or the scan below proves nothing.
	if !strings.Contains(got, "redaction_applied") {
		t.Fatal("the debug log records no redaction at all")
	}

	// The VISA is the widest match. It must be APPLIED, not skipped for a text mismatch.
	visaSkipped := false
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "text_mismatch_warning") && strings.Contains(line, "VISA") {
			visaSkipped = true
		}
	}
	if visaSkipped {
		t.Errorf("the widest match (VISA) was skipped because an earlier replacement had already "+
			"mutated its bytes, so the card was never redacted as a card.\n  output: %q", redacted)
	}

	// And the card must be gone from line 1, which is the observable consequence.
	if strings.Contains(redacted, wrongOccCard) {
		t.Errorf("the card survived: %q", redacted)
	}
}

// TestPlainDuplicatesWereNeverBroken is the control that keeps the fix honest about its own scope.
//
// The same value on several separate lines, with no overlapping longer match, redacted correctly
// BEFORE this change. Asserting it here means a future rewrite of the resolution cannot quietly
// break the common case while still passing the leak test above.
func TestPlainDuplicatesWereNeverBroken(t *testing.T) {
	ssn := strings.Join([]string{"449", "87", "4100"}, "-")
	content := strings.Join([]string{
		"Employee A taxpayer SSN " + ssn + ".",
		"Employee B taxpayer SSN " + ssn + ".",
		"Employee C taxpayer SSN " + ssn + ".",
	}, "\n")
	matches := []detector.Match{
		{Text: ssn, Type: "SSN", LineNumber: 1, Confidence: 100, Validator: "ssn"},
		{Text: ssn, Type: "SSN", LineNumber: 2, Confidence: 100, Validator: "ssn"},
		{Text: ssn, Type: "SSN", LineNumber: 3, Confidence: 100, Validator: "ssn"},
	}

	for _, strategy := range allStrategies() {
		t.Run(strategy.String(), func(t *testing.T) {
			ptr := NewPlainTextRedactor(nil, nil)
			redacted, _, err := ptr.RedactString(content, matches, strategy)
			if err != nil {
				t.Fatalf("RedactString: %v", err)
			}
			if n := strings.Count(redacted, ssn); n != 0 {
				t.Errorf("%d of 3 occurrences survived: %q", n, redacted)
			}
		})
	}
}

// TestMatchWhoseLineDoesNotHoldItIsStillRedacted pins the fallback, which is the coverage risk of
// scoping the search to a line.
//
// A bounded or consolidated match, or line-number drift from an extractor, leaves a match whose
// recorded line does not contain its text. Scoping without a fallback would stop locating those
// matches at all — turning a leak fix into a different leak. The document-wide search is kept for
// exactly that case.
func TestMatchWhoseLineDoesNotHoldItIsStillRedacted(t *testing.T) {
	ssn := strings.Join([]string{"449", "87", "4100"}, "-")
	content := strings.Join([]string{
		"Header line with nothing sensitive.",
		"Employee taxpayer SSN " + ssn + ".",
		"Footer line.",
	}, "\n")

	// LineNumber 1 is WRONG: the value is on line 2. This is the drift case.
	matches := []detector.Match{
		{Text: ssn, Type: "SSN", LineNumber: 1, Confidence: 100, Validator: "ssn"},
	}

	for _, strategy := range allStrategies() {
		t.Run(strategy.String(), func(t *testing.T) {
			ptr := NewPlainTextRedactor(nil, nil)
			redacted, _, err := ptr.RedactString(content, matches, strategy)
			if err != nil {
				t.Fatalf("RedactString: %v", err)
			}
			if strings.Contains(redacted, ssn) {
				t.Errorf("a match whose recorded line does not hold its text was not redacted at all; "+
					"the fallback must still locate it: %q", redacted)
			}
		})
	}
}

// TestLineNumberBeyondTheDocumentIsStillRedacted: an out-of-range line must not make the value
// unlocatable either. Zero and negative line numbers reach here from callers that never set one.
func TestLineNumberBeyondTheDocumentIsStillRedacted(t *testing.T) {
	ssn := strings.Join([]string{"449", "87", "4100"}, "-")
	content := "Employee taxpayer SSN " + ssn + "."

	for _, line := range []int{0, -1, 99} {
		matches := []detector.Match{
			{Text: ssn, Type: "SSN", LineNumber: line, Confidence: 100, Validator: "ssn"},
		}
		ptr := NewPlainTextRedactor(nil, nil)
		redacted, _, err := ptr.RedactString(content, matches, redactors.RedactionFormatPreserving)
		if err != nil {
			t.Fatalf("LineNumber %d: RedactString: %v", line, err)
		}
		if strings.Contains(redacted, ssn) {
			t.Errorf("LineNumber %d left the value in place: %q", line, redacted)
		}
	}
}

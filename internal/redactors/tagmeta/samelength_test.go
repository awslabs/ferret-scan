// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tagmeta

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
	"github.com/awslabs/ferret-scan/v2/internal/redactors/replacement"
)

// The per-type table from #863: what the same-length renderer writes for each strategy.
var sameLengthValues = []struct{ typ, val string }{
	{"VISA", "4123456789012349"},
	{"VISA", "4123-4567-8901-2349"},
	{"SSN", "000-00-0001"},
	{"EMAIL", "jane.doe@example.com"},
	{"GMAIL", "jane.doe@example.com"},
	{"BUSINESS", "jane.doe@example.com"},
	{"OUTLOOK", "jane.doe@example.com"},
	{"PHONE", "(555) 010-0199"},
	{"IP_ADDRESS", "10.0.0.1"},
	{"PERSON_NAME", "Jane Doe"},
	{"AUTHOR_INFO", "Jane Doe"},
	{"PASSPORT", "X12345678"},
	{"SECRETS", "AKIAIOSFODNN7EXAMPLE"},
}

// TestSimpleIsAFullMaskForEveryType: simple keeps nothing of the value. It used to be rendered as
// format_preserving, keeping a card's last four digits, an email's first character and domain, a
// phone's last four and an IP's first two octets.
func TestSimpleIsAFullMaskForEveryType(t *testing.T) {
	for _, v := range sameLengthValues {
		r := SameLengthRendering(v.val, v.typ, redactors.RedactionSimple)
		if r.Text != strings.Repeat("*", len(v.val)) {
			t.Errorf("simple %s %q = %q, want a %d-byte mask", v.typ, v.val, r.Text, len(v.val))
		}
		if r.Kept() != 0 || len(r.Copies) != 0 {
			t.Errorf("simple %s %q keeps %d byte(s) of the value", v.typ, v.val, r.Kept())
		}
		if got := SameLengthReplacement(v.val, v.typ, redactors.RedactionSimple); got != r.Text {
			t.Errorf("SameLengthReplacement and SameLengthRendering disagree for simple %s: %q vs %q", v.typ, got, r.Text)
		}
	}
}

// TestFormatPreservingIsTheDocxRendering pins the default unchanged: the rendering a .docx gets
// whenever it fits the value's length and differs from it, else the mask.
func TestFormatPreservingIsTheDocxRendering(t *testing.T) {
	for _, v := range sameLengthValues {
		want := replacement.FormatPreserving(v.val, v.typ)
		if len(want) != len(v.val) || want == v.val {
			want = strings.Repeat("*", len(v.val))
		}
		if got := SameLengthReplacement(v.val, v.typ, redactors.RedactionFormatPreserving); got != want {
			t.Errorf("format_preserving %s %q = %q, want %q", v.typ, v.val, got, want)
		}
	}
	// The documented examples, so a change to the shared renderer cannot pass unnoticed here.
	for _, c := range []struct{ typ, val, want string }{
		{"VISA", "4123456789012349", "************2349"},
		{"EMAIL", "jane.doe@example.com", "j*******@example.com"},
		{"PHONE", "(555) 010-0199", "(***) ***-0199"},
	} {
		if got := SameLengthReplacement(c.val, c.typ, redactors.RedactionFormatPreserving); got != c.want {
			t.Errorf("format_preserving %s = %q, want %q", c.typ, got, c.want)
		}
	}
}

// TestPlanUnderSimpleWritesNoPartial is the same promise through Plan, which audio and video call,
// in both UTF-8 and UTF-16.
func TestPlanUnderSimpleWritesNoPartial(t *testing.T) {
	text := "Card 4123456789012349 mail jane.doe@example.com"
	buf := append([]byte(text+"|"), UTF16LE(text)...)
	matches := []detector.Match{
		{Text: "4123456789012349", Type: "VISA"},
		{Text: "jane.doe@example.com", Type: "EMAIL"},
	}
	plan, perMatch := Plan(buf, []Region{{Start: 0, End: len(buf)}}, matches, redactors.RedactionSimple)
	// At least narrow and wide. The big-endian pattern also matches the little-endian copy one
	// byte over, which Plan merges into the same masked span.
	if perMatch[0] < 2 || perMatch[1] < 2 {
		t.Fatalf("perMatch = %v, want each value found narrow and wide", perMatch)
	}
	Apply(buf, plan)
	for _, kept := range []string{"2349", "example.com"} {
		if strings.Contains(string(buf), kept) || strings.Contains(string(buf), string(UTF16LE(kept))) {
			t.Errorf("%q survives under simple", kept)
		}
	}
	if !strings.HasPrefix(string(buf), "Card "+strings.Repeat("*", 16)+" mail "+strings.Repeat("*", 20)+"|") {
		t.Errorf("narrow copy = %q", string(buf[:len(text)+1]))
	}
}

func TestSameLengthGroupRenderingMasksUnderSimple(t *testing.T) {
	line := "Passport number: 512010001"
	matches := []detector.Match{
		{Text: "512010001", Type: "SSN", Confidence: 50, LineNumber: 1, Context: detector.ContextInfo{FullLine: line}},
		{Text: "512010001", Type: "PASSPORT", Confidence: 100, LineNumber: 1, Context: detector.ContextInfo{FullLine: line}},
	}
	groups := redactors.ResolveOverlaps(matches)
	if len(groups) != 1 || !groups[0].IsGroup() {
		t.Fatalf("fixture did not form one group: %+v", groups)
	}
	if got := SameLengthGroupRendering(groups[0], matches, redactors.RedactionSimple); got.Text != "*********" || got.Kept() != 0 {
		t.Errorf("simple group = %q (kept %d), want a full mask", got.Text, got.Kept())
	}
}

// TestCheckStrategyExplainsTheLengthRule: the refusal names the strategy and why this format
// cannot take it, and still matches the sentinel.
func TestCheckStrategyExplainsTheLengthRule(t *testing.T) {
	r := declining{}
	err := CheckStrategy(r, redactors.RedactionSynthetic, []detector.Match{{Text: "x", Type: "SSN"}})
	if err == nil || !strings.Contains(err.Error(), "own byte length") || !strings.Contains(err.Error(), "synthetic") {
		t.Fatalf("CheckStrategy = %v", err)
	}
	if err := CheckStrategy(r, redactors.RedactionSimple, []detector.Match{{Text: "x", Type: "SSN"}}); err != nil {
		t.Errorf("a declared strategy was refused: %v", err)
	}
}

type declining struct{}

func (declining) GetName() string             { return "declining" }
func (declining) GetSupportedTypes() []string { return []string{".bin"} }
func (declining) GetSupportedStrategies() []redactors.RedactionStrategy {
	return []redactors.RedactionStrategy{redactors.RedactionSimple, redactors.RedactionFormatPreserving}
}
func (declining) GetComponentName() string { return "declining" }
func (declining) RedactDocument(string, string, []detector.Match, redactors.RedactionStrategy) (*redactors.RedactionResult, error) {
	return nil, nil
}

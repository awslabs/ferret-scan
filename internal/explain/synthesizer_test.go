// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package explain

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/internal/detector"
)

func mk(conf float64, file string, meta map[string]any) detector.Match {
	return detector.Match{
		Text:       "5500000000000004",
		Type:       "VISA",
		Confidence: conf,
		Filename:   file,
		Validator:  "creditcard",
		Metadata:   meta,
	}
}

func TestVerdict_HighConfidenceAlwaysReal(t *testing.T) {
	s := NewSignalSynthesizer()
	// HIGH confidence must surface as likely_real even with strong test hints —
	// never talk a reviewer out of a real finding.
	m := mk(95, "internal/foo_test.go", map[string]any{
		"validation_checks": map[string]bool{"luhn": true, "not_test": false},
	})
	if v := s.Explain(m).Verdict; v != VerdictLikelyReal {
		t.Errorf("HIGH confidence with test hints: got verdict %q, want %q", v, VerdictLikelyReal)
	}
}

func TestVerdict_LowConfidenceTestSignal(t *testing.T) {
	s := NewSignalSynthesizer()
	m := mk(40, "pkg/redact/engine_test.go", map[string]any{
		"validation_checks": map[string]bool{"luhn": true, "not_test": false},
	})
	if v := s.Explain(m).Verdict; v != VerdictLikelyTest {
		t.Errorf("LOW confidence + test signal: got %q, want %q", v, VerdictLikelyTest)
	}
}

func TestVerdict_MediumIsReal(t *testing.T) {
	s := NewSignalSynthesizer()
	m := mk(75, "src/app.go", map[string]any{
		"validation_checks": map[string]bool{"luhn": true, "not_test": true},
	})
	if v := s.Explain(m).Verdict; v != VerdictLikelyReal {
		t.Errorf("MEDIUM, no test signal: got %q, want %q", v, VerdictLikelyReal)
	}
}

func TestVerdict_LowNoSignalUncertain(t *testing.T) {
	s := NewSignalSynthesizer()
	m := mk(40, "src/app.go", map[string]any{
		"validation_checks": map[string]bool{"luhn": true, "not_test": true},
	})
	if v := s.Explain(m).Verdict; v != VerdictUncertain {
		t.Errorf("LOW, no test signal: got %q, want %q", v, VerdictUncertain)
	}
}

func TestRationale_MentionsLuhnAndVendor(t *testing.T) {
	s := NewSignalSynthesizer()
	m := mk(95, "src/app.go", map[string]any{
		"vendor":            "Visa",
		"validation_checks": map[string]bool{"luhn": true, "length": true, "not_test": true},
		"context_impact":    float64(10),
	})
	r := s.Explain(m).Rationale
	for _, want := range []string{"Visa", "Luhn", "confidence 95%", "high"} {
		if !strings.Contains(r, want) {
			t.Errorf("rationale %q missing %q", r, want)
		}
	}
}

func TestRationale_TestFileCalledOut(t *testing.T) {
	s := NewSignalSynthesizer()
	m := mk(45, "internal/core/scanner_test.go", map[string]any{
		"validation_checks": map[string]bool{"luhn": true, "not_test": false},
	})
	r := s.Explain(m).Rationale
	if !strings.Contains(r, "test file") || !strings.Contains(r, "scanner_test.go") {
		t.Errorf("rationale should call out the test file: %q", r)
	}
	if !strings.Contains(r, "test/placeholder pattern") {
		t.Errorf("rationale should mention the test-pattern signal: %q", r)
	}
}

func TestDraftSuppressReason_RealIsCautious(t *testing.T) {
	s := NewSignalSynthesizer()
	m := mk(95, "src/config.go", map[string]any{
		"validation_checks": map[string]bool{"luhn": true, "not_test": true},
	})
	reason := s.Explain(m).DraftSuppressReason
	if !strings.Contains(strings.ToUpper(reason), "REVIEW") {
		t.Errorf("likely_real suppression reason should warn to review: %q", reason)
	}
}

func TestDraftSuppressReason_TestFixture(t *testing.T) {
	s := NewSignalSynthesizer()
	m := mk(40, "internal/x_test.go", map[string]any{
		"validation_checks": map[string]bool{"not_test": false},
	})
	reason := s.Explain(m).DraftSuppressReason
	if !strings.Contains(strings.ToLower(reason), "test fixture") {
		t.Errorf("test-file finding should draft a 'test fixture' reason: %q", reason)
	}
}

func TestExplain_DoesNotMutateMatch(t *testing.T) {
	s := NewSignalSynthesizer()
	meta := map[string]any{"validation_checks": map[string]bool{"luhn": true, "not_test": true}}
	m := mk(80, "src/app.go", meta)
	before := m.Confidence
	_ = s.Explain(m)
	if m.Confidence != before {
		t.Errorf("Explain mutated Confidence: %v -> %v", before, m.Confidence)
	}
	if _, exists := m.Metadata[MetadataKey]; exists {
		t.Errorf("Explain must not stash its own output on the match (Annotate does that)")
	}
}

func TestAnnotate_AttachesAndRoundTrips(t *testing.T) {
	s := NewSignalSynthesizer()
	matches := []detector.Match{
		mk(95, "src/a.go", map[string]any{"validation_checks": map[string]bool{"luhn": true, "not_test": true}}),
		mk(30, "src/b_test.go", map[string]any{"validation_checks": map[string]bool{"not_test": false}}),
	}
	Annotate(matches, s)
	for i := range matches {
		ex, ok := FromMatch(matches[i])
		if !ok {
			t.Fatalf("match %d: expected an attached explanation", i)
		}
		if ex.Rationale == "" || ex.Verdict == "" {
			t.Errorf("match %d: empty explanation %+v", i, ex)
		}
	}
}

func TestAnnotate_NilExplainerIsNoOp(t *testing.T) {
	matches := []detector.Match{mk(95, "a.go", nil)}
	Annotate(matches, nil)
	if _, ok := FromMatch(matches[0]); ok {
		t.Error("nil explainer should attach nothing")
	}
}

func TestAnnotate_InitializesNilMetadata(t *testing.T) {
	matches := []detector.Match{{Type: "EMAIL", Confidence: 50}} // nil Metadata
	Annotate(matches, NewSignalSynthesizer())
	if _, ok := FromMatch(matches[0]); !ok {
		t.Error("Annotate should initialize nil Metadata and attach")
	}
}

func TestClear_RemovesExplanation(t *testing.T) {
	m := mk(50, "a.go", map[string]any{"validation_checks": map[string]bool{}})
	Annotate([]detector.Match{m}, NewSignalSynthesizer())
	// Re-fetch via a slice to ensure the annotation is present, then Clear.
	slice := []detector.Match{m}
	Annotate(slice, NewSignalSynthesizer())
	if _, ok := FromMatch(slice[0]); !ok {
		t.Fatal("precondition: explanation should be attached")
	}
	slice[0].Clear()
	if _, ok := FromMatch(slice[0]); ok {
		t.Error("Match.Clear() must remove the explanation annotation")
	}
}

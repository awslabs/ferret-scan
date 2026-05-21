// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package parallel

import (
	"context"
	"errors"
	"testing"

	"github.com/awslabs/ferret-scan/internal/detector"
	"github.com/awslabs/ferret-scan/internal/preprocessors"
)

// stubContentValidator implements detector.Validator + ValidateContent
// for direct, deterministic unit testing without spinning up the real
// validator stack.
type stubContentValidator struct {
	name      string
	matches   []detector.Match
	err       error
	callCount int
}

func (v *stubContentValidator) Validate(filePath string) ([]detector.Match, error) {
	return nil, nil
}
func (v *stubContentValidator) CalculateConfidence(string) (float64, map[string]bool) {
	return 0, nil
}
func (v *stubContentValidator) AnalyzeContext(string, detector.ContextInfo) float64 { return 0 }

func (v *stubContentValidator) ValidateContent(content string, originalPath string) ([]detector.Match, error) {
	v.callCount++
	if v.err != nil {
		return nil, v.err
	}
	out := make([]detector.Match, len(v.matches))
	copy(out, v.matches)
	for i := range out {
		out[i].Filename = originalPath
		out[i].Validator = v.name
	}
	return out, nil
}

// stubProcessedContentValidator implements ValidateProcessedContent (the
// dual-path branch). It also provides ValidateContent so the type satisfies
// detector.Validator, but the runner should prefer the ProcessedContent
// path.
type stubProcessedContentValidator struct {
	name           string
	pcMatches      []detector.Match
	contentMatches []detector.Match
	pcCalled       bool
	contentCalled  bool
}

func (v *stubProcessedContentValidator) Validate(filePath string) ([]detector.Match, error) {
	return nil, nil
}
func (v *stubProcessedContentValidator) CalculateConfidence(string) (float64, map[string]bool) {
	return 0, nil
}
func (v *stubProcessedContentValidator) AnalyzeContext(string, detector.ContextInfo) float64 {
	return 0
}
func (v *stubProcessedContentValidator) ValidateContent(string, string) ([]detector.Match, error) {
	v.contentCalled = true
	return append([]detector.Match{}, v.contentMatches...), nil
}
func (v *stubProcessedContentValidator) ValidateProcessedContent(c *preprocessors.ProcessedContent) ([]detector.Match, error) {
	v.pcCalled = true
	return append([]detector.Match{}, v.pcMatches...), nil
}

func newProcessed(text, path string) *preprocessors.ProcessedContent {
	return &preprocessors.ProcessedContent{
		Text:          text,
		OriginalPath:  path,
		Filename:      path,
		ProcessorType: "plaintext",
		Success:       true,
	}
}

func TestRunValidators_NilStrategyInvokesOnce(t *testing.T) {
	v := &stubContentValidator{
		name: "stub",
		matches: []detector.Match{
			{Type: "T1", LineNumber: 1, Confidence: 50},
		},
	}

	matches, err := RunValidators(context.Background(),
		[]detector.Validator{v}, newProcessed("payload", "<stdin>"), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.callCount != 1 {
		t.Errorf("expected 1 invocation, got %d", v.callCount)
	}
	if len(matches) != 1 || matches[0].Type != "T1" {
		t.Errorf("unexpected matches: %+v", matches)
	}
	if matches[0].Filename != "<stdin>" {
		t.Errorf("expected Filename=<stdin>, got %q", matches[0].Filename)
	}
}

func TestRunValidators_NilStrategyDoesNotRetry(t *testing.T) {
	// Verifies that without a retry strategy, a failing validator is
	// invoked exactly once (no hidden retry behavior).
	v := &stubContentValidator{name: "stub", err: errors.New("boom")}

	_, err := RunValidators(context.Background(),
		[]detector.Validator{v}, newProcessed("p", "<stdin>"), nil)
	if err == nil {
		t.Fatal("expected error to surface from RunValidators")
	}
	if v.callCount != 1 {
		t.Errorf("expected exactly 1 invocation with nil strategy, got %d", v.callCount)
	}
}

func TestRunValidators_EmptyContentNoMatches(t *testing.T) {
	v := &stubContentValidator{name: "stub"} // no matches configured

	matches, err := RunValidators(context.Background(),
		[]detector.Validator{v}, newProcessed("", "<stdin>"), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected zero matches, got %d", len(matches))
	}
}

func TestRunValidators_DualPathPrefersProcessedContent(t *testing.T) {
	// When a validator implements ValidateProcessedContent, the runner must
	// use that path and not fall through to ValidateContent.
	v := &stubProcessedContentValidator{
		name: "dual",
		pcMatches: []detector.Match{
			{Type: "FROM_PC", LineNumber: 1},
		},
		contentMatches: []detector.Match{
			{Type: "FROM_CONTENT", LineNumber: 2},
		},
	}

	matches, err := RunValidators(context.Background(),
		[]detector.Validator{v}, newProcessed("p", "<stdin>"), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !v.pcCalled {
		t.Error("expected ValidateProcessedContent to be called")
	}
	if v.contentCalled {
		t.Error("ValidateContent must not be called when ValidateProcessedContent exists")
	}
	if len(matches) != 1 || matches[0].Type != "FROM_PC" {
		t.Errorf("expected matches from ProcessedContent path, got %+v", matches)
	}
}

func TestRunValidators_FallsBackToFilenameWhenOriginalPathEmpty(t *testing.T) {
	// When OriginalPath is empty, the runner should pass Filename through
	// to ValidateContent. This is the contract documented in RunValidators.
	v := &stubContentValidator{
		name:    "stub",
		matches: []detector.Match{{Type: "T1", LineNumber: 1}},
	}
	pc := &preprocessors.ProcessedContent{
		Text:          "x",
		OriginalPath:  "",
		Filename:      "<inline>",
		ProcessorType: "plaintext",
		Success:       true,
	}

	matches, err := RunValidators(context.Background(),
		[]detector.Validator{v}, pc, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Filename != "<inline>" {
		t.Errorf("expected Filename to fall back to <inline>, got %q", matches[0].Filename)
	}
}

func TestRunValidators_AggregatesMultipleValidators(t *testing.T) {
	v1 := &stubContentValidator{
		name:    "v1",
		matches: []detector.Match{{Type: "A", LineNumber: 1}},
	}
	v2 := &stubContentValidator{
		name:    "v2",
		matches: []detector.Match{{Type: "B", LineNumber: 2}, {Type: "C", LineNumber: 3}},
	}

	matches, err := RunValidators(context.Background(),
		[]detector.Validator{v1, v2}, newProcessed("p", "<stdin>"), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(matches) != 3 {
		t.Errorf("expected 3 aggregated matches, got %d (%+v)", len(matches), matches)
	}
	// Order is not guaranteed (parallel goroutines), so check by type set.
	seen := map[string]bool{}
	for _, m := range matches {
		seen[m.Type] = true
	}
	for _, want := range []string{"A", "B", "C"} {
		if !seen[want] {
			t.Errorf("expected match type %q in result, got %v", want, seen)
		}
	}
}

func TestRunValidators_ReturnsFirstError(t *testing.T) {
	v1 := &stubContentValidator{name: "v1", err: errors.New("err1")}
	v2 := &stubContentValidator{
		name:    "v2",
		matches: []detector.Match{{Type: "B", LineNumber: 1}},
	}

	matches, err := RunValidators(context.Background(),
		[]detector.Validator{v1, v2}, newProcessed("p", "<stdin>"), nil)
	if err == nil {
		t.Error("expected first validator's error to propagate")
	}
	// The successful validator's matches must still come through — error
	// from one validator does not poison the union.
	if len(matches) != 1 || matches[0].Type != "B" {
		t.Errorf("expected v2's match despite v1 error, got %+v", matches)
	}
}

func TestRunValidators_MetadataContentSkipsNonMetadata(t *testing.T) {
	// ProcessorType="metadata" means the content is purely metadata. A
	// non-metadata validator must skip it; the runner should not even call
	// ValidateContent for it.
	v := &stubContentValidator{
		name:    "non-metadata",
		matches: []detector.Match{{Type: "X", LineNumber: 1}},
	}
	pc := &preprocessors.ProcessedContent{
		Text:          "metadata payload",
		OriginalPath:  "<doc>",
		Filename:      "<doc>",
		ProcessorType: "metadata",
		Success:       true,
	}

	matches, err := RunValidators(context.Background(),
		[]detector.Validator{v}, pc, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.callCount != 0 {
		t.Errorf("non-metadata validator must not be invoked on metadata-only content, got %d calls", v.callCount)
	}
	if len(matches) != 0 {
		t.Errorf("expected zero matches, got %d", len(matches))
	}
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/internal/observability"
	"github.com/awslabs/ferret-scan/internal/preprocessors"
)

// These tests lock the combine step in processFileInternal (v2 gap 2.3
// combine-copy elision). The golden corpus only exercises the SINGLE-preprocessor
// path (a .wav routes to one metadata extractor), so the multi-preprocessor
// concatenation branch — the part the elision rewrote — has no other coverage.

// fakePreprocessor is a test double that reports it can process everything and
// returns a fixed ProcessedContent.
type fakePreprocessor struct {
	name    string
	text    string
	success bool
	words   int
	meta    map[string]interface{}
}

func (f *fakePreprocessor) CanProcess(string) bool { return true }
func (f *fakePreprocessor) GetName() string        { return f.name }
func (f *fakePreprocessor) GetSupportedExtensions() []string {
	return []string{".fake"}
}
func (f *fakePreprocessor) SetObserver(observability.Observer) {}
func (f *fakePreprocessor) Process(string) (*preprocessors.ProcessedContent, error) {
	return &preprocessors.ProcessedContent{
		Text:      f.text,
		Success:   f.success,
		WordCount: f.words,
		Metadata:  f.meta,
	}, nil
}

// routerWithPreprocessors builds a FileRouter and injects the given
// preprocessors directly (bypassing the registry/factory dance).
func routerWithPreprocessors(pp ...preprocessors.Preprocessor) *FileRouter {
	fr := NewFileRouter(false)
	fr.preprocessors = pp
	return fr
}

// TestCombine_SinglePreprocessor_TextByteIdentical is the fast path: one
// successful preprocessor must yield Text EXACTLY equal to its extracted text,
// with no separator prefix and no second copy semantics observable.
func TestCombine_SinglePreprocessor_TextByteIdentical(t *testing.T) {
	body := strings.Repeat("sensitive line\n", 1000)
	fr := routerWithPreprocessors(&fakePreprocessor{name: "text", text: body, success: true, words: 2000})

	got, err := fr.ProcessFile("x.fake", &ProcessingContext{FilePath: "x.fake"})
	if err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}
	if got.Text != body {
		t.Errorf("single-preprocessor Text differs from source extraction (len got=%d want=%d)", len(got.Text), len(body))
	}
	if got.ProcessorType != "text" {
		t.Errorf("ProcessorType = %q, want %q", got.ProcessorType, "text")
	}
	if got.WordCount != 2000 {
		t.Errorf("WordCount = %d, want 2000", got.WordCount)
	}
}

// TestCombine_MultiPreprocessor_MatchesReferenceConcat locks the combine branch:
// with 2+ successful preprocessors the output must be byte-identical to the
// original algorithm's concatenation (first text, then
// "\n\n--- name ---\n"+text per subsequent processor) FOR THE OBSERVED ARRIVAL
// ORDER. Because preprocessors run concurrently, arrival order is
// nondeterministic, so we reconstruct the expected string from the actual
// ProcessorType (which records the order the results were combined in) rather
// than assuming a fixed order.
func TestCombine_MultiPreprocessor_MatchesReferenceConcat(t *testing.T) {
	texts := map[string]string{
		"alpha": strings.Repeat("A", 500),
		"beta":  strings.Repeat("B", 700),
		"gamma": strings.Repeat("C", 300),
	}
	fr := routerWithPreprocessors(
		&fakePreprocessor{name: "alpha", text: texts["alpha"], success: true},
		&fakePreprocessor{name: "beta", text: texts["beta"], success: true},
		&fakePreprocessor{name: "gamma", text: texts["gamma"], success: true},
	)

	got, err := fr.ProcessFile("x.fake", &ProcessingContext{FilePath: "x.fake"})
	if err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}

	// ProcessorType is "a+b+c" in the exact order results were combined.
	order := strings.Split(got.ProcessorType, "+")
	if len(order) != 3 {
		t.Fatalf("expected 3 combined processors, got %q", got.ProcessorType)
	}

	// Reconstruct the reference concatenation using the SAME rule as the
	// original loop: first text raw, each subsequent prefixed with a separator.
	var want strings.Builder
	for i, name := range order {
		if i == 0 {
			want.WriteString(texts[name])
		} else {
			want.WriteString("\n\n--- " + name + " ---\n")
			want.WriteString(texts[name])
		}
	}
	if got.Text != want.String() {
		t.Errorf("multi-preprocessor combine not byte-identical to reference\n got len=%d\nwant len=%d", len(got.Text), want.Len())
	}
}

// TestCombine_SkipsFailedAndEmpty confirms the fast path still triggers when the
// only SUCCESSFUL result is one preprocessor, even if others ran but failed or
// returned empty text (they must not force the builder path or add separators).
func TestCombine_SkipsFailedAndEmpty(t *testing.T) {
	body := "the only real content"
	fr := routerWithPreprocessors(
		&fakePreprocessor{name: "empty", text: "", success: true},       // empty text → skipped
		&fakePreprocessor{name: "failed", text: "junk", success: false}, // not success → skipped
		&fakePreprocessor{name: "good", text: body, success: true},
	)

	got, err := fr.ProcessFile("x.fake", &ProcessingContext{FilePath: "x.fake"})
	if err != nil {
		t.Fatalf("ProcessFile: %v", err)
	}
	if got.Text != body {
		t.Errorf("Text = %q, want %q (only the one successful non-empty result, no separators)", got.Text, body)
	}
	if got.ProcessorType != "good" {
		t.Errorf("ProcessorType = %q, want %q", got.ProcessorType, "good")
	}
}

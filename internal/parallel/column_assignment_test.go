// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package parallel

import (
	"context"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/preprocessors"
)

// columnProbeValidator reports the same value twice on one line, as a validator does
// when a value genuinely repeats, and records NO column — the state every validator
// is in today.
type columnProbeValidator struct {
	line  string
	value string
	count int
}

func (v *columnProbeValidator) CalculateConfidence(string) (float64, map[string]bool) {
	return 90, nil
}

func (v *columnProbeValidator) AnalyzeContext(string, detector.ContextInfo) float64 { return 0 }

func (v *columnProbeValidator) ValidateContent(string, string) ([]detector.Match, error) {
	out := make([]detector.Match, 0, v.count)
	for i := 0; i < v.count; i++ {
		out = append(out, detector.Match{
			Text:       v.value,
			Type:       "PROBE",
			Confidence: 90,
			LineNumber: 1,
			Validator:  "probe",
			Context:    detector.ContextInfo{FullLine: v.line},
		})
	}
	return out, nil
}

// RunValidators must record a column on every match it returns.
//
// This is the wiring test. The formatters can only report a correct position if
// something populates it, and RunValidators is the single point every match in the
// system passes through: the worker pool calls it per file (covering the CLI,
// core.ScanFile and the redaction path) and core.ScanContent calls it directly.
//
// Without this, deleting the AssignLineColumns call would leave every formatter
// test passing — they construct matches with columns already set — while the actual
// scan reported none.
func TestRunValidatorsAssignsLineColumns(t *testing.T) {
	const line = "Contact a@b.com or a@b.com for access."
	v := &columnProbeValidator{line: line, value: "a@b.com", count: 2}

	processed := &preprocessors.ProcessedContent{
		OriginalPath:  "notes.txt",
		Filename:      "notes.txt",
		Text:          line,
		ProcessorType: "plaintext",
		Success:       true,
	}

	matches, err := RunValidators(context.Background(), []detector.Validator{v}, processed, nil)
	if err != nil {
		t.Fatalf("RunValidators: %v", err)
	}
	if len(matches) != 2 {
		t.Fatalf("got %d matches, want 2", len(matches))
	}

	for i, m := range matches {
		if m.StartColumn <= 0 {
			t.Fatalf("match %d has no column — nothing populated it, so every consumer must fall "+
				"back to a first-occurrence search", i)
		}
		if m.EndColumn <= m.StartColumn {
			t.Errorf("match %d has columns %d-%d", i, m.StartColumn, m.EndColumn)
		}
		if got := line[m.StartColumn-1 : m.EndColumn-1]; got != v.value {
			t.Errorf("match %d columns %d-%d address %q, want %q",
				i, m.StartColumn, m.EndColumn, got, v.value)
		}
	}
	if matches[0].StartColumn == matches[1].StartColumn {
		t.Errorf("both matches got column %d; two occurrences of one value on a line must be "+
			"distinguishable", matches[0].StartColumn)
	}
}

// The columns a scan reports must not vary run to run. Validators run in
// parallel, so the assignment has to happen after the union is restored to launch
// order — assigning in goroutine-completion order would hand the same finding a
// different column each run.
func TestRunValidatorsColumnAssignmentIsDeterministic(t *testing.T) {
	const line = "a 7 b 7 c 7 d 7"
	newRun := func() []detector.Match {
		// Two validators each reporting the same value on the same line, so the
		// union order (and therefore the occurrence order) is what is under test.
		v1 := &columnProbeValidator{line: line, value: "7", count: 2}
		v2 := &columnProbeValidator{line: line, value: "7", count: 2}
		processed := &preprocessors.ProcessedContent{
			OriginalPath: "notes.txt", Filename: "notes.txt", Text: line,
			ProcessorType: "plaintext", Success: true,
		}
		matches, err := RunValidators(context.Background(),
			[]detector.Validator{v1, v2}, processed, nil)
		if err != nil {
			t.Fatalf("RunValidators: %v", err)
		}
		return matches
	}

	want := newRun()
	if len(want) != 4 {
		t.Fatalf("got %d matches, want 4", len(want))
	}
	for run := 0; run < 40; run++ {
		got := newRun()
		if len(got) != len(want) {
			t.Fatalf("run %d: %d matches, want %d", run, len(got), len(want))
		}
		for i := range want {
			if got[i].StartColumn != want[i].StartColumn {
				t.Fatalf("run %d: match %d column %d != %d — the column depends on goroutine "+
					"completion order", run, i, got[i].StartColumn, want[i].StartColumn)
			}
		}
	}
}

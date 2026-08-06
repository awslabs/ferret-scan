// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scorecorpus

import (
	"bytes"
	"fmt"
	"os"
	"testing"
)

// sinkStrategies are the redaction strategies the gate covers.
//
// "synthetic" is deliberately absent: it substitutes generated values and is
// nondeterministic by design, so gating it would flake. It can be printed but
// never gated.
var sinkStrategies = []string{"simple", "format_preserving"}

// TestScoreCorpus is THE GATE.
//
// It scores detection AND the redaction sink, then ratchets both against
// testdata/baseline.json. Run it with SCORE_REPORT=1 to see the scorecard even on
// success (`make score`), or UPDATE_SCORE_BASELINE=1 to re-lock the floor after an
// intentional, explained change (`make score-update`).
func TestScoreCorpus(t *testing.T) {
	sc, err := Score()
	if err != nil {
		t.Fatalf("Score: %v", err)
	}

	sinks := map[string]*SinkOutcome{}
	sinkLabels := 0
	for _, st := range sinkStrategies {
		so, err := ScoreSink(st, t.TempDir())
		if err != nil {
			t.Fatalf("ScoreSink(%s): %v", st, err)
		}
		sinks[st] = so
		sinkLabels = so.Labels
	}

	supDir := t.TempDir()
	sup, err := ScoreSuppression(supDir)
	if err != nil {
		t.Fatalf("ScoreSuppression: %v", err)
	}

	var report bytes.Buffer
	sc.Render(&report)
	fmt.Fprintf(&report, "\nredaction sink (core.RedactFile, label-driven; %d labels)\n", sinkLabels)
	fmt.Fprintf(&report, "  %-20s %11s %10s\n", "strategy", "whole_leak", "residue4")
	for _, st := range sinkStrategies {
		fmt.Fprintf(&report, "  %-20s %11d %10d\n", st, sinks[st].WholeLeak, sinks[st].Residue4)
	}
	if sk := sinks[sinkStrategies[0]].Skipped; len(sk) > 0 {
		fmt.Fprintf(&report, "\n  no redactor registered for these file types (a disclosed CLI\n"+
			"  limitation, not a leak): %v\n", sk)
	}

	fmt.Fprintf(&report, "\nsuppression layer (a rule must silence exactly what it names)\n")
	fmt.Fprintf(&report, "  rules exercised %d   silenced %d   collateral %d   ineffective %d\n",
		sup.Targeted, sup.Silenced, sup.Collateral, sup.Ineffective)

	if os.Getenv("UPDATE_SCORE_BASELINE") == "1" {
		if err := NewBaseline(sc, sinks, sinkLabels, sup).Save("."); err != nil {
			t.Fatalf("save baseline: %v", err)
		}
		t.Logf("\n%s\nbaseline REWRITTEN — state the delta and its cause in the PR body", report.String())
		return
	}

	base, err := LoadBaseline(".")
	if err != nil {
		t.Fatalf("load baseline (run `make score-update` to create it): %v", err)
	}

	violations := sc.Compare(base, sinks, sinkLabels, sup)

	if os.Getenv("SCORE_REPORT") == "1" || len(violations) > 0 {
		t.Logf("\n%s", report.String())
	}

	// An IMPROVEMENT is reported, not failed. Making the tool better must never
	// cost a red build; only a regression does.
	blocking := 0
	for _, v := range violations {
		if v.Blocking {
			blocking++
			t.Errorf("%s", v.Message)
			continue
		}
		t.Logf("%s", v.Message)
	}

	if blocking == 0 {
		// Payload-free, and useful on a green run so the numbers appear in CI logs.
		t.Logf("score: PASS  recall_all=%.4f recall_hm=%.4f prec_hm=%.4f  whole_leak=%d",
			sc.Total.RecallAll(), sc.Total.RecallHM(), sc.Total.PrecisionHM(),
			sinks["format_preserving"].WholeLeak)
	}
}

// TestScoreDeterminism runs the corpus repeatedly in one process.
//
// The scan pipeline aggregates in goroutine-completion order and several map
// iterations feed output, so a gate built on these numbers must be proven stable
// or it will flake and be abandoned. Cross-process stability is covered by running
// this test with -count=N and by the mutation script.
func TestScoreDeterminism(t *testing.T) {
	first, err := Score()
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	want := fmt.Sprintf("%+v", first.Total)

	for i := 0; i < 5; i++ {
		got, err := Score()
		if err != nil {
			t.Fatalf("Score run %d: %v", i+2, err)
		}
		if g := fmt.Sprintf("%+v", got.Total); g != want {
			t.Fatalf("scorecard is nondeterministic across runs in one process:\n"+
				"  run 1: %s\n  run %d: %s\n"+
				"A gate that moves on its own will be ignored, then removed.", want, i+2, g)
		}
	}
}

// TestSinkDeterminism does the same for the redaction sink, which writes real
// files through the router and is therefore the more likely of the two to vary.
func TestSinkDeterminism(t *testing.T) {
	for _, st := range sinkStrategies {
		var want string
		for i := 0; i < 3; i++ {
			so, err := ScoreSink(st, t.TempDir())
			if err != nil {
				t.Fatalf("ScoreSink(%s): %v", st, err)
			}
			got := fmt.Sprintf("whole_leak=%d residue4=%d labels=%d", so.WholeLeak, so.Residue4, so.Labels)
			if i == 0 {
				want = got
				continue
			}
			if got != want {
				t.Fatalf("sink %s is nondeterministic:\n  run 1: %s\n  run %d: %s", st, want, i+1, got)
			}
		}
	}
}

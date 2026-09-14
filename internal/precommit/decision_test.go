// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package precommit

import (
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// The invariant that makes the #667 divergence unrepresentable: the user-facing verdict and the exit
// code are the same decision, so one cannot say "blocked" while the other says "fine".
//
// Asserted over the whole input space rather than on the one reported case. The bug was
// FERRET_PRECOMMIT_EXIT_ON=none printing "commit blocked for security" and exiting 0, and a test
// pinned to `none` would pass the day a fourth policy value behaved the same way. Every policy value
// crossed with every confidence band is 5 x 4 x (band combinations), which is small enough to
// enumerate exhaustively — so there is no sampling and no judgement about which cases matter.
func TestDecisionMessageAgreesWithExitCode(t *testing.T) {
	policies := []string{"", "none", "low", "medium", "high", "nonsense"}
	// Confidence values chosen at and around both band boundaries, so an off-by-one in the band
	// arithmetic shows up here rather than in the field.
	confidences := []float64{0, 59.9, 60, 60.1, 89.9, 90, 90.1, 100}

	checked := 0
	for _, policy := range policies {
		for _, a := range confidences {
			for _, b := range confidences {
				for _, n := range []int{0, 1, 2} {
					matches := make([]detector.Match, 0, n)
					if n >= 1 {
						matches = append(matches, detector.Match{Confidence: a})
					}
					if n >= 2 {
						matches = append(matches, detector.Match{Confidence: b})
					}
					cfg := &PrecommitConfig{ExitOnFindings: policy}
					d := Resolve(matches, cfg)
					checked++

					// The invariant, both directions.
					if d.Message != "" && d.ExitCode == 0 {
						t.Fatalf("policy=%q matches=%v: message %q but exit code 0 — this is exactly "+
							"the #667 lie: the tool says the commit is blocked and then lets it through",
							policy, matches, d.Message)
					}
					if d.Message == "" && d.Blocking {
						t.Fatalf("policy=%q matches=%v: blocking with no message — the commit stops "+
							"and the user is told nothing", policy, matches)
					}
					if d.Blocking != (d.ExitCode == 1) {
						t.Fatalf("policy=%q matches=%v: Blocking=%v but ExitCode=%d",
							policy, matches, d.Blocking, d.ExitCode)
					}
				}
			}
		}
	}
	if checked < 500 {
		t.Errorf("only %d combinations checked; the enumeration is not covering the space", checked)
	}
	t.Logf("%d policy x confidence combinations hold the invariant", checked)
}

// TestToolErrorNeverChangesTheMessage pins the split between Resolve and WithToolError.
//
// WithToolError exists so the finding policy is evaluated ONCE even though the two callers need the
// answer at different times — the formatter before the run ends, the exit after it. That is only safe
// while the escalation cannot touch what the user was told, so it is asserted rather than assumed.
func TestToolErrorNeverChangesTheMessage(t *testing.T) {
	for _, policy := range []string{"", "none", "low", "medium", "high"} {
		for _, conf := range []float64{0, 60, 90, 100} {
			for _, n := range []int{0, 1} {
				var matches []detector.Match
				if n == 1 {
					matches = []detector.Match{{Confidence: conf}}
				}
				base := Resolve(matches, &PrecommitConfig{ExitOnFindings: policy})
				withErr := base.WithToolError(true)
				if withErr.Message != base.Message {
					t.Fatalf("policy=%q conf=%v: WithToolError changed the message from %q to %q",
						policy, conf, base.Message, withErr.Message)
				}
				if base.Blocking && withErr.ExitCode != base.ExitCode {
					t.Fatalf("policy=%q conf=%v: a blocking decision was downgraded by a tool error "+
						"(%d -> %d)", policy, conf, base.ExitCode, withErr.ExitCode)
				}
				if !base.Blocking && withErr.ExitCode != 2 {
					t.Fatalf("policy=%q conf=%v: a tool error must escalate a non-blocking decision "+
						"to 2, got %d", policy, conf, withErr.ExitCode)
				}
			}
		}
	}
}

// TestExitOnNoneDoesNotClaimTheCommitIsBlocked is the reported case, kept as its own row.
//
// The invariant test above subsumes it, but this one names the configuration and the symptom, so a
// failure here reads as the bug rather than as an abstract violation. `none` matters specifically
// because it is what a team sets while adopting the tool — the one configuration chosen by people who
// do not yet trust the gate was the one that lied to them.
func TestExitOnNoneDoesNotClaimTheCommitIsBlocked(t *testing.T) {
	high := []detector.Match{{Confidence: 100}}
	d := Resolve(high, &PrecommitConfig{ExitOnFindings: "none"})
	if d.ExitCode != 0 {
		t.Errorf("EXIT_ON=none must not block: exit code %d", d.ExitCode)
	}
	if d.Message != "" {
		t.Errorf("EXIT_ON=none exits 0, so it must not print %q", d.Message)
	}
	// And the contrast: the default policy blocks on the same finding and says so.
	def := Resolve(high, &PrecommitConfig{ExitOnFindings: "high"})
	if def.ExitCode == 0 || def.Message == "" {
		t.Errorf("EXIT_ON=high on a HIGH finding must block and say so: exit=%d message=%q",
			def.ExitCode, def.Message)
	}
}

// TestHighestConfidenceLevelBands pins the band boundaries the decision rests on.
func TestHighestConfidenceLevelBands(t *testing.T) {
	cases := []struct {
		confidences []float64
		want        string
	}{
		{nil, ""},
		{[]float64{0}, "low"},
		{[]float64{59.9}, "low"},
		{[]float64{60}, "medium"},
		{[]float64{89.9}, "medium"},
		{[]float64{90}, "high"},
		{[]float64{100}, "high"},
		// The highest wins regardless of order — the property the old copies implemented with
		// nested conditionals in two places.
		{[]float64{0, 90}, "high"},
		{[]float64{90, 0}, "high"},
		{[]float64{0, 60, 0}, "medium"},
		{[]float64{59, 59}, "low"},
	}
	for _, c := range cases {
		matches := make([]detector.Match, 0, len(c.confidences))
		for _, v := range c.confidences {
			matches = append(matches, detector.Match{Confidence: v})
		}
		if got := HighestConfidenceLevel(matches); got != c.want {
			t.Errorf("HighestConfidenceLevel(%v) = %q, want %q", c.confidences, got, c.want)
		}
	}
}

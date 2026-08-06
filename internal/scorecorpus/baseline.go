// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scorecorpus

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// BaselinePath is the committed floor.
const BaselinePath = "testdata/baseline.json"

// CheckBaseline is the per-check floor.
//
// Counts, never percentages: a hand-edited ratio can hide which direction it
// moved, whereas "tp: 111" cannot be fudged without saying so in the diff.
type CheckBaseline struct {
	TP       int `json:"tp"`
	TPBanded int `json:"tp_high_medium"`
	FNMissed int `json:"fn_missed"`
	FNBand   int `json:"fn_band"`
	FPHigh   int `json:"fp_high_medium"`
	FPLow    int `json:"fp_low"`
	Extra    int `json:"extra_same_span"`
}

// SuppressionBaseline is the floor for the suppression layer.
//
// Collateral and Ineffective are both gated at zero, in both directions: a rule that
// silences a finding it does not name is a leak, and a rule that fails to silence the
// finding it does name makes users abandon suppression for a blunter tool.
type SuppressionBaseline struct {
	Cases       int `json:"cases"`
	Targeted    int `json:"targeted"`
	Silenced    int `json:"silenced"`
	Collateral  int `json:"collateral"`
	Ineffective int `json:"ineffective"`
}

// SinkBaseline is the floor for one redaction strategy.
type SinkBaseline struct {
	WholeLeak int `json:"whole_leak"`
	Residue4  int `json:"residue4"`
}

// Baseline is the whole committed floor.
type Baseline struct {
	SchemaVersion int                       `json:"schema_version"`
	Comment       string                    `json:"_comment"`
	Checks        map[string]*CheckBaseline `json:"checks"`
	Sink          map[string]*SinkBaseline  `json:"sink"`
	SinkLabels    int                       `json:"sink_labels"`
	Suppression   *SuppressionBaseline      `json:"suppression"`
	Undecided     struct {
		Cases    int `json:"cases"`
		Findings int `json:"findings"`
	} `json:"undecided"`
	Global struct {
		Cases     int `json:"cases"`
		Labels    int `json:"labels"`
		Negatives int `json:"negatives"`
	} `json:"global"`
}

// LoadBaseline reads the committed floor.
func LoadBaseline(dir string) (*Baseline, error) {
	b, err := os.ReadFile(filepath.Join(dir, BaselinePath)) //nolint:gosec // fixed test path
	if err != nil {
		return nil, err
	}
	var out Baseline
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("parse %s: %w", BaselinePath, err)
	}
	return &out, nil
}

// Save writes the baseline. json.MarshalIndent sorts map keys, so the file is
// byte-stable across runs and platforms.
func (b *Baseline) Save(dir string) error {
	body, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	return os.WriteFile(filepath.Join(dir, BaselinePath), body, 0o600)
}

// Violation is one gate finding.
type Violation struct {
	// Blocking distinguishes a REGRESSION, which fails the build, from an
	// IMPROVEMENT, which is reported and does not.
	//
	// Maintainer decision (2026-08-05): an improvement must NOT fail. The
	// alternative — failing with "run make score-update" — keeps the floor rising
	// automatically but taxes every PR that makes the tool better, which is
	// backwards. So an improvement prints a one-line note asking for a baseline
	// refresh and the build stays green.
	//
	// The floor therefore rises only when someone runs `make score-update`. That is
	// an accepted, stated tradeoff: a win that is never locked in can be given back
	// by a later change without the gate noticing. The IMPROVED lines exist to make
	// that easy to spot in CI output and in the PR body.
	Blocking bool
	Message  string
}

// FPAllowance grants a check headroom to add false positives.
//
// Default 0: the standing rule is that false positives go DOWN. A deliberate
// tradeoff — accepting some FPs to recover a missed detection — is expressed by
// editing this map, which makes the tradeoff visible in the diff and reviewable,
// rather than by quietly regenerating the baseline.
var FPAllowance = map[string]int{}

// Compare gates the scorecard against the baseline.
//
// The policy is deliberately ASYMMETRIC, because the two error directions are not
// equally serious for a redaction tool:
//
//   - A lost detection is a cleartext leak: the redactor only ever sees reported
//     findings. So TP and TPBanded are hard floors with no allowance and no
//     cross-check offsetting.
//   - A new false positive is noise: gated with optional per-check headroom.
//   - A leak that survives redaction is refused outright.
//
// An IMPROVEMENT also fails, asking for a regeneration. Without that the floor
// never rises, and the next change hands the win back for free.
func (s *Scorecard) Compare(base *Baseline, sinks map[string]*SinkOutcome, sinkLabels int, sup *SuppressionOutcome) []Violation {
	var v []Violation

	names := make([]string, 0, len(s.ByCheck))
	for k := range s.ByCheck {
		names = append(names, k)
	}
	sort.Strings(names)

	for _, n := range names {
		got := s.ByCheck[n]
		want, ok := base.Checks[n]
		if !ok {
			v = append(v, Violation{true, fmt.Sprintf(
				"check %s is scored but absent from the baseline; run `make score-update`", n)})
			continue
		}

		if got.TP < want.TP {
			v = append(v, Violation{true, fmt.Sprintf(
				"RECALL REGRESSION %s: TP %d -> %d (floor %d). Each lost label is a value "+
					"the redactor never sees, i.e. cleartext in the output.",
				n, want.TP, got.TP, want.TP)})
		}
		if got.TPBanded < want.TPBanded {
			v = append(v, Violation{true, fmt.Sprintf(
				"BAND REGRESSION %s: TP@H+M %d -> %d (floor %d). A LOW finding is still "+
					"redacted but no longer blocks a pre-commit hook.",
				n, want.TPBanded, got.TPBanded, want.TPBanded)})
		}
		if got.FNMissed > want.FNMissed {
			v = append(v, Violation{true, fmt.Sprintf(
				"MISSED LABELS %s: %d -> %d", n, want.FNMissed, got.FNMissed)})
		}

		ceiling := want.FPHigh + FPAllowance[n]
		if got.FPHigh > ceiling {
			v = append(v, Violation{true, fmt.Sprintf(
				"PRECISION REGRESSION %s: FP(H+M) %d -> %d (ceiling %d). Raise "+
					"FPAllowance[%q] in baseline.go if this is a deliberate tradeoff, so the "+
					"tradeoff is visible in the diff.",
				n, want.FPHigh, got.FPHigh, ceiling, n)})
		}
		if got.FPHigh < want.FPHigh {
			v = append(v, Violation{false, fmt.Sprintf(
				"IMPROVED %s: FP(H+M) %d -> %d. Run `make score-update` to lock the new "+
					"floor, or the next change gives the win back for free.",
				n, want.FPHigh, got.FPHigh)})
		}
		if got.TP > want.TP {
			v = append(v, Violation{false, fmt.Sprintf(
				"IMPROVED %s: TP %d -> %d. Run `make score-update`.", n, want.TP, got.TP)})
		}
	}

	// The sink is the half a detection-only score cannot see.
	strategies := make([]string, 0, len(sinks))
	for k := range sinks {
		strategies = append(strategies, k)
	}
	sort.Strings(strategies)

	for _, st := range strategies {
		got := sinks[st]
		want, ok := base.Sink[st]
		if !ok {
			v = append(v, Violation{true, fmt.Sprintf(
				"strategy %s scored but absent from the baseline; run `make score-update`", st)})
			continue
		}
		if got.WholeLeak > want.WholeLeak {
			v = append(v, Violation{true, fmt.Sprintf(
				"REDACTION SINK REGRESSION %s: whole_leak %d -> %d. A labelled value "+
					"survives verbatim in the redacted artifact.",
				st, want.WholeLeak, got.WholeLeak)})
		}
		if got.Residue4 > want.Residue4 {
			v = append(v, Violation{true, fmt.Sprintf(
				"MASK DEPTH REGRESSION %s: residue4 %d -> %d bytes. More of the original "+
					"value survives than before.",
				st, want.Residue4, got.Residue4)})
		}
		if got.Residue4 < want.Residue4 {
			v = append(v, Violation{false, fmt.Sprintf(
				"IMPROVED %s: residue4 %d -> %d bytes (deeper masking). Run `make score-update`.",
				st, want.Residue4, got.Residue4)})
		}
	}

	// The suppression layer: a rule must silence exactly the finding it names.
	//
	// Both directions are gated at the baseline, because both are real failures.
	// Collateral silencing is the dangerous one: the validator still detects the
	// value, the report says clean, and the suppression file makes it look reviewed.
	if sup != nil && base.Suppression != nil {
		if sup.Collateral > base.Suppression.Collateral {
			v = append(v, Violation{true, fmt.Sprintf(
				"SUPPRESSION OVER-REACH: collateral %d -> %d. A rule generated for one "+
					"finding silenced another. That finding is now invisible AND unredacted, "+
					"with an audit trail saying it was approved.",
				base.Suppression.Collateral, sup.Collateral)})
		}
		if sup.Ineffective > base.Suppression.Ineffective {
			v = append(v, Violation{true, fmt.Sprintf(
				"SUPPRESSION INEFFECTIVE: %d -> %d. A rule did not silence the finding it "+
					"names, so users will reach for --checks and disable a whole validator.",
				base.Suppression.Ineffective, sup.Ineffective)})
		}
		if sup.Targeted < base.Suppression.Targeted {
			v = append(v, Violation{true, fmt.Sprintf(
				"SUPPRESSION COVERAGE SHRANK: %d -> %d rules exercised.",
				base.Suppression.Targeted, sup.Targeted)})
		}
	}

	// A shrinking corpus must never look like a passing one: dropping the case that
	// carries a label is otherwise a free way to erase a failure.
	if s.Labels < base.Global.Labels {
		v = append(v, Violation{true, fmt.Sprintf(
			"CORPUS SHRANK: %d -> %d labels. Removing a case cannot be a way to pass.",
			base.Global.Labels, s.Labels)})
	}
	if sinkLabels < base.SinkLabels {
		v = append(v, Violation{true, fmt.Sprintf(
			"SINK COVERAGE SHRANK: %d -> %d labels exercised.", base.SinkLabels, sinkLabels)})
	}
	// The quarantine is count-gated so it cannot become a silent laundering channel:
	// moving a case in or out changes this number and fails until regenerated.
	if s.Undecided.Cases != base.Undecided.Cases {
		v = append(v, Violation{true, fmt.Sprintf(
			"QUARANTINE CHANGED: %d -> %d cases. Moving a case in or out of the ungated "+
				"set changes what is measured; regenerate and explain.",
			base.Undecided.Cases, s.Undecided.Cases)})
	}

	return v
}

// NewBaseline captures the current state as the floor.
func NewBaseline(s *Scorecard, sinks map[string]*SinkOutcome, sinkLabels int, sup *SuppressionOutcome) *Baseline {
	b := &Baseline{
		SchemaVersion: 1,
		Comment: "Committed floor for `make score`. Counts, not percentages. " +
			"Regenerate with `make score-update` and explain the delta in the PR body. " +
			"Some numbers record BUGS (the 45 fp_high_medium are real false positives " +
			"from non-SSN column headers), so a baseline is a floor to ratchet, never a goal.",
		Checks:     map[string]*CheckBaseline{},
		Sink:       map[string]*SinkBaseline{},
		SinkLabels: sinkLabels,
	}
	for n, o := range s.ByCheck {
		b.Checks[n] = &CheckBaseline{
			TP: o.TP, TPBanded: o.TPBanded,
			FNMissed: o.FNMissed, FNBand: o.FNBand,
			FPHigh: o.FPHigh, FPLow: o.FPLow, Extra: o.Extra,
		}
	}
	for st, so := range sinks {
		b.Sink[st] = &SinkBaseline{WholeLeak: so.WholeLeak, Residue4: so.Residue4}
	}
	if sup != nil {
		b.Suppression = &SuppressionBaseline{
			Cases: sup.Cases, Targeted: sup.Targeted, Silenced: sup.Silenced,
			Collateral: sup.Collateral, Ineffective: sup.Ineffective,
		}
	}
	b.Undecided.Cases = s.Undecided.Cases
	b.Undecided.Findings = s.Undecided.Findings
	b.Global.Cases = s.Cases
	b.Global.Labels = s.Labels
	for _, c := range GatedCases() {
		if c.Negative {
			b.Global.Negatives++
		}
	}
	return b
}

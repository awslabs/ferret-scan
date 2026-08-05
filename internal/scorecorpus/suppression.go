// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scorecorpus

import (
	"fmt"
	"path/filepath"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/suppressions"
)

// SuppressionOutcome measures whether a suppression rule silences EXACTLY the
// finding it names.
//
// Suppression is the one layer where the tool is asked to hide a real detection on
// purpose, which makes it the layer where a bug is least visible: the validator
// still detects the value, the report says clean, and the audit trail says a human
// approved it. An over-broad rule is a leak that looks like good hygiene.
//
// Two failures are measured, and they are opposites:
//
//   - Leaked: a rule generated for finding A also silences finding B. Collateral
//     damage — B is now invisible and, because only reported findings reach the
//     redactor, unredacted.
//   - Ineffective: a rule generated for A does not silence A. The user asked for
//     silence, the tool agreed, and the noise continues; they will stop trusting
//     suppression and start using --checks to exclude a whole validator instead.
type SuppressionOutcome struct {
	// Cases is how many cases were exercised.
	Cases int
	// Targeted is the number of findings a rule was generated for.
	Targeted int
	// Silenced is how many of those actually went quiet. Should equal Targeted.
	Silenced int
	// Collateral counts OTHER findings the rule silenced as a side effect.
	Collateral int
	// Ineffective counts targeted findings that stayed visible.
	Ineffective int
}

// ScoreSuppression generates a suppression rule for the FIRST finding of each
// multi-finding case, then rescans and checks what actually went quiet.
//
// The suppression file is written under dir (a t.TempDir()), never the user's
// ~/.ferret-scan/suppressions.yaml: NewSuppressionManager("") reads the real one,
// which would make this score depend on the developer's machine and could silence a
// labelled finding locally while CI sees it.
func ScoreSuppression(dir string) (*SuppressionOutcome, error) {
	cfg, err := config.LoadConfig("")
	if err != nil {
		return nil, fmt.Errorf("load pure default config: %w", err)
	}

	out := &SuppressionOutcome{}

	for _, c := range GatedCases() {
		// Need at least two findings: one to suppress and one that must survive.
		// A single-finding case cannot distinguish "silenced the target" from
		// "silenced everything".
		base, err := core.ScanContent(c.Input, scanConfig(c, cfg))
		if err != nil {
			return nil, fmt.Errorf("%s: baseline scan: %w", c.Name, err)
		}
		if len(base.Matches) < 2 {
			continue
		}

		before := canonical(base.Matches)
		target := before[0]

		// A fresh manager per case, rooted in a temp dir, so rules never accumulate
		// across cases and never touch the user's file.
		supPath := filepath.Join(dir, c.Name+"-suppressions.yaml")
		mgr := suppressions.NewSuppressionManager(supPath)
		if err := mgr.GenerateSuppressionRules([]detector.Match{target},
			"scorecorpus: suppression-layer measurement", true); err != nil {
			return nil, fmt.Errorf("%s: generate rule: %w", c.Name, err)
		}

		// Rescan WITH the manager applied.
		sc := scanConfig(c, cfg)
		sc.SuppressionManager = suppressions.NewSuppressionManager(supPath)
		after, err := core.ScanContent(c.Input, sc)
		if err != nil {
			return nil, fmt.Errorf("%s: suppressed scan: %w", c.Name, err)
		}

		out.Cases++
		out.Targeted++

		surviving := map[string]bool{}
		for _, m := range after.Matches {
			surviving[matchKey(m)] = true
		}

		if surviving[matchKey(target)] {
			out.Ineffective++
		} else {
			out.Silenced++
		}

		// Everything else that was visible before must still be visible.
		for _, m := range before[1:] {
			if !surviving[matchKey(m)] {
				out.Collateral++
			}
		}
	}

	return out, nil
}

// matchKey identifies a finding for before/after comparison.
//
// Text is included because a line can carry several findings; Type because two
// validators can claim the same bytes. Confidence is deliberately EXCLUDED: it is
// not an identity, and including it would report a confidence change as a
// suppression failure.
func matchKey(m detector.Match) string {
	return fmt.Sprintf("%d|%s|%s", m.LineNumber, m.Type, m.Text)
}

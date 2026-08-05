// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package precommit

import (
	"runtime"
	"testing"
)

// The exit code is this package's entire contract with a pre-commit hook, and the
// package shipped with no tests at all — which is how a precedence inversion in
// two copies of the same logic went unnoticed.
//
// The hook reads:
//
//	0 = nothing to stop the commit
//	1 = a blocking finding: STOP
//	2 = the tool could not complete: an infrastructure problem
//
// So returning 2 when a real secret was found does not merely mislabel the run,
// it changes what the hook does with it.

func blockAt(level string) *PrecommitConfig {
	return &PrecommitConfig{ExitOnFindings: level}
}

// The regression this file exists for: a blocking finding must outrank a
// processing error. Before the fix both exit-code functions tested hasErrors
// first, so one mislabeled file — a .docx that is really plain text, no attacker
// required — downgraded a real secret from "STOP" to "the tool broke".
func TestBlockingFindingOutranksProcessingError(t *testing.T) {
	got := GetExitCode(true, true, "high", blockAt("medium"))
	if got != 1 {
		t.Errorf("GetExitCode(findings=true, errors=true, high) = %d, want 1.\n"+
			"A blocking finding must win: a hook reads 2 as 'the tool broke' and lets the "+
			"commit through, so returning 2 here means one unreadable file silently "+
			"disables secret blocking for the whole commit.", got)
	}
}

// The complement, and the reason the fix is a REORDER rather than deleting the
// error branch: with nothing blocking to report, an incomplete scan must still not
// look like a clean pass.
func TestProcessingErrorStillReportedWhenNothingBlocks(t *testing.T) {
	if got := GetExitCode(false, true, "", blockAt("medium")); got != 2 {
		t.Errorf("GetExitCode(findings=false, errors=true) = %d, want 2 — an incomplete "+
			"scan must not exit 0, or a file that was never read passes as clean", got)
	}
	// Findings below the blocking threshold are not blocking, so the error is
	// still the most important thing to report.
	if got := GetExitCode(true, true, "low", blockAt("high")); got != 2 {
		t.Errorf("GetExitCode(low findings, errors=true, block-at-high) = %d, want 2: "+
			"nothing blocks, so the incomplete scan is the headline", got)
	}
}

// The full precedence table. Written as a table because the two failure modes are
// opposite — reporting 2 for a real finding lets a secret through, reporting 0 for
// a failed scan reports a file as clean that was never read — and only enumerating
// the combinations shows both.
func TestExitCodePrecedenceTable(t *testing.T) {
	cases := []struct {
		desc        string
		hasFindings bool
		hasErrors   bool
		confidence  string
		blockAt     string
		want        int
	}{
		{"clean scan", false, false, "", "medium", 0},
		{"clean scan, errors", false, true, "", "medium", 2},

		{"high finding, blocks at high", true, false, "high", "high", 1},
		{"high finding, blocks at medium", true, false, "high", "medium", 1},
		{"high finding, blocks at low", true, false, "high", "low", 1},

		{"medium finding, blocks at medium", true, false, "medium", "medium", 1},
		{"medium finding, blocks at high only", true, false, "medium", "high", 0},
		{"low finding, blocks at low", true, false, "low", "low", 1},
		{"low finding, blocks at medium", true, false, "low", "medium", 0},

		{"exit-on-findings none, high finding", true, false, "high", "none", 0},
		{"exit-on-findings none, high finding + errors", true, true, "high", "none", 2},

		// The regression rows.
		{"blocking finding AND errors", true, true, "high", "medium", 1},
		{"blocking medium finding AND errors", true, true, "medium", "medium", 1},
		{"non-blocking finding AND errors", true, true, "low", "high", 2},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			if got := GetExitCode(tc.hasFindings, tc.hasErrors, tc.confidence, blockAt(tc.blockAt)); got != tc.want {
				t.Errorf("GetExitCode(findings=%v, errors=%v, conf=%q, blockAt=%q) = %d, want %d",
					tc.hasFindings, tc.hasErrors, tc.confidence, tc.blockAt, got, tc.want)
			}
		})
	}
}

// A nil config must not block. The caller passes nil when pre-commit mode is off,
// and blocking a commit on a config that was never loaded would be a false stop.
func TestNilConfigNeverBlocks(t *testing.T) {
	if got := GetExitCode(true, false, "high", nil); got != 0 {
		t.Errorf("GetExitCode with nil config = %d, want 0 — with no pre-commit config "+
			"loaded there is no configured threshold to block against", got)
	}
	// An error is still an error without a config.
	if got := GetExitCode(true, true, "high", nil); got != 2 {
		t.Errorf("GetExitCode(errors=true, nil config) = %d, want 2", got)
	}
}

// The Windows and Unix functions must agree. They were separate copies of the same
// precedence, which is exactly how both came to carry the identical inversion —
// fixing one would have left the other wrong on the platform nobody tested by hand.
func TestWindowsAndUnixExitCodesAgree(t *testing.T) {
	for _, findings := range []bool{false, true} {
		for _, errs := range []bool{false, true} {
			for _, conf := range []string{"", "low", "medium", "high"} {
				for _, block := range []string{"none", "low", "medium", "high"} {
					cfg := blockAt(block)
					unix := GetExitCode(findings, errs, conf, cfg)
					win := GetWindowsExitCode(findings, errs, conf, cfg)
					if unix != win {
						t.Errorf("platform divergence for (findings=%v errors=%v conf=%q block=%q): "+
							"GetExitCode=%d GetWindowsExitCode=%d — the documented codes are "+
							"identical on both platforms, so a difference means one path was "+
							"fixed and the other was not",
							findings, errs, conf, block, unix, win)
					}
				}
			}
		}
	}
	t.Logf("checked both functions across the full combination space on %s", runtime.GOOS)
}

// ShouldExitOnFindings decides what "blocking" means, so the exit code inherits its
// behaviour. Pinned here because the exit-code table above assumes it.
func TestShouldExitOnFindingsThresholds(t *testing.T) {
	cases := []struct {
		blockAt    string
		confidence string
		want       bool
	}{
		{"none", "high", false},
		{"none", "medium", false},
		{"none", "low", false},

		{"high", "high", true},
		{"high", "medium", false},
		{"high", "low", false},

		{"medium", "high", true},
		{"medium", "medium", true},
		{"medium", "low", false},

		{"low", "high", true},
		{"low", "medium", true},
		{"low", "low", true},

		// An unrecognised setting must fail SAFE (block only on high), not open.
		{"nonsense", "high", true},
		{"nonsense", "medium", false},
		{"", "high", true},
		{"", "low", false},
	}
	for _, tc := range cases {
		got := blockAt(tc.blockAt).ShouldExitOnFindings(tc.confidence)
		if got != tc.want {
			t.Errorf("ExitOnFindings=%q, confidence=%q: got %v, want %v",
				tc.blockAt, tc.confidence, got, tc.want)
		}
	}
}

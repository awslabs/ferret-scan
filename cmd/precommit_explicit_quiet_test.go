// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/precommit"
)

// #547: the explicit-flag guard for --quiet was inert at the point it mattered.
//
// The detection path guards correctly — it applies the pre-commit quiet DEFAULT only when the operator
// did not ask, so `--quiet=false` survives. But four other places read `precommitConfig.QuietMode`
// DIRECTLY, which is the detected default rather than the decision. Measured on a clean file with
// --format json, before this change:
//
//	<no flags>                              238 bytes
//	--quiet=false                           238
//	--pre-commit-mode                         0   correct: quiet is the pre-commit default
//	--pre-commit-mode --quiet=false           0   DEFECT — the operator asked for a document
//
// An empty document is not a quiet document: a consumer gets a parse error or reads no findings. Same
// harm as the --output half of #353.
//
// The stdin path was broken differently and worse: it returns before the detection guard is ever
// reached, so no explicit --quiet was honoured there at all.
//
//	--stdin                                  20 bytes
//	--stdin --pre-commit-mode                 1
//	--stdin --pre-commit-mode --quiet=false   1   DEFECT
//
// After: only those two cases change (to 238 and 20). Every other row is byte-identical, which is what
// says this is a fix and not a behaviour change.
//
// Identifiers are prefixed pcq to stay distinct from the other cmd test files.

// pcqWithQuietFlag runs fn with a fresh FlagSet in which "quiet" is registered, and optionally SET to
// the given value — set meaning the operator passed it on the command line, which is what isFlagSet
// reports and what the whole guard turns on.
func pcqWithQuietFlag(t *testing.T, set bool, value bool, fn func()) {
	t.Helper()
	saved := flag.CommandLine
	t.Cleanup(func() { flag.CommandLine = saved })

	flag.CommandLine = flag.NewFlagSet("pcq", flag.ContinueOnError)
	q := flag.Bool("quiet", false, "")
	_ = q
	var args []string
	if set {
		if value {
			args = []string{"-quiet=true"}
		} else {
			args = []string{"-quiet=false"}
		}
	}
	if err := flag.CommandLine.Parse(args); err != nil {
		t.Fatalf("parse %v: %v", args, err)
	}
	// Non-vacuity of the harness itself: isFlagSet must agree with what we just did, or every case
	// below would be exercising the same branch.
	if got := isFlagSet("quiet"); got != set {
		t.Fatalf("harness bug: isFlagSet(\"quiet\") = %v after parsing %v, want %v", got, args, set)
	}
	fn()
}

func TestEffectivePrecommitQuietHonoursAnExplicitFlag(t *testing.T) {
	quietDetected := &precommit.PrecommitConfig{QuietMode: true}
	loudDetected := &precommit.PrecommitConfig{QuietMode: false}

	for _, tc := range []struct {
		name    string
		pc      *precommit.PrecommitConfig
		flagSet bool
		flagVal bool
		want    bool
	}{
		// Not in pre-commit mode at all: never quiet on this account.
		{"no precommit config", nil, false, false, false},
		{"no precommit config, --quiet=true", nil, true, true, false},

		// Detected quiet, operator silent: the DEFAULT applies. This is the behaviour the mode exists
		// to provide and must not regress.
		{"detected quiet, no flag", quietDetected, false, false, true},

		// Detected quiet, operator asked otherwise: the operator wins. This is the defect.
		{"detected quiet, --quiet=false", quietDetected, true, false, false},
		{"detected quiet, --quiet=true", quietDetected, true, true, true},

		// Detected non-quiet: an explicit --quiet=true still applies, so the helper cannot simply
		// return the detected value.
		{"detected loud, no flag", loudDetected, false, false, false},
		{"detected loud, --quiet=true", loudDetected, true, true, true},
		{"detected loud, --quiet=false", loudDetected, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pcqWithQuietFlag(t, tc.flagSet, tc.flagVal, func() {
				if got := effectivePrecommitQuiet(tc.pc); got != tc.want {
					t.Errorf("effectivePrecommitQuiet = %v, want %v\n"+
						"detected quiet=%v, flag set=%v value=%v.\n"+
						"When this is wrong in the true direction the operator asked for output and "+
						"got an empty document; in the false direction the pre-commit default stops "+
						"working and every hook run becomes noisy.",
						got, tc.want, tc.pc != nil && tc.pc.QuietMode, tc.flagSet, tc.flagVal)
				}
			})
		})
	}
}

// TestNoFormatterOptionReadsTheDetectedQuietDirectly is the guard that stops the four sites drifting
// apart again. The defect was not that any single site was wrong — it was that one rule had five
// implementations and four of them forgot the flag.
func TestNoFormatterOptionReadsTheDetectedQuietDirectly(t *testing.T) {
	raw := pcqReadCmdSources(t)
	// PrecommitMode must be computed by the shared helper, never from the detected value.
	for _, bad := range []string{
		"PrecommitMode:   precommitConfig != nil && precommitConfig.QuietMode",
		"PrecommitMode: precommitConfig != nil && precommitConfig.QuietMode",
		"PrecommitMode:   precommitConfig.QuietMode",
	} {
		for name, src := range raw {
			if pcqContains(src, bad) {
				t.Errorf("%s computes FormatterOptions.PrecommitMode from the DETECTED quiet value "+
					"(%q) instead of effectivePrecommitQuiet(precommitConfig). An explicit "+
					"--quiet=false is then discarded and the formatter emits an empty document.",
					name, bad)
			}
		}
	}
}

func pcqReadCmdSources(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, name := range []string{"main.go", "stdin.go"} {
		b, err := pcqReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		out[name] = b
	}
	if len(out) != 2 {
		t.Fatalf("read %d cmd sources, want 2", len(out))
	}
	return out
}

func pcqReadFile(name string) (string, error) {
	b, err := os.ReadFile(name) // #nosec G304 -- a file in this package's own directory
	return string(b), err
}

func pcqContains(hay, needle string) bool { return strings.Contains(hay, needle) }

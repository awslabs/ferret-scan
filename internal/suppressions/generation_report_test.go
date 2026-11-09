// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suppressions

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// TestGenerationCountsWhatItDid: LastGeneration counts the rules a regeneration added, refreshed and
// migrated (#885), for the CLI to report.
func TestGenerationCountsWhatItDid(t *testing.T) {
	if got := (&SuppressionManager{}).LastGeneration(); got != (GenerationReport{}) {
		t.Errorf("a manager that never generated reports %+v", got)
	}

	for _, version := range []hashVersion{hashVersionNoConfidence, hashVersionLegacyConfidence} {
		path, lf, _ := crlfRuleFile(t, version)
		sm, _ := loadWithWarnings(t, path)
		// The same finding twice, and one new: one rule migrated once, refreshed twice; one added.
		other := onLine("ssn 123-45-6781", "123-45-6781", "SSN", 5)
		if err := sm.GenerateSuppressionRules([]detector.Match{lf, lf, other}, "generated", false); err != nil {
			t.Fatal(err)
		}
		if got, want := sm.LastGeneration(), (GenerationReport{Added: 1, Refreshed: 2, Migrated: 1}); got != want {
			t.Errorf("v%d: %+v, want %+v", version, got, want)
		}
		// Regenerating again finds every rule in the current formula already.
		again, _ := loadWithWarnings(t, path)
		if err := again.GenerateSuppressionRules([]detector.Match{lf, other}, "generated", false); err != nil {
			t.Fatal(err)
		}
		if got, want := again.LastGeneration(), (GenerationReport{Refreshed: 2}); got != want {
			t.Errorf("v%d: second regeneration %+v, want %+v", version, got, want)
		}
	}

	t.Run("a refused rule is not counted as migrated", func(t *testing.T) {
		path, lf, before := crlfRuleFile(t, hashVersionNoConfidence)
		refused := insertAfter(before, "      enabled: true\n", "      expries_at: 2026-01-01T00:00:00Z")
		if err := os.WriteFile(path, []byte(refused), 0o600); err != nil {
			t.Fatal(err)
		}
		sm, _ := loadWithWarnings(t, path)
		if err := sm.GenerateSuppressionRules([]detector.Match{lf}, "generated", false); err != nil {
			t.Fatal(err)
		}
		if got := sm.LastGeneration(); got.Migrated != 0 {
			t.Errorf("%+v, want no migration", got)
		}
	})

	t.Run("a save that fails reports nothing", func(t *testing.T) {
		// A directory where the file should be: the write fails.
		sm, _ := loadWithWarnings(t, t.TempDir())
		if err := sm.GenerateSuppressionRules(strictTestMatches(), "generated", false); err == nil {
			t.Fatal("writing over a directory succeeded")
		}
		if got := sm.LastGeneration(); got != (GenerationReport{}) {
			t.Errorf("%+v, want the zero report", got)
		}
	})

	t.Run("a fresh file only adds", func(t *testing.T) {
		sm, _ := loadWithWarnings(t, filepath.Join(t.TempDir(), "rules.yaml"))
		if err := sm.GenerateSuppressionRules(strictTestMatches(), "generated", false); err != nil {
			t.Fatal(err)
		}
		if got, want := sm.LastGeneration(), (GenerationReport{Added: 2}); got != want {
			t.Errorf("%+v, want %+v", got, want)
		}
	})
}

// TestTheGenerationReportIsPrinted: the line --generate-suppressions prints replaces "existing rules had
// last_seen_at updated, new rules added", which it printed whatever had happened (#885).
func TestTheGenerationReportIsPrinted(t *testing.T) {
	var buf bytes.Buffer
	WriteGenerationReport(&buf, GenerationReport{Added: 3, Refreshed: 12})
	if want := "Updated suppression rules: added 3 (disabled by default), refreshed 12, re-anchored 0, migrated 0 " +
		"to the current hash formula\n"; buf.String() != want {
		t.Errorf("%q\nwant %q", buf.String(), want)
	}

	buf.Reset()
	WriteGenerationReport(&buf, GenerationReport{ReAnchored: 5, Ambiguous: 2, Unmatched: 1, NotEvaluated: 4})
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != 5 || !strings.Contains(lines[0], "re-anchored 5,") ||
		!strings.HasPrefix(lines[1], "Note: 5 rule(s) whose finding moved to another line now name that line") ||
		!strings.HasPrefix(lines[2], "Note: 2 rule(s) were not re-anchored because their finding cannot be told apart") ||
		!strings.HasPrefix(lines[3], "Note: 1 rule(s) for files with findings in this run matched none of them") ||
		lines[4] != "Note: re-anchoring stopped at its limit of 500000 comparisons; 4 rule(s) were not considered and are unchanged" {
		t.Errorf("report:\n%s", buf.String())
	}
}

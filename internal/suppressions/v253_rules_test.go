// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suppressions

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// A rule file written by the v2.5.3 binary loads, suppresses the findings it was written for, and is
// migrated by regenerating (#885 box 2).
//
// testdata/v2.5.3-rules.yaml is the output of `ferret-scan` built from the v2.5.3 tag, run with
// --generate-suppressions over the five-line fixture below, with the four rules switched on and nothing
// else touched. The other identity tests build their old-formula hashes with this package's own
// findingHashVersion, which is the code under test; this file's hashes were written by a binary that no
// longer exists, so a formula the package changed without meaning to fails here.

// v253Findings are the four findings v2.5.3 reported on the fixture, with the context windows the scanner
// gave them: lines 2-4 carry whitespace at an outer edge (indent, a trailing space, the CR of a CRLF file),
// line 5 carries none.
func v253Findings() []detector.Match {
	on := func(line, value, typ, validator string, confidence float64, lineNo int) detector.Match {
		start := strings.Index(line, value)
		return detector.Match{Type: typ, Text: value, Filename: "customers.txt", LineNumber: lineNo,
			Confidence: confidence, Validator: validator, Context: detector.LineContext(line, start, start+len(value))}
	}
	return []detector.Match{
		on("\tpayment card on file: 4539 0123 4567 8905\r", "4539 0123 4567 8905", "VISA", "creditcard", 100, 3),
		on("payment card on file: 4539 0123 4567 8905", "4539 0123 4567 8905", "VISA", "creditcard", 100, 5),
		on("    contact email: jordan.sample@example.com \r", "jordan.sample@example.com", "BUSINESS", "email", 56, 2),
		on("  social security number: 123-45-6780  \r", "123-45-6780", "SSN", "ssn", 100, 4),
	}
}

// v253RuleIDs is the rule each finding has in the file, in v253Findings' order.
var v253RuleIDs = []string{"SUP-00000001", "SUP-00000002", "SUP-00000003", "SUP-00000004"}

// lfForm is the finding as an LF checkout reads it: no CR, so only the other edge whitespace is left.
func lfForm(m detector.Match) detector.Match {
	m.Context.FullLine = strings.TrimSuffix(m.Context.FullLine, "\r")
	m.Context.AfterText = strings.TrimSuffix(m.Context.AfterText, "\r")
	return m
}

func TestV253RuleFileLoadsAndSuppressesItsFindings(t *testing.T) {
	sm, warnings := loadWithWarnings(t, filepath.Join("testdata", "v2.5.3-rules.yaml"))
	if warnings != "" {
		t.Errorf("a v2.5.3 rule file loaded with warnings:\n%s", warnings)
	}
	rules := sm.ListSuppressions()
	if len(rules) != 4 {
		t.Fatalf("%d rules loaded, want the file's 4", len(rules))
	}
	byID := map[string]SuppressionRule{}
	for _, r := range rules {
		byID[r.ID] = r
		if !r.Enabled {
			t.Errorf("%s: loaded disabled", r.ID)
		}
	}

	found := v253Findings()
	v2 := map[string]bool{}
	v5 := map[string]bool{}
	for i, m := range found {
		rule, ok := byID[v253RuleIDs[i]]
		if !ok {
			t.Fatalf("rule %s is not in the file", v253RuleIDs[i])
		}
		// The calibration: the hash v2.5.3 wrote is the v2 formula over this finding. It is what makes the
		// finding above the one the binary saw rather than a lookalike.
		hv2, hv5 := sm.findingHashVersion(m, hashVersionNoConfidence), sm.generateFindingHash(m)
		if rule.Hash != hv2 {
			t.Errorf("%s: the v2.5.3 hash is %s, the v2 formula gives %s", rule.ID, rule.Hash, hv2)
		}
		// Distinct identities: v2 and v5 differ exactly where the line has edge whitespace.
		if edge := m.Context.FullLine != strings.TrimSpace(m.Context.FullLine); edge == (hv2 == hv5) {
			t.Errorf("%s: edge whitespace %v, but v2 == v5 is %v", rule.ID, edge, hv2 == hv5)
		}
		v2[hv2], v5[hv5] = true, true

		// The old rule suppresses its finding as scanned (CRLF) and in the LF copy.
		for name, form := range map[string]detector.Match{"CRLF": m, "LF": lfForm(m)} {
			if ok, matched := sm.IsSuppressed(form); !ok || matched.ID != rule.ID {
				t.Errorf("%s: the v2.5.3 rule does not suppress its %s finding (got %q)", rule.ID, name, matched.ID)
			}
		}
	}
	if len(v2) != len(found) || len(v5) != len(found) {
		t.Errorf("distinct identities: %d under v2, %d under v5, want %d each", len(v2), len(v5), len(found))
	}
}

// TestV253RuleFileIsMigratedByRegenerating: the three rules whose finding has edge whitespace get their
// hash rewritten to v5 and nothing else; the fourth, whose v2 and v5 hashes are one, is only refreshed;
// the file's header and the other fields stay.
func TestV253RuleFileIsMigratedByRegenerating(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("testdata", "v2.5.3-rules.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}
	sm, _ := loadWithWarnings(t, path)
	found := v253Findings()
	if err := sm.GenerateSuppressionRules(found, "generated", false); err != nil {
		t.Fatal(err)
	}
	report := sm.LastGeneration()
	if report.Added != 0 || report.Migrated != 3 || report.ReAnchored != 0 {
		t.Errorf("generation: added %d, migrated %d, re-anchored %d, want 0, 3, 0", report.Added, report.Migrated, report.ReAnchored)
	}

	reloaded, _ := loadWithWarnings(t, path)
	rules := reloaded.ListSuppressions()
	if len(rules) != 4 {
		t.Fatalf("%d rules after regenerating, want 4", len(rules))
	}
	for i, m := range found {
		var got SuppressionRule
		for _, r := range rules {
			if r.ID == v253RuleIDs[i] {
				got = r
			}
		}
		if want := reloaded.generateFindingHash(m); got.Hash != want {
			t.Errorf("%s: hash %s after regenerating, want the v5 hash %s", got.ID, got.Hash, want)
		}
		if ok, _ := reloaded.IsSuppressed(lfForm(m)); !ok {
			t.Errorf("%s: the migrated rule no longer suppresses the LF copy", got.ID)
		}
	}
	after, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(after), "# A rule file written by ferret-scan v2.5.3") {
		t.Errorf("the header comment was lost:\n%s", after)
	}
}

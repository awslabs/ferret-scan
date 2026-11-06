// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suppressions

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// Migration happens at an explicit write only: --generate-suppressions rewrites a rule it matched
// through an older formula to the current one and keeps every other field (#885). Scan time never
// writes. These tests use only methods that predate the change, so they also run against the parent
// commit, where the migration test fails and the other two, the controls, pass.

// crlfRuleFile writes a one-rule file whose hash is formula version of the finding's CRLF form, the
// rule a v2.5 binary wrote for it in a CRLF checkout, and returns the path, the LF finding and the text.
func crlfRuleFile(t *testing.T, version hashVersion) (string, detector.Match, string) {
	t.Helper()
	sm := &SuppressionManager{}
	lf := onLine("ssn 123-45-6780 \t", "123-45-6780", "SSN", 4)
	crlf := onLine("ssn 123-45-6780 \t\r", "123-45-6780", "SSN", 4)
	old := sm.findingHashVersion(crlf, version)
	if old == currentHashOf(lf) {
		t.Fatal("fixture error: the old hash already is the current one")
	}
	text := "# reviewed by the security team\nversion: \"1.0\"\nrules:\n" +
		"    - id: SUP-00000007\n" +
		"      hash: " + old + " # pragma: allowlist secret\n" +
		"      reason: Reviewed, a test value\n" +
		"      enabled: true\n" +
		"      created_by: reviewer\n" +
		"      created_at: 2026-05-01T10:00:00Z\n" +
		"      last_seen_at: 2026-05-01T10:00:00Z\n" +
		"      expires_at: 2030-01-01T00:00:00Z\n" +
		"      metadata:\n" +
		"        confidence: \"90.00\"\n" +
		"        filename: customers.txt\n" +
		"        finding_type: SSN\n" +
		"        line_number: \"4\"\n" +
		"        ticket: SEC-42\n"
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, lf, text
}

// currentHashOf is the hash a rule written today records for m. It is the identity's known answer
// for this fixture's shape, so the assertion does not rest on the code under test.
func currentHashOf(m detector.Match) string {
	trimmed := m
	trimmed.Context.BeforeText = strings.TrimLeft(m.Context.BeforeText, " \t\r")
	trimmed.Context.AfterText = strings.TrimRight(m.Context.AfterText, " \t\r")
	trimmed.Text = strings.TrimSpace(m.Text)
	return (&SuppressionManager{}).findingHashVersion(trimmed, hashVersionNoConfidence)
}

func TestRegeneratingMigratesAnOlderRuleInPlace(t *testing.T) {
	for _, version := range []hashVersion{hashVersionNoConfidence, hashVersionLegacyConfidence} {
		path, lf, before := crlfRuleFile(t, version)
		sm, _ := loadWithWarnings(t, path)
		if ok, _ := sm.IsSuppressed(lf); !ok {
			t.Errorf("v%d: the old rule does not suppress the finding in the LF copy", version)
			continue
		}
		if err := sm.GenerateSuppressionRules([]detector.Match{lf, lf}, "generated", false); err != nil {
			t.Fatal(err)
		}

		reloaded, _ := loadWithWarnings(t, path)
		rules := reloaded.ListSuppressions()
		if len(rules) != 1 {
			t.Fatalf("v%d: %d rules after regenerating, want the one, migrated", version, len(rules))
		}
		r := rules[0]
		if want := currentHashOf(lf); r.Hash != want {
			t.Errorf("v%d: hash %s after regenerating, want the current formula's %s", version, r.Hash, want)
		}
		expires := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
		if r.ID != "SUP-00000007" || r.Reason != "Reviewed, a test value" || !r.Enabled || r.CreatedBy != "reviewer" ||
			r.ExpiresAt == nil || !r.ExpiresAt.Equal(expires) || r.Metadata["ticket"] != "SEC-42" || r.Metadata["line_number"] != "4" {
			t.Errorf("v%d: the migrated rule lost a field: %+v", version, r)
		}
		if ok, _ := reloaded.IsSuppressed(lf); !ok {
			t.Errorf("v%d: the migrated rule does not suppress its finding", version)
		}

		// Only the hash and last_seen_at lines changed; the comments stayed.
		after := readText(t, path)
		bl, al := strings.Split(before, "\n"), strings.Split(after, "\n")
		if len(bl) != len(al) {
			t.Fatalf("v%d: %d lines became %d:\n%s", version, len(bl), len(al), after)
		}
		for i := range bl {
			if bl[i] != al[i] && !strings.HasPrefix(bl[i], "      hash: ") && !strings.HasPrefix(bl[i], "      last_seen_at: ") {
				t.Errorf("v%d: line %d changed: %q -> %q", version, i+1, bl[i], al[i])
			}
		}
		if !strings.Contains(after, " # pragma: allowlist secret\n") {
			t.Errorf("v%d: the migrated hash lost its pragma comment:\n%s", version, after)
		}
	}
}

// TestRegeneratingLeavesARefusedRuleAlone: a rule the loader refused (#866) is not rewritten.
func TestRegeneratingLeavesARefusedRuleAlone(t *testing.T) {
	path, lf, before := crlfRuleFile(t, hashVersionNoConfidence)
	refused := strings.Replace(before, "      enabled: true\n", "      enabled: true\n      expries_at: 2026-01-01T00:00:00Z\n", 1)
	if err := os.WriteFile(path, []byte(refused), 0o600); err != nil {
		t.Fatal(err)
	}
	sm, _ := loadWithWarnings(t, path)
	oldHash := sm.ListSuppressions()[0].Hash
	if err := sm.GenerateSuppressionRules([]detector.Match{lf}, "generated", false); err != nil {
		t.Fatal(err)
	}
	if got := sm.ListSuppressions()[0].Hash; got != oldHash {
		t.Errorf("the refused rule's hash was rewritten to %s", got)
	}
}

// TestScanningNeverMigrates: matching through an older formula changes nothing on disk.
func TestScanningNeverMigrates(t *testing.T) {
	path, lf, before := crlfRuleFile(t, hashVersionNoConfidence)
	sm, _ := loadWithWarnings(t, path)
	for i := 0; i < 3; i++ {
		sm.IsSuppressed(lf)
	}
	if readText(t, path) != before {
		t.Error("IsSuppressed wrote the rule file")
	}
}

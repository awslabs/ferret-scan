// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suppressions

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"

	"gopkg.in/yaml.v3"
)

// A save used to yaml.Marshal the struct, deleting every comment and every key the struct does not
// model: measured, one --generate-suppressions run removed this repository's 33-line baseline header,
// and a disable from the web UI removed a header comment, a misspelled expiry and a custom metadata key
// in one go (#866). These tests pin what a save must leave alone.

// copyToTemp copies src into a temp dir and returns the copy's path; the original is never written.
func copyToTemp(t *testing.T, src string) string {
	t.Helper()
	data, err := os.ReadFile(src) // #nosec G304 -- repository fixture
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), filepath.Base(src))
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return dst
}

func readText(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestASaveKeepsWhatItDoesNotOwn drives the mutations the web UI and the CLI perform against a file
// carrying all six things a save used to delete: a header comment, a rule head comment, a line comment
// on a key, an unknown rule key, an unknown top-level key and a custom metadata key.
func TestASaveKeepsWhatItDoesNotOwn(t *testing.T) {
	path := copyToTemp(t, filepath.Join("testdata", "commented-rules.yaml"))
	sm, warnings := loadWithWarnings(t, path)
	if !strings.Contains(warnings, `SUP-00000002 "reviewer_note" (line 22)`) ||
		!strings.Contains(warnings, `"owner" (line 6)`) {
		t.Errorf("the fixture's unknown rule key was not named; got:\n%s", warnings)
	}

	if err := sm.DisableSuppressionByID("SUP-00000001"); err != nil {
		t.Fatal(err)
	}
	if err := sm.EditSuppression("SUP-00000003", "Reviewed: a fixture", "reviewer", true, nil); err != nil {
		t.Fatal(err)
	}
	extra := detector.Match{Type: "SSN", Text: "fixture-value", Filename: "extra.txt", LineNumber: 3, Validator: "ssn"}
	if err := sm.AddSuppression(extra, "added", "unit test", nil); err != nil {
		t.Fatal(err)
	}

	text := readText(t, path)
	for _, want := range []string{
		"# Team suppression baseline (fixture for preserving_save_test.go).\n#\n# Reviewed by the security team; keep this header.\n\nversion: \"1.0\"\n",
		"owner: platform-security\n",
		"    # Rule 1: test fixture in the docs.\n",
		"      enabled: false # reviewed 2026-10-01\n",
		"      reason: 'Documented example, not a real value'\n",
		"        ticket: SEC-1234\n",
		"      reviewer_note: keep until the benchmark is rewritten\n",
		"    # Rule 3: generated, still under review.\n",
		"      reason: 'Reviewed: a fixture'\n",
		"      created_by: reviewer\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("after three saves the file lacks %q:\n%s", want, text)
		}
	}

	// And the edits are real: a reload sees them, and the refused rule is still refused.
	reloaded, warnings := loadWithWarnings(t, path)
	rules := reloaded.ListSuppressions()
	if len(rules) != 4 {
		t.Fatalf("%d rules after the saves, want 4", len(rules))
	}
	if rules[0].Enabled || !rules[2].Enabled || rules[2].Reason != "Reviewed: a fixture" || rules[3].Reason != "added" {
		t.Errorf("the saved values did not survive a reload: %+v", rules)
	}
	if !strings.Contains(warnings, `SUP-00000002 "reviewer_note"`) {
		t.Errorf("after the saves the rule with the unknown key is no longer refused; the key must survive "+
			"the save and keep refusing it. Reload printed:\n%s", warnings)
	}
}

// TestASaveWithNoChangeIsByteIdentical, on the fixture and on the committed baseline.
func TestASaveWithNoChangeIsByteIdentical(t *testing.T) {
	for _, src := range []string{
		filepath.Join("testdata", "commented-rules.yaml"),
		filepath.Join("..", "..", ".ferret-scan-suppressions.yaml"),
	} {
		path := copyToTemp(t, src)
		before := readText(t, path)
		sm, _ := loadWithWarnings(t, path)
		if err := sm.saveConfig(); err != nil {
			t.Fatal(err)
		}
		if after := readText(t, path); after != before {
			t.Errorf("%s changed on a save with nothing to change:\n%s", src, firstDifference(before, after))
		}
	}
}

// TestRegeneratingTheBaselineTouchesOnlyLastSeenAtAndTheNewRules is the issue's baseline check: a
// --generate-suppressions run may refresh last_seen_at and append rules, and nothing else. The 245 rules
// are all lapsed, so this checks bytes, not suppression.
func TestRegeneratingTheBaselineTouchesOnlyLastSeenAtAndTheNewRules(t *testing.T) {
	path := copyToTemp(t, filepath.Join("..", "..", ".ferret-scan-suppressions.yaml"))
	before := readText(t, path)
	sm, _ := loadWithWarnings(t, path)
	now := time.Now()
	for _, i := range []int{0, 100, len(sm.config.Rules) - 1} {
		sm.config.Rules[i].LastSeenAt = &now // what GenerateSuppressionRules does for a finding it already has
	}
	if err := sm.GenerateSuppressionRules(strictTestMatches(), "Auto-generated suppression rule (disabled by default)", false); err != nil {
		t.Fatal(err)
	}
	after := readText(t, path)

	if !strings.HasPrefix(after, before[:strings.Index(before, "version:")]) {
		t.Errorf("the header changed:\n%s", firstDifference(before, after))
	}
	old := strings.Split(strings.TrimSuffix(before, "\n"), "\n")
	cur := strings.Split(strings.TrimSuffix(after, "\n"), "\n")
	isLastSeen := func(l string) bool { return strings.HasPrefix(strings.TrimSpace(l), "last_seen_at:") }
	i, j, changed := 0, 0, 0
	for i < len(old) && j < len(cur) {
		switch {
		case old[i] == cur[j]:
			i, j = i+1, j+1
		case isLastSeen(old[i]) && isLastSeen(cur[j]):
			i, j, changed = i+1, j+1, changed+1
		default:
			t.Fatalf("line %d changed and it is not a last_seen_at line:\n- %s\n+ %s", i+1, old[i], cur[j])
		}
	}
	if changed != 3 {
		t.Errorf("%d last_seen_at lines changed, want 3", changed)
	}
	if i < len(old) {
		t.Fatalf("the saved file is shorter than the original: stopped at line %d of %d", i+1, len(old))
	}
	tail := strings.Join(cur[j:], "\n")
	if got := strings.Count(tail, "    - id: SUP-"); got != 2 || !strings.HasPrefix(tail, "    - id: SUP-00000246\n") {
		t.Errorf("the appended tail is not the 2 new rules:\n%s", tail)
	}
}

// TestAPatchedFileIsLaidOutLikeAGeneratedOne: for a file the tool wrote, saving through the node tree
// must produce exactly what the old marshal-the-struct saver produced, or every regeneration would
// churn the layout.
func TestAPatchedFileIsLaidOutLikeAGeneratedOne(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sup.yaml")
	if err := os.WriteFile(path, []byte(generatedTwoRuleText(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	sm, _ := loadWithWarnings(t, path)
	more := detector.Match{Type: "SSN", Text: "third-value", Filename: "other.txt", LineNumber: 9, Validator: "ssn"}
	if err := sm.GenerateSuppressionRules([]detector.Match{more}, "Auto-generated suppression rule", false); err != nil {
		t.Fatal(err)
	}
	marshalled, err := yaml.Marshal(sm.config)
	if err != nil {
		t.Fatal(err)
	}
	if want, got := string(annotateHashesWithAllowlistPragma(marshalled)), readText(t, path); got != want {
		t.Errorf("a patched generated file differs from what yaml.Marshal writes:\n%s", firstDifference(want, got))
	}
}

// TestSettingAndClearingAnExpiryEditsOneLine: the web UI's edit sets and clears expires_at; each is a
// one-line change, in the place a generated rule has it, and clearing it restores the file exactly.
func TestSettingAndClearingAnExpiryEditsOneLine(t *testing.T) {
	path := copyToTemp(t, filepath.Join("testdata", "commented-rules.yaml"))
	before := readText(t, path)
	sm, _ := loadWithWarnings(t, path)
	rule := sm.ListSuppressions()[2]
	at := time.Date(2027, 6, 30, 0, 0, 0, 0, time.UTC)
	if err := sm.EditSuppression(rule.ID, rule.Reason, rule.CreatedBy, rule.Enabled, &at); err != nil {
		t.Fatal(err)
	}
	set := readText(t, path)
	if want := "      last_seen_at: 2026-10-03T09:00:00Z\n      expires_at: 2027-06-30T00:00:00Z\n"; !strings.Contains(set, want) {
		t.Errorf("the expiry was not written after last_seen_at:\n%s", set)
	}
	if got := len(strings.Split(set, "\n")) - len(strings.Split(before, "\n")); got != 1 {
		t.Errorf("setting an expiry changed the line count by %d, want 1", got)
	}
	if err := sm.EditSuppression(rule.ID, rule.Reason, rule.CreatedBy, rule.Enabled, nil); err != nil {
		t.Fatal(err)
	}
	if cleared := readText(t, path); cleared != before {
		t.Errorf("clearing the expiry did not restore the file:\n%s", firstDifference(before, cleared))
	}
}

// TestRemovingARuleRemovesOnlyItsLines: the rule's own head comment goes with it; nothing else moves.
func TestRemovingARuleRemovesOnlyItsLines(t *testing.T) {
	path := copyToTemp(t, filepath.Join("testdata", "commented-rules.yaml"))
	before := readText(t, path)
	sm, _ := loadWithWarnings(t, path)
	if err := sm.RemoveSuppression("SUP-00000003"); err != nil {
		t.Fatal(err)
	}
	cut := strings.Index(before, "    # Rule 3: generated, still under review.\n")
	if want, got := before[:cut], readText(t, path); got != want {
		t.Errorf("removing the last rule changed more than its own lines:\n%s", firstDifference(want, got))
	}
}

// firstDifference shows where two texts first differ, for a readable failure.
func firstDifference(a, b string) string {
	al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
	for i := 0; i < len(al) || i < len(bl); i++ {
		var x, y string
		if i < len(al) {
			x = al[i]
		}
		if i < len(bl) {
			y = bl[i]
		}
		if x != y {
			return fmt.Sprintf("first difference at line %d:\n- %s\n+ %s", i+1, x, y)
		}
	}
	return "(identical)"
}

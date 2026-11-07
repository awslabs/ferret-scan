// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suppressions

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// Re-anchoring (#885): --generate-suppressions moves a rule whose finding moved to another line, and
// only then. These tests are the issue's list: an in-place update with no new rule; decoys for an edited
// line, one rule with two identical lines, two rules with one finding, the same basename in two
// directories; a v1 rule through metadata.confidence; a rule without line_number skipped and counted;
// the cap honoured.

// noteLines is the issue's fixture, customers.txt, with placeholder values where it had an email.
var noteLines = []struct{ line, value, typ, validator string }{
	{"Customer onboarding notes", "", "", ""},
	{"contact email: contact-value-2", "contact-value-2", "BUSINESS", "email"},
	{"payment card on file: 4539 0123 4567 8905", "4539 0123 4567 8905", "VISA", "creditcard"},
	{"social security number: 123-45-6780", "123-45-6780", "SSN", "ssn"},
	{"date of birth: 03/17/1984", "03/17/1984", "DATE_OF_BIRTH", "dob"},
	{"alt card 5520 1234 5678 9015 for refunds", "5520 1234 5678 9015", "MASTERCARD", "creditcard"},
}

// noteFindings is the findings of the fixture in file path, with `above` lines inserted at its top.
func noteFindings(path string, above int) []detector.Match {
	var out []detector.Match
	for i, l := range noteLines {
		if l.value == "" {
			continue
		}
		m := onLine(l.line, l.value, l.typ, i+1+above)
		m.Filename, m.Validator = path, l.validator
		out = append(out, m)
	}
	return out
}

// enabledRulesFor writes the rules GenerateSuppressionRules creates for findings, enabled, with an
// expiry, a reviewer and a comment, and returns the file's path and text.
func enabledRulesFor(t *testing.T, findings []detector.Match) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := NewSuppressionManager(path).GenerateSuppressionRules(findings, "generated", false); err != nil {
		t.Fatal(err)
	}
	text := strings.ReplaceAll(readText(t, path), "enabled: false", "enabled: true")
	text = strings.ReplaceAll(text, "    reason: generated\n", "    reason: reviewed by the onboarding team\n")
	text = insertAfter(text, "      enabled: true\n", "      expires_at: 2030-01-01T00:00:00Z")
	text = "# baseline, reviewed 2026-11-01\n" + text
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, text
}

func countSuppressed(sm *SuppressionManager, findings []detector.Match) int {
	n := 0
	for _, f := range findings {
		if ok, _ := sm.IsSuppressed(f); ok {
			n++
		}
	}
	return n
}

// regenerate loads path, regenerates it with findings and returns the report and the reloaded rules.
func regenerate(t *testing.T, path string, findings []detector.Match) (GenerationReport, []SuppressionRule) {
	t.Helper()
	sm, _ := loadWithWarnings(t, path)
	if err := sm.GenerateSuppressionRules(findings, "generated", false); err != nil {
		t.Fatal(err)
	}
	reloaded, _ := loadWithWarnings(t, path)
	return sm.LastGeneration(), reloaded.ListSuppressions()
}

func TestALineInsertedAboveReanchorsEveryRuleInPlace(t *testing.T) {
	path, before := enabledRulesFor(t, noteFindings("customers.txt", 0))
	moved := noteFindings("customers.txt", 1)
	sm, _ := loadWithWarnings(t, path)
	if got := countSuppressed(sm, moved); got != 0 {
		t.Fatalf("fixture error: %d of the moved findings are suppressed before regenerating", got)
	}
	old := sm.ListSuppressions()

	report, rules := regenerate(t, path, moved)
	if want := (GenerationReport{ReAnchored: 5}); report != want {
		t.Errorf("report %+v, want %+v", report, want)
	}
	if len(rules) != 5 {
		t.Fatalf("%d rules after regenerating, want the same 5", len(rules))
	}
	for i, r := range rules {
		o := old[i]
		if r.ID != o.ID || r.Reason != o.Reason || !r.Enabled || r.ExpiresAt == nil || !r.ExpiresAt.Equal(*o.ExpiresAt) ||
			!r.CreatedAt.Equal(o.CreatedAt) || r.Metadata["confidence"] != o.Metadata["confidence"] ||
			r.Metadata["filename"] != o.Metadata["filename"] || r.Metadata["finding_type"] != o.Metadata["finding_type"] {
			t.Errorf("rule %s changed more than its hash, line and last_seen_at:\nwas %+v\nnow %+v", o.ID, o, r)
		}
		if want := strconv.Itoa(moved[i].LineNumber); r.Metadata["line_number"] != want {
			t.Errorf("rule %s records line %s, want %s", r.ID, r.Metadata["line_number"], want)
		}
		if want := currentHashOf(moved[i]); r.Hash != want {
			t.Errorf("rule %s: hash %s, want the moved finding's current-formula hash %s", r.ID, r.Hash, want)
		}
	}
	reloaded, _ := loadWithWarnings(t, path)
	if got := countSuppressed(reloaded, moved); got != 5 {
		t.Errorf("a rescan suppresses %d of the 5 moved findings", got)
	}

	// The file changed in exactly the three fields, and kept its comment and pragmas.
	after := readText(t, path)
	bl, al := strings.Split(before, "\n"), strings.Split(after, "\n")
	if len(bl) != len(al) {
		t.Fatalf("%d lines became %d:\n%s", len(bl), len(al), after)
	}
	changed := map[string]int{}
	for i := range bl {
		if bl[i] == al[i] {
			continue
		}
		key := strings.TrimSpace(strings.SplitN(bl[i], ":", 2)[0])
		changed[key]++
	}
	if want := map[string]int{"hash": 5, "last_seen_at": 5, "line_number": 5}; fmt.Sprint(changed) != fmt.Sprint(want) {
		t.Errorf("changed lines by key %v, want %v", changed, want)
	}
	if strings.Count(after, "# pragma: allowlist secret") != 5 || !strings.HasPrefix(after, "# baseline, reviewed 2026-11-01\n") {
		t.Errorf("a pragma or the header comment was lost:\n%s", after)
	}

	// Regenerating again finds every rule where it now is.
	if report, _ := regenerate(t, path, moved); report != (GenerationReport{Refreshed: 5}) {
		t.Errorf("a second regeneration reports %+v, want only 5 refreshed", report)
	}
}

// TestAMiddleInsertMovesOnlyTheRulesBelowIt: the issue's mid1 case, 3 rules in place, 2 moved.
func TestAMiddleInsertMovesOnlyTheRulesBelowIt(t *testing.T) {
	path, _ := enabledRulesFor(t, noteFindings("customers.txt", 0))
	moved := noteFindings("customers.txt", 0)
	for i := range moved {
		if moved[i].LineNumber > 4 {
			moved[i].LineNumber++
		}
	}
	report, rules := regenerate(t, path, moved)
	if want := (GenerationReport{Refreshed: 3, ReAnchored: 2}); report != want {
		t.Errorf("report %+v, want %+v", report, want)
	}
	if len(rules) != 5 {
		t.Errorf("%d rules, want 5", len(rules))
	}
	reloaded, _ := loadWithWarnings(t, path)
	if got := countSuppressed(reloaded, moved); got != 5 {
		t.Errorf("a rescan suppresses %d of 5", got)
	}
}

// ssnRuleFile is a file of enabled rules for an SSN finding on each of lines, in file path.
func ssnRuleFile(t *testing.T, path string, lines map[int]string) string {
	t.Helper()
	var findings []detector.Match
	for _, n := range sortedKeys(lines) {
		findings = append(findings, ssnAt(path, lines[n], n))
	}
	file, _ := enabledRulesFor(t, findings)
	return file
}

func ssnAt(path, line string, lineNo int) detector.Match {
	m := onLine(line, "123-45-6780", "SSN", lineNo)
	m.Filename = path
	return m
}

func sortedKeys(m map[int]string) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := range keys {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	return keys
}

// assertUntouched fails unless the file at path still holds exactly the hashes and lines it had.
func assertUntouched(t *testing.T, before []SuppressionRule, path string) {
	t.Helper()
	after, _ := loadWithWarnings(t, path)
	rules := after.ListSuppressions()
	for i, r := range before {
		if i >= len(rules) || rules[i].Hash != r.Hash || rules[i].Metadata["line_number"] != r.Metadata["line_number"] {
			t.Errorf("rule %s was rewritten", r.ID)
		}
	}
}

const ssnLine = "social security number: 123-45-6780"

func TestTheReanchorDecoysAreRefused(t *testing.T) {
	cases := []struct {
		name  string
		rules map[int]string                     // the rules' findings, by line
		now   func(path string) []detector.Match // the run's findings
		want  GenerationReport
	}{
		{
			name:  "the line was edited as well as moved",
			rules: map[int]string{3: ssnLine},
			now: func(p string) []detector.Match {
				return []detector.Match{ssnAt(p, "social security number (verified): 123-45-6780", 4)}
			},
			want: GenerationReport{Added: 1, Unmatched: 1},
		},
		{
			name:  "one rule, its line now twice",
			rules: map[int]string{3: ssnLine},
			now: func(p string) []detector.Match {
				return []detector.Match{ssnAt(p, ssnLine, 4), ssnAt(p, ssnLine, 9)}
			},
			want: GenerationReport{Added: 2, Ambiguous: 1},
		},
		{
			name:  "two rules for one repeated line, one copy left",
			rules: map[int]string{3: ssnLine, 5: ssnLine},
			now:   func(p string) []detector.Match { return []detector.Match{ssnAt(p, ssnLine, 4)} },
			want:  GenerationReport{Added: 1, Ambiguous: 2},
		},
		{
			name:  "a repeated line moved while its twin kept its rule",
			rules: map[int]string{3: ssnLine, 5: ssnLine},
			now: func(p string) []detector.Match {
				return []detector.Match{ssnAt(p, ssnLine, 3), ssnAt(p, ssnLine, 6)}
			},
			want: GenerationReport{Added: 1, Refreshed: 1, Ambiguous: 1},
		},
		{
			name:  "a repeated line removed while its twin kept its rule",
			rules: map[int]string{3: ssnLine, 5: ssnLine},
			now:   func(p string) []detector.Match { return []detector.Match{ssnAt(p, ssnLine, 3)} },
			want:  GenerationReport{Refreshed: 1, Unmatched: 1},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := ssnRuleFile(t, "notes.txt", c.rules)
			before, _ := loadWithWarnings(t, path)
			old := before.ListSuppressions()
			report, rules := regenerate(t, path, c.now("notes.txt"))
			if report != c.want {
				t.Errorf("report %+v, want %+v", report, c.want)
			}
			if len(rules) != len(old)+c.want.Added {
				t.Errorf("%d rules, want %d", len(rules), len(old)+c.want.Added)
			}
			assertUntouched(t, old, path)
		})
	}
}

// TestSameNamedFilesAreDecidedTogether: a rule names a basename, so findings in two directories are
// candidates together. At one line they are one identity, which the rule matched before they moved; at
// two lines the move is ambiguous.
func TestSameNamedFilesAreDecidedTogether(t *testing.T) {
	path := ssnRuleFile(t, "a/notes.txt", map[int]string{3: ssnLine})

	report, rules := regenerate(t, path, []detector.Match{ssnAt("a/notes.txt", ssnLine, 4), ssnAt("b/notes.txt", ssnLine, 5)})
	if want := (GenerationReport{Added: 2, Ambiguous: 1}); report != want {
		t.Errorf("at two lines: %+v, want %+v", report, want)
	}
	if rules[0].Metadata["line_number"] != "3" {
		t.Errorf("the ambiguous rule moved to line %s", rules[0].Metadata["line_number"])
	}

	path = ssnRuleFile(t, "a/notes.txt", map[int]string{3: ssnLine})
	both := []detector.Match{ssnAt("a/notes.txt", ssnLine, 4), ssnAt("b/notes.txt", ssnLine, 4)}
	report, rules = regenerate(t, path, both)
	if want := (GenerationReport{ReAnchored: 1}); report != want {
		t.Errorf("at one line: %+v, want %+v", report, want)
	}
	if len(rules) != 1 || rules[0].Metadata["line_number"] != "4" {
		t.Errorf("rules after regenerating: %+v", rules)
	}
	reloaded, _ := loadWithWarnings(t, path)
	if got := countSuppressed(reloaded, both); got != 2 {
		t.Errorf("the re-anchored rule suppresses %d of the 2 same-named findings, as it did before they moved", got)
	}
}

// legacyRuleFile is one enabled rule for f written with formula version, its metadata recording conf.
func legacyRuleFile(t *testing.T, f detector.Match, version hashVersion, conf string, extra string) string {
	t.Helper()
	text := "version: \"1.0\"\nrules:\n" +
		"    - id: SUP-00000042\n" +
		"      hash: " + (&SuppressionManager{}).findingHashVersion(f, version) + "\n" +
		"      reason: reviewed\n" +
		"      enabled: true\n" +
		"      created_at: 2026-05-01T10:00:00Z\n" +
		extra +
		"      metadata:\n" +
		"        confidence: \"" + conf + "\"\n" +
		"        filename: " + filepath.Base(f.Filename) + "\n" +
		"        finding_type: " + f.Type + "\n" +
		"        line_number: \"" + strconv.Itoa(f.LineNumber) + "\"\n"
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestALegacyRuleIsReanchoredThroughTheConfidenceItRecorded: a v1 hash folds in the score, so a v1 rule
// whose finding moved and was rescored is found only by recomputing at the rule's line AND confidence.
func TestALegacyRuleIsReanchoredThroughTheConfidenceItRecorded(t *testing.T) {
	was := ssnAt("notes.txt", ssnLine, 3)
	was.Confidence = 90
	for _, c := range []struct {
		name string
		now  detector.Match
	}{
		{"moved and rescored", func() detector.Match { m := ssnAt("notes.txt", ssnLine, 4); m.Confidence = 75; return m }()},
		{"rescored in place", func() detector.Match { m := ssnAt("notes.txt", ssnLine, 3); m.Confidence = 75; return m }()},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := legacyRuleFile(t, was, hashVersionLegacyConfidence, "90.00", "")
			sm, _ := loadWithWarnings(t, path)
			if ok, _ := sm.IsSuppressed(c.now); ok {
				t.Fatal("fixture error: the v1 rule already matches")
			}
			report, rules := regenerate(t, path, []detector.Match{c.now})
			if want := (GenerationReport{ReAnchored: 1}); report != want {
				t.Errorf("%+v, want %+v", report, want)
			}
			if rules[0].Hash != currentHashOf(c.now) || rules[0].Metadata["confidence"] != "90.00" {
				t.Errorf("rule after regenerating: %+v", rules[0])
			}
		})
	}

	t.Run("without the recorded confidence it is not found", func(t *testing.T) {
		path := legacyRuleFile(t, was, hashVersionLegacyConfidence, "not a number", "")
		now := ssnAt("notes.txt", ssnLine, 4)
		now.Confidence = 75
		if report, _ := regenerate(t, path, []detector.Match{now}); report != (GenerationReport{Added: 1, Unmatched: 1}) {
			t.Errorf("%+v", report)
		}
	})
}

// TestOlderFormulasAreReanchoredToo: the v2 rule a v2.5 binary wrote on an LF copy, for a finding now
// in a CRLF copy and one line lower, and the contextless rule of a validator that recorded no context.
func TestOlderFormulasAreReanchoredToo(t *testing.T) {
	lf := ssnAt("notes.txt", ssnLine, 3)
	crlf := onLine(ssnLine+"\r", "123-45-6780", "SSN", 4)
	crlf.Filename = "notes.txt"
	path := legacyRuleFile(t, lf, hashVersionNoConfidence, "90.00", "")
	if report, rules := regenerate(t, path, []detector.Match{crlf}); report != (GenerationReport{ReAnchored: 1}) ||
		rules[0].Hash != currentHashOf(crlf) {
		t.Errorf("v2 LF rule, CRLF finding moved: %+v, %+v", report, rules)
	}

	moved := withContext(awsKey())
	moved.LineNumber++
	path = legacyRuleFile(t, awsKey(), hashVersionNoConfidenceContextless, "90.00", "")
	if report, _ := regenerate(t, path, []detector.Match{moved}); report != (GenerationReport{ReAnchored: 1}) {
		t.Errorf("contextless rule: %+v", report)
	}
}

// awsKey is a secrets finding as it was recorded before secrets recorded context.
func awsKey() detector.Match {
	return contextlessFinding("secrets", "AWS_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE")
}

func TestWhatReanchoringLeavesAlone(t *testing.T) {
	now := ssnAt("notes.txt", ssnLine, 4)

	t.Run("a rule without line_number is skipped and counted", func(t *testing.T) {
		path := ssnRuleFile(t, "notes.txt", map[int]string{3: ssnLine})
		text := strings.Replace(readText(t, path), "        line_number: \"3\"\n", "", 1)
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		if report, _ := regenerate(t, path, []detector.Match{now}); report != (GenerationReport{Added: 1, Unmatched: 1}) {
			t.Errorf("%+v", report)
		}
	})

	t.Run("a rule for a file the run has no findings in is not counted", func(t *testing.T) {
		path := ssnRuleFile(t, "other.txt", map[int]string{3: ssnLine})
		if report, _ := regenerate(t, path, []detector.Match{now}); report != (GenerationReport{Added: 1}) {
			t.Errorf("%+v", report)
		}
	})

	t.Run("a rule the loader refused is neither moved nor counted", func(t *testing.T) {
		path := ssnRuleFile(t, "notes.txt", map[int]string{3: ssnLine})
		text := insertAfter(readText(t, path), "      enabled: true\n", "      enabeld: true")
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		before, _ := loadWithWarnings(t, path)
		old := before.ListSuppressions()
		if report, _ := regenerate(t, path, []detector.Match{now}); report != (GenerationReport{Added: 1}) {
			t.Errorf("%+v", report)
		}
		assertUntouched(t, old, path)
	})

	t.Run("a disabled or expired rule moves and keeps its state", func(t *testing.T) {
		for _, extra := range []string{"", "      expires_at: 2020-01-01T00:00:00Z\n"} {
			path := legacyRuleFile(t, ssnAt("notes.txt", ssnLine, 3), hashVersionCurrent, "90.00", extra)
			text := strings.Replace(readText(t, path), "enabled: true", "enabled: false", 1)
			if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
				t.Fatal(err)
			}
			report, rules := regenerate(t, path, []detector.Match{now})
			if report != (GenerationReport{ReAnchored: 1}) || rules[0].Enabled {
				t.Errorf("%q: %+v, enabled=%v", extra, report, rules[0].Enabled)
			}
			if extra != "" && (rules[0].ExpiresAt == nil || !rules[0].ExpiresAt.Equal(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))) {
				t.Errorf("the expiry changed: %v", rules[0].ExpiresAt)
			}
		}
	})
}

// TestTheGeneratingRunIsNotRelocated: --stdin generates before it reports. The re-anchored rule must
// not suppress in that run, or the two channels would disagree on the same input and rules (#697);
// the next load applies it.
func TestTheGeneratingRunIsNotRelocated(t *testing.T) {
	path, _ := enabledRulesFor(t, noteFindings("customers.txt", 0))
	moved := noteFindings("customers.txt", 1)
	sm, _ := loadWithWarnings(t, path)
	if err := sm.GenerateSuppressionRules(moved, "generated", false); err != nil {
		t.Fatal(err)
	}
	if sm.LastGeneration().ReAnchored != 5 {
		t.Fatalf("fixture error: %+v", sm.LastGeneration())
	}
	if got := countSuppressed(sm, moved); got != 0 {
		t.Errorf("the generating manager suppresses %d moved findings; the file-mode run reports all 5", got)
	}
	if unmatched := sm.UnmatchedRules(RunScope{Files: []string{"customers.txt"}, AllChecks: true}); unmatched.Count() != 0 {
		t.Errorf("re-anchored rules reported as matching nothing: %v", unmatched.IDs)
	}
	reloaded, _ := loadWithWarnings(t, path)
	if got := countSuppressed(reloaded, moved); got != 5 {
		t.Errorf("the next load suppresses %d of 5", got)
	}
}

// TestTheComparisonLimitIsHonoured: a group whose comparisons do not fit is not searched at all, its
// rules counted and left alone, while a cheaper group is still decided.
func TestTheComparisonLimitIsHonoured(t *testing.T) {
	var findings []detector.Match
	big := map[int]string{}
	for i := 1; i <= 20; i++ {
		line := fmt.Sprintf("row %d ssn 123-45-6780", i)
		big[i] = line
	}
	path := ssnRuleFile(t, "big.txt", big)
	for _, n := range sortedKeys(big) {
		findings = append(findings, ssnAt("big.txt", big[n], n+1))
	}
	// A second file, one rule, one moved finding: cost 1.
	small := ssnAt("small.txt", ssnLine, 3)
	text := readText(t, path)
	if err := NewSuppressionManager(path).GenerateSuppressionRules([]detector.Match{small}, "generated", true); err != nil {
		t.Fatal(err)
	}
	if readText(t, path) == text {
		t.Fatal("fixture error: the small file's rule was not added")
	}
	movedSmall := ssnAt("small.txt", ssnLine, 4)

	for _, c := range []struct {
		limit int
		want  GenerationReport
		cmp   int
	}{
		{limit: 20*20 + 1, want: GenerationReport{ReAnchored: 21}, cmp: 20*20 + 1},
		{limit: 20 * 20, want: GenerationReport{ReAnchored: 1, Added: 20, NotEvaluated: 20}, cmp: 1},
		{limit: 1, want: GenerationReport{ReAnchored: 1, Added: 20, NotEvaluated: 20}, cmp: 1},
	} {
		dst := filepath.Join(t.TempDir(), "rules.yaml")
		if err := os.WriteFile(dst, []byte(readText(t, path)), 0o600); err != nil {
			t.Fatal(err)
		}
		sm, _ := loadWithWarnings(t, dst)
		sm.reanchorLimit = c.limit
		batch := append(append([]detector.Match{}, findings...), movedSmall)
		identities, ruled, identified := sm.batchState(batch)
		if got := sm.planReanchor(batch, identities, ruled, identified).comparisons; got != c.cmp || got > c.limit {
			t.Errorf("limit %d: %d comparisons, want %d", c.limit, got, c.cmp)
		}
		if err := sm.GenerateSuppressionRules(batch, "generated", false); err != nil {
			t.Fatal(err)
		}
		if got := sm.LastGeneration(); got != c.want {
			t.Errorf("limit %d: %+v, want %+v", c.limit, got, c.want)
		}
	}
}

// batchState is what GenerateSuppressionRules hands planReanchor, for tests of the search alone.
func (sm *SuppressionManager) batchState(matches []detector.Match) ([]string, []bool, map[int]bool) {
	identities := make([]string, len(matches))
	ruled := make([]bool, len(matches))
	carried := map[string]bool{}
	byHash := map[string]bool{}
	for _, r := range sm.config.Rules {
		byHash[r.Hash] = true
	}
	for i, m := range matches {
		c := sm.findingHashCandidates(m)
		identities[i] = c[0]
		for _, h := range c {
			if byHash[h] {
				carried[h] = true
				ruled[i] = true
			}
		}
	}
	identified := map[int]bool{}
	for i, r := range sm.config.Rules {
		if carried[r.Hash] {
			identified[i] = true
		}
	}
	return identities, ruled, identified
}

// TestTheLineOpenIdentityIsTheIdentity: re-anchoring recomputes identities from a saved hash state, and
// must get exactly what findingHashVersion computes at that line, for every candidate form, through
// the fast path and the fallback alike.
func TestTheLineOpenIdentityIsTheIdentity(t *testing.T) {
	sm := &SuppressionManager{}
	shapes := []detector.Match{
		identityFixtures["indented CRLF line, trailing space"],
		identityFixtures["span with its trailing space and CR, empty windows"],
		identityFixtures["no whitespace at any edge"],
		withContext(awsKey()),
		onLongLine(64 << 10),
		onLine("ssn: 123-45-6780", "123-45-6780", "SSN", 0),
	}
	hasher := newAnchorHasher()
	for _, m := range shapes {
		var forms []candidateForm
		eachCandidateForm(m, func(f detector.Match, v hashVersion) { forms = append(forms, candidateForm{f, v}) })
		for _, line := range []int{0, 1, 9, 10, 4096, m.LineNumber} {
			for _, f := range forms {
				at := f.match
				at.LineNumber = line
				want := sm.findingHashVersion(at, f.version)
				open := sm.newLineOpenForm(f.match, f.version)
				fast := hasher.at(&open, line)
				open.state = nil
				slow := hasher.at(&open, line)
				if fmt.Sprintf("%x", fast) != want || fmt.Sprintf("%x", slow) != want {
					t.Errorf("%q v%d at line %d: fast %x, fallback %x, want %s", m.Type, f.version, line, fast, slow, want)
				}
			}
		}
	}
}

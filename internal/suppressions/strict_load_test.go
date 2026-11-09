// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suppressions

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// The load table for #866. Every row is the two-rule file the CLI generates for two findings, both
// rules enabled, with one edit — the issue's reproduction, line numbers included.
//
// The fail-open rows are the reason for the strict pass: on the unfixed loader every misspelled or
// nested expiry turned a lapsed rule into a permanent one (both findings suppressed, no expiry warning).

// strictTestMatches are the two findings: rule 1 is the card on line 2, rule 2 the contact on line 1.
func strictTestMatches() []detector.Match {
	return []detector.Match{
		{Type: "VISA", Text: "card-value-1", Filename: "sample.txt", LineNumber: 2, Confidence: 100, Validator: "creditcard",
			Context: detector.ContextInfo{FullLine: "card number: card-value-1", BeforeText: "card number: "}},
		{Type: "BUSINESS", Text: "contact-value-2", Filename: "sample.txt", LineNumber: 1, Confidence: 93, Validator: "email",
			Context: detector.ContextInfo{FullLine: "Contact: contact-value-2", BeforeText: "Contact: "}},
	}
}

// generatedTwoRuleText is the file --generate-suppressions writes for strictTestMatches, with both
// rules enabled. Its layout is the issue's: rule 1 on lines 3-13, rule 2 on lines 14-24.
func generatedTwoRuleText(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sup.yaml")
	sm, warnings := loadWithWarnings(t, path)
	if warnings != "" {
		t.Fatalf("a missing file printed %q", warnings)
	}
	if err := sm.GenerateSuppressionRules(strictTestMatches(), "Auto-generated suppression rule", true); err != nil {
		t.Fatalf("GenerateSuppressionRules: %v", err)
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if got := strings.Count(text, "      enabled: true\n"); got != 2 {
		t.Fatalf("the generated file has %d enabled rules, want 2:\n%s", got, text)
	}
	return text
}

// loadWithWarnings loads path and returns the manager and everything its loader printed.
func loadWithWarnings(t *testing.T, path string) (*SuppressionManager, string) {
	t.Helper()
	var buf bytes.Buffer
	sm := NewSuppressionManagerWithOptions(path, ManagerOptions{Warnings: &buf})
	return sm, buf.String()
}

// loadText writes text to a temp file and loads it.
func loadText(t *testing.T, text string) (*SuppressionManager, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return loadWithWarnings(t, path)
}

// suppressedCount is how many of strictTestMatches the manager suppresses.
func suppressedCount(sm *SuppressionManager) int {
	n := 0
	for _, m := range strictTestMatches() {
		if ok, _ := sm.IsSuppressed(m); ok {
			n++
		}
	}
	return n
}

// insertAfter puts line after every occurrence of anchor (a whole line, newline included).
func insertAfter(text, anchor, line string) string {
	return strings.ReplaceAll(text, anchor, anchor+line+"\n")
}

// withExpiry adds key: <a past date> to both rules, as a rule key or under metadata.
func withExpiry(text, key string, nested bool) string {
	if nested {
		text = insertAfter(text, "        line_number: \"2\"\n", "        "+key+": 2026-01-01T00:00:00Z")
		return insertAfter(text, "        line_number: \"1\"\n", "        "+key+": 2026-01-01T00:00:00Z")
	}
	return insertAfter(text, "      enabled: true\n", "      "+key+": 2026-01-01T00:00:00Z")
}

func TestAMisspelledOrNestedExpiryIsNotAppliedAndNamed(t *testing.T) {
	base := generatedTwoRuleText(t)

	// The control: the correct key takes the expired path, so both findings are reported and counted.
	sm, warnings := loadText(t, withExpiry(base, "expires_at", false))
	if warnings != "" {
		t.Errorf("the correctly spelled expiry printed a load warning: %q", warnings)
	}
	if got := suppressedCount(sm); got != 0 {
		t.Fatalf("a rule that expired on 2026-01-01 suppressed %d of 2 findings; the control is broken", got)
	}
	if n, _ := sm.ExpiredSkips(); n != 2 {
		t.Errorf("ExpiredSkips = %d with two lapsed rules, want 2", n)
	}

	cases := []struct {
		key    string
		nested bool
		lines  [2]int
	}{
		{key: "expries_at", lines: [2]int{7, 19}},
		{key: "expiresAt", lines: [2]int{7, 19}},
		{key: "expires", lines: [2]int{7, 19}},
		{key: "expiry", lines: [2]int{7, 19}},
		{key: "expire_at", lines: [2]int{7, 19}},
		{key: "expires_on", lines: [2]int{7, 19}},
		{key: "expiration", lines: [2]int{7, 19}},
		{key: "expires_at", nested: true, lines: [2]int{14, 26}},
	}
	for _, tc := range cases {
		name := tc.key
		shown := tc.key
		if tc.nested {
			name, shown = "metadata."+tc.key, "metadata."+tc.key
		}
		t.Run(name, func(t *testing.T) {
			sm, warnings := loadText(t, withExpiry(base, tc.key, tc.nested))
			if got := suppressedCount(sm); got != 0 {
				t.Errorf("%d of 2 findings suppressed. A lapsed rule whose expiry is misspelled must not become "+
					"a permanent one: the rule is refused, so the finding is reported.", got)
			}
			if n, _ := sm.ExpiredSkips(); n != 0 {
				t.Errorf("ExpiredSkips = %d; a refused rule takes no part in matching, so it is not counted", n)
			}
			for i, id := range []string{"SUP-00000001", "SUP-00000002"} {
				want := fmt.Sprintf("%s %q (line %d)", id, shown, tc.lines[i])
				if !strings.Contains(warnings, want) {
					t.Errorf("the warning does not name %s; got:\n%s", want, warnings)
				}
			}
			if !strings.Contains(warnings, "2 suppression rule(s)") || !strings.Contains(warnings, "NOT applied") {
				t.Errorf("the warning does not say 2 rules are NOT applied; got:\n%s", warnings)
			}
		})
	}
}

func TestEveryUnknownRuleKeyRefusesItsRule(t *testing.T) {
	base := generatedTwoRuleText(t)
	cases := []struct {
		name, text, want string
		suppressed       int
	}{
		{"enabeld", strings.ReplaceAll(base, "enabled: true", "enabeld: true"), `SUP-00000001 "enabeld" (line 6)`, 0},
		{"enable", strings.ReplaceAll(base, "enabled: true", "enable: true"), `SUP-00000002 "enable" (line 17)`, 0},
		{"hsah", strings.ReplaceAll(base, "hash:", "hsah:"), `SUP-00000001 "hsah" (line 4)`, 0},
		// A misspelled reason narrows nothing, but every unknown key is refused alike: the loader cannot
		// tell a harmless misspelling from a constraint it does not know.
		{"reasn", strings.ReplaceAll(base, "reason:", "reasn:"), `SUP-00000002 "reasn" (line 16)`, 0},
		{"metadata.enabled", insertAfter(base, "        line_number: \"1\"\n", "        enabled: \"true\""), `SUP-00000002 "metadata.enabled" (line 25)`, 1},
		{"pattern", replaceFirstHash(base, `pattern: "card-value-1"`), `SUP-00000001 "pattern" (line 4)`, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sm, warnings := loadText(t, tc.text)
			if !strings.Contains(warnings, tc.want) {
				t.Errorf("the warning does not name %s; got:\n%s", tc.want, warnings)
			}
			if got := suppressedCount(sm); got != tc.suppressed {
				t.Errorf("%d of 2 suppressed, want %d", got, tc.suppressed)
			}
			if strings.Contains(warnings, "can never match") {
				t.Errorf("a refused rule also had its hash named; one entry per fix is enough:\n%s", warnings)
			}
		})
	}
}

// replaceFirstHash replaces rule 1's hash line with line.
func replaceFirstHash(text, line string) string {
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, "      hash: ") {
			lines[i] = "      " + line
			break
		}
	}
	return strings.Join(lines, "\n")
}

func TestRulesOutsideRulesLoadNothingAndSaySo(t *testing.T) {
	base := generatedTwoRuleText(t)
	for _, key := range []string{"rule", "suppressions"} {
		t.Run(key, func(t *testing.T) {
			sm, warnings := loadText(t, strings.Replace(base, "\nrules:\n", "\n"+key+":\n", 1))
			want := fmt.Sprintf(`0 rules loaded from %s: unknown top-level key %q (line 2); rules belong under "rules:"`,
				sm.GetConfigPath(), key)
			if !strings.Contains(warnings, want) {
				t.Errorf("want %q in the warning, got:\n%s", want, warnings)
			}
			if got := suppressedCount(sm); got != 0 {
				t.Errorf("%d suppressed from a file with no rules: key", got)
			}
		})
	}

	// An unknown top-level key BESIDE rules: is named and changes nothing else.
	sm, warnings := loadText(t, strings.Replace(base, "version: \"1.0\"\n", "version: \"1.0\"\nnotes: team baseline\n", 1))
	if !strings.Contains(warnings, `top-level key this version does not recognise, which is ignored: "notes" (line 2)`) {
		t.Errorf("the unknown top-level key was not named; got:\n%s", warnings)
	}
	if got := suppressedCount(sm); got != 2 {
		t.Errorf("%d of 2 suppressed; an unknown top-level key next to rules: must not stop them applying", got)
	}
}

func TestAnotherFileVersionAppliesNoRules(t *testing.T) {
	base := generatedTwoRuleText(t)

	sm, warnings := loadText(t, strings.Replace(base, `version: "1.0"`, `version: "9.9"`, 1))
	if got := suppressedCount(sm); got != 0 {
		t.Errorf("a version \"9.9\" file suppressed %d of 2; a version this loader does not read applies nothing", got)
	}
	if !strings.Contains(warnings, `declares version "9.9"`) || !strings.Contains(warnings, "none of its 2 rule(s) are applied") {
		t.Errorf("the version was not named; got:\n%s", warnings)
	}

	// A missing version is how hand-written files start; it is accepted silently.
	sm, warnings = loadText(t, strings.Replace(base, "version: \"1.0\"\n", "", 1))
	if warnings != "" || suppressedCount(sm) != 2 {
		t.Errorf("a file with no version: warnings %q, %d of 2 suppressed; want none and 2", warnings, suppressedCount(sm))
	}
}

func TestInertShapesAreNamedAndLoadedAsBefore(t *testing.T) {
	base := generatedTwoRuleText(t)
	firstHash := func() string {
		for _, l := range strings.Split(base, "\n") {
			if strings.HasPrefix(l, "      hash: ") {
				return strings.Fields(l)[1]
			}
		}
		t.Fatal("no hash line")
		return ""
	}()
	cases := []struct {
		name, text, want string
		suppressed       int
	}{
		{"non-hex hash", strings.Replace(base, firstHash, "not-a-hash", 1),
			`SUP-00000001 hash "not-a-hash" (line 4) is not 64 lower-case hexadecimal digits`, 1},
		// Lower-casing it would make a rule that suppresses nothing today start suppressing; named instead.
		{"upper-case hash", strings.Replace(base, firstHash, strings.ToUpper(firstHash), 1),
			`SUP-00000001 hash "` + strings.ToUpper(firstHash)[:24] + `"… (line 4) is not 64 lower-case`, 1},
		{"duplicated id", strings.Replace(base, "id: SUP-00000002", "id: SUP-00000001", 1),
			`gives 2 rules the same id SUP-00000001 (lines 3, 14)`, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sm, warnings := loadText(t, tc.text)
			if !strings.Contains(warnings, tc.want) {
				t.Errorf("want %q in the warning, got:\n%s", tc.want, warnings)
			}
			if got := suppressedCount(sm); got != tc.suppressed {
				t.Errorf("%d of 2 suppressed, want %d: an inert shape is named, not refused", got, tc.suppressed)
			}
			if strings.Contains(warnings, "NOT applied") {
				t.Errorf("an inert shape refused a rule:\n%s", warnings)
			}
		})
	}
}

func TestFreeFormMetadataIsSilentAndApplied(t *testing.T) {
	text := insertAfter(generatedTwoRuleText(t), "        line_number: \"2\"\n", "        ticket: SEC-1234")
	sm, warnings := loadText(t, text)
	if warnings != "" {
		t.Errorf("a custom metadata key printed %q; metadata is free-form unless a key reuses a rule key's name", warnings)
	}
	if got := suppressedCount(sm); got != 2 {
		t.Errorf("%d of 2 suppressed with a custom metadata key, want 2", got)
	}
}

// TestTheBaselineAndGeneratedOutputNameNothing is the precision floor: the strict pass must be silent
// on every file the tool writes, and on the self-scan ledger this repository commits (#927).
func TestTheBaselineAndGeneratedOutputNameNothing(t *testing.T) {
	sm, warnings := loadWithWarnings(t, filepath.Join("..", "..", ".ferret-scan-suppressions.yaml"))
	if warnings != "" {
		t.Errorf("the committed baseline printed load warnings:\n%s", warnings)
	}
	if n := len(sm.ListSuppressions()); n < 200 {
		t.Fatalf("the committed baseline loaded %d rules; the test is not reading it", n)
	}

	path := filepath.Join(t.TempDir(), "generated.yaml")
	if err := os.WriteFile(path, []byte(generatedTwoRuleText(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, warnings := loadWithWarnings(t, path); warnings != "" {
		t.Errorf("generated output printed load warnings:\n%s", warnings)
	}
}

// TestALapsedRuleIsCountedOnTheLazyIndexPathToo pins the second matching branch: a manager whose
// index was never built used to skip an expired rule without counting it (#866).
func TestALapsedRuleIsCountedOnTheLazyIndexPathToo(t *testing.T) {
	sm, _ := loadText(t, withExpiry(generatedTwoRuleText(t), "expires_at", false))
	sm.indexMu.Lock()
	sm.rulesByHash = nil
	sm.indexMu.Unlock()
	if got := suppressedCount(sm); got != 0 {
		t.Fatalf("%d suppressed by lapsed rules", got)
	}
	if n, _ := sm.ExpiredSkips(); n != 2 {
		t.Errorf("ExpiredSkips = %d on the lazy-index path, want 2", n)
	}
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suppressions

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestRuleKeysAreTheStructsYAMLTags keeps the strict pass's key list and the struct it guards in step.
// A field added to SuppressionRule without its key here would be refused on every file that uses it;
// a key here without a field would be accepted and then ignored, which is the defect this list exists
// to prevent.
func TestRuleKeysAreTheStructsYAMLTags(t *testing.T) {
	var tags []string
	rt := reflect.TypeOf(SuppressionRule{})
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		tag := strings.Split(f.Tag.Get("yaml"), ",")[0]
		if !f.IsExported() || tag == "-" || tag == "" {
			continue
		}
		tags = append(tags, tag)
	}
	if !reflect.DeepEqual(tags, ruleKeys) {
		t.Errorf("SuppressionRule's yaml tags are %v, ruleKeys is %v; they must be the same list in the same order",
			tags, ruleKeys)
	}
}

// TestCheckSuppressionFileGivesTheLoadersVerdict: the exported check is what a documentation guard
// calls, so it must agree with the loader.
func TestCheckSuppressionFileGivesTheLoadersVerdict(t *testing.T) {
	text := withExpiry(generatedTwoRuleText(t), "expries_at", false)
	problems, err := CheckSuppressionFile([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 2 {
		t.Fatalf("got %d problems, want 2: %v", len(problems), problems)
	}
	for i, p := range problems {
		if !p.Refuses() || p.Key != "expries_at" || p.RuleIndex != i || p.Line != []int{7, 19}[i] {
			t.Errorf("problem %d = %+v (%s)", i, p, p)
		}
	}
	if _, err := CheckSuppressionFile([]byte("rules: [")); err == nil {
		t.Error("a syntax error was not returned as an error")
	}
	if problems, err := CheckSuppressionFile([]byte(generatedTwoRuleText(t))); err != nil || len(problems) != 0 {
		t.Errorf("generated output: %v, %v; want no problems", problems, err)
	}
}

// TestARefusedRuleTellsTheWebUIWhy: the rules table reads ListSuppressions as JSON, and NotApplied is
// how it can mark a refused rule the way it marks an expired one.
func TestARefusedRuleTellsTheWebUIWhy(t *testing.T) {
	sm, _ := loadText(t, withExpiry(generatedTwoRuleText(t), "expries_at", false))
	rules := sm.ListSuppressions()
	if len(rules) != 2 {
		t.Fatalf("%d rules listed; a refused rule must still be listed", len(rules))
	}
	raw, err := json.Marshal(rules[0])
	if err != nil {
		t.Fatal(err)
	}
	if want := `"NotApplied":"unknown key \"expries_at\" (line 7)"`; !strings.Contains(string(raw), want) {
		t.Errorf("the rule's JSON lacks %s:\n%s", want, raw)
	}

	clean, _ := loadText(t, generatedTwoRuleText(t))
	raw, _ = json.Marshal(clean.ListSuppressions()[0])
	if strings.Contains(string(raw), "NotApplied") {
		t.Errorf("an applied rule's JSON carries NotApplied:\n%s", raw)
	}
}

// TestWarningsCanBeWithheld: a caller whose stderr is a findings document passes io.Discard. The rule
// is refused all the same; only the prose is withheld.
func TestWarningsCanBeWithheld(t *testing.T) {
	path := filepath.Join(t.TempDir(), "typo.yaml")
	if err := os.WriteFile(path, []byte(withExpiry(generatedTwoRuleText(t), "expries_at", false)), 0o600); err != nil {
		t.Fatal(err)
	}
	sm := NewSuppressionManagerWithOptions(path, ManagerOptions{Warnings: io.Discard})
	if got := suppressedCount(sm); got != 0 {
		t.Errorf("%d suppressed with warnings withheld; withholding the prose must not change the verdict", got)
	}
}

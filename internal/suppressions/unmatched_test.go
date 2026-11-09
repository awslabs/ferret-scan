// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suppressions

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// UnmatchedRules (#885): IsSuppressed records which rules matched, and the enabled rules that matched
// nothing are reported, but only the ones the run could have matched.

var notesScope = RunScope{Files: []string{"/repo/docs/customers.txt"}, AllChecks: true}

func TestARuleWhoseFindingMovedIsReportedAndTheRestAreNot(t *testing.T) {
	path, _ := enabledRulesFor(t, noteFindings("customers.txt", 0))
	moved := noteFindings("customers.txt", 0)
	for i := range moved {
		if moved[i].LineNumber > 4 { // the issue's mid1: a line after line 4
			moved[i].LineNumber++
		}
	}
	sm, _ := loadWithWarnings(t, path)
	// Twice, as the worker pool and the report path both ask under --enable-redaction.
	for pass := 0; pass < 2; pass++ {
		if got := countSuppressed(sm, moved); got != 3 {
			t.Fatalf("pass %d: %d suppressed, want 3", pass, got)
		}
	}
	got := sm.UnmatchedRules(notesScope)
	if want := []string{"SUP-00000004", "SUP-00000005"}; fmt.Sprint(got.IDs) != fmt.Sprint(want) || got.Partial || got.Unattributed != 0 {
		t.Errorf("%+v, want IDs %v", got, want)
	}
	if again := sm.UnmatchedRules(notesScope); fmt.Sprint(again) != fmt.Sprint(got) {
		t.Errorf("asking again changed the report: %+v", again)
	}
}

// TestARuleForAFileNotScannedIsNotReported is the decoy: rules for a file the run never read matched
// nothing because they could not.
func TestARuleForAFileNotScannedIsNotReported(t *testing.T) {
	findings := append(noteFindings("customers.txt", 0), noteFindings("other/archive.txt", 0)...)
	path, _ := enabledRulesFor(t, findings)
	sm, _ := loadWithWarnings(t, path)
	countSuppressed(sm, noteFindings("customers.txt", 0))
	if got := sm.UnmatchedRules(notesScope); got.Count() != 0 {
		t.Errorf("rules for archive.txt, which the run did not scan, were reported: %v", got.IDs)
	}
	// Scanned, and its findings gone: now they are news.
	scope := RunScope{Files: []string{"customers.txt", "elsewhere/archive.txt"}, AllChecks: true}
	if got := sm.UnmatchedRules(scope); got.Count() != 5 {
		t.Errorf("%d rules reported for the scanned archive.txt with no findings, want its 5", got.Count())
	}
	if got := sm.UnmatchedRules(RunScope{AllChecks: true}); got.Count() != 0 {
		t.Errorf("an empty scope reported %v", got.IDs)
	}
}

// TestANarrowedRunCountsOnlyTypesItReported: under --checks SSN the other four rules matched nothing
// because their checks did not run.
func TestANarrowedRunCountsOnlyTypesItReported(t *testing.T) {
	findings := noteFindings("customers.txt", 0)
	path, _ := enabledRulesFor(t, findings)
	var ssn []detector.Match
	for _, f := range findings {
		if f.Type == "SSN" {
			ssn = append(ssn, f)
		}
	}

	sm, _ := loadWithWarnings(t, path)
	countSuppressed(sm, ssn)
	narrowed := RunScope{Files: []string{"customers.txt"}}
	if got := sm.UnmatchedRules(narrowed); got.Count() != 0 || !got.Partial {
		t.Errorf("--checks SSN on the identical file: %+v, want none, partial", got)
	}

	// The SSN moved: its type was reported, so its rule counts even in a narrowed run.
	moved := ssn[0]
	moved.LineNumber++
	sm, _ = loadWithWarnings(t, path)
	countSuppressed(sm, []detector.Match{moved})
	if got := sm.UnmatchedRules(narrowed); fmt.Sprint(got.IDs) != "[SUP-00000003]" || !got.Partial {
		t.Errorf("--checks SSN with the SSN moved: %+v", got)
	}
	if got := sm.UnmatchedRules(RunScope{Files: narrowed.Files, AllChecks: true}); got.Count() != 5 || got.Partial {
		t.Errorf("the same run reported as complete: %+v", got)
	}
}

func TestOnlyEnabledLiveRulesAreReported(t *testing.T) {
	findings := noteFindings("customers.txt", 0)
	path, text := enabledRulesFor(t, findings)
	// Rule 1 disabled, rule 2 expired, rule 3 refused, rule 4 without a filename; rule 5 is the one.
	rules := strings.Split(text, "    - id: ")
	rules[1] = strings.Replace(rules[1], "enabled: true", "enabled: false", 1)
	rules[2] = strings.Replace(rules[2], "expires_at: 2030-01-01T00:00:00Z", "expires_at: 2020-01-01T00:00:00Z", 1)
	rules[3] = strings.Replace(rules[3], "      enabled: true\n", "      enabled: true\n      enabeld: true\n", 1)
	rules[4] = strings.Replace(rules[4], "        filename: customers.txt\n", "", 1)
	if err := os.WriteFile(path, []byte(strings.Join(rules, "    - id: ")), 0o600); err != nil {
		t.Fatal(err)
	}
	sm, _ := loadWithWarnings(t, path)
	got := sm.UnmatchedRules(notesScope)
	if fmt.Sprint(got.IDs) != "[SUP-00000005]" || got.Unattributed != 1 {
		t.Errorf("%+v, want only SUP-00000005, and 1 unattributed", got)
	}

	sm.SetEnabled(false)
	if got := sm.UnmatchedRules(notesScope); got.Count() != 0 || got.Unattributed != 0 {
		t.Errorf("with suppression disabled: %+v", got)
	}
}

// TestASecondRuleForOneFindingMatchedToo: the matcher returns the first rule, but a second rule for the
// same finding (an older formula's, say) did not match "nothing".
func TestASecondRuleForOneFindingMatchedToo(t *testing.T) {
	f := ssnAt("customers.txt", ssnLine, 3)
	sm := &SuppressionManager{}
	mgr := ruleManager(sm.findingHashVersion(f, hashVersionCurrent), sm.findingHashVersion(f, hashVersionLegacyConfidence))
	for i := range mgr.config.Rules {
		mgr.config.Rules[i].ID = fmt.Sprintf("R%d", i+1)
		mgr.config.Rules[i].Metadata = map[string]string{"filename": "customers.txt", "finding_type": "SSN"}
	}
	if ok, rule := mgr.IsSuppressed(f); !ok || rule.ID != "R1" {
		t.Fatalf("fixture error: %v %v", ok, rule)
	}
	if got := mgr.UnmatchedRules(notesScope); got.Count() != 0 {
		t.Errorf("the second rule was reported as matching nothing: %v", got.IDs)
	}
}

// TestHitAccountingIsSafeConcurrently: the redaction filter calls IsSuppressed on worker goroutines
// while the report path may already be asking. Meaningful under -race.
func TestHitAccountingIsSafeConcurrently(t *testing.T) {
	findings := noteFindings("customers.txt", 0)
	path, _ := enabledRulesFor(t, findings)
	sm, _ := loadWithWarnings(t, path)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				f := findings[(w+i)%len(findings)]
				sm.IsSuppressed(f)
				if i%50 == 0 {
					sm.UnmatchedRules(notesScope)
				}
			}
		}(w)
	}
	wg.Wait()
	if got := sm.UnmatchedRules(notesScope); got.Count() != 0 {
		t.Errorf("%v reported after every finding matched", got.IDs)
	}
}

func TestTheUnmatchedNote(t *testing.T) {
	var buf bytes.Buffer
	WriteUnmatchedRulesNote(&buf, UnmatchedReport{Partial: true, Unattributed: 3})
	if buf.Len() != 0 {
		t.Errorf("a report naming no rule printed %q", buf.String())
	}

	WriteUnmatchedRulesNote(&buf, UnmatchedReport{IDs: []string{"SUP-00000001", "SUP-00000002"}})
	want := "Note: 2 enabled suppression rule(s) for files scanned in this run matched no finding (the finding " +
		"moved, changed, or was removed): SUP-00000001, SUP-00000002. Run --generate-suppressions to re-anchor " +
		"the ones whose finding only moved.\n"
	if buf.String() != want {
		t.Errorf("note:\n%q\nwant\n%q", buf.String(), want)
	}

	buf.Reset()
	var ids []string
	for i := 1; i <= 12; i++ {
		ids = append(ids, fmt.Sprintf("SUP-%08d", i))
	}
	WriteUnmatchedRulesNote(&buf, UnmatchedReport{IDs: ids, Partial: true})
	if s := buf.String(); !strings.Contains(s, "Note: 12 enabled") || !strings.Contains(s, "SUP-00000010, and 2 more.") ||
		strings.Contains(s, "SUP-00000011") || !strings.HasSuffix(s, "narrowed run reported no finding of were not checked.\n") ||
		strings.Count(s, "\n") != 1 {
		t.Errorf("long note: %q", s)
	}
}

// TestAnUnnamedRuleIsNamedByItsPosition: hand-written rules may have no id.
func TestAnUnnamedRuleIsNamedByItsPosition(t *testing.T) {
	f := ssnAt("customers.txt", ssnLine, 3)
	mgr := ruleManager("0000000000000000000000000000000000000000000000000000000000000000", (&SuppressionManager{}).findingHashVersion(f, hashVersionCurrent))
	for i := range mgr.config.Rules {
		mgr.config.Rules[i].Metadata = map[string]string{"filename": "customers.txt", "finding_type": "SSN"}
	}
	mgr.IsSuppressed(f)
	if got := mgr.UnmatchedRules(notesScope); fmt.Sprint(got.IDs) != "[rule #1]" {
		t.Errorf("%v", got.IDs)
	}
}

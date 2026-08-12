// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suppressions

import (
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// contextlessFinding is a finding as secrets / personname / cloudresources used to
// emit it: no ContextInfo at all.
func contextlessFinding(validator, findingType, text string) detector.Match {
	return detector.Match{
		Type:       findingType,
		Text:       text,
		Filename:   "config/app.env",
		LineNumber: 4,
		Validator:  validator,
		Confidence: 90,
	}
}

// withContext is the same finding once its validator started recording context.
func withContext(m detector.Match) detector.Match {
	m.Context = detector.ContextInfo{
		FullLine:   "AWS key AKIAIOSFODNN7EXAMPLE rotate quarterly",
		BeforeText: "AWS key ",
		AfterText:  " rotate quarterly",
	}
	return m
}

func ruleManager(hashes ...string) *SuppressionManager {
	rules := make([]SuppressionRule, 0, len(hashes))
	for _, h := range hashes {
		rules = append(rules, SuppressionRule{
			Hash:    h,
			Enabled: true,
			Reason:  "reviewed: documentation example",
		})
	}
	return &SuppressionManager{enabled: true, config: &SuppressionConfig{Rules: rules}}
}

// TestExistingRulesSurviveContextRecording is the whole point of the contextless
// hash variants. An operator's rule file records decisions already made; a
// validator gaining context must not quietly turn those accepted findings back
// into noise (and, in a pre-commit gate, back into a block).
func TestExistingRulesSurviveContextRecording(t *testing.T) {
	for _, tc := range []struct {
		validator   string
		findingType string
		text        string
	}{
		{"secrets", "AWS_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE"},
		{"PERSON_NAME", "PERSON_NAME", "Michael Thompson"},
		{"cloud_resources", "AWS_ARN", "arn:aws:s3:::prod-customer-exports"},
	} {
		t.Run(tc.validator, func(t *testing.T) {
			before := contextlessFinding(tc.validator, tc.findingType, tc.text)
			after := withContext(before)

			sm := ruleManager()

			// Both legacy formulas are covered: a rule file may predate the
			// confidence change as well as the context change.
			for _, version := range []hashVersion{hashVersionNoConfidence, hashVersionLegacyConfidence} {
				oldHash := sm.findingHashVersion(before, version)
				mgr := ruleManager(oldHash)

				if ok, _ := mgr.IsSuppressed(before); !ok {
					t.Fatalf("precondition: rule under formula %d should suppress the pre-change finding", version)
				}
				if ok, rule := mgr.IsSuppressed(after); !ok {
					t.Errorf("rule written under formula %d stopped matching once context was recorded", version)
				} else if rule.Reason != "reviewed: documentation example" {
					t.Errorf("matched the wrong rule: %q", rule.Reason)
				}
			}
		})
	}
}

// TestContextlessVariantsAreScopedToTheAffectedValidators guards the deliberate
// narrowness. Offering an empty-context identity to every validator would weaken
// suppression identity across the board — two findings agreeing on type, basename,
// line and value but sitting on different line content would become
// indistinguishable, so a rule could keep suppressing after the line changed.
func TestContextlessVariantsAreScopedToTheAffectedValidators(t *testing.T) {
	sm := ruleManager()

	affected := contextlessFinding("secrets", "AWS_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE")
	if got, want := len(sm.findingHashCandidates(withContext(affected))), 4; got != want {
		t.Errorf("affected validator: %d hash candidates, want %d", got, want)
	}

	// A validator that always recorded context has no pre-existing contextless
	// rules, so it keeps exactly the two candidates it had.
	unaffected := contextlessFinding("creditcard", "VISA", "4111-1111-1111-1111")
	if got, want := len(sm.findingHashCandidates(withContext(unaffected))), 2; got != want {
		t.Errorf("unaffected validator: %d hash candidates, want %d", got, want)
	}

	// And the loosening does not leak: a contextful finding from an unaffected
	// validator is not suppressed by a rule recorded against its context-free form.
	contextfulHash := sm.findingHashVersion(withContext(unaffected), hashVersionNoConfidence)
	contextlessHash := sm.findingHashVersion(unaffected, hashVersionNoConfidence)
	if contextfulHash == contextlessHash {
		t.Fatal("fixture error: hashes should differ with and without context")
	}
	if ok, _ := ruleManager(contextlessHash).IsSuppressed(withContext(unaffected)); ok {
		t.Error("an unaffected validator's finding was suppressed by a contextless hash; " +
			"identity for the other validators must be unchanged")
	}
}

// TestNewRulesAreWrittenWithContext confirms the compatibility is read-only: rules
// generated from now on carry the current, context-bearing identity, so a rule
// file migrates as it is regenerated rather than pinning the weaker form forever.
func TestNewRulesAreWrittenWithContext(t *testing.T) {
	sm := ruleManager()
	finding := withContext(contextlessFinding("secrets", "AWS_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE"))

	written := sm.generateFindingHash(finding)
	if want := sm.findingHashVersion(finding, hashVersionNoConfidence); written != want {
		t.Errorf("generateFindingHash = %s, want the current formula %s", written, want)
	}
	for _, legacy := range []hashVersion{
		hashVersionNoConfidenceContextless,
		hashVersionLegacyConfidenceContextless,
		hashVersionLegacyConfidence,
	} {
		if written == sm.findingHashVersion(finding, legacy) {
			t.Errorf("new rules must not be written under compatibility formula %d", legacy)
		}
	}
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suppressions

import (
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// A finding's suppression identity must not depend on its confidence score.
//
// It used to. Confidence was the second component of the hash, so a saved rule stopped
// matching whenever the score moved — including for reasons unrelated to the finding.
// Measured on two .docx files with identical content and identical basenames, differing
// only by an unrelated author name in the metadata: the same API_KEY_OR_SECRET scored 55
// in one and 60 in the other, because the bridge adds a cross-path correlation boost
// when both validation paths report. A rule written against the first file left the
// finding unsuppressed in the second. The same mechanism broke 1 of 78 rules when one
// EXIF finding was demoted from 80 to 55.
//
// Confidence is a SCORE, not an identity — it is precisely the field the tool keeps
// tuning. Hashing it meant every scoring improvement silently invalidated operators'
// files, turning findings they had reviewed and accepted back into noise, and in a
// pre-commit gate back into a block.
//
// Existing rule files must keep working regardless, so matching accepts the legacy
// formula too. A file migrates as it is regenerated; an operator who never regenerates
// loses nothing.

func testMatch(confidence float64) detector.Match {
	return detector.Match{
		Type:       "API_KEY_OR_SECRET",
		Text:       "14f6364997257b9170c016a13d1f1127",
		Filename:   "report.docx",
		LineNumber: 12,
		Confidence: confidence,
		Context: detector.ContextInfo{
			FullLine:   `value "14f6364997257b9170c016a13d1f1127"`,
			BeforeText: "before",
			AfterText:  "after",
		},
	}
}

// TestHashIsStableAcrossConfidenceChange is the regression. Two findings identical in
// every respect except score must share one identity.
func TestHashIsStableAcrossConfidenceChange(t *testing.T) {
	sm := &SuppressionManager{}

	low := sm.generateFindingHash(testMatch(55))
	high := sm.generateFindingHash(testMatch(60))

	if low != high {
		t.Errorf("the same finding hashed differently at confidence 55 vs 60:\n"+
			"  55 -> %s\n  60 -> %s\n"+
			"A saved rule would stop matching after any scoring change — including one "+
			"caused by an unrelated finding elsewhere in the same document.", low, high)
	}
}

// TestLegacyHashStillMatches is the compatibility half. A rule file written before this
// change records the confidence-sensitive hash, and it must keep suppressing.
func TestLegacyHashStillMatches(t *testing.T) {
	sm := &SuppressionManager{}
	match := testMatch(55)

	legacy := sm.findingHashVersion(match, hashVersionLegacyConfidence)
	current := sm.findingHashVersion(match, hashVersionNoConfidence)

	if legacy == current {
		t.Fatal("legacy and current hashes are identical, so this test proves nothing — " +
			"the version switch is not actually changing the composite")
	}
	if !sm.hashMatchesFinding(legacy, match) {
		t.Error("a rule recorded under the legacy formula no longer matches its own " +
			"finding; every pre-existing suppression file would stop working")
	}
	if !sm.hashMatchesFinding(current, match) {
		t.Error("a rule recorded under the current formula does not match its own finding")
	}
}

// TestLegacyHashRemainsConfidenceBound documents the honest limit of the compatibility
// shim, so nobody later mistakes it for a broader guarantee. A v1 hash encodes the score
// it was written with, so it can only ever match a finding at that score. The fix is
// that NEW rules are score-free — not that old rules become so.
func TestLegacyHashRemainsConfidenceBound(t *testing.T) {
	sm := &SuppressionManager{}

	legacyAt55 := sm.findingHashVersion(testMatch(55), hashVersionLegacyConfidence)

	if sm.hashMatchesFinding(legacyAt55, testMatch(60)) {
		t.Error("a legacy hash written at confidence 55 matched a finding at 60; that " +
			"would mean the legacy formula is not being reproduced faithfully")
	}
	if !sm.hashMatchesFinding(legacyAt55, testMatch(55)) {
		t.Error("a legacy hash written at confidence 55 no longer matches at 55")
	}
}

// TestNewRulesAreWrittenWithTheCurrentFormula pins which version AddSuppression records.
// If new rules were still written with the legacy hash the change would be inert.
func TestNewRulesAreWrittenWithTheCurrentFormula(t *testing.T) {
	sm := &SuppressionManager{
		config:  &SuppressionConfig{Version: "1.0"},
		enabled: true,
	}
	match := testMatch(55)

	if err := sm.AddSuppression(match, "reviewed", "tester", nil); err != nil {
		t.Fatalf("AddSuppression: %v", err)
	}
	if len(sm.config.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(sm.config.Rules))
	}

	want := sm.findingHashVersion(match, hashVersionNoConfidence)
	if got := sm.config.Rules[0].Hash; got != want {
		t.Errorf("new rule hash = %s, want the current (confidence-free) formula %s", got, want)
	}
}

// TestDuplicateDetectionSpansBothFormulas guards the regeneration path. A file holding a
// legacy rule must not gain a second rule for the same finding, or it would grow one
// duplicate per finding on every regeneration.
func TestDuplicateDetectionSpansBothFormulas(t *testing.T) {
	sm := &SuppressionManager{
		config:  &SuppressionConfig{Version: "1.0"},
		enabled: true,
	}
	match := testMatch(55)

	// Seed a rule as an older binary would have written it.
	sm.config.Rules = append(sm.config.Rules, SuppressionRule{
		ID:      "SUP-00000001",
		Hash:    sm.findingHashVersion(match, hashVersionLegacyConfidence),
		Enabled: true,
	})
	sm.rebuildHashIndex()

	err := sm.AddSuppression(match, "reviewed", "tester", nil)
	if err == nil {
		t.Errorf("AddSuppression accepted a finding already covered by a legacy rule; the "+
			"file now holds %d rules for one decision", len(sm.config.Rules))
	}
}

// TestSuppressionSurvivesAConfidenceShift is the end-to-end property, expressed through
// IsSuppressed rather than the hash helpers: a rule written when a finding scored 55
// still suppresses it at 60.
func TestSuppressionSurvivesAConfidenceShift(t *testing.T) {
	sm := &SuppressionManager{
		config:  &SuppressionConfig{Version: "1.0"},
		enabled: true,
	}

	if err := sm.AddSuppression(testMatch(55), "reviewed", "tester", nil); err != nil {
		t.Fatalf("AddSuppression: %v", err)
	}
	sm.config.Rules[0].Enabled = true
	sm.rebuildHashIndex()

	if ok, _ := sm.IsSuppressed(testMatch(55)); !ok {
		t.Fatal("the rule does not suppress the finding it was written against; the rest " +
			"of this test would pass for the wrong reason")
	}
	if ok, _ := sm.IsSuppressed(testMatch(60)); !ok {
		t.Error("a rule written at confidence 55 stopped suppressing the same finding at " +
			"60. That is the defect: an unrelated finding elsewhere in the document can " +
			"move this score, and the operator's reviewed-and-accepted finding comes back.")
	}
}

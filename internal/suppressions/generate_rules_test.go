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

// newLineMatch builds a match that occupies a distinct line, so each one gets a
// distinct finding hash (the hash folds in LineNumber and FullLine).
func newLineMatch(matchType, text string, line int) detector.Match {
	return detector.Match{
		Type:       matchType,
		Text:       text,
		Filename:   "f.txt",
		LineNumber: line,
		Confidence: 70,
		Context:    detector.ContextInfo{FullLine: "value = " + text},
	}
}

// A finding that appears more than once in a single scan must produce exactly
// one rule. Previously the batch loop looked up existing hashes in a map that
// was never updated with the hashes it appended, so N occurrences of the same
// finding wrote N byte-identical rules differing only in their SUP- id.
func TestGenerateSuppressionRules_DuplicateFindingYieldsOneRule(t *testing.T) {
	sm := NewSuppressionManager(filepath.Join(t.TempDir(), "s.yaml"))

	m := newLineMatch("SSN", "123-45-6789", 3)
	if err := sm.GenerateSuppressionRules([]detector.Match{m, m, m}, "bulk", true); err != nil {
		t.Fatalf("GenerateSuppressionRules failed: %v", err)
	}

	rules := sm.ListSuppressions()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule for one distinct finding, got %d", len(rules))
	}
}

// Re-running a scan must refresh last_seen_at on rules that already exist.
// Previously the lookup map held *SuppressionRule into config.Rules while the
// same loop appended to that slice; once an append reallocated the backing
// array, the update wrote into the abandoned copy and was lost on save. The
// order matters — the pre-existing finding must come AFTER new ones for the
// realloc to happen before the update.
func TestGenerateSuppressionRules_UpdatesLastSeenAfterAppend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.yaml")

	seed := newLineMatch("SSN", "123-45-6789", 1)

	sm := NewSuppressionManager(path)
	if err := sm.GenerateSuppressionRules([]detector.Match{seed}, "bulk", true); err != nil {
		t.Fatalf("seed failed: %v", err)
	}
	seeded := sm.ListSuppressions()
	if len(seeded) != 1 || seeded[0].LastSeenAt == nil {
		t.Fatalf("seed rule not written as expected: %+v", seeded)
	}
	seedSeenAt := *seeded[0].LastSeenAt

	// Reload from disk the way a second CLI invocation would, then re-scan with
	// enough NEW findings ahead of the seeded one to force a slice growth.
	sm2 := NewSuppressionManager(path)
	batch := make([]detector.Match, 0, 12)
	for i := 2; i <= 12; i++ {
		batch = append(batch, newLineMatch("EMAIL", "a@b.com", i))
	}
	batch = append(batch, seed)

	// Guarantee a distinguishable timestamp regardless of clock granularity.
	time.Sleep(2 * time.Millisecond)
	if err := sm2.GenerateSuppressionRules(batch, "bulk", true); err != nil {
		t.Fatalf("second pass failed: %v", err)
	}

	var found bool
	for _, r := range sm2.ListSuppressions() {
		if r.Hash != seeded[0].Hash {
			continue
		}
		found = true
		if r.LastSeenAt == nil {
			t.Fatal("existing rule lost its last_seen_at")
		}
		if !r.LastSeenAt.After(seedSeenAt) {
			t.Errorf("last_seen_at was not refreshed: still %v (seeded %v)", *r.LastSeenAt, seedSeenAt)
		}
	}
	if !found {
		t.Fatal("seeded rule missing from the rule set after the second pass")
	}

	// And the refresh must be persisted, not just held in memory.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if strings.Count(string(data), "- id:") != 12 {
		t.Errorf("expected 12 rules on disk, got %d", strings.Count(string(data), "- id:"))
	}
}

// The existing-rule path must not silently swallow new findings that arrive in
// the same batch, and IDs must stay unique after the index fix.
func TestGenerateSuppressionRules_MixedBatchIDsAreUnique(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.yaml")
	sm := NewSuppressionManager(path)

	first := newLineMatch("SSN", "123-45-6789", 1)
	if err := sm.GenerateSuppressionRules([]detector.Match{first}, "bulk", true); err != nil {
		t.Fatalf("seed failed: %v", err)
	}

	sm2 := NewSuppressionManager(path)
	batch := []detector.Match{
		first,                                    // existing -> touch
		newLineMatch("EMAIL", "a@b.com", 2),      // new
		newLineMatch("EMAIL", "a@b.com", 2),      // duplicate of the new one
		newLineMatch("PHONE", "555-010-1234", 3), // new
	}
	if err := sm2.GenerateSuppressionRules(batch, "bulk", true); err != nil {
		t.Fatalf("second pass failed: %v", err)
	}

	rules := sm2.ListSuppressions()
	if len(rules) != 3 {
		t.Fatalf("expected 3 distinct rules (1 seeded + 2 new), got %d", len(rules))
	}

	seenIDs := make(map[string]bool, len(rules))
	seenHashes := make(map[string]bool, len(rules))
	for _, r := range rules {
		if seenIDs[r.ID] {
			t.Errorf("duplicate rule ID %q", r.ID)
		}
		if seenHashes[r.Hash] {
			t.Errorf("duplicate rule hash for ID %q", r.ID)
		}
		seenIDs[r.ID] = true
		seenHashes[r.Hash] = true
	}
}

// Generated metadata records confidence at the same precision the finding hash
// consumes (%.2f). It used to be written at %.0f, so a user could not
// reconstruct the hash from the rule file — and the troubleshooting guide's
// "verify confidence formatting (2 decimal places)" advice was unfollowable.
func TestGenerateSuppressionRules_ConfidenceMetadataMatchesHashPrecision(t *testing.T) {
	sm := NewSuppressionManager(filepath.Join(t.TempDir(), "s.yaml"))

	m := newLineMatch("SSN", "123-45-6789", 1)
	m.Confidence = 84.5
	if err := sm.GenerateSuppressionRules([]detector.Match{m}, "bulk", true); err != nil {
		t.Fatalf("GenerateSuppressionRules failed: %v", err)
	}

	rules := sm.ListSuppressions()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if got := rules[0].Metadata["confidence"]; got != "84.50" {
		t.Errorf("confidence metadata = %q, want %q", got, "84.50")
	}
}

// Whatever else changes, a generated rule must still suppress the finding it
// was generated from — the round trip is the whole point of the feature.
func TestGenerateSuppressionRules_GeneratedRuleStillSuppresses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.yaml")
	sm := NewSuppressionManager(path)

	m := newLineMatch("SSN", "123-45-6789", 7)
	if err := sm.GenerateSuppressionRules([]detector.Match{m, m}, "bulk", true); err != nil {
		t.Fatalf("GenerateSuppressionRules failed: %v", err)
	}

	// Fresh manager reading the file back, as a later scan would.
	sm2 := NewSuppressionManager(path)
	if ok, rule := sm2.IsSuppressed(m); !ok {
		t.Error("generated rule does not suppress the finding it came from")
	} else if rule == nil {
		t.Error("suppressed but no rule returned")
	}
}

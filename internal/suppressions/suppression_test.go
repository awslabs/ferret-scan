// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suppressions

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/explain"
)

func newTestMatch(matchType, text, filename string) detector.Match {
	return detector.Match{
		Type:       matchType,
		Text:       text,
		Filename:   filename,
		LineNumber: 1,
		Confidence: 0.9,
	}
}

func TestNewSuppressionManager_NoFile(t *testing.T) {
	sm := NewSuppressionManager("/nonexistent/path.yaml")
	if sm == nil {
		t.Fatal("expected non-nil manager")
	}
	if !sm.IsEnabled() {
		t.Error("suppression manager should be enabled by default")
	}
}

func TestAddAndIsSuppressed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "suppressions.yaml")

	sm := NewSuppressionManager(path)
	match := newTestMatch("EMAIL", "test@example.com", "test.txt")

	if err := sm.AddSuppression(match, "test reason", "tester", nil); err != nil {
		t.Fatalf("AddSuppression failed: %v", err)
	}

	suppressed, rule := sm.IsSuppressed(match)
	if !suppressed {
		t.Error("match should be suppressed")
	}
	if rule == nil {
		t.Error("expected non-nil rule")
	}
	if rule.Reason != "test reason" {
		t.Errorf("expected reason 'test reason', got %q", rule.Reason)
	}
}

func TestIsSuppressed_NotSuppressed(t *testing.T) {
	sm := NewSuppressionManager("")
	match := newTestMatch("EMAIL", "nobody@example.com", "file.txt")

	suppressed, rule := sm.IsSuppressed(match)
	if suppressed {
		t.Error("match should not be suppressed")
	}
	if rule != nil {
		t.Error("expected nil rule for unsuppressed match")
	}
}

func TestRemoveSuppression(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "suppressions.yaml")

	sm := NewSuppressionManager(path)
	match := newTestMatch("SSN", "123-45-6789", "doc.txt")

	if err := sm.AddSuppression(match, "false positive", "tester", nil); err != nil {
		t.Fatalf("AddSuppression failed: %v", err)
	}

	rules := sm.ListSuppressions()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	if err := sm.RemoveSuppression(rules[0].ID); err != nil {
		t.Fatalf("RemoveSuppression failed: %v", err)
	}

	suppressed, _ := sm.IsSuppressed(match)
	if suppressed {
		t.Error("match should no longer be suppressed after removal")
	}
}

func TestCleanupExpired(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "suppressions.yaml")

	sm := NewSuppressionManager(path)
	match := newTestMatch("PHONE", "555-1234", "file.txt")

	past := time.Now().Add(-time.Hour)
	if err := sm.AddSuppression(match, "expired", "tester", &past); err != nil {
		t.Fatalf("AddSuppression failed: %v", err)
	}

	removed := sm.CleanupExpired()
	if removed != 1 {
		t.Errorf("expected 1 expired rule removed, got %d", removed)
	}

	suppressed, _ := sm.IsSuppressed(match)
	if suppressed {
		t.Error("expired suppression should not suppress match")
	}
}

func TestSetEnabled(t *testing.T) {
	sm := NewSuppressionManager("")
	sm.SetEnabled(false)
	if sm.IsEnabled() {
		t.Error("expected manager to be disabled")
	}
	sm.SetEnabled(true)
	if !sm.IsEnabled() {
		t.Error("expected manager to be enabled")
	}
}

func TestListSuppressions_Empty(t *testing.T) {
	// Use a path that definitely doesn't exist to get a fresh manager
	sm := NewSuppressionManager("/nonexistent/path/that/does/not/exist.yaml")
	rules := sm.ListSuppressions()
	if rules == nil {
		t.Error("expected non-nil slice (empty is fine)")
	}
	if len(rules) != 0 {
		t.Errorf("expected 0 rules, got %d", len(rules))
	}
}

func TestGenerateSuppressionRules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "suppressions.yaml")

	sm := NewSuppressionManager(path)
	matches := []detector.Match{
		newTestMatch("EMAIL", "a@b.com", "f.txt"),
		newTestMatch("SSN", "111-22-3333", "f.txt"),
	}

	if err := sm.GenerateSuppressionRules(matches, "bulk suppress", true); err != nil {
		t.Fatalf("GenerateSuppressionRules failed: %v", err)
	}

	rules := sm.ListSuppressions()
	if len(rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(rules))
	}
}

func TestGenerateSuppressionRules_PrefersDraftedExplanationReason(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "suppressions.yaml")
	sm := NewSuppressionManager(path)

	annotated := newTestMatch("CREDIT_CARD", "4111111111111111", "card_test.go")
	plain := newTestMatch("EMAIL", "a@b.com", "f.txt")
	// Attach a drafted suppression reason only to the first match.
	withReason := []detector.Match{annotated}
	explain.Annotate(withReason, explain.NewSignalSynthesizer())

	matches := []detector.Match{withReason[0], plain}
	if err := sm.GenerateSuppressionRules(matches, "GENERIC FALLBACK", false); err != nil {
		t.Fatalf("GenerateSuppressionRules failed: %v", err)
	}

	rules := sm.ListSuppressions()
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}

	// Find each rule by finding_type and assert its reason.
	var ccReason, emailReason string
	for _, r := range rules {
		switch r.Metadata["finding_type"] {
		case "CREDIT_CARD":
			ccReason = r.Reason
		case "EMAIL":
			emailReason = r.Reason
		}
	}

	if ccReason == "GENERIC FALLBACK" || ccReason == "" {
		t.Errorf("annotated finding should use the drafted reason, got %q", ccReason)
	}
	if emailReason != "GENERIC FALLBACK" {
		t.Errorf("unannotated finding should fall back to the generic reason, got %q", emailReason)
	}
}

func TestSuppressionRoundTrip_ExplainDoesNotChangeHash(t *testing.T) {
	// Regression: the --explain annotation must not alter a finding's
	// suppression identity. A rule generated from an annotated match must
	// still suppress the same finding on re-scan (and the un-annotated
	// equivalent), proving the explanation didn't change the hash.
	dir := t.TempDir()
	path := filepath.Join(dir, "suppressions.yaml")
	sm := NewSuppressionManager(path)

	base := newTestMatch("CREDIT_CARD", "4111111111111111", "card.txt")

	// Annotate a copy and generate a rule from it (enabled).
	annotated := []detector.Match{base}
	explain.Annotate(annotated, explain.NewSignalSynthesizer())
	if _, ok := explain.FromMatch(annotated[0]); !ok {
		t.Fatal("precondition: match should be annotated")
	}
	if err := sm.GenerateSuppressionRules(annotated, "generic", true); err != nil {
		t.Fatalf("GenerateSuppressionRules: %v", err)
	}

	// The annotated match is suppressed...
	if ok, _ := sm.IsSuppressed(annotated[0]); !ok {
		t.Error("annotated finding should be suppressed by the rule generated from it")
	}
	// ...and so is the identical UN-annotated match (same hash).
	if ok, _ := sm.IsSuppressed(base); !ok {
		t.Error("un-annotated finding should be suppressed by the same rule — explanation must not change the hash")
	}
}

func TestGetConfigPath(t *testing.T) {
	path := "/some/path.yaml"
	sm := NewSuppressionManager(path)
	if sm.GetConfigPath() != path {
		t.Errorf("expected config path %q, got %q", path, sm.GetConfigPath())
	}
}

func TestPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "suppressions.yaml")

	sm1 := NewSuppressionManager(path)
	match := newTestMatch("CREDIT_CARD", "4111111111111111", "card.txt")
	if err := sm1.AddSuppression(match, "test card", "tester", nil); err != nil {
		t.Fatalf("AddSuppression failed: %v", err)
	}

	// Verify file was written
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("suppression file should have been created")
	}

	// Load in a new manager and verify the rule persists
	sm2 := NewSuppressionManager(path)
	suppressed, _ := sm2.IsSuppressed(match)
	if !suppressed {
		t.Error("suppression should persist across manager instances")
	}
}

// TestIsSuppressed_ConcurrentReads exercises the read path under load to
// make sure the lazy index build can't race itself. Run with `go test -race`
// to catch lock-protocol regressions.
func TestIsSuppressed_ConcurrentReads(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "sup.yaml")

	sm := NewSuppressionManager(path)

	// Seed a few real rules through the public API so the index is built
	// the same way production code builds it.
	for i := 0; i < 5; i++ {
		match := newTestMatch("EMAIL", fmt.Sprintf("user%d@example.com", i), "sample.txt")
		match.LineNumber = i + 1
		if err := sm.AddSuppression(match, "concurrent test", "tester", nil); err != nil {
			t.Fatalf("AddSuppression: %v", err)
		}
	}

	// Two test matches: one that exists in the rules, one that doesn't.
	hit := newTestMatch("EMAIL", "user2@example.com", "sample.txt")
	hit.LineNumber = 3
	miss := newTestMatch("EMAIL", "nobody@example.com", "missing.txt")

	const goroutines = 100
	const iters = 1000

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				if g%2 == 0 {
					suppressed, _ := sm.IsSuppressed(hit)
					if !suppressed {
						t.Errorf("g=%d i=%d: hit case returned false", g, i)
						return
					}
				} else {
					suppressed, _ := sm.IsSuppressed(miss)
					if suppressed {
						t.Errorf("g=%d i=%d: miss case returned true", g, i)
						return
					}
				}
			}
		}(g)
	}
	wg.Wait()
}

// TestIsSuppressed_LazyIndexBuildIsRaceFree forces the lazy-build branch by
// constructing a manager and clearing its index before the first call. Each
// test goroutine sees rulesByHash == nil on entry and would race the
// rebuildHashIndex write under the old code. Run with `go test -race`.
func TestIsSuppressed_LazyIndexBuildIsRaceFree(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "sup.yaml")

	sm := NewSuppressionManager(path)
	for i := 0; i < 10; i++ {
		match := newTestMatch("EMAIL", fmt.Sprintf("u%d@example.com", i), "f.txt")
		match.LineNumber = i + 1
		if err := sm.AddSuppression(match, "lazy", "t", nil); err != nil {
			t.Fatalf("AddSuppression: %v", err)
		}
	}
	// Force the lazy path by clearing the index. Done under the same lock
	// IsSuppressed uses so we don't fight with the production code path.
	sm.indexMu.Lock()
	sm.rulesByHash = nil
	sm.indexMu.Unlock()

	probe := newTestMatch("EMAIL", "u3@example.com", "f.txt")
	probe.LineNumber = 4

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			suppressed, _ := sm.IsSuppressed(probe)
			if !suppressed {
				t.Error("expected suppression match after lazy build")
			}
		}()
	}
	wg.Wait()
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suppressions

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"ferret-scan/internal/detector"
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

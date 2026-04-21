// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package gitignore

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestNew_NoGitignore_Disabled(t *testing.T) {
	dir := t.TempDir()

	m, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// .git is always skipped, so matcher reports enabled. But with no rules
	// and no .git path segment, Match should be false for normal files.
	if m.Match(filepath.Join(dir, "file.go")) {
		t.Error("expected no match for plain file without .gitignore")
	}
}

func TestMatch_BasicPatterns(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".gitignore"), "*.log\nvendor/\n")

	m, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cases := map[string]bool{
		"app.log":               true,
		"src/app.log":           true,
		"vendor/github.com/x/y": true,
		"src/main.go":           false,
		"README.md":             false,
	}
	for rel, want := range cases {
		got := m.Match(filepath.Join(dir, rel))
		if got != want {
			t.Errorf("Match(%s) = %v, want %v", rel, got, want)
		}
	}
}

func TestMatch_NestedGitignore(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".gitignore"), "*.log\n")
	writeFile(t, filepath.Join(dir, "sub", ".gitignore"), "*.tmp\n")

	m, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Parent .gitignore rule applies everywhere under root.
	if !m.Match(filepath.Join(dir, "a.log")) {
		t.Error("parent *.log should ignore a.log at root")
	}
	if !m.Match(filepath.Join(dir, "sub", "a.log")) {
		t.Error("parent *.log should ignore sub/a.log")
	}
	// Nested rule applies only to its subtree.
	if !m.Match(filepath.Join(dir, "sub", "a.tmp")) {
		t.Error("nested *.tmp should ignore sub/a.tmp")
	}
	if m.Match(filepath.Join(dir, "a.tmp")) {
		t.Error("nested *.tmp should NOT ignore root a.tmp")
	}
	// Siblings of the nested gitignore dir are not affected.
	if m.Match(filepath.Join(dir, "other", "a.tmp")) {
		t.Error("nested *.tmp should NOT ignore other/a.tmp")
	}
}

func TestMatch_Negation(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".gitignore"), "*.log\n!keep.log\n")

	m, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if !m.Match(filepath.Join(dir, "app.log")) {
		t.Error("expected app.log to be ignored")
	}
	if m.Match(filepath.Join(dir, "keep.log")) {
		t.Error("expected keep.log to be un-ignored by negation")
	}
}

func TestMatch_DotGitAlwaysSkipped(t *testing.T) {
	dir := t.TempDir()

	m, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if !m.Match(filepath.Join(dir, ".git", "config")) {
		t.Error(".git directory should always be matched (skipped)")
	}
	if !m.Match(filepath.Join(dir, "sub", ".git", "HEAD")) {
		t.Error("nested .git directory should always be matched")
	}
}

func TestMatch_NilMatcher(t *testing.T) {
	var m *Matcher
	if m.Match("anything") {
		t.Error("nil matcher should never match")
	}
	if m.Enabled() {
		t.Error("nil matcher should not be enabled")
	}
}

func TestReadPatterns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".gitignore")
	writeFile(t, path, "# comment\n\n*.log\n  vendor/  \n")

	patterns, err := ReadPatterns(path)
	if err != nil {
		t.Fatalf("ReadPatterns: %v", err)
	}
	want := []string{"*.log", "vendor/"}
	if len(patterns) != len(want) {
		t.Fatalf("patterns = %v, want %v", patterns, want)
	}
	for i := range want {
		if patterns[i] != want[i] {
			t.Errorf("patterns[%d] = %q, want %q", i, patterns[i], want[i])
		}
	}
}

func TestMatch_FilePathAsRoot(t *testing.T) {
	// If a file (not a directory) is passed to New, it should use the parent
	// directory as root.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".gitignore"), "*.log\n")
	file := filepath.Join(dir, "main.go")
	writeFile(t, file, "package main\n")

	m, err := New(file)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !m.Match(filepath.Join(dir, "a.log")) {
		t.Error("expected .gitignore in parent of file-root to apply")
	}
}

func TestMatch_AnchoredRootPattern(t *testing.T) {
	// '/build/' is anchored to the .gitignore's directory (the root here),
	// so it should only match root-level build/, not nested/build/.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".gitignore"), "/build/\n")
	writeFile(t, filepath.Join(dir, "build", "a.py"), "x")
	writeFile(t, filepath.Join(dir, "nested", "build", "b.py"), "x")

	m, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if !m.Match(filepath.Join(dir, "build", "a.py")) {
		t.Error("/build/ should match root-level build/a.py")
	}
	if m.Match(filepath.Join(dir, "nested", "build", "b.py")) {
		t.Error("/build/ should NOT match nested/build/b.py")
	}
}

func TestMatch_GitInfoExcludeScoped(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".git", "info", "exclude"), "local.txt\n")
	writeFile(t, filepath.Join(dir, "local.txt"), "x")
	writeFile(t, filepath.Join(dir, "keep.py"), "x")

	m, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if !m.Match(filepath.Join(dir, "local.txt")) {
		t.Error(".git/info/exclude rule should apply")
	}
	if m.Match(filepath.Join(dir, "keep.py")) {
		t.Error("unrelated file should not be ignored")
	}
}

func TestMatch_NodeModulesPreWalkSkipped(t *testing.T) {
	// Matcher's pre-walk for nested .gitignore files should skip node_modules
	// so we don't waste time parsing package-internal ignores. Verify by
	// planting a .gitignore inside node_modules that would (if loaded) affect
	// a sibling file.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "node_modules", ".gitignore"), "sibling.py\n")
	writeFile(t, filepath.Join(dir, "sibling.py"), "x")

	m, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if m.Match(filepath.Join(dir, "sibling.py")) {
		t.Error("rules inside node_modules/.gitignore should not be loaded")
	}
}

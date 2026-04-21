// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package gitignore

// Integration tests exercise the full .gitignore pipeline — nested discovery,
// scoped matching, negation, and the interaction of multiple .gitignore files
// in a realistic tree. These go beyond the single-file unit tests and mirror
// the scenarios that the CLI end-to-end harness previously caught.

import (
	"os"
	"path/filepath"
	"testing"
)

// buildTree lays out a fixture tree under dir. Each entry maps a relative path
// to its file contents (empty value = empty file). Intermediate directories
// are created automatically.
func buildTree(t *testing.T, dir string, tree map[string]string) {
	t.Helper()
	for rel, content := range tree {
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
	}
}

// assertMatch runs Match for each rel path in want and verifies the result.
// want maps relative-to-root paths to the expected Match() boolean.
func assertMatch(t *testing.T, m *Matcher, root string, want map[string]bool) {
	t.Helper()
	for rel, expect := range want {
		got := m.Match(filepath.Join(root, rel))
		if got != expect {
			t.Errorf("Match(%s) = %v, want %v", rel, got, expect)
		}
	}
}

// TestIntegration_NestedRulesScopedToSubtree verifies a nested .gitignore
// only affects files within its directory, not siblings. This is the exact
// bug the CLI harness caught before we made ignorers scope-aware.
func TestIntegration_NestedRulesScopedToSubtree(t *testing.T) {
	dir := t.TempDir()
	buildTree(t, dir, map[string]string{
		".gitignore":       "# parent has no rules\n",
		"src/.gitignore":   "*.log\n",
		"src/main.py":      "x",
		"src/secret.log":   "x", // ignored by src/.gitignore
		"other/secret.log": "x", // NOT ignored — different subtree
		"other/main.py":    "x",
	})

	m, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	assertMatch(t, m, dir, map[string]bool{
		"src/main.py":      false,
		"src/secret.log":   true,
		"other/secret.log": false,
		"other/main.py":    false,
	})
}

// TestIntegration_RootAndNestedCombined verifies that root-level rules apply
// globally while nested rules add extra scoped restrictions.
func TestIntegration_RootAndNestedCombined(t *testing.T) {
	dir := t.TempDir()
	buildTree(t, dir, map[string]string{
		".gitignore":     "*.log\n",
		"src/.gitignore": "*.tmp\n",
		"src/a.log":      "x", // ignored by root rule
		"src/a.tmp":      "x", // ignored by nested rule
		"src/keep.py":    "x",
		"other/a.log":    "x", // ignored by root rule
		"other/a.tmp":    "x", // NOT ignored — nested rule doesn't apply here
	})

	m, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	assertMatch(t, m, dir, map[string]bool{
		"src/a.log":   true,
		"src/a.tmp":   true,
		"src/keep.py": false,
		"other/a.log": true,
		"other/a.tmp": false,
	})
}

// TestIntegration_NegationAcrossFiles verifies that negation within a single
// .gitignore still un-ignores files covered by a prior pattern.
func TestIntegration_NegationAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	buildTree(t, dir, map[string]string{
		".gitignore": "*.log\n!keep.log\n",
		"drop.log":   "x",
		"keep.log":   "x",
		"main.py":    "x",
	})

	m, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	assertMatch(t, m, dir, map[string]bool{
		"drop.log": true,
		"keep.log": false,
		"main.py":  false,
	})
}

// TestIntegration_DirPatternSkipsWholeSubtree verifies that trailing-slash
// directory patterns (like node_modules/) skip everything inside.
func TestIntegration_DirPatternSkipsWholeSubtree(t *testing.T) {
	dir := t.TempDir()
	buildTree(t, dir, map[string]string{
		".gitignore":                "node_modules/\n",
		"src/main.py":               "x",
		"node_modules/pkg/index.js": "x",
		"node_modules/pkg/deep.js":  "x",
	})

	m, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	assertMatch(t, m, dir, map[string]bool{
		"src/main.py":               false,
		"node_modules/pkg/index.js": true,
		"node_modules/pkg/deep.js":  true,
	})
}

// TestIntegration_GlobstarAtAnyDepth verifies **/*.log skips logs at any depth.
func TestIntegration_GlobstarAtAnyDepth(t *testing.T) {
	dir := t.TempDir()
	buildTree(t, dir, map[string]string{
		".gitignore":     "**/*.log\n",
		"src/main.py":    "x",
		"top.log":        "x",
		"a/b/c/deep.log": "x",
		"a/b/keep.py":    "x",
	})

	m, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	assertMatch(t, m, dir, map[string]bool{
		"src/main.py":    false,
		"top.log":        true,
		"a/b/c/deep.log": true,
		"a/b/keep.py":    false,
	})
}

// TestIntegration_AnchoredRootOnly verifies /build/ only matches at root.
func TestIntegration_AnchoredRootOnly(t *testing.T) {
	dir := t.TempDir()
	buildTree(t, dir, map[string]string{
		".gitignore":        "/build/\n",
		"src/main.py":       "x",
		"build/a.py":        "x", // matches /build/
		"nested/build/b.py": "x", // does NOT match /build/
	})

	m, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	assertMatch(t, m, dir, map[string]bool{
		"src/main.py":       false,
		"build/a.py":        true,
		"nested/build/b.py": false,
	})
}

// TestIntegration_GitInfoExclude verifies .git/info/exclude is honored.
func TestIntegration_GitInfoExclude(t *testing.T) {
	dir := t.TempDir()
	buildTree(t, dir, map[string]string{
		".git/info/exclude": "local-secret.txt\n",
		"src/main.py":       "x",
		"local-secret.txt":  "x",
	})

	m, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	assertMatch(t, m, dir, map[string]bool{
		"src/main.py":      false,
		"local-secret.txt": true,
	})
}

// TestIntegration_NodeModulesGitignoreSkipped verifies that .gitignore files
// inside node_modules are NOT loaded during pre-walk. This avoids parsing
// every package's internal gitignore (which is both slow and usually wrong
// for a host scanner — those rules target the package's own build system).
func TestIntegration_NodeModulesGitignoreSkipped(t *testing.T) {
	dir := t.TempDir()
	buildTree(t, dir, map[string]string{
		// Would ignore sibling.py if loaded, but it MUST NOT be loaded.
		"node_modules/pkg/.gitignore": "/../sibling.py\n",
		"sibling.py":                  "x",
	})

	m, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if m.Match(filepath.Join(dir, "sibling.py")) {
		t.Error("sibling.py should not be ignored — node_modules/.gitignore must be skipped")
	}
}

// TestIntegration_DotGitAlwaysSkippedRegardlessOfRules verifies that a user
// whose .gitignore explicitly un-ignores .git (`!.git/`) still has .git
// skipped. This is a safety guarantee — we never let ferret walk into .git.
func TestIntegration_DotGitAlwaysSkippedRegardlessOfRules(t *testing.T) {
	dir := t.TempDir()
	buildTree(t, dir, map[string]string{
		".gitignore":  "!.git/\n",
		".git/config": "x",
		".git/HEAD":   "x",
		"src/main.py": "x",
	})

	m, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	assertMatch(t, m, dir, map[string]bool{
		".git/config": true,
		".git/HEAD":   true,
		"src/main.py": false,
	})
}

// TestIntegration_EmptyTree verifies the matcher handles a scan root with no
// .gitignore files anywhere as a safe no-op (except .git auto-skip).
func TestIntegration_EmptyTree(t *testing.T) {
	dir := t.TempDir()
	buildTree(t, dir, map[string]string{
		"src/main.py": "x",
		"secrets.env": "x",
		"config.yaml": "x",
	})

	m, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	assertMatch(t, m, dir, map[string]bool{
		"src/main.py": false,
		"secrets.env": false,
		"config.yaml": false,
	})
}

// TestIntegration_LargeGitignore verifies a big .gitignore (many rules) is
// parsed and applied correctly. This is a smoke test; it doesn't assert on
// perf but ensures no upper bound surprise.
func TestIntegration_LargeGitignore(t *testing.T) {
	dir := t.TempDir()

	// Build a 500-rule .gitignore, none of which match main.py, plus one
	// that ignores secret.bin.
	rules := ""
	for i := 0; i < 500; i++ {
		rules += "ignored-" + string(rune('a'+i%26)) + "-dir/\n"
	}
	rules += "secret.bin\n"

	buildTree(t, dir, map[string]string{
		".gitignore":  rules,
		"src/main.py": "x",
		"secret.bin":  "x",
	})

	m, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	assertMatch(t, m, dir, map[string]bool{
		"src/main.py": false,
		"secret.bin":  true,
	})
}

// TestIntegration_GlobalExcludesOption verifies the WithGlobalExcludes option
// loads and applies rules from an XDG-style global excludes file. We point
// XDG_CONFIG_HOME at a controlled directory so the test is hermetic.
func TestIntegration_GlobalExcludesOption(t *testing.T) {
	xdg := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", xdg)

	globalIgnore := filepath.Join(xdg, "git", "ignore")
	if err := os.MkdirAll(filepath.Dir(globalIgnore), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(globalIgnore, []byte("*.bak\n"), 0o644); err != nil {
		t.Fatalf("write global excludes: %v", err)
	}

	dir := t.TempDir()
	buildTree(t, dir, map[string]string{
		"src/main.py": "x",
		"notes.bak":   "x",
	})

	m, err := New(dir, WithGlobalExcludes())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	assertMatch(t, m, dir, map[string]bool{
		"src/main.py": false,
		"notes.bak":   true,
	})
}

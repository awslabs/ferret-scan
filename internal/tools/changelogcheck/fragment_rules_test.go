// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestFragmentRulesEndToEnd drives run() -- git diff-tree, git cat-file, go list -- over a throwaway
// module for each rule #821 added, so the wiring is tested and not only the decision. It touches
// nothing but run's signature and Result's fields, both unchanged since before #821, so the same
// file also runs against the check that predates fragments, and there every case marked `new` gets
// the opposite answer.
func TestFragmentRulesEndToEnd(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	dir := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com", "GIT_CONFIG_GLOBAL=", "GIT_CONFIG_NOSYSTEM=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}

	// main after #821: a pointer under [Unreleased], a fragment directory with one note in it.
	const changelog = "# Changelog\n\n## [Unreleased]\n\nEntries for the next release live in changelog.d/.\n\n" +
		"## [v1.0.0] - 2026-01-01\n\n### 🐛 Bug Fixes\n\n- old\n"
	const fragment = "### 🐛 Bug Fixes\n\n- **x (shape):** a note\n  with a continuation line\n"
	write("go.mod", "module example.com/m\n\ngo 1.21\n")
	write("cmd/main.go", "package main\n\nfunc main() {}\n")
	write("pkg/lib/l.go", "package lib\n")
	write("docs/x.md", "# Docs\n")
	write("CHANGELOG.md", changelog)
	write("changelog.d/README.md", "# Fragments\n")
	write("changelog.d/0001-existing.md", fragment)
	git("init", "-q")
	git("add", ".")
	git("commit", "-q", "-m", "base")
	base := git("rev-parse", "HEAD")

	t.Chdir(dir)
	t.Setenv("PR_TITLE", "fix: x")
	t.Setenv("PR_AUTHOR", "someone")

	shipCode := func() { write("cmd/main.go", "package main\n\nfunc main() { _ = 1 }\n") }
	touchDocs := func() { write("docs/x.md", "# Docs\n\nMore.\n") }
	oldStyle := func() {
		write("CHANGELOG.md", strings.Replace(changelog, "changelog.d/.\n\n", "changelog.d/.\n\n### 🐛 Bug Fixes\n\n- **x:** the old way\n\n", 1))
	}

	for _, tc := range []struct {
		name         string
		labels       string
		change       func()
		wantRequired bool
		wantPass     bool
		wantMessage  string
	}{
		{name: "new: a shipped change with a new fragment passes",
			change: func() { shipCode(); write("changelog.d/0800-a-fix.md", fragment) }, wantRequired: true, wantPass: true,
			wantMessage: "changelog.d/0800-a-fix.md"},
		{name: "new: a shipped change with an old-style entry under [Unreleased] fails",
			change: func() { shipCode(); oldStyle() }, wantRequired: true, wantMessage: "fragment under changelog.d/ instead"},
		{name: "new: a docs change that adds an entry under [Unreleased] fails",
			change: func() { touchDocs(); oldStyle() }, wantMessage: "fragment under changelog.d/ instead"},
		{name: "new: the no-changelog label does not excuse an old-style entry",
			labels: `["no-changelog"]`, change: func() { shipCode(); oldStyle() }, wantRequired: true,
			wantMessage: "fragment under changelog.d/ instead"},
		{name: "new: a malformed fragment fails a docs-only PR",
			change:      func() { touchDocs(); write("changelog.d/0801-bad.md", "### Bug Fixes\n\n- y\n") },
			wantMessage: "not one of the canonical headings"},
		{name: "new: a fragment plus a correction under a released section passes",
			change: func() {
				shipCode()
				write("changelog.d/0800-a-fix.md", fragment)
				write("CHANGELOG.md", strings.Replace(changelog, "- old\n", "- old\n- a forgotten note for v1.0.0\n", 1))
			}, wantRequired: true, wantPass: true},
		{name: "a shipped change with no fragment fails",
			change: shipCode, wantRequired: true, wantMessage: "NNNN-slug.md"},
		{name: "a shipped change with a misnamed fragment fails",
			change: func() { shipCode(); write("changelog.d/fix-thing.md", fragment) }, wantRequired: true,
			wantMessage: "changelog.d/fix-thing.md would stop the release"},
		{name: "editing an existing fragment does not satisfy the requirement",
			change:       func() { shipCode(); write("changelog.d/0001-existing.md", fragment+"- another bullet\n") },
			wantRequired: true, wantMessage: "does not count"},
		{name: "a symlinked fragment fails",
			change: func() {
				shipCode()
				if err := os.Symlink("0001-existing.md", filepath.Join(dir, "changelog.d", "0802-link.md")); err != nil {
					t.Fatal(err)
				}
			}, wantRequired: true, wantMessage: "symlink"},
		{name: "the no-changelog label still opts a shipped change out",
			labels: `["no-changelog"]`, change: shipCode, wantRequired: true, wantPass: true},
		{name: "prose added under [Unreleased] passes",
			change: func() {
				touchDocs()
				write("CHANGELOG.md", strings.Replace(changelog, "changelog.d/.\n", "changelog.d/.\nOne more sentence.\n", 1))
			}, wantPass: true},
		{name: "deleting a fragment passes",
			change: func() { touchDocs(); os.Remove(filepath.Join(dir, "changelog.d", "0001-existing.md")) }, wantPass: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			git("reset", "-q", "--hard", base)
			git("clean", "-q", "-fd")
			labels := tc.labels
			if labels == "" {
				labels = "[]"
			}
			t.Setenv("PR_LABELS", labels)
			tc.change()
			git("add", "-A")
			git("commit", "-q", "--allow-empty", "-m", tc.name)
			r, err := run(base, "HEAD")
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if r.Required != tc.wantRequired || r.Pass != tc.wantPass {
				t.Fatalf("required=%v pass=%v, want %v/%v: %q", r.Required, r.Pass, tc.wantRequired, tc.wantPass, r.Messages)
			}
			if tc.wantMessage != "" && !strings.Contains(strings.Join(r.Messages, "\n"), tc.wantMessage) {
				t.Errorf("messages do not mention %q: %q", tc.wantMessage, r.Messages)
			}
		})
	}
}

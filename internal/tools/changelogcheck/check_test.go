// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func testSet() ShippedSet {
	return NewShippedSet(
		[]string{"cmd", "internal/validators/personname", "pkg/scan"},
		[]string{"internal/validators/personname/data/first_names.txt.gz"},
	)
}

func TestShippedSetContains(t *testing.T) {
	s := testSet()
	for p, want := range map[string]bool{
		"cmd/main.go":          true,
		"cmd/stdin_windows.go": true, // build-tagged files ship on their OS
		"cmd/main_test.go":     false,
		"cmd/testdata/x.go":    false, // testdata/ is not the package dir
		"cmd/README.md":        false,
		"internal/validators/personname/data/first_names.txt.gz": true,  // embedded, in a subdirectory
		"internal/validators/personname/data/notes.txt":          false, // beside an embed, not embedded
		"internal/perfguard/perfguard.go":                        false, // test support, not imported by cmd/ or pkg/
		"go.mod":                                                 true,
		".go-version":                                            true,
		"go.sum":                                                 false,
		"CHANGELOG.md":                                           false,
		// Published at the same tag, but not Go: the hook definition every pre-commit user pins, its
		// install stub, and the PyPI wrapper's entry point.
		".pre-commit-hooks.yaml":                 true,
		"pyproject.toml":                         true,
		"python-package/ferret_scan/cli.py":      true,
		"python-package/ferret_scan/test_cli.py": false,
		"python-package/README.md":               false,
		"config.yaml":                            false, // read at runtime from the user's tree; no release contains it
		"examples/ferret.yaml":                   false,
		// A root package missing from the merge result's graph — deleted, or moved under internal/ —
		// still ships until this release; removing it is the most breaking change a v2 module can make.
		"pkg/redact/redact.go":          true,
		"cmd/suppress/main.go":          true,
		"cmd/_scratch/x.go":             false, // the go command ignores _ and . directories
		"internal/unimported/x.go":      false,
		"internal/unimported/x_test.go": false,
	} {
		if got := s.Contains(p); got != want {
			t.Errorf("Contains(%q) = %v, want %v", p, got, want)
		}
	}
}

// changelog builds a CHANGELOG with an [Unreleased] section and one released section, and returns
// the 1-based line numbers of the first line under each.
func changelog() (lines []string, underUnreleased, underReleased int) {
	lines = strings.Split(strings.Join([]string{
		"# Changelog", // 1
		"",            // 2
		"## [Unreleased]",
		"",
		"### 🐛 Bug Fixes", // 5
		"",
		"- **x:** new entry", // 7
		"",
		"## [v1.0.0] - 2026-01-01", // 9
		"",
		"### 🐛 Bug Fixes", // 11
		"",
		"- **y:** old entry", // 13
	}, "\n"), "\n")
	return lines, 7, 13
}

func TestEvaluate(t *testing.T) {
	cl, inU, inRel := changelog()
	shipped := []string{"cmd/main.go"}
	for _, tc := range []struct {
		name         string
		in           Input
		wantRequired bool
		wantPass     bool
		wantWarning  bool
	}{
		{name: "test-only change needs nothing",
			in: Input{ChangedFiles: []string{"cmd/main_test.go", "docs/x.md"}}, wantPass: true},
		{name: "shipped change without CHANGELOG fails",
			in: Input{ChangedFiles: shipped}, wantRequired: true},
		{name: "shipped change with entry under Unreleased passes",
			in:           Input{ChangedFiles: append(shipped, "CHANGELOG.md"), ChangelogAfter: cl, ChangelogAdded: []int{inU}},
			wantRequired: true, wantPass: true},
		// The stale-anchor case: a PR open across a release whose entry merged into the section that
		// release promoted. The file changed, so a "did CHANGELOG.md change" check would pass it.
		{name: "entry only under a released section fails",
			in:           Input{ChangedFiles: append(shipped, "CHANGELOG.md"), ChangelogAfter: cl, ChangelogAdded: []int{inRel}},
			wantRequired: true, wantWarning: true},
		{name: "entry plus a history correction passes with a warning",
			in:           Input{ChangedFiles: append(shipped, "CHANGELOG.md"), ChangelogAfter: cl, ChangelogAdded: []int{inU, inRel}},
			wantRequired: true, wantPass: true, wantWarning: true},
		{name: "only a blank line added under Unreleased is not an entry",
			in:           Input{ChangedFiles: append(shipped, "CHANGELOG.md"), ChangelogAfter: cl, ChangelogAdded: []int{6}},
			wantRequired: true},
		{name: "a subsection heading alone is not an entry",
			in:           Input{ChangedFiles: append(shipped, "CHANGELOG.md"), ChangelogAfter: cl, ChangelogAdded: []int{5}},
			wantRequired: true},
		// The shape of the 12 historical misplacements: the heading added where it belongs, the bullet
		// beside the same heading in an old release.
		{name: "a heading under Unreleased with its bullet under an old release fails",
			in:           Input{ChangedFiles: append(shipped, "CHANGELOG.md"), ChangelogAfter: cl, ChangelogAdded: []int{5, inRel}},
			wantRequired: true, wantWarning: true},
		{name: "an Unreleased heading the promotion script would reject does not count",
			in: Input{ChangedFiles: append(shipped, "CHANGELOG.md"),
				ChangelogAfter: append([]string{"## [Unreleased] "}, cl[3:]...), ChangelogAdded: []int{5}},
			wantRequired: true, wantWarning: true},
		{name: "no Unreleased heading on the merge result fails",
			in:           Input{ChangedFiles: append(shipped, "CHANGELOG.md"), ChangelogAfter: cl[8:], ChangelogAdded: []int{5}},
			wantRequired: true, wantWarning: true},
		{name: "deleted CHANGELOG fails",
			in:           Input{ChangedFiles: append(shipped, "CHANGELOG.md"), ChangelogAfter: []string{}},
			wantRequired: true},
		{name: "opt-out label passes a required PR",
			in:           Input{ChangedFiles: shipped, Labels: []string{"bug", "No-Changelog "}},
			wantRequired: true, wantPass: true},
		{name: "dependabot is exempt",
			in: Input{ChangedFiles: []string{"go.mod"}, Author: "dependabot[bot]"}, wantPass: true},
		{name: "a human go.mod bump is required",
			in: Input{ChangedFiles: []string{"go.mod", "go.sum"}, Author: "someone"}, wantRequired: true},
		{name: "breaking title requires an entry with no shipped change",
			in: Input{Title: "refactor(config)!: rename the profile key", ChangedFiles: []string{"docs/x.md"}}, wantRequired: true},
		{name: "unscoped breaking title",
			in: Input{Title: "feat!: drop v1 output", ChangedFiles: []string{"docs/x.md"}}, wantRequired: true},
		{name: "a docs PR filing its entry under an old release is warned, not failed",
			in:       Input{ChangedFiles: []string{"docs/x.md", "CHANGELOG.md"}, ChangelogAfter: cl, ChangelogAdded: []int{inRel}},
			wantPass: true, wantWarning: true},
		{name: "a bang outside the type is not breaking",
			in: Input{Title: "fix: stop the panic!", ChangedFiles: []string{"docs/x.md"}}, wantPass: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.in.Shipped = testSet()
			r := Evaluate(tc.in)
			if r.Required != tc.wantRequired || r.Pass != tc.wantPass || (len(r.Warnings) > 0) != tc.wantWarning {
				t.Errorf("got required=%v pass=%v warnings=%q; want required=%v pass=%v warning=%v\nmessages: %q",
					r.Required, r.Pass, r.Warnings, tc.wantRequired, tc.wantPass, tc.wantWarning, r.Messages)
			}
			if len(r.Messages) == 0 {
				t.Error("every decision must say why")
			}
		})
	}
}

func TestEvaluatePostMerge(t *testing.T) {
	cl, inU, inRel := changelog()
	for _, tc := range []struct {
		name        string
		own, merged placement
		wantPass    bool
	}{
		{"stale anchor: branch said Unreleased, merge said a release",
			place(cl, []int{inU}), place(cl, []int{inRel}), false},
		{"consistent: both under Unreleased", place(cl, []int{inU}), place(cl, []int{inU}), true},
		{"a deliberate backfill is filed under the release on its own branch too",
			place(cl, []int{inRel}), place(cl, []int{inRel}), true},
		{"no CHANGELOG change", place(nil, nil), place(nil, nil), true},
	} {
		if r := EvaluatePostMerge(tc.own, tc.merged); r.Pass != tc.wantPass || len(r.Messages) == 0 {
			t.Errorf("%s: pass=%v, want %v (%q)", tc.name, r.Pass, tc.wantPass, r.Messages)
		}
	}
}

func TestAddedLines(t *testing.T) {
	diff := strings.Join([]string{
		"diff --git a/CHANGELOG.md b/CHANGELOG.md",
		"--- a/CHANGELOG.md",
		"+++ b/CHANGELOG.md",
		"@@ -3,0 +4,2 @@ ## [Unreleased]",
		"+- one",
		"+",
		"@@ -10 +12 @@ heading",
		"-old",
		"+new",
		"@@ -20,3 +21,0 @@", // deletion only: adds nothing
		"-a",
		"-b",
		"-c",
		"@@ -30 +28 @@",
		"-x",
		"+++ starts like a file header but is content",
		`\ No newline at end of file`,
	}, "\n")
	got := addedLines(diff)
	want := []int{4, 5, 12, 28}
	if len(got) != len(want) {
		t.Fatalf("addedLines = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("addedLines = %v, want %v", got, want)
		}
	}
}

// TestRunEndToEnd drives the real I/O path — go list, git diff, git show — against a throwaway
// module, so the wiring is tested and not only the decision. The module ships cmd/ and, only from a
// _windows.go file, internal/winonly: a linux-only `go list` would miss that package.
func TestRunEndToEnd(t *testing.T) {
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
	write("go.mod", "module example.com/m\n\ngo 1.21\n")
	write("cmd/main.go", "package main\n\nfunc main() {}\n")
	write("cmd/win_windows.go", "package main\n\nimport _ \"example.com/m/internal/winonly\"\n")
	write("internal/winonly/w.go", "package winonly\n")
	write("internal/support/s.go", "package support\n")
	write("pkg/lib/l.go", "package lib\n")
	write("CHANGELOG.md", "# Changelog\n\n## [Unreleased]\n\n## [v1.0.0] - 2026-01-01\n\n- old\n")
	git("init", "-q")
	git("add", ".")
	git("commit", "-q", "-m", "base")
	base := git("rev-parse", "HEAD")

	t.Chdir(dir)
	t.Setenv("PR_TITLE", "fix: x")
	t.Setenv("PR_AUTHOR", "someone")
	t.Setenv("PR_LABELS", "[]")

	step := func(name string, change func(), wantRequired, wantPass bool) {
		t.Helper()
		git("reset", "-q", "--hard", base)
		change()
		git("add", "-A")
		git("commit", "-q", "--allow-empty", "-m", name)
		r, err := run(base, "HEAD")
		if err != nil {
			t.Fatalf("%s: run: %v", name, err)
		}
		if r.Required != wantRequired || r.Pass != wantPass {
			t.Errorf("%s: required=%v pass=%v, want %v/%v: %q", name, r.Required, r.Pass, wantRequired, wantPass, r.Messages)
		}
	}
	step("windows-only package", func() { write("internal/winonly/w.go", "package winonly\n\nvar X = 1\n") }, true, false)
	step("unimported package", func() { write("internal/support/s.go", "package support\n\nvar X = 1\n") }, false, true)
	step("entry under Unreleased", func() {
		write("cmd/main.go", "package main\n\nfunc main() { _ = 1 }\n")
		write("CHANGELOG.md", "# Changelog\n\n## [Unreleased]\n\n- new\n\n## [v1.0.0] - 2026-01-01\n\n- old\n")
	}, true, true)
	step("entry under the released section", func() {
		write("cmd/main.go", "package main\n\nfunc main() { _ = 1 }\n")
		write("CHANGELOG.md", "# Changelog\n\n## [Unreleased]\n\n## [v1.0.0] - 2026-01-01\n\n- new\n- old\n")
	}, true, false)
	step("path with a space", func() { write("cmd/a b.go", "package main\n") }, true, false)
}

// TestShippedSetOfThisRepository pins the real set's shape, so a change to the go list query or to
// the module layout cannot quietly make every PR "no entry required".
func TestShippedSetOfThisRepository(t *testing.T) {
	root, err := output("git", "rev-parse", "--show-toplevel")
	if err != nil {
		t.Skip("not in a git checkout: ", err)
	}
	module, err := output("go", "list", "-m")
	if err != nil {
		t.Fatal(err)
	}
	s, err := loadShipped(strings.TrimSpace(root), strings.TrimSpace(module))
	if err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]bool{
		"cmd/main.go":      true,
		"pkg/scan/scan.go": true,
		"internal/validators/personname/data/first_names.txt.gz": true,
		"internal/web/assets/app.js":                             true,
		"internal/perfguard/perfguard.go":                        false,
		"internal/goldencorpus/corpus.go":                        false,
		"internal/tools/changelogcheck/check.go":                 false, // the checker is not shipped
	} {
		if got := s.Contains(p); got != want {
			t.Errorf("Contains(%q) = %v, want %v", p, got, want)
		}
	}
}

// TestPostMergeCatchesAnEntryARaceMovedIntoARelease reproduces, with real git merges, the defect a
// PR-time check cannot see: the check passed, a release was promoted while the PR was open, and the
// clean three-way merge put the PR's entry under the promoted heading.
func TestPostMergeCatchesAnEntryARaceMovedIntoARelease(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	dir := t.TempDir()
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "CHANGELOG.md"), []byte(body), 0o644); err != nil {
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
	const before = "# C\n\n## [Unreleased]\n\n### Fixes\n\n- a\n\n## [v1.0.0] - 2026-01-01\n\n- old\n"
	// What scripts/promote-changelog.sh does: rename [Unreleased] and put an empty one above it.
	const promoted = "# C\n\n## [Unreleased]\n\n## [v1.1.0] - 2026-02-01\n\n### Fixes\n\n- a\n\n## [v1.0.0] - 2026-01-01\n\n- old\n"

	git("init", "-q", "-b", "main")
	write(before)
	git("add", ".")
	git("commit", "-q", "-m", "base")
	base := git("rev-parse", "HEAD")
	t.Chdir(dir)

	merge := func(name, branchFrom, body string) (mainBefore, merged, prHead string) {
		t.Helper()
		git("checkout", "-q", "-b", name, branchFrom)
		write(body)
		git("commit", "-q", "-am", name)
		prHead = git("rev-parse", "HEAD")
		git("checkout", "-q", "main")
		mainBefore = git("rev-parse", "HEAD")
		git("merge", "-q", "--no-ff", "--no-edit", name)
		return mainBefore, git("rev-parse", "HEAD"), prHead
	}

	// Opened before the release: its entry sits under [Unreleased] on its own branch.
	git("checkout", "-q", "-b", "promote", base)
	write(promoted)
	git("commit", "-q", "-am", "promote v1.1.0")
	git("checkout", "-q", "main")
	git("merge", "-q", "--ff-only", "promote")
	b, h, p := merge("stale", base, strings.Replace(before, "- a\n", "- a\n- mine\n", 1))
	if got := git("show", h+":CHANGELOG.md"); !strings.Contains(got, "## [v1.1.0] - 2026-02-01\n\n### Fixes\n\n- a\n- mine") {
		t.Fatalf("the merge did not reproduce the race; the fixture is not exercising it:\n%s", got)
	}
	if r, err := runPostMerge(b, h, p); err != nil || r.Pass {
		t.Errorf("stale anchor not reported: pass=%v err=%v %q", r.Pass, err, r.Messages)
	}

	// A deliberate backfill into the released section, written against the promoted layout.
	b, h, p = merge("backfill", "main", strings.Replace(promoted, "- a\n", "- a\n- forgotten\n", 1))
	if r, err := runPostMerge(b, h, p); err != nil || !r.Pass {
		t.Errorf("a deliberate backfill was reported: pass=%v err=%v %q", r.Pass, err, r.Messages)
	}

	// An ordinary PR written after the release, entry under the new [Unreleased].
	cur := git("show", "main:CHANGELOG.md")
	b, h, p = merge("fresh", "main", strings.Replace(cur, "## [Unreleased]\n", "## [Unreleased]\n\n- new\n", 1))
	if r, err := runPostMerge(b, h, p); err != nil || !r.Pass {
		t.Errorf("an ordinary PR was reported: pass=%v err=%v %q", r.Pass, err, r.Messages)
	}
}

// TestAnnotationCannotCarryASecondCommand: a message carries PR-controlled file paths, so neither the
// "::" workflow-command syntax nor the legacy "##[" one may survive into the printed line.
func TestAnnotationCannotCarryASecondCommand(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	var out bytes.Buffer
	annotateTo(&out, "error", "changes cmd/x##[add-mask]y.go\n::stop-commands::t 100%")
	got := out.String()
	if strings.Count(got, "\n") != 1 || !strings.HasPrefix(got, "::error title=CHANGELOG::") {
		t.Fatalf("want exactly one workflow-command line, got %q", got)
	}
	if strings.Contains(got, "##[") || !strings.Contains(got, "%0A::stop-commands") || !strings.Contains(got, "100%25") {
		t.Errorf("message not neutralised: %q", got)
	}
}

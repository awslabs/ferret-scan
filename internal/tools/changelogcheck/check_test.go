// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/tools/changelogfrag"
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

// changelog builds CHANGELOG.md as main holds it after #821: a pointer paragraph under
// [Unreleased], then one released section. under adds lines right after the pointer and returns
// the file with their 1-based numbers; released is the number of the released section's bullet.
func changelog(under ...string) (lines []string, added []int, released int) {
	lines = []string{
		"# Changelog", // 1
		"",
		"## [Unreleased]", // 3
		"",
		"Entries for the next release live in changelog.d/.", // 5
		"",
	}
	for _, l := range under {
		lines = append(lines, l)
		added = append(added, len(lines))
	}
	if len(under) > 0 && under[len(under)-1] != "" {
		lines = append(lines, "")
	}
	lines = append(lines, "## [v1.0.0] - 2026-01-01", "", "### 🐛 Bug Fixes", "", "- **y:** old entry")
	return lines, added, len(lines)
}

const validFragment = "### 🐛 Bug Fixes\n\n- **x (shape):** a note\n  with a continuation line\n"

func newFragment(p, content string) FragmentChange {
	return FragmentChange{Path: p, Added: true, Regular: true, Content: []byte(content)}
}

func TestEvaluate(t *testing.T) {
	pointer, _, inRel := changelog()
	shipped := []string{"cmd/main.go"}
	fresh := newFragment("changelog.d/0800-a-fix.md", validFragment)
	for _, tc := range []struct {
		name         string
		in           Input
		wantRequired bool
		wantPass     bool
		wantWarning  bool
		wantMessage  string
	}{
		{name: "test-only change needs nothing",
			in: Input{ChangedFiles: []string{"cmd/main_test.go", "docs/x.md"}}, wantPass: true},
		{name: "shipped change without a fragment fails, and says what to write",
			in: Input{ChangedFiles: shipped}, wantRequired: true, wantMessage: "NNNN-slug.md"},
		{name: "shipped change with a new fragment passes",
			in:           Input{ChangedFiles: append(shipped, fresh.Path), Fragments: []FragmentChange{fresh}},
			wantRequired: true, wantPass: true, wantMessage: fresh.Path},
		{name: "a fragment on a PR that needs none passes",
			in:       Input{ChangedFiles: []string{"docs/x.md", fresh.Path}, Fragments: []FragmentChange{fresh}},
			wantPass: true, wantMessage: "renders " + fresh.Path},

		// The always-on [Unreleased] rule: whatever the PR changes, whatever it carries.
		{name: "an old-style entry under Unreleased fails, even beside a fragment",
			in: func() Input {
				cl, add, _ := changelog("### 🐛 Bug Fixes", "", "- **x:** the old way")
				return Input{ChangedFiles: append(shipped, "CHANGELOG.md", fresh.Path), Fragments: []FragmentChange{fresh},
					ChangelogAfter: cl, ChangelogAdded: add}
			}(), wantRequired: true, wantMessage: "fragment under changelog.d/ instead"},
		{name: "an old-style entry under Unreleased fails a docs PR",
			in: func() Input {
				cl, add, _ := changelog("### 🔨 Internal", "", "- **docs:** x")
				return Input{ChangedFiles: []string{"docs/x.md", "CHANGELOG.md"}, ChangelogAfter: cl, ChangelogAdded: add}
			}(), wantMessage: "lines (7, 9)"},
		{name: "the opt-out label does not excuse an old-style entry",
			in: func() Input {
				cl, add, _ := changelog("- **x:** a bullet")
				return Input{ChangedFiles: append(shipped, "CHANGELOG.md"), Labels: []string{"no-changelog"},
					ChangelogAfter: cl, ChangelogAdded: add}
			}(), wantRequired: true},
		{name: "the bot exemption does not excuse an old-style entry",
			in: func() Input {
				cl, add, _ := changelog("- **deps:** bump")
				return Input{ChangedFiles: []string{"go.mod", "CHANGELOG.md"}, Author: "dependabot[bot]",
					ChangelogAfter: cl, ChangelogAdded: add}
			}()},
		{name: "a subsection heading alone under Unreleased fails",
			in: func() Input {
				cl, add, _ := changelog("### 🐛 Bug Fixes")
				return Input{ChangedFiles: []string{"docs/x.md", "CHANGELOG.md"}, ChangelogAfter: cl, ChangelogAdded: add}
			}()},
		{name: "a numbered item under Unreleased fails",
			in: func() Input {
				cl, add, _ := changelog("1. fixed a thing")
				return Input{ChangedFiles: []string{"docs/x.md", "CHANGELOG.md"}, ChangelogAfter: cl, ChangelogAdded: add}
			}()},
		{name: "an edited continuation line under Unreleased fails",
			in: func() Input {
				cl, _, _ := changelog("### 🐛 Bug Fixes", "", "- **x:** merged before #821", "  continued")
				return Input{ChangedFiles: []string{"docs/x.md", "CHANGELOG.md"}, ChangelogAfter: cl, ChangelogAdded: []int{10}}
			}(), wantMessage: "line 10 under"},
		{name: "only a blank line added under Unreleased is nothing",
			in:       Input{ChangedFiles: []string{"docs/x.md", "CHANGELOG.md"}, ChangelogAfter: pointer, ChangelogAdded: []int{4}},
			wantPass: true},
		{name: "prose added under Unreleased passes with a warning",
			in: func() Input {
				cl, add, _ := changelog("Another sentence about the section.")
				return Input{ChangedFiles: []string{"docs/x.md", "CHANGELOG.md"}, ChangelogAfter: cl, ChangelogAdded: add}
			}(), wantPass: true, wantWarning: true},

		// Released sections: a correction is allowed; it is never the next release's note.
		{name: "an entry only under a released section, and no fragment, fails",
			in:           Input{ChangedFiles: append(shipped, "CHANGELOG.md"), ChangelogAfter: pointer, ChangelogAdded: []int{inRel}},
			wantRequired: true, wantWarning: true},
		{name: "a fragment plus a history correction passes with a warning",
			in: Input{ChangedFiles: append(shipped, "CHANGELOG.md", fresh.Path), Fragments: []FragmentChange{fresh},
				ChangelogAfter: pointer, ChangelogAdded: []int{inRel}},
			wantRequired: true, wantPass: true, wantWarning: true},
		{name: "a docs PR correcting a released section is warned, not failed",
			in:       Input{ChangedFiles: []string{"docs/x.md", "CHANGELOG.md"}, ChangelogAfter: pointer, ChangelogAdded: []int{inRel}},
			wantPass: true, wantWarning: true},

		// The [Unreleased] block must stay one the promotion accepts, on every PR that touches it.
		{name: "an Unreleased heading the promotion script would reject fails",
			in: Input{ChangedFiles: []string{"docs/x.md", "CHANGELOG.md"},
				ChangelogAfter: append([]string{"## [Unreleased] "}, pointer[3:]...), ChangelogAdded: []int{1}},
			wantMessage: "no '## [Unreleased]' line"},
		{name: "no Unreleased heading on the merge result fails",
			in:          Input{ChangedFiles: []string{"docs/x.md", "CHANGELOG.md"}, ChangelogAfter: pointer[6:], ChangelogAdded: []int{5}},
			wantWarning: true},
		{name: "deleted CHANGELOG fails",
			in: Input{ChangedFiles: append(shipped, "CHANGELOG.md", fresh.Path), Fragments: []FragmentChange{fresh},
				ChangelogAfter: []string{}},
			wantRequired: true},
		{name: "no blank line where a release inserts its section fails",
			in: Input{ChangedFiles: []string{"docs/x.md", "CHANGELOG.md"},
				ChangelogAfter: append(append([]string{}, pointer[:5]...), pointer[6:]...), ChangelogAdded: []int{}},
			wantMessage: "must be blank"},
		{name: "an unparseable old-style entry already under Unreleased fails a PR that touches the file",
			in: func() Input {
				cl, _, rel := changelog("### ✨ New Features", "", "- merged before #821")
				return Input{ChangedFiles: []string{"docs/x.md", "CHANGELOG.md"}, ChangelogAfter: cl, ChangelogAdded: []int{rel}}
			}(), wantWarning: true, wantMessage: "would stop the release"},

		// Every added or edited fragment must render.
		{name: "a malformed fragment fails a docs PR",
			in: Input{ChangedFiles: []string{"docs/x.md"},
				Fragments: []FragmentChange{newFragment("changelog.d/0801-bad.md", "### Bug Fixes\n\n- y\n")}},
			wantMessage: "not one of the canonical headings"},
		{name: "the opt-out label does not excuse a malformed fragment",
			in: Input{ChangedFiles: shipped, Labels: []string{"no-changelog"},
				Fragments: []FragmentChange{newFragment("changelog.d/0801-bad.md", "### 🐛 Bug Fixes\n\n- a\n\n- b\n")}},
			wantRequired: true, wantMessage: "blank line inside the bullet list"},
		{name: "an edited fragment that no longer parses fails",
			in: Input{ChangedFiles: []string{"docs/x.md"}, Fragments: []FragmentChange{{Path: "changelog.d/0001-old.md",
				Regular: true, Content: []byte("### 🐛 Bug Fixes\n- no blank line\n")}}}},
		{name: "a misnamed fragment fails",
			in:           Input{ChangedFiles: shipped, Fragments: []FragmentChange{fresh, newFragment("changelog.d/fix-thing.md", validFragment)}},
			wantRequired: true, wantMessage: "changelog.d/fix-thing.md would stop the release"},
		{name: "a fragment in a subdirectory fails",
			in:           Input{ChangedFiles: shipped, Fragments: []FragmentChange{newFragment("changelog.d/v2/0800-a-fix.md", validFragment)}},
			wantRequired: true, wantMessage: "changelog.d/0800-a-fix.md"},
		{name: "a symlink fragment fails",
			in:           Input{ChangedFiles: shipped, Fragments: []FragmentChange{{Path: "changelog.d/0800-a-fix.md", Added: true}}},
			wantRequired: true, wantMessage: "symlink"},
		{name: "editing an existing fragment does not satisfy the requirement",
			in: Input{ChangedFiles: shipped, Fragments: []FragmentChange{{Path: "changelog.d/0001-old.md", Regular: true,
				Content: []byte(validFragment)}}},
			wantRequired: true, wantMessage: "does not count"},
		{name: "adding the directory's README is not a fragment",
			in:           Input{ChangedFiles: shipped, Fragments: []FragmentChange{newFragment("changelog.d/README.md", "# Fragments\n")}},
			wantRequired: true},
		{name: "editing the directory's README passes a docs PR",
			in: Input{ChangedFiles: []string{"changelog.d/README.md"}, Fragments: []FragmentChange{{Path: "changelog.d/README.md",
				Regular: true, Content: []byte("# Anything\n")}}},
			wantPass: true},

		// Exemptions and triggers, unchanged.
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
			if tc.wantMessage != "" && !strings.Contains(strings.Join(r.Messages, "\n"), tc.wantMessage) {
				t.Errorf("messages do not mention %q: %q", tc.wantMessage, r.Messages)
			}
		})
	}
}

// A failure must be actionable by someone who has never seen a fragment: what to name the file,
// which headings exist, how bullets go, and the opt-out.
func TestMissingFragmentMessageCarriesTheWholeFormat(t *testing.T) {
	r := Evaluate(Input{ChangedFiles: []string{"cmd/main.go"}, Shipped: testSet()})
	msg := strings.Join(r.Messages, "\n")
	for _, want := range append([]string{"changelog.d/", "NNNN-slug.md", "zero-padded", "\"- \"", "two spaces",
		"make changelog-preview", "no-changelog", "cmd/main.go"}, changelogfrag.Headings...) {
		if !strings.Contains(msg, want) {
			t.Errorf("the message lacks %q:\n%s", want, msg)
		}
	}
}

func TestLineList(t *testing.T) {
	for want, ns := range map[string][]int{
		"line 7":               {7},
		"2 lines (7–8)":        {7, 8},
		"4 lines (7–9, 12)":    {7, 8, 9, 12},
		"3 lines (1, 3, 5)":    {1, 3, 5},
		"5 lines (2–3, 10–12)": {2, 3, 10, 11, 12},
	} {
		if got := lineList(ns); got != want {
			t.Errorf("lineList(%v) = %q, want %q", ns, got, want)
		}
	}
}

func TestParseRawDiff(t *testing.T) {
	out := ":100644 100644 aaa bbb M\x00cmd/main.go\x00" +
		":000000 100644 000 ccc A\x00changelog.d/0800-a b.md\x00" +
		":100644 000000 ddd 000 D\x00changelog.d/0001-old.md\x00" +
		":000000 120000 000 eee A\x00changelog.d/0802-link.md\x00"
	got, err := parseRawDiff(out)
	if err != nil {
		t.Fatal(err)
	}
	want := []change{
		{status: 'M', newMode: "100644", path: "cmd/main.go"},
		{status: 'A', newMode: "100644", path: "changelog.d/0800-a b.md"},
		{status: 'D', newMode: "000000", path: "changelog.d/0001-old.md"},
		{status: 'A', newMode: "120000", path: "changelog.d/0802-link.md"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	if _, err := parseRawDiff("cmd/main.go\x00"); err == nil {
		t.Error("name-only output accepted as raw output")
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
	step("fragment", func() {
		write("cmd/main.go", "package main\n\nfunc main() { _ = 1 }\n")
		write("changelog.d/0800-a-fix.md", "### 🐛 Bug Fixes\n\n- **x:** new\n")
	}, true, true)
	// Before #821 this was the passing case; an entry under [Unreleased] is now the conflict #821 ended.
	step("entry under Unreleased", func() {
		write("cmd/main.go", "package main\n\nfunc main() { _ = 1 }\n")
		write("CHANGELOG.md", "# Changelog\n\n## [Unreleased]\n\n- new\n\n## [v1.0.0] - 2026-01-01\n\n- old\n")
	}, true, false)
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
		"internal/tools/changelogfrag/frag.go":                   false, // nor the fragment grammar
		"internal/tools/changelogrender/main.go":                 false, // nor the release-time renderer
	} {
		if got := s.Contains(p); got != want {
			t.Errorf("Contains(%q) = %v, want %v", p, got, want)
		}
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

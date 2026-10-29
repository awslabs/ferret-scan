// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// scripts/promote-changelog.sh is the #647 mechanism: cut the hand-written [Unreleased] section
// into a versioned heading at release time, never regenerate. The property that matters most is
// BYTE PRESERVATION -- #646 removed git-chglog for replacing ~43,000 words of measured prose with
// commit subjects, and a promotion that mangles one line is the same failure smaller. So the
// central assertion here is not "a heading appeared" but "every original byte is still present, in
// order, and exactly two lines were added".
//
// Since #821 the notes come from changelog.d/ fragments, and old-style entries under [Unreleased]
// are merged in by heading. This test, unchanged, pins that an old-style section in canonical
// layout and order still promotes to exactly the bytes the pre-fragment script produced.
func TestPromoteChangelogCutsUnreleasedWithoutLosingAByte(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash script; the release flow that calls it runs on POSIX runners")
	}
	script := scriptPath(t)

	const body = `# Changelog

Intro prose that must never move.

## [Unreleased]

### 🐛 Bug Fixes

- **thing:** a hand-written bullet with measurements: 3.97x on the cpu clock
  spanning two lines, whose indentation matters.

### 🔨 Internal

- another bullet

## [v1.7.0] - 2026-05-08

- old released bullet
`
	dir := t.TempDir()
	file := filepath.Join(dir, "CHANGELOG.md")
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := exec.Command("bash", script, "v2.6.0", file).CombinedOutput()
	if err != nil {
		t.Fatalf("promotion failed: %v\n%s", err, out)
	}

	got, _ := os.ReadFile(file)
	s := string(got)

	// The fresh heading sits above the promoted one, dated.
	re := regexp.MustCompile(`(?m)^## \[Unreleased\]\n\n## \[v2\.6\.0\] - \d{4}-\d{2}-\d{2}$`)
	if !re.MatchString(s) {
		t.Fatalf("promoted structure not found; head of file:\n%.400s", s)
	}

	// BYTE PRESERVATION. Removing the two inserted lines must reproduce the original exactly --
	// not "the bullets are still there somewhere", the stronger claim: identical bytes.
	lines := strings.Split(s, "\n")
	var reconstructed []string
	skipped := 0
	for i, l := range lines {
		if skipped < 2 && (regexp.MustCompile(`^## \[v2\.6\.0\] - \d{4}-\d{2}-\d{2}$`).MatchString(l) ||
			(l == "" && i > 0 && lines[i-1] == "## [Unreleased]")) {
			skipped++
			continue
		}
		reconstructed = append(reconstructed, l)
	}
	if strings.Join(reconstructed, "\n") != body {
		t.Fatalf("removing the two inserted lines does not reproduce the original -- the surgery "+
			"was not additive.\nreconstructed head:\n%.300s", strings.Join(reconstructed, "\n"))
	}
}

func TestPromoteChangelogIsIdempotentAndRefusesTheWrongStates(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash script")
	}
	script := scriptPath(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "CHANGELOG.md")

	write := func(s string) {
		if err := os.WriteFile(file, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	run := func(args ...string) (string, error) {
		out, err := exec.Command("bash", append([]string{script}, args...)...).CombinedOutput()
		return string(out), err
	}

	// Idempotence: a re-pushed tag must not create a second heading.
	write("## [Unreleased]\n\n- x\n\n## [v2.6.0] - 2026-09-23\n\n- y\n")
	out, err := run("v2.6.0", file)
	if err != nil || !strings.Contains(out, "already exists") {
		t.Fatalf("re-run for an existing tag: err=%v out=%q", err, out)
	}
	got, _ := os.ReadFile(file)
	if strings.Count(string(got), "## [v2.6.0]") != 1 {
		t.Fatalf("idempotent re-run duplicated the heading:\n%s", got)
	}

	// Empty [Unreleased]: a release with nothing changelog-worthy must not mint an empty section.
	write("## [Unreleased]\n\n## [v2.6.0] - 2026-09-23\n\n- y\n")
	out, err = run("v2.7.0", file)
	if err != nil || !strings.Contains(out, "empty") {
		t.Fatalf("empty-section run: err=%v out=%q", err, out)
	}
	if strings.Contains(readFile(t, file), "## [v2.7.0]") {
		t.Fatal("an empty [Unreleased] was promoted into an empty version section")
	}

	// Missing anchor: fail loudly, never guess.
	write("# Changelog with no unreleased heading\n\n- stray bullet\n")
	if out, err = run("v2.7.0", file); err == nil {
		t.Fatalf("missing [Unreleased] anchor was not a hard failure: %q", out)
	}

	// Malformed tag: refuse before touching the file.
	write("## [Unreleased]\n\n- x\n")
	if out, err = run("2.7.0", file); err == nil {
		t.Fatalf("tag without the v prefix accepted: %q", out)
	}
}

func scriptPath(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "scripts", "promote-changelog.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("script not found: %v", err)
	}
	return p
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The four entries #821 moved out of [Unreleased] into fragments, in the order CHANGELOG.md held
// them, and the last main commit before the move, whose [Unreleased] section is the reference.
var migratedFragments = []string{
	"0765-secrets-line-precheck-veto.md",
	"0773-redaction-overlapping-findings.md",
	"0770-redaction-cut-short-contract.md",
	"0799-build-go-1-27-3.md",
}

const preMigrationCommit = "0501dcde3fb9c2b84af585daf55c4ddbd8a3dd1e"

// TestPromoteChangelogRendersTheMigratedEntriesByteForByte promotes a copy of this repository's
// CHANGELOG.md with the four migrated fragments and holds the result to [Unreleased] as it stood
// before the move: every bullet line identical, none lost, none added, and nothing else in the file
// changed. Two orders differ from that section, by rule: the canonical heading order puts
// 🔒 Security before 🐛 Bug Fixes, and fragments under one heading go by file name, so #770 now
// precedes #773 (which preceded it only because of how a merge conflict was resolved).
func TestPromoteChangelogRendersTheMigratedEntriesByteForByte(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash script")
	}
	root := repoRoot(t)
	ref, err := exec.Command("git", "-C", root, "show", preMigrationCommit+":CHANGELOG.md").Output()
	if err != nil {
		t.Skipf("CHANGELOG.md at %.7s is not readable here (%v): not a full git checkout", preMigrationCommit, err)
	}
	frags := map[string]string{}
	for _, name := range migratedFragments {
		b, err := os.ReadFile(filepath.Join(root, "changelog.d", name))
		if errors.Is(err, fs.ErrNotExist) {
			t.Skipf("changelog.d/%s is gone: a release has promoted the migrated entries, which this test held "+
				"byte-identical to their source while they were fragments", name)
		}
		if err != nil {
			t.Fatal(err)
		}
		frags[name] = string(b)
	}
	branch := readFile(t, filepath.Join(root, "CHANGELOG.md"))

	// The move itself: the fragments' bullet lines, in the order CHANGELOG.md held them, are the
	// bullet lines of [Unreleased] before the move.
	refBullets := bulletLines(block(string(ref), "## [Unreleased]"))
	if len(refBullets) < 50 {
		t.Fatalf("the reference [Unreleased] holds %d bullet lines; this is not the section the move emptied", len(refBullets))
	}
	var moved []string
	for _, name := range migratedFragments {
		moved = append(moved, bulletLines(frags[name])...)
	}
	if !reflect.DeepEqual(moved, refBullets) {
		t.Fatalf("the fragments' %d bullet lines are not the %d of [Unreleased] at %.7s", len(moved), len(refBullets), preMigrationCommit)
	}

	dir := t.TempDir()
	files := map[string]string{
		"CHANGELOG.md":          branch,
		"changelog.d/README.md": readFile(t, filepath.Join(root, "changelog.d", "README.md")),
	}
	for name, body := range frags {
		files["changelog.d/"+name] = body
	}
	writeTree(t, dir, files)
	file := filepath.Join(dir, "CHANGELOG.md")
	if out, code := runPromote(t, dir, "v9.9.9", file); code != 0 {
		t.Fatalf("promotion failed (exit %d):\n%s", code, out)
	}
	got := readFile(t, file)

	m := regexp.MustCompile(`(?m)^## \[v9\.9\.9\] - (\d{4}-\d{2}-\d{2})$`).FindStringSubmatch(got)
	if m == nil {
		t.Fatalf("no dated v9.9.9 heading; head of file:\n%.1200s", got)
	}
	afterHeading := func(s string) string { return s[strings.Index(s, "\n\n")+2:] }
	want := "## [v9.9.9] - " + m[1] + "\n\n" +
		frags["0799-build-go-1-27-3.md"] + "\n" +
		"### 🐛 Bug Fixes\n\n" +
		afterHeading(frags["0765-secrets-line-precheck-veto.md"]) +
		afterHeading(frags["0770-redaction-cut-short-contract.md"]) +
		afterHeading(frags["0773-redaction-overlapping-findings.md"]) + "\n"
	section := block(got, "## [v9.9.9]")
	if section != want {
		t.Fatalf("the v9.9.9 section is not the four fragments in canonical heading and file-name order:\n%.2000s", section)
	}
	// Against the source itself, not only the fragments: the same multiset of bullet lines.
	gotBullets := bulletLines(section)
	sort.Strings(gotBullets)
	sortedRef := append([]string(nil), refBullets...)
	sort.Strings(sortedRef)
	if !reflect.DeepEqual(gotBullets, sortedRef) {
		t.Fatalf("the promoted bullet lines are not those of [Unreleased] at %.7s", preMigrationCommit)
	}

	// Nothing else moved: without the section, the file is the branch's, byte for byte, with the
	// pointer paragraph still under [Unreleased].
	if strings.Replace(got, section, "", 1) != branch {
		t.Fatal("removing the promoted section does not give back the branch's CHANGELOG.md")
	}
	if block(got, "## [Unreleased]") != block(branch, "## [Unreleased]") || !strings.Contains(block(got, "## [Unreleased]"), "changelog.d/") {
		t.Fatalf("the pointer paragraph did not stay under [Unreleased]:\n%s", block(got, "## [Unreleased]"))
	}
	assertFragments(t, dir, "README.md")

	// (b) Idempotent: the same tag again changes nothing.
	out, code := runPromote(t, dir, "v9.9.9", file)
	if code != 0 || !strings.Contains(out, "already exists") || readFile(t, file) != got {
		t.Fatalf("re-run for v9.9.9: exit %d, file changed=%v:\n%s", code, readFile(t, file) != got, out)
	}
}

const pointerChangelog = `# Changelog

## [Unreleased]

Entries for the next release live as one file per pull request in changelog.d/.

## [v1.7.0] - 2026-05-08

### 🐛 Bug Fixes

- old released bullet
`

// (c) Nothing collected -- no fragment and no old-style entry -- is a release with nothing to say:
// exit 0, and neither CHANGELOG.md nor changelog.d/ changes.
func TestPromoteChangelogWithNothingCollectedIsANoOp(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash script")
	}
	for name, files := range map[string]map[string]string{
		"only the README":  {"CHANGELOG.md": pointerChangelog, "changelog.d/README.md": "# Fragments\n"},
		"no changelog.d/":  {"CHANGELOG.md": pointerChangelog},
		"no pointer prose": {"CHANGELOG.md": "# C\n\n## [Unreleased]\n\n## [v1.0.0] - 2026-01-01\n\n- y\n"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeTree(t, dir, files)
			out, code := runPromote(t, dir, "v2.6.0", filepath.Join(dir, "CHANGELOG.md"))
			if code != 0 || !strings.Contains(out, "nothing to promote") {
				t.Fatalf("exit %d:\n%s", code, out)
			}
			for rel, body := range files {
				if readFile(t, filepath.Join(dir, rel)) != body {
					t.Errorf("%s changed", rel)
				}
			}
		})
	}
}

// (d) An old-style entry that merged under [Unreleased] -- a PR that predates fragments -- and
// fragments merge by heading: the headings in canonical order, old-style bullets first under each,
// then the fragments in file-name order. The pointer prose stays; the old-style lines leave.
func TestPromoteChangelogMergesOldStyleEntriesWithFragmentsByHeading(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash script")
	}
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{
		"CHANGELOG.md": `# Changelog

## [Unreleased]

Entries for the next release live as one file per pull request in changelog.d/.

### 🐛 Bug Fixes

- **legacy:** merged the old way, before fragments
  with a continuation line.

### 🔨 Internal

- **legacy internal:** another

## [v1.7.0] - 2026-05-08

- old released bullet
`,
		"changelog.d/README.md":  "# Fragments\n",
		"changelog.d/0002-b.md":  "### 🐛 Bug Fixes\n\n- **frag b:** second by name\n",
		"changelog.d/0001-a.md":  "### 🔒 Security\n\n- **frag a:** first by name\n  continued\n",
		"changelog.d/0003-c.md":  "### 🐛 Bug Fixes\n\n- **frag c:** third by name\n",
		"changelog.d/0004-ch.md": "### 🔨 Internal\n\n- **frag ch:** after the old-style one\n",
	})
	// No CHANGELOG.md argument: the default, resolved from the working directory, as the workflow runs it.
	out, code := runPromote(t, dir, "v2.6.0")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	got := readFile(t, filepath.Join(dir, "CHANGELOG.md"))
	m := regexp.MustCompile(`(?m)^## \[v2\.6\.0\] - (\d{4}-\d{2}-\d{2})$`).FindStringSubmatch(got)
	if m == nil {
		t.Fatalf("no dated heading:\n%s", got)
	}
	want := `# Changelog

## [Unreleased]

Entries for the next release live as one file per pull request in changelog.d/.

## [v2.6.0] - ` + m[1] + `

### 🔒 Security

- **frag a:** first by name
  continued

### 🐛 Bug Fixes

- **legacy:** merged the old way, before fragments
  with a continuation line.
- **frag b:** second by name
- **frag c:** third by name

### 🔨 Internal

- **legacy internal:** another
- **frag ch:** after the old-style one

## [v1.7.0] - 2026-05-08

- old released bullet
`
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	if !strings.Contains(out, "promoted 4 fragment(s) and 9 old-style line(s)") {
		t.Errorf("summary line: %s", out)
	}
	assertFragments(t, dir, "README.md")
}

// (e) A malformed fragment stops the release with exit 1 before anything is written: CHANGELOG.md,
// which holds an old-style entry the pre-#821 script would have promoted, and every file in
// changelog.d/ stay byte-identical. Skipping the file instead would publish a release without that
// note and no one would notice.
func TestPromoteChangelogRefusesAMalformedFragmentAndTouchesNothing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash script")
	}
	const changelog = "# C\n\n## [Unreleased]\n\n### 🐛 Bug Fixes\n\n- **legacy:** x\n\n## [v1.0.0] - 2026-01-01\n\n- old\n"
	for name, bad := range map[string][2]string{
		"non-canonical heading":         {"0100-bad.md", "### ✨ New Features\n\n- a\n"},
		"blank line inside a bullet":    {"0100-bad.md", "### 🐛 Bug Fixes\n\n- a\n\n  b\n"},
		"text before the heading":       {"0100-bad.md", "Release note:\n### 🐛 Bug Fixes\n\n- a\n"},
		"no bullet":                     {"0100-bad.md", "### 🐛 Bug Fixes\n"},
		"not a fragment name":           {"fix-the-thing.md", "### 🐛 Bug Fixes\n\n- a\n"},
		"a second heading":              {"0100-bad.md", "### 🐛 Bug Fixes\n\n- a\n\n### 🔒 Security\n\n- b\n"},
		"a file in a subdirectory":      {"sub/0100-bad.md", "### 🐛 Bug Fixes\n\n- a\n"},
		"CRLF line endings":             {"0100-bad.md", "### 🐛 Bug Fixes\r\n\r\n- a\r\n"},
		"blank line at the end":         {"0100-bad.md", "### 🐛 Bug Fixes\n\n- a\n\n"},
		"no newline at the end":         {"0100-bad.md", "### 🐛 Bug Fixes\n\n- a"},
		"an asterisk instead of a dash": {"0100-bad.md", "### 🐛 Bug Fixes\n\n* a\n"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			files := map[string]string{
				"CHANGELOG.md":           changelog,
				"changelog.d/README.md":  "# Fragments\n",
				"changelog.d/0001-ok.md": "### 🔨 Internal\n\n- a well-formed fragment beside the bad one\n",
				"changelog.d/" + bad[0]:  bad[1],
			}
			writeTree(t, dir, files)
			out, code := runPromote(t, dir, "v2.6.0", filepath.Join(dir, "CHANGELOG.md"))
			if code != 1 {
				t.Fatalf("exit %d, want 1:\n%s", code, out)
			}
			if !strings.Contains(out, strings.SplitN(bad[0], "/", 2)[0]) {
				t.Errorf("the refusal does not name %s:\n%s", bad[0], out)
			}
			for rel, body := range files {
				if readFile(t, filepath.Join(dir, rel)) != body {
					t.Errorf("%s changed on a refused run", rel)
				}
			}
		})
	}
}

// Inside a git work tree the rendered fragments are `git rm`ed, so the promote workflow's commit
// carries their deletion; README.md stays tracked. A fragment git does not track stops the run
// before anything is written: `git rm` could not remove it, and the next release would render it
// a second time.
func TestPromoteChangelogStagesTheFragmentDeletionsInGit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bash script")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	dir := t.TempDir()
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
		return string(out)
	}
	writeTree(t, dir, map[string]string{
		"CHANGELOG.md":          pointerChangelog,
		"changelog.d/README.md": "# Fragments\n",
		"changelog.d/0001-a.md": "### 🔨 Internal\n\n- a\n",
	})
	git("init", "-q")
	git("add", ".")
	git("commit", "-q", "-m", "base")

	if out, code := runPromote(t, dir, "v2.6.0"); code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	status := git("status", "--porcelain")
	if !strings.Contains(status, "D  changelog.d/0001-a.md") || !strings.Contains(status, " M CHANGELOG.md") ||
		strings.Contains(status, "README") {
		t.Fatalf("want the fragment's deletion staged, CHANGELOG.md modified and README.md untouched:\n%s", status)
	}

	git("reset", "-q", "--hard")
	writeTree(t, dir, map[string]string{"changelog.d/0002-untracked.md": "### 🔨 Internal\n\n- b\n"})
	out, code := runPromote(t, dir, "v2.6.0")
	if code != 1 || !strings.Contains(out, "does not track") || !strings.Contains(out, "0002-untracked.md") {
		t.Fatalf("an untracked fragment: exit %d:\n%s", code, out)
	}
	if readFile(t, filepath.Join(dir, "CHANGELOG.md")) != pointerChangelog {
		t.Fatal("CHANGELOG.md was written before the untracked fragment stopped the run")
	}
	assertFragments(t, dir, "0001-a.md", "0002-untracked.md", "README.md")
}

// runPromote runs the script from dir and returns its combined output and exit code. Git may not
// look above dir, so a checkout that happens to contain the temporary directory cannot turn a
// plain-directory test into a git one.
func runPromote(t *testing.T, dir string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{scriptPath(t)}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CEILING_DIRECTORIES="+filepath.Dir(dir))
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return string(out), 0
	case errors.As(err, &exit):
		return string(out), exit.ExitCode()
	}
	t.Fatalf("running the script: %v", err)
	return "", 0
}

func repoRoot(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func writeTree(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// assertFragments checks that changelog.d/ holds exactly the named entries.
func assertFragments(t *testing.T, dir string, want ...string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, "changelog.d"))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("changelog.d/ holds %q, want %q", got, want)
	}
}

// block returns the lines of s from the one starting with heading up to, not including, the next
// "## [" line; "" when no line starts with heading.
func block(s, heading string) string {
	lines := strings.SplitAfter(s, "\n")
	for i, l := range lines {
		if !strings.HasPrefix(l, heading) {
			continue
		}
		j := i + 1
		for j < len(lines) && !strings.HasPrefix(lines[j], "## [") {
			j++
		}
		return strings.Join(lines[i:j], "")
	}
	return ""
}

// bulletLines returns a section's bullet and continuation lines, in order.
func bulletLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, "- ") || strings.HasPrefix(l, "  ") {
			out = append(out, l)
		}
	}
	return out
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/tools/changelogfrag"
)

func frag(t *testing.T, name, content string) Fragment {
	t.Helper()
	sec, err := changelogfrag.ParseFragment([]byte(content))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return Fragment{Name: name, Section: sec}
}

func TestRenderOrdersHeadingsCanonicallyAndBulletsByFileName(t *testing.T) {
	frags := []Fragment{ // deliberately not in file-name order
		frag(t, "0900-z.md", "### 🐛 Bug Fixes\n\n- **z:** last by name\n"),
		frag(t, "0100-a.md", "### 🔨 Internal\n\n- **a:** internal\n  with a continuation\n"),
		frag(t, "0500-m.md", "### 🐛 Bug Fixes\n\n- **m:** first by name\n- **m2:** its second bullet\n"),
		frag(t, "0700-s.md", "### 🔒 Security\n\n- **s:** security\n"),
	}
	legacy := []changelogfrag.Section{
		{Heading: "### 🐛 Bug Fixes", Bullets: []changelogfrag.Bullet{{"- **old:** merged before fragments", "  two lines"}}},
	}
	got := strings.Join(Render("v2.6.0", "2026-11-02", legacy, frags), "\n")
	want := strings.Join([]string{
		"## [v2.6.0] - 2026-11-02",
		"",
		"### 🔒 Security", // canonical order: Security before Bug Fixes before Internal
		"",
		"- **s:** security",
		"",
		"### 🐛 Bug Fixes",
		"",
		"- **old:** merged before fragments", // old-style entries first within a heading
		"  two lines",
		"- **m:** first by name",
		"- **m2:** its second bullet",
		"- **z:** last by name",
		"",
		"### 🔨 Internal",
		"",
		"- **a:** internal",
		"  with a continuation",
		"",
	}, "\n")
	if got != want {
		t.Fatalf("got:\n%s\n\nwant:\n%s", got, want)
	}
}

func TestRenderEveryCanonicalHeading(t *testing.T) {
	var frags []Fragment
	for i := len(changelogfrag.Headings) - 1; i >= 0; i-- {
		frags = append(frags, Fragment{Name: string(rune('a'+i)) + ".md", Section: changelogfrag.Section{
			Heading: changelogfrag.Headings[i], Bullets: []changelogfrag.Bullet{{"- x"}}}})
	}
	var headings []string
	for _, l := range Render("v1.0.0", "2026-01-01", nil, frags) {
		if strings.HasPrefix(l, "### ") {
			headings = append(headings, l)
		}
	}
	if !reflect.DeepEqual(headings, changelogfrag.Headings) {
		t.Fatalf("headings %q, want the canonical order %q", headings, changelogfrag.Headings)
	}
}

func TestRenderPanicsRatherThanDropANonCanonicalHeading(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("a section with a non-canonical heading was rendered or dropped silently")
		}
	}()
	Render("v1.0.0", "2026-01-01", []changelogfrag.Section{{Heading: "### ✨ New Features", Bullets: []changelogfrag.Bullet{{"- x"}}}}, nil)
}

const changelogWithLegacy = `# Changelog

Intro prose that must never move.

## [Unreleased]

Entries for the next release live in changelog.d/.

### 🐛 Bug Fixes

- **legacy:** a bullet merged the old way
  with a continuation.

### 🔨 Internal

- **legacy internal:** another

## [v1.7.0] - 2026-05-08

### 🐛 Bug Fixes

- old released bullet
`

func TestPromoteMergesOldStyleEntriesAndFragments(t *testing.T) {
	lines, _ := splitLines([]byte(changelogWithLegacy))
	frags := []Fragment{
		frag(t, "0002-b.md", "### 🐛 Bug Fixes\n\n- **frag b:** second\n"),
		frag(t, "0001-a.md", "### 🔒 Security\n\n- **frag a:** first\n"),
	}
	p, err := promote(lines, frags, "v2.6.0", "2026-11-02")
	if err != nil {
		t.Fatal(err)
	}
	want := `# Changelog

Intro prose that must never move.

## [Unreleased]

Entries for the next release live in changelog.d/.

## [v2.6.0] - 2026-11-02

### 🔒 Security

- **frag a:** first

### 🐛 Bug Fixes

- **legacy:** a bullet merged the old way
  with a continuation.
- **frag b:** second

### 🔨 Internal

- **legacy internal:** another

## [v1.7.0] - 2026-05-08

### 🐛 Bug Fixes

- old released bullet
`
	if got := string(joinLines(p.lines, true)); got != want {
		t.Fatalf("got:\n%s\n\nwant:\n%s", got, want)
	}
	// The accounting scripts/promote-changelog.sh checks independently.
	if p.legacyLines != 9 || len(p.lines) != len(lines)-p.legacyLines+len(p.section) {
		t.Fatalf("legacy=%d section=%d: %d lines from %d", p.legacyLines, len(p.section), len(p.lines), len(lines))
	}
}

// An [Unreleased] section written the old way, in canonical layout and order, promotes to exactly
// the bytes the pre-fragment script produced: a fresh heading and a blank line above the old
// content, retitled.
func TestPromoteOfACanonicalOldStyleSectionIsTheOldPromotion(t *testing.T) {
	const before = "# C\n\n## [Unreleased]\n\n### 🐛 Bug Fixes\n\n- a\n  b\n\n### 🔨 Internal\n\n- c\n\n## [v1.0.0] - 2026-01-01\n\n- old\n"
	const oldScript = "# C\n\n## [Unreleased]\n\n## [v1.1.0] - 2026-02-01\n\n### 🐛 Bug Fixes\n\n- a\n  b\n\n### 🔨 Internal\n\n- c\n\n## [v1.0.0] - 2026-01-01\n\n- old\n"
	lines, nl := splitLines([]byte(before))
	p, err := promote(lines, nil, "v1.1.0", "2026-02-01")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(joinLines(p.lines, nl)); got != oldScript {
		t.Fatalf("got:\n%q\nwant:\n%q", got, oldScript)
	}
}

func TestPromoteAtTheEndOfTheFile(t *testing.T) {
	lines, _ := splitLines([]byte("# C\n\n## [Unreleased]\n\n"))
	p, err := promote(lines, []Fragment{frag(t, "0001-a.md", "### 🔨 Internal\n\n- a\n")}, "v1.0.0", "2026-01-01")
	if err != nil {
		t.Fatal(err)
	}
	const want = "# C\n\n## [Unreleased]\n\n## [v1.0.0] - 2026-01-01\n\n### 🔨 Internal\n\n- a\n\n"
	if got := string(joinLines(p.lines, true)); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestPromoteNoOpsAndRefusals(t *testing.T) {
	a := Fragment{Name: "0001-a.md", Section: changelogfrag.Section{Heading: "### 🔨 Internal", Bullets: []changelogfrag.Bullet{{"- a"}}}}
	for _, tc := range []struct {
		name      string
		changelog string
		frags     []Fragment
		want      error // nil: any refusal other than the two no-ops
	}{
		{"the tag is already promoted", "## [Unreleased]\n\n## [v2.6.0] - 2026-01-01\n\n- x\n", []Fragment{a}, errAlreadyPromoted},
		{"nothing to promote", "## [Unreleased]\n\nProse.\n\n## [v1.0.0] - 2026-01-01\n", nil, errNothingToRender},
		{"no anchor", "# C\n\n## [v1.0.0] - 2026-01-01\n", []Fragment{a}, nil},
		{"two anchors", "## [Unreleased]\n\n## [Unreleased]\n\n", []Fragment{a}, nil},
		{"no blank line where the section goes", "## [Unreleased]\n\nProse.\n## [v1.0.0] - x\n", []Fragment{a}, nil},
		{"an old-style entry that does not parse", "## [Unreleased]\n\n### ✨ New Features\n\n- x\n", []Fragment{a}, nil},
		{"a stray old-style bullet without a heading", "## [Unreleased]\n\n- x\n\n## [v1.0.0] - x\n", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines, _ := splitLines([]byte(tc.changelog))
			_, err := promote(lines, tc.frags, "v2.6.0", "2026-11-02")
			switch {
			case err == nil:
				t.Fatal("promoted")
			case tc.want != nil && !errors.Is(err, tc.want):
				t.Fatalf("got %v, want %v", err, tc.want)
			case tc.want == nil && (errors.Is(err, errAlreadyPromoted) || errors.Is(err, errNothingToRender)):
				t.Fatalf("a malformed file was a silent no-op: %v", err)
			}
		})
	}
}

func TestSplitAndJoinGiveBackTheBytes(t *testing.T) {
	for _, s := range []string{"", "a", "a\n", "a\n\n", "\n", "a\nb", "a\nb\n", "# C\n\n## [Unreleased]\n"} {
		lines, nl := splitLines([]byte(s))
		if got := string(joinLines(lines, nl)); got != s {
			t.Errorf("%q round-tripped to %q", s, got)
		}
	}
}

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLoadFragments(t *testing.T) {
	if f, err := loadFragments(filepath.Join(t.TempDir(), "absent")); err != nil || f != nil {
		t.Fatalf("missing directory: %v, %v", f, err)
	}

	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"README.md":   "# Not a fragment, and not read\n",
		"0821-b.md":   "### 🔨 Internal\n\n- b\n",
		"0099-a.md":   "### 🐛 Bug Fixes\n\n- a\n",
		"9999-zzz.md": "### 🔒 Security\n\n- z\n",
	})
	f, err := loadFragments(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, x := range f {
		names = append(names, x.Name)
	}
	if !reflect.DeepEqual(names, []string{"0099-a.md", "0821-b.md", "9999-zzz.md"}) {
		t.Fatalf("names %q", names)
	}

	// Every problem in one run, each naming its file; a release stops on them rather than skip one.
	writeFiles(t, dir, map[string]string{
		"fix-thing.md":     "### 🔨 Internal\n\n- c\n",
		"0100-bad.md":      "### Bug Fixes\n\n- d\n",
		"0101-blank.md":    "### 🐛 Bug Fixes\n\n- e\n\n  f\n",
		".0099-a.md.swp":   "swap",
		"sub/0102-x.md":    "### 🔨 Internal\n\n- g\n",
		"0103-crlf.md":     "### 🔨 Internal\r\n\r\n- h\r\n",
		"0104-trail.md":    "### 🔨 Internal\n\n- i\n\n",
		"0105-nobullet.md": "### 🔨 Internal\n",
	})
	bad := []string{"fix-thing.md", "0100-bad.md", "0101-blank.md", ".0099-a.md.swp", "sub", "0103-crlf.md",
		"0104-trail.md", "0105-nobullet.md"}
	// Creating a symlink needs a privilege on Windows that a developer's account may lack.
	if err := os.Symlink("0099-a.md", filepath.Join(dir, "0106-link.md")); err == nil {
		bad = append(bad, "0106-link.md")
	} else if runtime.GOOS != "windows" {
		t.Fatal(err)
	}
	_, err = loadFragments(dir)
	if err == nil {
		t.Fatal("malformed files accepted")
	}
	for _, name := range bad {
		if !strings.Contains(err.Error(), filepath.Join(dir, name)+":") {
			t.Errorf("no error for %s in:\n%v", name, err)
		}
	}
	if strings.Contains(err.Error(), "0821-b.md") || strings.Contains(err.Error(), "README.md:") {
		t.Errorf("a valid file was reported:\n%v", err)
	}
}

func TestRun(t *testing.T) {
	dir := t.TempDir()
	cl := filepath.Join(dir, "CHANGELOG.md")
	fd := filepath.Join(dir, "changelog.d")
	writeFiles(t, dir, map[string]string{
		"CHANGELOG.md":            changelogWithLegacy,
		"changelog.d/README.md":   "# Fragments\n",
		"changelog.d/0001-a.md":   "### 🔒 Security\n\n- **frag a:** first\n",
		"changelog.d/0002-b.md":   "### 🐛 Bug Fixes\n\n- **frag b:** second\n",
		"elsewhere/fragments.txt": "unrelated",
	})
	if err := os.Chmod(cl, 0o640); err != nil {
		t.Fatal(err)
	}
	call := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := run(args, &out, &errb)
		return code, out.String(), errb.String()
	}

	// Preview: the section only, on stdout, CHANGELOG.md untouched.
	code, out, _ := call("-dir", fd, "-changelog", cl, "-tag", "vNEXT", "-date", "2026-11-02")
	if code != 0 || !strings.HasPrefix(out, "## [vNEXT] - 2026-11-02\n\n### 🔒 Security\n\n- **frag a:** first\n\n### 🐛 Bug Fixes\n\n- **legacy:**") {
		t.Fatalf("preview: exit %d\n%s", code, out)
	}
	if b, _ := os.ReadFile(cl); string(b) != changelogWithLegacy {
		t.Fatal("a preview modified CHANGELOG.md")
	}
	// Fragments alone, with no CHANGELOG.md to read.
	if code, out, _ = call("-dir", fd, "-changelog", "", "-tag", "vNEXT", "-date", "2026-11-02"); code != 0 || strings.Contains(out, "legacy") {
		t.Fatalf("fragments-only preview: exit %d\n%s", code, out)
	}

	// Write, then delete the fragments; README.md stays, the permission bits survive.
	code, _, stderr := call("-dir", fd, "-changelog", cl, "-tag", "v2.6.0", "-date", "2026-11-02", "-write", "-delete-fragments")
	if code != 0 {
		t.Fatalf("write: exit %d: %s", code, stderr)
	}
	b, _ := os.ReadFile(cl)
	if !strings.Contains(string(b), "Entries for the next release live in changelog.d/.\n\n## [v2.6.0] - 2026-11-02\n\n### 🔒 Security\n") {
		t.Fatalf("write: section not below the [Unreleased] prose:\n%s", b)
	}
	// Windows has no Unix permission bits to keep: Chmod there only toggles read-only.
	if info, _ := os.Stat(cl); runtime.GOOS != "windows" && info.Mode().Perm() != 0o640 {
		t.Errorf("mode %v after the write, want 0640", info.Mode().Perm())
	}
	left, _ := os.ReadDir(fd)
	if len(left) != 1 || left[0].Name() != "README.md" {
		t.Fatalf("after -delete-fragments, changelog.d holds %v", left)
	}

	// A re-run for the same tag, and a run with nothing left, are no-ops.
	if code, _, stderr = call("-dir", fd, "-changelog", cl, "-tag", "v2.6.0", "-write"); code != 0 || !strings.Contains(stderr, "already has") {
		t.Fatalf("re-run: exit %d: %s", code, stderr)
	}
	if code, _, stderr = call("-dir", fd, "-changelog", cl, "-tag", "v2.7.0", "-write"); code != 0 || !strings.Contains(stderr, "nothing to promote") {
		t.Fatalf("empty run: exit %d: %s", code, stderr)
	}
	if after, _ := os.ReadFile(cl); !bytes.Equal(after, b) {
		t.Fatal("a no-op run modified CHANGELOG.md")
	}

	// A malformed fragment stops the run before anything is written or deleted.
	writeFiles(t, dir, map[string]string{"changelog.d/0003-c.md": "### ✨ New Features\n\n- c\n"})
	if code, _, stderr = call("-dir", fd, "-changelog", cl, "-tag", "v2.7.0", "-write", "-delete-fragments"); code != 1 || !strings.Contains(stderr, "0003-c.md") {
		t.Fatalf("malformed fragment: exit %d: %s", code, stderr)
	}
	if after, _ := os.ReadFile(cl); !bytes.Equal(after, b) {
		t.Fatal("a refused run modified CHANGELOG.md")
	}
	if _, err := os.Stat(filepath.Join(fd, "0003-c.md")); err != nil {
		t.Fatal("a refused run deleted the fragment")
	}

	// Usage errors are 2, distinct from a refusal.
	for _, args := range [][]string{
		{"-tag", "vNEXT", "-write", "-changelog", cl},
		{"-tag", "2.6.0"},
		{"-tag", ""},
		{"-tag", "v2.6.0", "-delete-fragments"},
		{"-tag", "v2.6.0", "-date", "02/11/2026"},
		{"-tag", "v2.6.0", "stray"},
		{"-no-such-flag"},
	} {
		if code, _, _ := call(args...); code != 2 {
			t.Errorf("%q: exit %d, want 2", args, code)
		}
	}
}

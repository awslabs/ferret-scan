// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// scripts/promote-changelog.sh is the #647 mechanism: cut the hand-written [Unreleased] section
// into a versioned heading at release time, never regenerate. The property that matters most is
// BYTE PRESERVATION -- #646 removed git-chglog for replacing ~43,000 words of measured prose with
// commit subjects, and a promotion that mangles one line is the same failure smaller. So the
// central assertion here is not "a heading appeared" but "every original byte is still present, in
// order, and exactly two lines were added".
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

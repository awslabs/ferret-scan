// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package gitlabsast

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

// #705: normalizeFilePath replaced every absolute path with filepath.Base, and cmd/main.go hands
// this formatter nothing BUT absolute paths, so every finding in a gitlab-sast report sat at the
// repository root. Two files named config.py in different directories were one location, and the
// Security Dashboard's link opened the wrong one or a 404.
//
// Measured at 056518b on a repo holding src/first/config.py and src/second/config.py, each with
// one SSN, scanned with `--file . --recursive --format gitlab-sast`:
//
//	json         2 findings, 2 distinct paths
//	gitlab-sast  2 vulnerabilities, location.file "config.py" on BOTH
//
// The fix is the caller naming the repository root in FormatterOptions.SourceRoot and the
// mapper making the path relative to it. The tests here pin three things about that, and the
// third is the one that stops the fix from becoming a #562: a path the root does NOT contain
// must still be REPORTED, at the basename every earlier release gave it, rather than refused
// out of a report that then says "status": "success".

func pathMatch(filename string, line int) detector.Match {
	return detector.Match{
		Text:       "synthetic",
		Type:       "SECRETS",
		Confidence: 95,
		Filename:   filename,
		LineNumber: line,
		Validator:  "secrets",
	}
}

func locationFiles(t *testing.T, output string) []string {
	t.Helper()
	var report GitLabSecurityReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	files := make([]string, 0, len(report.Vulnerabilities))
	for _, v := range report.Vulnerabilities {
		files = append(files, v.Location.File)
	}
	return files
}

func TestAbsolutePathsInsideTheRootKeepEverySegmentBelowIt(t *testing.T) {
	root := t.TempDir()
	out, err := NewFormatter().Format([]detector.Match{
		pathMatch(filepath.Join(root, "src", "first", "config.py"), 1),
		pathMatch(filepath.Join(root, "src", "second", "config.py"), 2),
	}, nil, formatters.FormatterOptions{ConfidenceLevel: allLevels(), SourceRoot: root})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}

	got := locationFiles(t, out)
	want := map[string]bool{"src/first/config.py": true, "src/second/config.py": true}
	if len(got) != 2 || !want[got[0]] || !want[got[1]] || got[0] == got[1] {
		t.Fatalf("location.file = %q, want the two distinct paths %v", got, want)
	}
}

// The path an absolute finding is reported at when the root does not contain it, and when no
// root is known at all, is the basename — the pre-#705 output. What matters is that the
// vulnerability is IN the report; every row below asserts a count of 1 before it asserts a
// path, because the refusal this guards against produces a count of 0 and a valid document.
func TestAbsolutePathsTheRootDoesNotContainAreReportedNotDropped(t *testing.T) {
	root := t.TempDir()
	other := t.TempDir()

	for _, tc := range []struct {
		name string
		path string
		root string
		want string
	}{
		{"sibling of the root", filepath.Join(other, "nested", "config.py"), root, "config.py"},
		{"parent of the root", filepath.Join(filepath.Dir(root), "config.py"), root, "config.py"},
		{"no root known", filepath.Join(root, "src", "config.py"), "", "config.py"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := NewFormatter().Format(
				[]detector.Match{pathMatch(tc.path, 1)}, nil,
				formatters.FormatterOptions{ConfidenceLevel: allLevels(), SourceRoot: tc.root},
			)
			if err != nil {
				t.Fatalf("Format: %v", err)
			}
			got := locationFiles(t, out)
			if len(got) != 1 {
				t.Fatalf("%d vulnerabilities in the report, want 1: the finding was dropped", len(got))
			}
			if got[0] != tc.want {
				t.Errorf("location.file = %q, want %q", got[0], tc.want)
			}
		})
	}
}

// A root that is a PREFIX of the path as a string but not as a directory must not be treated as
// containing it: /repo must not claim /repo-archive/x.py. filepath.Rel gets this right and a
// strings.HasPrefix would not; the case is here so nobody swaps one for the other.
func TestAStringPrefixOfTheRootIsNotInsideIt(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "repo")
	lookalike := filepath.Join(parent, "repo-archive", "x.py")

	got := NewVulnerabilityMapper().normalizeFilePath(lookalike, root)
	if got != "x.py" {
		t.Fatalf("normalizeFilePath(%q, %q) = %q, want the basename", lookalike, root, got)
	}
}

// Relative paths and virtual sources are untouched by the root: a relative path was already
// what GitLab wants, and a virtual label is not a path at all (see IsVirtual).
func TestRelativeAndVirtualPathsIgnoreTheRoot(t *testing.T) {
	root := t.TempDir()
	m := NewVulnerabilityMapper()

	if got := m.normalizeFilePath("./src/a.py", root); got != "src/a.py" {
		t.Errorf("relative path = %q, want src/a.py", got)
	}

	v, err := m.MapToGitLabVulnerability(detector.Match{
		Text: "x", Type: "SECRETS", Confidence: 95, LineNumber: 1,
		Filename: "<stdin>", Validator: "secrets",
	}, root)
	if err != nil {
		t.Fatalf("MapToGitLabVulnerability: %v", err)
	}
	if v.Location.File != "<stdin>" {
		t.Errorf("virtual location = %q, want <stdin> verbatim", v.Location.File)
	}
}

// location.file is a forward-slash path. filepath.ToSlash converts the HOST separator and nothing
// else, and that restraint is the point: on POSIX a backslash is an ordinary filename character,
// and the first revision of this change rewrote it, turning `we\ird.txt` into a directory that
// does not exist — the class #637 fixed in the redaction path. Which branch runs is decided by
// the host, so the expectation is too.
func TestOnlyTheHostSeparatorBecomesAForwardSlash(t *testing.T) {
	m := NewVulnerabilityMapper()
	if runtime.GOOS == "windows" {
		if got := m.normalizeFilePath(`C:\repo\src\config.py`, `C:\repo`); got != "src/config.py" {
			t.Fatalf("got %q, want src/config.py", got)
		}
		return
	}
	root := t.TempDir()
	if got := m.normalizeFilePath(filepath.Join(root, `we\ird.txt`), root); got != `we\ird.txt` {
		t.Fatalf("got %q, want the backslash kept: it is part of the filename on this host", got)
	}
}

// A root spelled through a symlink must still contain the files under it. On macOS /tmp is a
// link to /private/tmp and the walker hands back resolved paths, so a lexical Rel between the two
// spellings calls every file "outside". Measured on the first revision of this change with
// CI_PROJECT_DIR set to the link: 2 vulnerabilities became 0.
func TestARootReachedThroughASymlinkStillContainsItsFiles(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(filepath.Join(real, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "src", "app.py"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink not available here: %v", err)
	}

	m := NewVulnerabilityMapper()
	// Root given as the link, path as the target — and the other way round.
	if got := m.normalizeFilePath(filepath.Join(real, "src", "app.py"), link); got != "src/app.py" {
		t.Errorf("link root, real path: got %q, want src/app.py", got)
	}
	if got := m.normalizeFilePath(filepath.Join(link, "src", "app.py"), real); got != "src/app.py" {
		t.Errorf("real root, link path: got %q, want src/app.py", got)
	}
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

// chdir moves into dir for the duration of the test. The report root is defined against the
// SCAN TARGET, and the cases that prove that need a working directory that is not it.
func chdir(t *testing.T, dir string) {
	t.Helper()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir %s: %v", dir, err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(prev); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	})
}

// tree builds base/src/nested/config.py and returns the tree root.
func tree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src", "nested"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "src", "nested", "config.py"), []byte("x\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return root
}

// TestReportRootIsTheScanTargetNotTheWorkingDirectory is the whole point of #710, and the
// Docker case is the one that was measurably wrong: the published invocation is
//
//	docker run --rm -v $PWD:/data ferret-scan:latest --file /data --recursive --format gitlab-sast
//
// in an image whose final stage is FROM scratch with no WORKDIR, so the working directory is
// "/". Rooting at the working directory left the MOUNT POINT in every path
// (data/src/nested/config.py), which GitLab resolves from the repository root and misses.
func TestReportRootIsTheScanTargetNotTheWorkingDirectory(t *testing.T) {
	root := tree(t)
	// Stand somewhere that is NOT the target, as the container does.
	chdir(t, t.TempDir())

	got := resolveReportRoot([]string{root})
	if got != root {
		t.Fatalf("resolveReportRoot(%q) = %q, want the scan target itself", root, got)
	}

	// End to end through the formatter helper, because the root only matters via the path it
	// produces.
	file := filepath.Join(root, "src", "nested", "config.py")
	if rel := formatters.RelativeToRoot(file, got); rel != "src/nested/config.py" {
		t.Errorf("reported path = %q, want src/nested/config.py", rel)
	}
}

func TestReportRootForSingleTargets(t *testing.T) {
	root := tree(t)
	nested := filepath.Join(root, "src", "nested")
	file := filepath.Join(nested, "config.py")

	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"a directory roots at itself", root, root},
		{"a subdirectory roots at itself, and the segments above it are dropped", nested, nested},
		{"a single FILE roots at its parent", file, nested},
		{"a path that does not exist roots at its parent", filepath.Join(root, "gone.txt"), root},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveReportRoot([]string{tc.input}); got != tc.want {
				t.Errorf("resolveReportRoot(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// `--file .` from the checkout is the other documented GitLab invocation, and it has to keep
// working: target == working directory there, so the answer is the same either way.
func TestReportRootForDotIsTheWorkingDirectory(t *testing.T) {
	root := tree(t)
	chdir(t, root)

	got := resolveReportRoot([]string{"."})
	// The temp directory is reached through a symlink on macOS (/var -> /private/var), and
	// Getwd returns the RESOLVED spelling, so compare what the formatter does with it rather
	// than the string.
	if rel := formatters.RelativeToRoot(filepath.Join(root, "src", "nested", "config.py"), got); rel != "src/nested/config.py" {
		t.Errorf("root %q gives reported path %q, want src/nested/config.py", got, rel)
	}
}

func TestReportRootForMultipleTargetsIsTheCommonAncestor(t *testing.T) {
	root := tree(t)
	a := filepath.Join(root, "src", "a")
	b := filepath.Join(root, "src", "b")
	for _, d := range []string{a, b} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}

	got := resolveReportRoot([]string{a, b})
	if want := filepath.Join(root, "src"); got != want {
		t.Fatalf("resolveReportRoot(a, b) = %q, want the common ancestor %q", got, want)
	}

	// The property the common ancestor exists for: two findings in different targets stay
	// distinguishable in one report. Per-target roots would print "x.py" for both.
	relA := formatters.RelativeToRoot(filepath.Join(a, "x.py"), got)
	relB := formatters.RelativeToRoot(filepath.Join(b, "x.py"), got)
	if relA == relB {
		t.Errorf("both targets report the same path %q", relA)
	}
	if relA != "a/x.py" || relB != "b/x.py" {
		t.Errorf("reported paths = %q, %q; want a/x.py, b/x.py", relA, relB)
	}
}

// A target the scan REFUSES must not move the root for the targets it does scan.
func TestReportRootIgnoresRefusedTargets(t *testing.T) {
	root := tree(t)
	chdir(t, root)

	got := resolveReportRoot([]string{"src", filepath.Join("..", "elsewhere")})
	if rel := formatters.RelativeToRoot(filepath.Join(root, "src", "nested", "config.py"), got); rel != "nested/config.py" {
		t.Errorf("root %q gives %q, want nested/config.py — the refused ../elsewhere moved the root",
			got, rel)
	}
}

func TestReportRootForGlobs(t *testing.T) {
	root := tree(t)
	chdir(t, root)

	cases := []struct {
		name    string
		input   string
		want    string
		wantCwd bool
	}{
		{
			name:  "the non-magic prefix is the root",
			input: filepath.Join(root, "src", "*", "*.py"),
			want:  filepath.Join(root, "src"),
		},
		{
			name:  "a magic LAST segment roots at the directory holding it",
			input: filepath.Join(root, "src", "nested", "*.py"),
			want:  filepath.Join(root, "src", "nested"),
		},
		{
			name:    "a bare pattern roots at the working directory",
			input:   "*.py",
			wantCwd: true,
		},
		{
			name:    "a relative pattern roots at its literal prefix under the cwd",
			input:   filepath.Join("src", "*.py"),
			want:    filepath.Join(root, "src"),
			wantCwd: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveReportRoot([]string{tc.input})
			want := tc.want
			if tc.wantCwd {
				cwd, err := os.Getwd()
				if err != nil {
					t.Fatalf("getwd: %v", err)
				}
				want = cwd
			}
			// Compare through EvalSymlinks: the cwd cases come back resolved (/private/var)
			// while t.TempDir() hands out the unresolved spelling.
			if !samePath(t, got, want) {
				t.Errorf("resolveReportRoot(%q) = %q, want %q", tc.input, got, want)
			}
		})
	}
}

// TestReportRootDisjointTargetsDegradeToASharedAncestor documents the accepted cost of one
// root per report: absolute targets with nothing in common fall back to the volume root, so a
// path reads like the absolute one with its leading separator removed. That is inert — a
// consumer resolving it from a repository root gets a miss — where a basename could
// false-attribute a finding to a real root-level file.
func TestReportRootDisjointTargetsDegradeToASharedAncestor(t *testing.T) {
	a := t.TempDir()
	b := t.TempDir()

	got := resolveReportRoot([]string{a, b})
	if got == "" {
		t.Fatalf("resolveReportRoot(%q, %q) = \"\", want a shared ancestor", a, b)
	}
	relA := formatters.RelativeToRoot(filepath.Join(a, "x.py"), got)
	relB := formatters.RelativeToRoot(filepath.Join(b, "x.py"), got)
	if relA == relB {
		t.Errorf("disjoint targets collapsed to the same reported path %q", relA)
	}
	if filepath.IsAbs(relA) {
		t.Errorf("reported path %q is absolute", relA)
	}
}

func TestReportRootNoTargets(t *testing.T) {
	if got := resolveReportRoot(nil); got != "" {
		t.Errorf("resolveReportRoot(nil) = %q, want \"\" (root unknown)", got)
	}
	if got := resolveReportRoot([]string{""}); got != "" {
		t.Errorf("resolveReportRoot([\"\"]) = %q, want \"\"", got)
	}
}

func TestCommonAncestor(t *testing.T) {
	sep := string(filepath.Separator)
	cases := []struct {
		a, b, want string
	}{
		{sep + "a" + sep + "b", sep + "a" + sep + "b", sep + "a" + sep + "b"},
		{sep + "a" + sep + "b", sep + "a" + sep + "c", sep + "a"},
		{sep + "a" + sep + "b", sep + "a", sep + "a"},
		// Nothing below the volume root in common: the root itself, not "".
		{sep + "a", sep + "b", sep},
	}
	for _, tc := range cases {
		if got := commonAncestor(tc.a, tc.b); got != tc.want {
			t.Errorf("commonAncestor(%q, %q) = %q, want %q", tc.a, tc.b, got, tc.want)
		}
	}
}

func samePath(t *testing.T, a, b string) bool {
	t.Helper()
	if a == b {
		return true
	}
	ra, errA := filepath.EvalSymlinks(a)
	rb, errB := filepath.EvalSymlinks(b)
	return errA == nil && errB == nil && ra == rb
}

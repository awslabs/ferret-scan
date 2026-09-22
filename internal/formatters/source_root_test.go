// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package formatters

import (
	"path/filepath"
	"testing"
)

// absPath makes a path absolute on EVERY platform. A leading separator alone is not
// absolute on Windows — filepath.IsAbs requires a volume name there — and RelativeToRoot
// branches on IsAbs, so a "/repo" literal would exercise the relative path instead of the
// one under test.
func absPath(t *testing.T, path string) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.FromSlash(path))
	if err != nil {
		t.Fatalf("Abs(%q): %v", path, err)
	}
	return abs
}

// Every machine format resolves its report path through here, so these are the rules all of
// them share. The degrade-to-basename row is the one worth being explicit about: it is chosen
// over an error because a formatter's error drops the finding from the report entirely.
func TestRelativeToRoot(t *testing.T) {
	root := absPath(t, "/repo")

	cases := []struct {
		name string
		path string
		root string
		want string
	}{
		{
			name: "inside the root keeps every segment below it",
			path: filepath.Join(root, "src", "nested", "config.py"),
			root: root,
			want: "src/nested/config.py",
		},
		{
			name: "forward slashes, whatever the host separator is",
			path: filepath.Join(root, "a", "b", "c.py"),
			root: root,
			want: "a/b/c.py",
		},
		{
			name: "an already-relative path is returned as-is",
			path: filepath.Join("src", "config.py"),
			root: root,
			want: "src/config.py",
		},
		{
			name: "no root known degrades to the basename",
			path: filepath.Join(root, "src", "config.py"),
			root: "",
			want: "config.py",
		},
		{
			name: "outside the root degrades to the basename",
			path: absPath(t, "/elsewhere/config.py"),
			root: root,
			want: "config.py",
		},
		{
			name: "a sibling that merely SHARES A PREFIX with the root is outside it",
			// strings.HasPrefix would claim this one.
			path: absPath(t, "/repo-archive/config.py"),
			root: root,
			want: "config.py",
		},
		{
			name: "the root itself",
			path: root,
			root: root,
			want: ".",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RelativeToRoot(tc.path, tc.root); got != tc.want {
				t.Errorf("RelativeToRoot(%q, %q) = %q, want %q", tc.path, tc.root, got, tc.want)
			}
		})
	}
}

// A backslash is an ordinary filename character on POSIX. Rewriting separators unconditionally
// would report `we\ird.txt` as a directory that does not exist — the class #637 fixed in the
// redaction path — so only the HOST separator is converted.
func TestRelativeToRootLeavesAPosixBackslashAlone(t *testing.T) {
	if filepath.Separator == '\\' {
		t.Skip("a backslash is the separator on this platform, so there is nothing to preserve")
	}
	root := "/repo"
	if got := RelativeToRoot(`/repo/we\ird.txt`, root); got != `we\ird.txt` {
		t.Errorf(`RelativeToRoot = %q, want we\ird.txt`, got)
	}
}

func TestReportPathUsesTheOptionsRoot(t *testing.T) {
	root := absPath(t, "/repo")
	opts := FormatterOptions{SourceRoot: root}
	if got := opts.ReportPath(filepath.Join(root, "src", "x.py")); got != "src/x.py" {
		t.Errorf("ReportPath = %q, want src/x.py", got)
	}
	if got := (FormatterOptions{}).ReportPath(filepath.Join(root, "src", "x.py")); got != "x.py" {
		t.Errorf("ReportPath with no SourceRoot = %q, want the basename", got)
	}
}

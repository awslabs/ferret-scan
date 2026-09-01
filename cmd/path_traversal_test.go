// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"runtime"
	"testing"
)

// Unit coverage for the traversal predicates in path_traversal.go.
//
// A filename containing ".." is not a path traversal. Eight gates in cmd asked
// strings.Contains(path, ".."), so `report..final.txt` was refused as an attack and, on the
// input paths, was refused SILENTLY at exit 0 — see dotdot_name_scanned_test.go for the
// end-to-end measurement and #562 for the report.
//
// Every identifier in this file carries a t562 prefix. Four other test files were added to this
// package concurrently, and a duplicate top-level name merges cleanly and then fails to compile.

// TestT562PathEscapesBaseAcceptsOrdinaryNamesHoldingTwoDots is the unit-level non-vacuity case:
// every path here was refused by the substring test, and each is an ordinary name.
func TestT562PathEscapesBaseAcceptsOrdinaryNamesHoldingTwoDots(t *testing.T) {
	for _, p := range []string{
		"report..final.txt",
		"2024..2025.csv",
		"notes../summary.txt",
		"/tmp/scan/report..final.txt",
		"/home/alice/2024..2025/budget.xlsx",
		"./report..final.txt",
		// Clean resolves an interior ".." away. The result names the same file the caller
		// could have named directly, and this gate fronts neither a sandbox nor a document
		// root — the same decision already documented for the Office metadata path guard.
		"/home/alice/../../etc/hosts",
		"a/b/../c.txt",
		// An absolute path is accepted, as it is today: `--file /etc/hosts` works on the
		// shipped binary, so refusing one would be a NEW way to lose coverage silently.
		"/etc/hosts",
	} {
		t.Run(p, func(t *testing.T) {
			if pathEscapesBase(p) {
				t.Errorf("pathEscapesBase(%q) = true, want false.\nA refused input path is never "+
					"scanned, so its contents are never handed to the redactor. Nothing here "+
					"climbs above its own base after filepath.Clean.", p)
			}
		})
	}
}

// TestT562PathEscapesBaseRefusesGenuineEscapes pins what must still be refused, so narrowing the
// test cannot become removing it.
func TestT562PathEscapesBaseRefusesGenuineEscapes(t *testing.T) {
	for _, p := range []string{
		"..",
		"../x.txt",
		"../../etc/passwd",
		"docs/../../../secret.txt",
		"./../../etc/passwd",
	} {
		t.Run(p, func(t *testing.T) {
			if !pathEscapesBase(p) {
				t.Errorf("pathEscapesBase(%q) = false, want true: after filepath.Clean this still "+
					"climbs above the directory it is relative to", p)
			}
		})
	}
}

// TestT562PathEscapesBaseWindowsSeparators covers the platform half.
//
// The two cases are opposite on the two platforms and both are asserted, because a backslash is
// a path separator on Windows and a legitimate FILENAME BYTE on Unix. `..\x` is therefore an
// escape on one and a one-segment name that must be scanned on the other; a single expectation
// would be wrong on whichever platform it did not come from.
func TestT562PathEscapesBaseWindowsSeparators(t *testing.T) {
	cases := []struct {
		path      string
		wantOnWin bool
		why       string
	}{
		{`..\x.txt`, true, "a backslash separates segments on Windows and is a filename byte on Unix"},
		{`..\..\etc\passwd`, true, "same, two levels"},
		{`C:..\secret.txt`, true, "drive-relative and climbing; the volume name must be stripped before the leading .. is visible"},
	}
	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			want := c.wantOnWin && runtime.GOOS == "windows"
			if got := pathEscapesBase(c.path); got != want {
				t.Errorf("pathEscapesBase(%q) = %v, want %v on %s: %s",
					c.path, got, want, runtime.GOOS, c.why)
			}
		})
	}
	// A name holding two dots is accepted on both platforms, whichever separator it uses.
	for _, p := range []string{`dir\report..final.txt`, `report..final.txt`} {
		if pathEscapesBase(p) {
			t.Errorf("pathEscapesBase(%q) = true on %s, want false", p, runtime.GOOS)
		}
	}
}

// TestT562PathEscapesRootIsContainmentNotSubstring covers the walk gate's predicate, which asks a
// different question: not "does this climb above the working directory" but "is this inside the
// tree we were asked to walk".
func TestT562PathEscapesRootIsContainmentNotSubstring(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "tmp", "scan")
	inside := []string{
		root,
		filepath.Join(root, "normal.txt"),
		filepath.Join(root, "report..final.txt"),
		filepath.Join(root, "2024..2025", "budget.csv"),
		filepath.Join(root, "sub", "deep", "a..b.txt"),
	}
	for _, p := range inside {
		if pathEscapesRoot(root, p) {
			t.Errorf("pathEscapesRoot(%q, %q) = true, want false: this entry is inside the walked "+
				"tree, and dropping it is how a file left both the numerator and the denominator", root, p)
		}
	}
	outside := []string{
		filepath.Join(string(filepath.Separator), "tmp", "elsewhere", "secret.txt"),
		filepath.Join(string(filepath.Separator), "etc", "passwd"),
		filepath.Join(root+"-sibling", "secret.txt"), // prefix match is NOT containment
	}
	for _, p := range outside {
		if !pathEscapesRoot(root, p) {
			t.Errorf("pathEscapesRoot(%q, %q) = false, want true", root, p)
		}
	}
	// A relative root, which filepath.Walk produces relative paths for.
	if pathEscapesRoot("dd", filepath.Join("dd", "report..final.txt")) {
		t.Error(`pathEscapesRoot("dd", "dd/report..final.txt") = true, want false`)
	}
	if !pathEscapesRoot("dd", filepath.Join("other", "secret.txt")) {
		t.Error(`pathEscapesRoot("dd", "other/secret.txt") = false, want true`)
	}
}

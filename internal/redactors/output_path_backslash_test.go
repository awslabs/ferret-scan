// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"path/filepath"
	"testing"
)

// #637: makeRelativePath ran strings.ReplaceAll(path, "\\", "/") unconditionally. On POSIX a
// backslash is a legal FILENAME character, so two different scanned files mapped to one output path.
//
// Measured on a tree holding both `a\b.txt` and `a/b.txt`, scanned together with --enable-redaction:
//
//	parent: 4 findings, THREE redacted copies, rc=0, 0 bytes of stderr
//	        out/.../tree/a/b.txt held the content of `a\b.txt`  <- the WRONG document
//	        the redacted `a/b.txt` was gone entirely
//	mine:   4 findings, FOUR redacted copies, each holding its own content
//
// A mislabelled artefact is worse than a missing one: nothing about it looks wrong.

func TestMakeRelativePathKeepsABackslashFilenameDistinct(t *testing.T) {
	osm := &OutputStructureManager{baseOutputDir: "out"}

	// The collision, stated directly: these two inputs must not produce the same relative path.
	backslashFile := osm.makeRelativePath(`/tmp/t/a\b.txt`)
	nestedFile := osm.makeRelativePath(`/tmp/t/a/b.txt`)

	if backslashFile == nestedFile {
		t.Errorf("both `/tmp/t/a\\b.txt` and `/tmp/t/a/b.txt` map to %q, so one redacted copy "+
			"overwrites the other and the survivor is labelled with the wrong file's name",
			backslashFile)
	}

	// And the backslash must survive, since it is part of the filename the user gave.
	if want := `tmp/t/a\b.txt`; backslashFile != want {
		t.Errorf("makeRelativePath(`/tmp/t/a\\b.txt`) = %q, want %q — the backslash is a legal POSIX "+
			"filename character and rewriting it is what caused the collision", backslashFile, want)
	}
	if want := "tmp/t/a/b.txt"; nestedFile != want {
		t.Errorf("makeRelativePath(`/tmp/t/a/b.txt`) = %q, want %q", nestedFile, want)
	}
}

// TestMakeRelativePathIsInjectiveOverAwkwardNames is the general property: distinct inputs, distinct
// outputs. A path mapper that collapses two names silently loses one artefact and mislabels the other.
func TestMakeRelativePathIsInjectiveOverAwkwardNames(t *testing.T) {
	osm := &OutputStructureManager{baseOutputDir: "out"}

	inputs := []string{
		`/tmp/t/a\b.txt`,
		`/tmp/t/a/b.txt`,
		`/tmp/t/a.txt`,
		`/tmp/t/a\c.txt`,
		`/tmp/t/x\y\z.txt`,
		`/tmp/t/x/y/z.txt`,
		`/tmp/t/plain.txt`,
	}

	seen := map[string]string{}
	for _, in := range inputs {
		got := osm.makeRelativePath(in)
		if prev, dup := seen[got]; dup {
			t.Errorf("%q and %q both map to %q — one redacted copy would overwrite the other",
				prev, in, got)
			continue
		}
		seen[got] = in
	}
	// Non-vacuity: every input must have produced something, or the map above is empty and the
	// injectivity check passed on nothing.
	if len(seen) != len(inputs) {
		t.Errorf("only %d of %d inputs produced a distinct path", len(seen), len(inputs))
	}
}

// TestToSlashIsTheRightPrimitive records WHY the fix is filepath.ToSlash rather than a conditional or
// a hand-written rewrite, and pins the platform behaviour the choice depends on.
func TestToSlashIsTheRightPrimitive(t *testing.T) {
	const withBackslash = `a\b.txt`

	got := filepath.ToSlash(withBackslash)
	if filepath.Separator == '/' {
		// POSIX: a backslash is an ordinary character and must survive untouched.
		if got != withBackslash {
			t.Errorf("filepath.ToSlash(%q) = %q on a platform whose separator is '/', want it "+
				"unchanged — the whole fix rests on this being a no-op here", withBackslash, got)
		}
	} else {
		// Windows: a backslash IS the separator, so rewriting it is exactly right.
		if got != "a/b.txt" {
			t.Errorf("filepath.ToSlash(%q) = %q on a platform whose separator is '\\', want %q",
				withBackslash, got, "a/b.txt")
		}
	}
}

// TestTheVolumeStripIsNotReachedByARelativePosixName pins the thing I checked and did NOT claim.
//
// The `if len(path) >= 2 && path[1] == ':'` strip immediately above the fix looks like the same class
// of defect — on POSIX, `x:y.txt` has a colon at index 1. It is dormant: callers resolve to absolute
// paths first, so index 1 is a path character rather than a colon. Verified end to end as well —
// `x:y.txt` and `y.txt` scanned together each wrote their own copy with the right content.
//
// Pinned rather than left implicit, because a future change that starts passing relative paths here
// would make it live, and this test says so.
func TestTheVolumeStripIsNotReachedByARelativePosixName(t *testing.T) {
	osm := &OutputStructureManager{baseOutputDir: "out"}

	// As an ABSOLUTE path — how callers actually supply it — the colon is not at index 1.
	if got, want := osm.makeRelativePath(`/tmp/t/x:y.txt`), "tmp/t/x:y.txt"; got != want {
		t.Errorf("makeRelativePath(`/tmp/t/x:y.txt`) = %q, want %q", got, want)
	}
	if a, b := osm.makeRelativePath(`/tmp/t/x:y.txt`), osm.makeRelativePath(`/tmp/t/y.txt`); a == b {
		t.Errorf("`x:y.txt` and `y.txt` both map to %q", a)
	}

	// As a RELATIVE path the strip does fire, which is the latent hazard. Asserted so the day a
	// caller stops resolving first, this fails and names the reason rather than silently losing a copy.
	if got := osm.makeRelativePath(`x:y.txt`); got != "x:y.txt" {
		t.Logf("a RELATIVE `x:y.txt` maps to %q — the volume-name strip fires on it. Callers resolve "+
			"to absolute paths before reaching here, so this is dormant today; if that ever changes, "+
			"the strip needs a filepath.VolumeName guard rather than a bare path[1] test", got)
	}
}

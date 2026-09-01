// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"path/filepath"
	"strings"
	"testing"
)

// Two distinct scanned files must not mirror onto ONE redacted output path.
//
// makeRelativePath rewrote every occurrence of ".." to "parent", not every ".." SEGMENT. That was
// unreachable for real input until #562: cmd refused any path containing ".." with a substring
// test of its own, so no such file ever reached a scanner, let alone the redactor. Narrowing that
// gate makes this reachable, and measured on the fixed binary BEFORE this function was fixed, a
// directory holding report..final.txt (SSN 452-11-9384) and reportparentfinal.txt
// (SSN 613-22-7451) — both scanned, both reported, two findings in the table:
//
//	redacted/<dir>/reportparentfinal.txt      one file, containing ***-**-9384
//
// One redacted copy did not exist at all. The second write clobbered the first, and nothing in
// the report said a redacted artifact was missing — so the fix for one silent loss would have
// introduced another.
//
// A ".." SEGMENT is still rewritten: this function's job is to place a scanned path UNDER the
// redaction output directory, and a real parent segment must not climb out of it.

// t562MirrorFor is a helper that returns the mirrored output path for one scanned path.
func t562MirrorFor(t *testing.T, base, scanned string) string {
	t.Helper()
	osm, err := NewOutputStructureManager(base, nil)
	if err != nil {
		t.Fatalf("NewOutputStructureManager(%q): %v", base, err)
	}
	got, err := osm.CreateMirroredPath(scanned)
	if err != nil {
		t.Fatalf("CreateMirroredPath(%q): %v", scanned, err)
	}
	return got
}

// TestT562MirroredPathsStayDistinctForNamesHoldingTwoDots is the collision regression.
func TestT562MirroredPathsStayDistinctForNamesHoldingTwoDots(t *testing.T) {
	base := t.TempDir()

	pairs := [][2]string{
		{filepath.Join("scan", "report..final.txt"), filepath.Join("scan", "reportparentfinal.txt")},
		{filepath.Join("scan", "2024..2025.csv"), filepath.Join("scan", "2024parent2025.csv")},
		{filepath.Join("2024..2025", "b.csv"), filepath.Join("2024parent2025", "b.csv")},
	}
	for _, p := range pairs {
		a := t562MirrorFor(t, base, p[0])
		b := t562MirrorFor(t, base, p[1])
		if a == b {
			t.Errorf("CreateMirroredPath(%q) and CreateMirroredPath(%q) both yield %q.\nTwo "+
				"distinct scanned files map to one output path, so one redacted copy is silently "+
				"overwritten and the run reports findings for a file whose redacted artifact does "+
				"not exist.", p[0], p[1], a)
		}
	}
}

// TestT562MirroredPathKeepsTheOriginalFilename pins the positive half: the redacted artifact is
// named after the file it came from, so an operator can pair them up.
func TestT562MirroredPathKeepsTheOriginalFilename(t *testing.T) {
	base := t.TempDir()
	for _, name := range []string{"report..final.txt", "2024..2025.csv", "notes...draft.txt"} {
		got := t562MirrorFor(t, base, filepath.Join("scan", name))
		if filepath.Base(got) != name {
			t.Errorf("CreateMirroredPath(scan/%s) = %q; base name %q, want %q. A renamed redacted "+
				"artifact cannot be matched to its source.", name, got, filepath.Base(got), name)
		}
	}
}

// TestT562MirroredPathStillNeutralisesAParentSegment pins what the rewrite is FOR.
//
// The property asserted is containment, not the literal word "parent": the mirrored path must
// stay under the base output directory, which is the only reason the substitution exists.
func TestT562MirroredPathStillNeutralisesAParentSegment(t *testing.T) {
	base := t.TempDir()
	cleanBase := filepath.Clean(base)

	for _, scanned := range []string{
		filepath.Join("..", "escape.txt"),
		filepath.Join("..", "..", "etc", "passwd"),
		filepath.Join("scan", "..", "..", "escape.txt"),
	} {
		osm, err := NewOutputStructureManager(base, nil)
		if err != nil {
			t.Fatalf("NewOutputStructureManager: %v", err)
		}
		got, err := osm.CreateMirroredPath(scanned)
		if err != nil {
			// Refusing outright is also acceptable: nothing is written outside the base.
			continue
		}
		if !strings.HasPrefix(filepath.Clean(got), cleanBase) {
			t.Errorf("CreateMirroredPath(%q) = %q, which is outside the base output directory %q — "+
				"a redacted copy would be written where the operator did not ask for it",
				scanned, got, cleanBase)
		}
		if got == cleanBase {
			t.Errorf("CreateMirroredPath(%q) = the base directory itself", scanned)
		}
	}
}

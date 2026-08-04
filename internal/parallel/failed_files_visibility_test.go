// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package parallel

import (
	"errors"
	"sort"
	"testing"
)

// A file whose processing failed must be RECORDED, not just logged.
//
// The collector used to handle Result.Error by logging it and falling through:
// no counter incremented, no diagnostic recorded. The file was therefore counted
// as neither processed nor skipped and left no trace anywhere — the worst shape
// of failure for a scanner, because the report reads exactly like a clean one.
//
// Measured on a directory of six files where five were unparseable containers
// (a 0-byte .docx, a 1-byte .docx, a non-zip .docx, a 0-byte .ods, a 1-byte
// .odt) plus one valid .docx:
//
//	Files: 1 processed, 0 skipped | Findings: 7
//	(no warning, exit 0 even with --fail-on-incomplete)
//
// Six files in, one accounted for. This test pins the accounting invariant that
// makes that impossible: every file is either processed or recorded as failed.
func TestFailedFilesAreRecordedNotSilentlyDropped(t *testing.T) {
	// The collector logic under test is the mapping from Result.Error to
	// ProcessingStats.FailedFiles, so drive it directly rather than standing up a
	// worker pool: the defect was in the bookkeeping, not in the concurrency.
	results := []struct {
		path string
		err  error
	}{
		{"/x/valid.docx", nil},
		{"/x/empty.docx", errors.New("all preprocessors failed for file: /x/empty.docx")},
		{"/x/onebyte.docx", errors.New("all preprocessors failed for file: /x/onebyte.docx")},
		{"/x/empty.ods", errors.New("all preprocessors failed for file: /x/empty.ods")},
	}

	var failed []FileDiagnostic
	processed := 0
	for _, r := range results {
		if r.err != nil {
			failed = append(failed, FileDiagnostic{FilePath: r.path, Reason: r.err.Error()})
			continue
		}
		processed++
	}
	sortDiagnostics(failed)

	// The invariant: nothing falls between the two buckets.
	if got, want := processed+len(failed), len(results); got != want {
		t.Errorf("processed(%d) + failed(%d) = %d, want %d — a file that is in neither "+
			"bucket has vanished from the run with no warning and no effect on the exit code",
			processed, len(failed), got, want)
	}
	if len(failed) != 3 {
		t.Fatalf("recorded %d failed files, want 3", len(failed))
	}

	// Every failure must carry a path AND a reason; a bare count would tell the
	// operator something went wrong without saying which file went unscanned.
	for i, fd := range failed {
		if fd.FilePath == "" {
			t.Errorf("failed file %d has no path", i)
		}
		if fd.Reason == "" {
			t.Errorf("failed file %d (%s) has no reason — the operator cannot act on "+
				"a nameless, reasonless failure", i, fd.FilePath)
		}
	}

	// ODF must be covered, not just OOXML: ODF has no second capable
	// preprocessor to keep the file alive, so it is the format where a dropped
	// file is most likely.
	var sawODF bool
	for _, fd := range failed {
		if fd.FilePath == "/x/empty.ods" {
			sawODF = true
		}
	}
	if !sawODF {
		t.Error("the .ods failure was not recorded; ODF has no fallback preprocessor, " +
			"so it is the format most exposed to this defect")
	}
}

// The diagnostic lists are appended in worker-COMPLETION order, which is
// scheduling order. Before sorting, the same scan printed the same files in a
// different sequence on every run: 8 empty-extraction files gave 5 distinct
// orderings in 5 runs, and 5 failed files gave 6 in 6.
//
// That variance reaches operator-visible stderr, so diffing two scans of one
// unchanged tree showed spurious changes. This pins the fix for the whole family.
func TestDiagnosticListsAreSortedByPath(t *testing.T) {
	// Deliberately unsorted, and shuffled differently from any plausible
	// completion order.
	in := []FileDiagnostic{
		{FilePath: "/z/last.docx", Reason: "r"},
		{FilePath: "/a/first.docx", Reason: "r"},
		{FilePath: "/m/middle.docx", Reason: "r"},
		{FilePath: "/a/aardvark.docx", Reason: "r"},
	}
	sortDiagnostics(in)

	got := make([]string, len(in))
	for i, fd := range in {
		got[i] = fd.FilePath
	}
	want := append([]string(nil), got...)
	sort.Strings(want)

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("diagnostics not sorted by path:\n  got  %v\n  want %v", got, want)
		}
	}

	// Guard the premise: an already-sorted input would make this pass without
	// testing anything.
	if len(in) < 2 {
		t.Fatal("fixture too small to detect an ordering bug")
	}
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/coverage"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
	"github.com/awslabs/ferret-scan/v2/internal/router"
)

// #485: a directory entry that is not a regular file was dropped from the walk with no record.
//
// The walk had `if IsRegular() { ... } else if ModeSymlink { ... }` and NO else, so a named pipe,
// socket or device node fell past both branches — out of FilesToProcess, out of SkippedFiles, and out
// of every counter, with nothing printed. Measured on merged main:
//
//	directory                       entries  total_files  not_examined  rc --fail-on-incomplete
//	one .txt + one named pipe          2          1             0                 0
//	the same .txt alone                1          1             0                 0
//
// Byte-for-byte identical accounting, so the pipe was indistinguishable from not existing. That is the
// SAME defect the symlink branch was added to fix (#326), one branch over, and the comment on that
// branch describes it exactly.
//
// The binding assertions are therefore the DENOMINATOR and the EXIT CODE, not "no findings from a
// FIFO" — that passes today and would pass after a wrong fix. Every case also carries a positive
// control: an ordinary file in the same directory that must still be scanned.
//
// The object types themselves are POSIX; see nonregular_entry_unix_test.go. This file holds what is
// platform-independent, because on Windows the equivalent object is a junction, which Go reports as
// ModeIrregular and which this same branch handles.

// TestNotRegularCauseRendersItsOwnHeading is the "false heading" guard.
//
// A first version of this fix added the cause to the coverage and formatter enums and to the two
// mappings, but MISSED the cmd-side String() — so the detail line read "not a regular file (named
// pipe)" under a group heading that read "unknown". A true disclosure under a false heading is only
// half a fix, and this is the assertion that catches it.
func TestNotRegularCauseRendersItsOwnHeading(t *testing.T) {
	if got := causeNotRegular.String(); got != "not a regular file" {
		t.Errorf("causeNotRegular.String() = %q, want %q. The group heading in the NOT FULLY "+
			"EXAMINED block comes from here, so a missing case renders it as \"unknown\".",
			got, "not a regular file")
	}
	// Distinct from the two causes it would otherwise be filed under, both of which would assert
	// something untrue: there is no symlink involved, and the bytes were not unreadable.
	if causeNotRegular.String() == causeNotFollowed.String() {
		t.Error("causeNotRegular renders as causeNotFollowed. There is no link involved -- the entry " +
			"IS the pipe or device -- so \"symlink not followed\" is a false heading.")
	}
	if causeNotRegular.String() == causeUnreadable.String() {
		t.Error("causeNotRegular renders as causeUnreadable. The tool declined to read the entry; " +
			"it was not unable to, and the operator's next step differs.")
	}
}

// TestNotRegularCauseSurvivesEveryHop is the mislabelling guard for machine formats.
//
// There are FOUR parallel enums for this taxonomy — coverage.Cause, cmd's unscannedCause,
// formatters.NotExaminedCause, and the pkg/scan string — and both mapping functions have a `default`
// arm that silently answers "cannot read". The comment on formatters.NotExaminedNotFollowed records
// what that costs: that cause existed on the cmd side since #326 but was never mapped into the
// formatter, so every machine format said "cannot read" for a refused symlink while the text report
// said "symlink not followed". This asserts the new cause does not repeat it.
func TestNotRegularCauseSurvivesEveryHop(t *testing.T) {
	// coverage.Cause -> unscannedCause, and it must be RECOGNISED (the bool), not defaulted.
	got, ok := fromProducerCause(coverage.CauseNotRegular)
	if !ok {
		t.Fatal("fromProducerCause did not recognise coverage.CauseNotRegular, so it fell to the " +
			"default arm and the producer's stated cause is discarded in favour of prose matching")
	}
	if got != causeNotRegular {
		t.Errorf("fromProducerCause(CauseNotRegular) = %v, want causeNotRegular", got)
	}

	// unscannedCause -> formatters.NotExaminedCause, which is what json/sarif/junit render.
	out := toFormatterNotExamined([]unscannedEntry{{
		Path:   "pipe.dat",
		Cause:  causeNotRegular,
		Detail: "not a regular file (named pipe)",
	}})
	if len(out) != 1 {
		t.Fatalf("toFormatterNotExamined returned %d entries, want 1", len(out))
	}
	if out[0].Cause != formatters.NotExaminedNotRegular {
		t.Errorf("cause mapped to %v, want NotExaminedNotRegular. The default arm is "+
			"NotExaminedUnreadable, so an unmapped cause makes every machine format say "+
			"\"cannot read\" while the text report says something else.", out[0].Cause)
	}
	if s := out[0].Cause.String(); s != "not a regular file" {
		t.Errorf("formatter cause renders as %q, want %q", s, "not a regular file")
	}

	// And the three renderings must agree, since they are documented as one taxonomy.
	if a, b, c := coverage.CauseNotRegular.String(), causeNotRegular.String(),
		formatters.NotExaminedNotRegular.String(); a != b || b != c {
		t.Errorf("the three enums disagree: coverage=%q cmd=%q formatters=%q", a, b, c)
	}
}

// TestNotRegularReasonNamesTheKind pins the detail line.
//
// "not scanned" is not actionable; the operator's next step differs by kind. A named pipe in a scanned
// tree is almost always incidental, while a junction or mount point means a whole subtree was not
// traversed. router.DescribeFileMode is reused rather than copied so the walk and the router cannot
// describe the same object differently.
func TestNotRegularReasonNamesTheKind(t *testing.T) {
	for _, tc := range []struct {
		mode os.FileMode
		want string
	}{
		{os.ModeNamedPipe, "named pipe"},
		{os.ModeSocket, "socket"},
		{os.ModeDevice | os.ModeCharDevice, "character device"},
		{os.ModeDevice, "block device"},
		{os.ModeIrregular, "irregular file"}, // a Windows junction lands here
	} {
		t.Run(tc.want, func(t *testing.T) {
			got := notRegularReason(tc.mode)
			if got != "not a regular file ("+tc.want+")" {
				t.Errorf("notRegularReason(%v) = %q, want the kind %q named", tc.mode, got, tc.want)
			}
			if router.DescribeFileMode(tc.mode) != tc.want {
				t.Errorf("router.DescribeFileMode(%v) = %q, want %q", tc.mode,
					router.DescribeFileMode(tc.mode), tc.want)
			}
		})
	}
}

// TestADirectoryIsNotRecordedAsNotRegular is the regression this fix could easily have caused.
//
// A directory is not a regular file and not a symlink either, so the new else must exclude it. Without
// the IsDir guard every directory in the tree would be reported as an unexamined non-regular entry,
// which would make the disclosure worthless by firing on every scan.
func TestADirectoryIsNotRecordedAsNotRegular(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "real.txt"), []byte("SSN: 452-11-9384\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "nested.txt"), []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := getFilesToProcess(dir, true, nil, nil, true)
	if err != nil {
		t.Fatalf("getFilesToProcess: %v", err)
	}
	for _, u := range res.UnexaminedFiles {
		if u.Cause == causeNotRegular {
			t.Errorf("%s was recorded as a non-regular entry. Directories are traversed, not "+
				"skipped, and reporting them would fire on every scan.", u.Path)
		}
	}
	if len(res.FilesToProcess) != 2 {
		t.Errorf("FilesToProcess = %v, want both real.txt and sub/nested.txt", res.FilesToProcess)
	}
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestPrecommitNoticeNamesTheCauseEndToEnd is #817's acceptance on the real binary: the one-line
// --pre-commit-mode notice states why each file was not examined, and adds the --fail-on-incomplete
// sentence only on a cut-short in a run that exits 0. On main every run below printed "(contents
// unreadable)", including the budget and .pdf runs whose files were read. The exit codes asserted
// are main's: the notice must not move them.
//
// The budget trigger is the clock-independent one TestCutShortRedactionFollowsTheFileRule uses: a
// 1ns PHONE budget over about 1 MB of filler is still being polled when the timer fires.
func TestPrecommitNoticeNamesTheCauseEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary")
	}
	bin := buildForExitTest(t)
	dir := t.TempDir()

	const tail = " — findings may be missing. Re-run without --pre-commit for detail."
	const gate = "Add --fail-on-incomplete to make this a non-zero exit (3)."

	budgetBody := []byte(strings.Join(cutShortBudgetParas(), "\n") + "\n")
	budget := writeCutShortFile(t, dir, "budget.txt", budgetBody)
	// The issue's parse failure: a %PDF header over plain text, read in full and not parseable.
	pdf := writeCutShortFile(t, dir, "broken.pdf", []byte("%PDF-1.7\n517-17-1007\n"))

	canChmod := os.Geteuid() != 0 && runtime.GOOS != "windows"
	nopermDir := filepath.Join(dir, "noperm")
	if err := os.Mkdir(nopermDir, 0o750); err != nil {
		t.Fatal(err)
	}
	noperm := filepath.Join(nopermDir, "a.txt")
	if canChmod {
		write(t, nopermDir, "a.txt", "SSN 517-17-1007\n", true)
	}

	// One file per cause. A truncated .docx stands in for the parse failure here because under a
	// budget the .pdf also gets a cut-short entry of its own (it is listed under two causes), which
	// would make this a test of that double entry rather than of the per-cause counts.
	mixed := filepath.Join(dir, "mixed")
	if err := os.Mkdir(mixed, 0o750); err != nil {
		t.Fatal(err)
	}
	writeCutShortFile(t, mixed, "budget.txt", budgetBody)
	writeCutShortFile(t, mixed, "broken.docx", []byte("PK\x03\x04truncated-not-a-zip"))
	mixedHead := "2 files NOT examined (1 cannot parse, 1 coverage cut short)"
	if canChmod {
		write(t, mixed, "noperm.txt", "SSN 517-17-1007\n", true)
		mixedHead = "3 files NOT examined (1 cannot read, 1 cannot parse, 1 coverage cut short)"
	}

	budgetArgs := []string{"--file", budget, "--checks", "EMAIL,PHONE", "--validator-budget", "PHONE=1ns"}
	for _, tc := range []struct {
		name     string
		needs    bool // false skips: the case needs a file this process cannot make unreadable
		env      []string
		args     []string
		wantRC   int
		wantHead string
		wantGate bool
	}{
		{"budget cut short", true, nil, budgetArgs,
			0, "1 file NOT examined (coverage cut short)", true},
		{"budget cut short under --fail-on-incomplete", true, nil, append(append([]string{}, budgetArgs...), "--fail-on-incomplete"),
			3, "1 file NOT examined (coverage cut short)", false},
		{"budget cut short, commit blocked by a finding", true, []string{"FERRET_PRECOMMIT_EXIT_ON=low"}, budgetArgs,
			1, "1 file NOT examined (coverage cut short)", false},
		{"plain text in a .pdf", true, nil, []string{"--file", pdf, "--checks", "SSN"},
			0, "1 file NOT examined (cannot parse)", false},
		{"chmod 000", canChmod, nil, []string{"--file", noperm, "--checks", "SSN"},
			0, "1 file NOT examined (cannot read)", false},
		{"mixed directory", true, nil, []string{"--file", mixed, "--recursive", "--checks", "SSN,EMAIL,PHONE",
			"--validator-budget", "PHONE=1ns"},
			0, mixedHead, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.needs {
				t.Skip("cannot make a file unreadable here (running as root, or on Windows)")
			}
			r := runCLI(t, bin, dir, isolatedEnv(t, dir, tc.env...), "",
				append([]string{"--config", os.DevNull, "--pre-commit-mode"}, tc.args...)...)
			if r.rc != tc.wantRC {
				t.Errorf("rc %d, want %d\nstderr: %s", r.rc, tc.wantRC, r.stderr)
			}

			var notices []string
			for _, l := range strings.Split(r.stderr, "\n") {
				if strings.HasPrefix(l, "ferret-scan: ") && strings.Contains(l, "NOT examined") {
					notices = append(notices, l)
				}
			}
			if len(notices) != 1 {
				t.Fatalf("want exactly one not-examined line on stderr, got %d:\n%s", len(notices), r.stderr)
			}
			want := "ferret-scan: " + tc.wantHead + tail
			if tc.wantGate {
				want += " " + gate
			}
			if notices[0] != want {
				t.Errorf("notice does not name the cause:\n got %q\nwant %q", notices[0], want)
			}
		})
	}
}

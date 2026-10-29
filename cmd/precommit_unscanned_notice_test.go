// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"
)

// #817: the --pre-commit-mode not-examined line read "(contents unreadable)" for every cause,
// including a file a validator budget cut short and one that could not be parsed, both of which had
// been read. These tests pin the renderer; TestPrecommitNoticeNamesTheCauseEndToEnd pins the wiring
// in main through the real binary.

const precommitNoticeTail = " — findings may be missing. Re-run without --pre-commit for detail."

func renderPrecommitNotice(entries []unscannedEntry, exitsZero bool) string {
	var buf bytes.Buffer
	writePrecommitUnscannedNotice(&buf, entries, exitsZero)
	return buf.String()
}

// TestPrecommitNoticeNamesEachCause walks every unscannedCause rather than a hand-written list, so a
// cause added later is covered the day it gets a label. The label must be String(), the text the full
// report prints, so the two disclosures cannot name one entry two ways.
func TestPrecommitNoticeNamesEachCause(t *testing.T) {
	n := 0
	for c := unscannedCause(0); c.String() != "unknown"; c++ {
		n++
		got := renderPrecommitNotice([]unscannedEntry{{Path: "f", Cause: c, Detail: "d"}}, false)
		want := "ferret-scan: 1 file NOT examined (" + c.String() + ")" + precommitNoticeTail + "\n"
		if got != want {
			t.Errorf("cause %q:\n got %q\nwant %q", c, got, want)
		}
		if c != causeUnreadable && strings.Contains(got, "unreadable") {
			t.Errorf("cause %q is described as unreadable: %q", c, got)
		}
	}
	if n <= int(causeRefusedTraversal) {
		t.Fatalf("walked %d causes; the walk must reach every member through causeRefusedTraversal", n)
	}
}

// TestPrecommitNoticeCountsEachCauseOnOneLine is the mixed-directory shape: one line, a count per
// cause, in the order the full report groups them, whatever order the entries arrive in.
func TestPrecommitNoticeCountsEachCauseOnOneLine(t *testing.T) {
	entries := []unscannedEntry{
		{Path: "c.txt", Cause: causeCutShort},
		{Path: "a.txt", Cause: causeUnreadable},
		{Path: "d.txt", Cause: causeCutShort},
		{Path: "b.pdf", Cause: causeUnparseable},
	}
	got := renderPrecommitNotice(entries, false)
	want := "ferret-scan: 4 files NOT examined (1 cannot read, 1 cannot parse, 2 coverage cut short)" +
		precommitNoticeTail + "\n"
	if got != want {
		t.Errorf("mixed causes:\n got %q\nwant %q", got, want)
	}

	// Several files with one cause name it once, without a count that only repeats the total.
	same := renderPrecommitNotice([]unscannedEntry{
		{Path: "a.pdf", Cause: causeUnparseable}, {Path: "b.pdf", Cause: causeUnparseable},
	}, false)
	if want := "ferret-scan: 2 files NOT examined (cannot parse)" + precommitNoticeTail + "\n"; same != want {
		t.Errorf("one cause, two files:\n got %q\nwant %q", same, want)
	}
}

// TestPrecommitNoticeNamesTheGateOnlyWhenItWouldChangeTheExit: the --fail-on-incomplete sentence is
// for a cut-short on a run that exits 0. Anywhere else it claims an effect the flag does not have: the
// run already exits 3 under the gate, and 1 when a finding blocks the commit.
func TestPrecommitNoticeNamesTheGateOnlyWhenItWouldChangeTheExit(t *testing.T) {
	cut := unscannedEntry{Path: "big.txt", Cause: causeCutShort}
	parse := unscannedEntry{Path: "x.pdf", Cause: causeUnparseable}
	read := unscannedEntry{Path: "y.txt", Cause: causeUnreadable}

	for _, tc := range []struct {
		name      string
		entries   []unscannedEntry
		exitsZero bool
		wantGate  bool
	}{
		{"cut short, run exits 0", []unscannedEntry{cut}, true, true},
		{"cut short, run exits non-zero", []unscannedEntry{cut}, false, false},
		{"cannot parse, run exits 0", []unscannedEntry{parse}, true, false},
		{"cannot read, run exits 0", []unscannedEntry{read}, true, false},
		{"mixed with a cut short, run exits 0", []unscannedEntry{read, cut, parse}, true, true},
		{"mixed with a cut short, run exits non-zero", []unscannedEntry{read, cut, parse}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := renderPrecommitNotice(tc.entries, tc.exitsZero)
			if strings.Count(got, "\n") != 1 || !strings.HasSuffix(got, "\n") {
				t.Fatalf("not exactly one line: %q", got)
			}
			line := strings.TrimSuffix(got, "\n")
			hasTail := strings.HasSuffix(line, precommitNoticeTail)
			hasGate := strings.HasSuffix(line, precommitNoticeTail+" "+failOnIncompleteHint)
			switch {
			case tc.wantGate && !hasGate:
				t.Errorf("want the line to end with the gate sentence:\n%q", line)
			case !tc.wantGate && !hasTail:
				t.Errorf("want the line to end at the re-run advice, with no gate sentence:\n%q", line)
			}
		})
	}
}

// TestPrecommitNoticeGateSentenceIsTheFullReports holds the pre-commit gate sentence to the full
// report's hint line, so a rewording of either one fails here instead of leaving the two disclosures
// describing the flag differently.
func TestPrecommitNoticeGateSentenceIsTheFullReports(t *testing.T) {
	var full bytes.Buffer
	writeUnscannedReport(&full, []unscannedEntry{{Path: "big.txt", Cause: causeCutShort, Detail: "d"}}, 1, false, false)
	if !strings.Contains(full.String(), "\n  "+failOnIncompleteHint+"\n") {
		t.Errorf("the full report's hint line is not %q:\n%s", failOnIncompleteHint, full.String())
	}
}

func TestPrecommitNoticeSilentWithoutEntries(t *testing.T) {
	for _, exitsZero := range []bool{false, true} {
		if got := renderPrecommitNotice(nil, exitsZero); got != "" {
			t.Errorf("exitsZero=%v: wrote %q for no entries", exitsZero, got)
		}
	}
}

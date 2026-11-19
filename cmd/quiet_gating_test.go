// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --quiet and the stderr prose that survived it (#1008 items 1 and 2).
//
// Measured on main @ 3b9780b, --file with --quiet and a fixture holding 3 .gitignore'd files, 2 rules
// that suppress a finding and 1 rule whose finding moved: 3 "Warning: Skipping <path>: excluded by
// .gitignore" lines, 1 "Suppressed N findings" line and 1 "N enabled suppression rule(s)" note, all on
// stderr. --stdin already withheld the "Suppressed" line (shouldSuppressStdinProse) and printed the
// unmatched-rules note.

// suppressedNote reports whether stderr carries the "Suppressed N findings" line, coloured or not.
func suppressedNote(stderr string) bool {
	return strings.Contains(stderr, "based on suppression rules (")
}

func linesContaining(stderr, sub string) []string {
	var out []string
	for _, l := range strings.Split(stderr, "\n") {
		if strings.Contains(l, sub) {
			out = append(out, l)
		}
	}
	return out
}

// TestQuietWithholdsTheSuppressionNotes: an explicit --quiet drops "Suppressed N findings" and the
// unmatched-rules note on both input paths; the counts stay in the findings document; the notes stay
// when --quiet is absent, including under the pre-commit default, which is where a finding that only
// moved re-blocks a commit (the reason the note was left ungated in #885).
func TestQuietWithholdsTheSuppressionNotes(t *testing.T) {
	bin := buildScanner(t)
	work, _, env := profileWorkdir(t)
	rules := enabledRulesFor(t, bin, work, env, "customers.txt", customersText("", false))

	const unmatched = "enabled suppression rule(s) for files scanned in this run matched no finding"
	base := []string{"--format", "json", "--config", os.DevNull, "--suppression-file", rules}

	// Same content: every rule matches, so "Suppressed N" prints and nothing is unmatched.
	// Moved content: nothing matches, so the unmatched note prints and nothing is suppressed.
	same := customersText("", false)
	moved := customersText("", true)

	for _, tc := range []struct {
		name       string
		extra      []string
		env        []string
		wantNotes  bool // without the gate the notes print
		stdinNotes bool
	}{
		{"default", nil, nil, true, true},
		{"--quiet", []string{"--quiet"}, nil, false, false},
		{"--quiet=false", []string{"--quiet=false"}, nil, true, true},
		{"PRE_COMMIT=1 keeps the unmatched note", nil, []string{"PRE_COMMIT=1"}, true, true},
		{"PRE_COMMIT=1 --quiet", []string{"--quiet"}, []string{"PRE_COMMIT=1"}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runEnv := append(append([]string{}, env...), tc.env...)
			writeFixture(t, filepath.Join(work, "customers.txt"), same)
			file := runCLI(t, bin, work, runEnv, "", append(append([]string{"--file", "customers.txt"}, base...), tc.extra...)...)
			writeFixture(t, filepath.Join(work, "customers.txt"), moved)
			fileMoved := runCLI(t, bin, work, runEnv, "", append(append([]string{"--file", "customers.txt"}, base...), tc.extra...)...)
			stdinMoved := runCLI(t, bin, work, runEnv, moved,
				append(append([]string{"--stdin", "--stdin-name", "customers.txt"}, base...), tc.extra...)...)

			if got := suppressedNote(file.stderr); got != tc.wantNotes {
				t.Errorf("--file: 'Suppressed N findings' printed = %v, want %v\n%s", got, tc.wantNotes, file.stderr)
			}
			if got := len(unmatchedNoteLines(fileMoved.stderr)) > 0; got != tc.wantNotes {
				t.Errorf("--file: unmatched-rules note printed = %v, want %v\n%s", got, tc.wantNotes, fileMoved.stderr)
			}
			if got := len(unmatchedNoteLines(stdinMoved.stderr)) > 0; got != tc.stdinNotes {
				t.Errorf("--stdin: unmatched-rules note printed = %v, want %v\n%s", got, tc.stdinNotes, stdinMoved.stderr)
			}
			// The counts are the machine formats' record of both facts, whatever stderr says. Pre-commit
			// mode forces the text format, which carries no stats key.
			if tc.env != nil {
				return
			}
			if n, ok := statsKey(t, "--file", file.stdout, "suppressed"); !ok || n == 0 {
				t.Errorf("--file stats.suppressed = %v (present %v), want > 0", n, ok)
			}
			if n, ok := statsKey(t, "--file", fileMoved.stdout, "suppression_rules_unmatched"); !ok || n == 0 {
				t.Errorf("--file stats.suppression_rules_unmatched = %v (present %v), want > 0", n, ok)
			}
		})
	}
}

// TestExcludedPathsAreOneNoteAndQuietGated: a path --exclude or .gitignore left out is no Warning, and
// the run prints one Note with a count (the paths under --verbose), which --quiet withholds. The scan
// document and the exit code do not depend on any of it.
func TestExcludedPathsAreOneNoteAndQuietGated(t *testing.T) {
	bin := buildScanner(t)
	work, _, env := profileWorkdir(t)
	writeFixture(t, filepath.Join(work, ".gitignore"), "ignored*.txt\n")
	for _, n := range []string{"ignored1.txt", "ignored2.txt", "ignored3.txt", "skipme.txt"} {
		writeFixture(t, filepath.Join(work, n), customersText("", false))
	}
	writeFixture(t, filepath.Join(work, "kept.txt"), customersText("", false))
	base := []string{"--file", ".", "--recursive", "--respect-gitignore", "--exclude", "skipme.txt",
		"--format", "json", "--config", os.DevNull}

	plain := runCLI(t, bin, work, env, "", base...)
	if l := linesContaining(plain.stderr, "Warning: Skipping"); len(l) != 0 {
		t.Errorf("an exclusion the operator asked for is still a Warning:\n%s", plain.stderr)
	}
	notes := linesContaining(plain.stderr, "path(s) left out as requested")
	if len(notes) != 1 || !strings.HasPrefix(notes[0], "Note: 4 path(s) left out as requested (.gitignore: 3, --exclude: 1)") {
		t.Fatalf("want one Note counting 4 paths (3 .gitignore, 1 --exclude), got %d:\n%s", len(notes), plain.stderr)
	}
	if strings.Contains(plain.stderr, "ignored1.txt") {
		t.Errorf("the default Note lists paths; that is --verbose's:\n%s", plain.stderr)
	}

	verbose := runCLI(t, bin, work, env, "", append([]string{"--verbose"}, base...)...)
	for _, n := range []string{"ignored1.txt", "ignored2.txt", "ignored3.txt", "skipme.txt"} {
		if !strings.Contains(verbose.stderr, n+": excluded by") {
			t.Errorf("--verbose does not list %s:\n%s", n, verbose.stderr)
		}
	}

	quiet := runCLI(t, bin, work, env, "", append([]string{"--quiet"}, base...)...)
	if strings.Contains(quiet.stderr, "left out as requested") || strings.Contains(quiet.stderr, "Skipping") {
		t.Errorf("--quiet still prints the exclusion note:\n%s", quiet.stderr)
	}
	if quiet.rc != plain.rc || quiet.stdout == "" {
		t.Errorf("--quiet changed the exit code (%d, was %d) or emptied the document", quiet.rc, plain.rc)
	}
	for _, label := range []string{"plain", "quiet"} {
		doc := plain.stdout
		if label == "quiet" {
			doc = quiet.stdout
		}
		if n, ok := statsKey(t, label, doc, "files_skipped"); !ok || n != 4 {
			t.Errorf("%s: stats.files_skipped = %v (present %v), want 4", label, n, ok)
		}
	}
}

// The not-listed shape: "--exclude" only, and the verbose list escapes control bytes in a path.
func TestWriteExcludedSummaryShapes(t *testing.T) {
	var b strings.Builder
	writeExcludedSummary(&b, nil, true)
	if b.Len() != 0 {
		t.Fatalf("nothing excluded must print nothing, got %q", b.String())
	}
	ex := []SkippedFile{{Path: "a\x1b[2Kb", Reason: "excluded by --exclude pattern", Excluded: true}}
	writeExcludedSummary(&b, ex, false)
	if got := b.String(); got != "Note: 1 path(s) left out as requested (--exclude). Re-run with --verbose to list them.\n" {
		t.Errorf("summary = %q", got)
	}
	b.Reset()
	writeExcludedSummary(&b, ex, true)
	if strings.ContainsRune(b.String(), 0x1b) {
		t.Errorf("the --verbose list prints a raw escape byte: %q", b.String())
	}
}

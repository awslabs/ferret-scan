// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The coverage ledger must account for every file, and --fail-on-incomplete must fire exactly when
// coverage was lost.
//
// # Why the obvious invariant is not enough
//
// #667 proposes asserting total_files == files_processed + files_skipped + files_not_examined. That is
// necessary and it is NOT sufficient, which is worth stating because it nearly hid one of the three
// bugs. Measured on the unfixed tool with two files in a directory and --exclude '*.log':
//
//	total_files 1, files_processed 1, files_skipped 0, files_not_examined 0
//
// The arithmetic holds perfectly — 1 == 1 + 0 + 0 — while a file has vanished from the accounting
// entirely, because the recursive walk dropped excluded paths without recording them. A sum can only
// catch a file counted in no bucket if the DENOMINATOR is independent of the buckets, and here it was
// not: total_files was derived from what survived exclusion.
//
// So this test anchors the denominator to the filesystem: it creates a known number of files and
// requires the ledger to account for exactly that many. That is what makes it a real invariant rather
// than a restatement of how the counters are computed.
//
// # One row per refusal reason
//
// Each cause gets a row, so a new refusal reason is one row here rather than a bug report. The rows
// are deliberately a mix of coverage LOSSES and genuine SCOPE: a test containing only losses would
// pass if the tool escalated everything, which would make --fail-on-incomplete fire on every
// repository containing a PNG and be switched off within a day.

type ledgerStats struct {
	TotalFiles       int `json:"total_files"`
	FilesProcessed   int `json:"files_processed"`
	FilesSkipped     int `json:"files_skipped"`
	FilesNotExamined int `json:"files_not_examined"`
}

func scanLedger(t *testing.T, bin string, args ...string) (ledgerStats, int) {
	t.Helper()
	cmd := exec.Command(bin, append([]string{"--config", os.DevNull, "--checks", "all",
		"--format", "json", "--limit", "0"}, args...)...)
	out, err := cmd.Output()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil && len(out) == 0 {
		t.Fatalf("running scanner: %v", err)
	}
	var doc struct {
		Stats ledgerStats `json:"stats"`
	}
	if jsonErr := json.Unmarshal(out, &doc); jsonErr != nil {
		t.Fatalf("parsing stats JSON: %v\noutput: %s", jsonErr, truncateForLog(string(out)))
	}
	return doc.Stats, code
}

func truncateForLog(s string) string {
	if len(s) > 500 {
		return s[:500] + "…"
	}
	return s
}

// exitCodeOf runs the scanner and returns only its exit code, so a test can assert on
// --fail-on-incomplete without parsing output.
func exitCodeOf(t *testing.T, bin string, args ...string) int {
	t.Helper()
	cmd := exec.Command(bin, append([]string{"--config", os.DevNull, "--checks", "all"}, args...)...)
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		t.Fatalf("running scanner: %v", err)
	}
	return 0
}

func TestCoverageLedgerAccountsForEveryFile(t *testing.T) {
	bin := buildScanner(t)
	dir := t.TempDir()

	type fixture struct {
		name    string
		content []byte
		mode    os.FileMode
		// coverageLoss: this file must land in files_not_examined and trip --fail-on-incomplete.
		coverageLoss bool
		why          string
	}
	fixtures := []fixture{
		{"notes.txt", []byte("Employee SSN: 449-87-4100\n"), 0o600, false,
			"CONTROL: an ordinary scanned file. If this is not processed, every other row is vacuous."},
		{"secrets.env", []byte("API_KEY=abc123\x00binary\nSECRET=xyz\nDB=postgres://h/db\n"), 0o600, true,
			"THE #667 CASE: read fine, IS text, refused for a NUL byte. Was counted as files_skipped " +
				"with skipped_types {\".env\": 1} while --fail-on-incomplete exited 0."},
		{"image.png", append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 400)...), 0o600, false,
			"CONTROL the other way: a genuine binary is SCOPE, not a loss. If this escalates, " +
				"--fail-on-incomplete fires on every repository with an image and gets switched off."},
		{"empty.csv", nil, 0o600, false,
			"0 bytes is readable and contains nothing, so nothing is undetected."},
		{"broken.docx", []byte("this is not a zip archive at all"), 0o600, false,
			"A corrupt container. Recorded here to pin whichever bucket it lands in, so a change " +
				"to that classification is a visible decision rather than a surprise."},
	}
	if runtime.GOOS != "windows" {
		// chmod is a no-op on Windows, so a 000 file there is readable and the row would assert
		// the opposite of what it means.
		fixtures = append(fixtures, fixture{"locked.txt", []byte("SSN: 578-24-9163\n"), 0o000, true,
			"Permission denied: the tool could not read it, so its contents are undisclosed."})
	}

	for _, f := range fixtures {
		p := filepath.Join(dir, f.name)
		if err := os.WriteFile(p, f.content, 0o600); err != nil {
			t.Fatalf("writing %s: %v", f.name, err)
		}
		if f.mode != 0o600 {
			if err := os.Chmod(p, f.mode); err != nil {
				t.Fatalf("chmod %s: %v", f.name, err)
			}
			t.Cleanup(func() { _ = os.Chmod(p, 0o600) }) // so t.TempDir cleanup can remove it
		}
	}

	stats, _ := scanLedger(t, bin, "--file", dir, "--recursive")

	// (1) The denominator is anchored to the filesystem, NOT to the sum of the buckets. See the
	// note above: a sum-only check passes while a file is invisible.
	wantTotal := len(fixtures)
	if stats.TotalFiles != wantTotal {
		t.Errorf("total_files = %d, but %d files were created.\n"+
			"  A file present on disk and absent from the ledger is unaccounted for: no invariant "+
			"over the counters can detect it, because the counters all agree.\n  stats: %+v",
			stats.TotalFiles, wantTotal, stats)
	}

	// (2) The buckets partition the total.
	sum := stats.FilesProcessed + stats.FilesSkipped + stats.FilesNotExamined
	if sum != stats.TotalFiles {
		t.Errorf("total_files %d != processed %d + skipped %d + not_examined %d (= %d)",
			stats.TotalFiles, stats.FilesProcessed, stats.FilesSkipped, stats.FilesNotExamined, sum)
	}

	// (3) At least one coverage loss exists, so the exit-code assertion below is not vacuous.
	//
	// Deliberately NOT "every loss is counted" — that assertion belongs per-file and is made by
	// TestEachRefusalLandsInTheRightBucket. Asserting it in aggregate here was WRONG and nearly
	// shipped: with a mixed directory the check was files_not_examined >= 2, and a corrupt .docx
	// is a loss on the unfixed tool too, so the count reached 2 whether or not the .env was
	// classified correctly. The test passed on the parent commit while the bug it was written for
	// was fully present. An aggregate count cannot say WHICH file is in a bucket.
	if stats.FilesNotExamined == 0 {
		t.Fatalf("no coverage losses in a directory containing an unreadable file and a refused "+
			"one; the exit-code assertion below would be vacuous (stats: %+v)", stats)
	}

	// (4) --fail-on-incomplete is non-zero exactly when coverage was lost.
	if code := exitCodeOf(t, bin, "--file", dir, "--recursive", "--fail-on-incomplete"); code == 0 {
		t.Errorf("--fail-on-incomplete exited 0 with files_not_examined = %d. The flag's entire job "+
			"is to report incomplete coverage; exiting 0 here is what let a .env full of secrets go "+
			"unscanned in CI without a signal (#667)", stats.FilesNotExamined)
	}

	// (5) And the converse: a directory with nothing lost must NOT trip it, or the flag is noise.
	clean := t.TempDir()
	if err := os.WriteFile(filepath.Join(clean, "a.txt"), []byte("SSN: 601-42-7788\n"), 0o600); err != nil {
		t.Fatalf("writing clean fixture: %v", err)
	}
	cleanStats, _ := scanLedger(t, bin, "--file", clean, "--recursive")
	if cleanStats.FilesNotExamined != 0 {
		t.Fatalf("clean directory reported files_not_examined = %d, so (5) cannot test the converse",
			cleanStats.FilesNotExamined)
	}
	if code := exitCodeOf(t, bin, "--file", clean, "--recursive", "--fail-on-incomplete"); code != 0 {
		t.Errorf("--fail-on-incomplete exited %d on a directory with nothing lost; a flag that fires "+
			"when coverage is complete is one people turn off", code)
	}
}

// TestExclusionsAreAccountedFor is the same invariant for --exclude, which had its own hole.
//
// Excluded files were dropped by the recursive walk with no ledger entry, so the counters agreed with
// each other while files went missing. This asserts the denominator sees them.
func TestExclusionsAreAccountedFor(t *testing.T) {
	bin := buildScanner(t)
	dir := t.TempDir()
	for _, n := range []string{"a.log", "b.txt", "c.log"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("SSN: 449-87-4100\n"), 0o600); err != nil {
			t.Fatalf("writing %s: %v", n, err)
		}
	}

	base, _ := scanLedger(t, bin, "--file", dir, "--recursive")
	if base.TotalFiles != 3 || base.FilesProcessed != 3 {
		t.Fatalf("control: expected 3 files processed, got %+v", base)
	}

	excluded, _ := scanLedger(t, bin, "--file", dir, "--recursive", "--exclude", "*.log")
	if excluded.TotalFiles != 3 {
		t.Errorf("total_files = %d after excluding 2 of 3 files, want 3.\n"+
			"  The excluded files must still be COUNTED — the walk used to drop them with no entry, "+
			"so the ledger read total_files 1, files_skipped 0 and the two files simply vanished.\n"+
			"  stats: %+v", excluded.TotalFiles, excluded)
	}
	if excluded.FilesSkipped != 2 {
		t.Errorf("files_skipped = %d after excluding 2 files, want 2 (stats: %+v)",
			excluded.FilesSkipped, excluded)
	}
	if excluded.FilesProcessed != 1 {
		t.Errorf("files_processed = %d, want 1 (stats: %+v)", excluded.FilesProcessed, excluded)
	}
	if sum := excluded.FilesProcessed + excluded.FilesSkipped + excluded.FilesNotExamined; sum != excluded.TotalFiles {
		t.Errorf("partition broken under --exclude: %d != %d", excluded.TotalFiles, sum)
	}
}

// TestAShortExcludePatternDoesNotMatchEverything pins the substring bug that made a typo scan nothing.
//
// Behavioural rather than a unit test of the matcher, because the symptom was a whole run reporting a
// clean tree: `--exclude t` matched every path containing the letter "t", so nothing was scanned and
// the tool exited 0 with no warning. Any short typo did it.
func TestAShortExcludePatternDoesNotMatchEverything(t *testing.T) {
	bin := buildScanner(t)
	dir := t.TempDir()
	for _, n := range []string{"notes.txt", "report.log"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("SSN: 449-87-4100\n"), 0o600); err != nil {
			t.Fatalf("writing %s: %v", n, err)
		}
	}

	// Every one of these appears as a substring of at least one path, and none of them is a path
	// SEGMENT or a glob that should match. All must leave both files scanned.
	for _, pattern := range []string{"t", "o", "e", "not", "log", "report"} {
		stats, _ := scanLedger(t, bin, "--file", dir, "--recursive", "--exclude", pattern)
		if stats.FilesProcessed != 2 {
			t.Errorf("--exclude %q left files_processed = %d, want 2.\n"+
				"  %q is a substring of a path but not a segment or a glob, so it must exclude "+
				"nothing. Matching it silently scanned an empty set and exited 0 (#667).\n"+
				"  stats: %+v", pattern, stats.FilesProcessed, pattern, stats)
		}
	}

	// The spellings that SHOULD match still do, or the fix has broken exclusion.
	for _, c := range []struct {
		pattern       string
		wantProcessed int
	}{
		{"*.log", 1},
		{"report.log", 1},
		{"*t*", 0}, // an explicit substring glob: this is how a user asks for the old behaviour
	} {
		stats, _ := scanLedger(t, bin, "--file", dir, "--recursive", "--exclude", c.pattern)
		if stats.FilesProcessed != c.wantProcessed {
			t.Errorf("--exclude %q left files_processed = %d, want %d (stats: %+v)",
				c.pattern, stats.FilesProcessed, c.wantProcessed, stats)
		}
	}
}

// TestAnUnusableExcludePatternIsRejected: a pattern that cannot compile as a glob must be an error,
// not a silent no-op. filepath.Match returns ErrBadPattern for an unterminated character class, and
// every call site used to discard that error.
func TestAnUnusableExcludePatternIsRejected(t *testing.T) {
	bin := buildScanner(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("SSN: 449-87-4100\n"), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	cmd := exec.Command(bin, "--file", dir, "--recursive", "--config", os.DevNull,
		"--checks", "all", "--exclude", "[abc")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Errorf("--exclude '[abc' exited 0. An uncompilable pattern silently matched nothing, so "+
			"the exclusion the user asked for did not happen and they were not told.\noutput: %s",
			truncateForLog(string(out)))
	}
	if !strings.Contains(string(out), "invalid --exclude pattern") {
		t.Errorf("the error should name the pattern and why it is invalid, got: %s",
			truncateForLog(string(out)))
	}
}

// TestEachRefusalLandsInTheRightBucket is the per-reason table, scanning ONE file at a time.
//
// One file per row, because the counters only describe a file unambiguously when it is the only file
// in the run. An earlier version of this suite asserted bucket counts over a mixed directory and was
// vacuous: files_not_examined >= 2 was satisfied by a corrupt .docx that is a coverage loss on the
// unfixed tool as well, so the row for the .env passed while the .env was still being reported as an
// unsupported type.
//
// The rows deliberately include both kinds. A table of losses alone would pass if the tool escalated
// everything, and a tool whose --fail-on-incomplete fires on every PNG is a tool with the flag turned
// off.
func TestEachRefusalLandsInTheRightBucket(t *testing.T) {
	bin := buildScanner(t)

	type row struct {
		name    string
		content []byte
		mode    os.FileMode

		wantProcessed    int
		wantSkipped      int
		wantNotExamined  int
		wantIncompleteRC int // exit code under --fail-on-incomplete
		why              string
	}
	rows := []row{
		{
			name: "notes.txt", content: []byte("Employee SSN: 449-87-4100\n"), mode: 0o600,
			wantProcessed: 1, wantSkipped: 0, wantNotExamined: 0, wantIncompleteRC: 0,
			why: "CONTROL: an ordinary file. If this row fails, every other row is measuring the harness.",
		},
		{
			name:    "secrets.env",
			content: []byte("API_KEY=abc123\x00binary\nSECRET=xyz\nDB=postgres://h/db\n"), mode: 0o600,
			wantProcessed: 0, wantSkipped: 0, wantNotExamined: 1, wantIncompleteRC: 3,
			why: "THE #667 CASE. Read fine, IS text, refused for a NUL byte. On the parent commit this " +
				"was files_skipped 1 with skipped_types {\".env\": 1} and --fail-on-incomplete exited 0 " +
				"— a top-value target reported as deliberately out of scope.",
		},
		{
			name: "image.png", content: append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 400)...), mode: 0o600,
			wantProcessed: 1, wantSkipped: 0, wantNotExamined: 0, wantIncompleteRC: 0,
			why: "CONTROL IN THE OTHER DIRECTION: a PNG is PROCESSED — the preprocessors read its " +
				"metadata — so it must not become a coverage loss. Measured, not assumed: an earlier " +
				"version of this row expected files_skipped 1 and was simply wrong about the tool.",
		},
		{
			name: "opaque.xyz", content: bytes.Repeat([]byte{0xff, 0xfe, 0x80, 0x81}, 150), mode: 0o600,
			wantProcessed: 0, wantSkipped: 1, wantNotExamined: 0, wantIncompleteRC: 0,
			why: "A genuine SKIP: an unsupported type whose bytes are not text and for which no " +
				"preprocessor exists. This row is what stops the fix over-reaching — if an " +
				"unsupported type became a coverage loss, --fail-on-incomplete would fire on any " +
				"tree containing one and be turned off.",
		},
		{
			name: "empty.csv", content: nil, mode: 0o600,
			wantProcessed: 1, wantSkipped: 0, wantNotExamined: 0, wantIncompleteRC: 0,
			why: "0 bytes is readable and holds nothing, so nothing is undetected — it is not a loss.",
		},
	}
	if runtime.GOOS != "windows" {
		rows = append(rows, row{
			name: "locked.txt", content: []byte("SSN: 578-24-9163\n"), mode: 0o000,
			wantProcessed: 0, wantSkipped: 0, wantNotExamined: 1, wantIncompleteRC: 3,
			why: "Permission denied: unreadable, so its contents are undisclosed. Already handled " +
				"before #667; kept as the row proving the unreadable channel still works.",
		})
	}

	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, r.name)
			if err := os.WriteFile(p, r.content, 0o600); err != nil {
				t.Fatalf("writing fixture: %v", err)
			}
			if r.mode != 0o600 {
				if err := os.Chmod(p, r.mode); err != nil {
					t.Fatalf("chmod: %v", err)
				}
				t.Cleanup(func() { _ = os.Chmod(p, 0o600) })
			}

			stats, _ := scanLedger(t, bin, "--file", dir, "--recursive")
			if stats.TotalFiles != 1 {
				t.Fatalf("total_files = %d for a one-file directory; the row cannot attribute the "+
					"counters (stats: %+v)", stats.TotalFiles, stats)
			}
			if stats.FilesProcessed != r.wantProcessed ||
				stats.FilesSkipped != r.wantSkipped ||
				stats.FilesNotExamined != r.wantNotExamined {
				t.Errorf("ledger for %s = (processed %d, skipped %d, not_examined %d), want (%d, %d, %d)\n  %s",
					r.name, stats.FilesProcessed, stats.FilesSkipped, stats.FilesNotExamined,
					r.wantProcessed, r.wantSkipped, r.wantNotExamined, r.why)
			}
			if got := exitCodeOf(t, bin, "--file", dir, "--recursive", "--fail-on-incomplete"); got != r.wantIncompleteRC {
				t.Errorf("--fail-on-incomplete on %s exited %d, want %d\n  %s",
					r.name, got, r.wantIncompleteRC, r.why)
			}
		})
	}
}

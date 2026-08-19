// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The four printed summary counters must reconcile against each other.
//
// #342: every discovery-time skip incremented files_skipped without entering total_files,
// because those paths are never appended to filesToProcess. Measured on the shipped binary,
// a directory holding one small .txt plus one oversize unprocessable file:
//
//	total_files=1  files_processed=1  files_skipped=1
//
// Two files accounted against a total of one, off by exactly one per skip — three matched
// directories gave a gap of three. No coverage was lost; the harm is that an operator cannot
// use the printed numbers to confirm a scan was complete.
//
// # Why this test drives the real binary
//
// internal/formatters/text.TestSummaryCountsReconcile already asserted reconciliation, and
// could not catch this. It builds ScanStats BY HAND and asserts
// processed+notExamined+skipped <= total, failing with "the caller must not hand the formatter
// overlapping categories". The real caller hands it overlapping categories deliberately, so
// the fixture was internally consistent while contradicting the pipeline it stands in for.
// The counters only interact in cmd/main.go, so the assertion has to come from a real scan.
//
// # The identity being asserted
//
//	files_processed + files_skipped + files_not_examined
//	    == total_files + overlapMetaOnly + overlapCutShort
//
// The overlap terms are deliberate double counts, and each fixture below states how many it
// contains BY CONSTRUCTION, so the term is asserted rather than assumed. A plain-sum
// assertion would be wrong in the other direction: unreadable and failed-processing files sit
// in total_files and files_not_examined but in neither processed nor skipped.

// scanStats mirrors the JSON stats block this test reconciles.
type scanStats struct {
	TotalFiles       int `json:"total_files"`
	FilesProcessed   int `json:"files_processed"`
	FilesSkipped     int `json:"files_skipped"`
	FilesNotExamined int `json:"files_not_examined"`
	TotalFindings    int `json:"total_findings"`
}

func (s scanStats) gap() int {
	return s.FilesProcessed + s.FilesSkipped + s.FilesNotExamined - s.TotalFiles
}

func (s scanStats) String() string {
	return fmt.Sprintf("total=%d processed=%d skipped=%d notExamined=%d findings=%d",
		s.TotalFiles, s.FilesProcessed, s.FilesSkipped, s.FilesNotExamined, s.TotalFindings)
}

// runStats scans dir with the real binary and returns the parsed stats block plus stdout.
//
// Pre-commit auto-detection is defeated deliberately, and it is not optional. Detection has a
// Windows-only branch that treats GIT_EXEC_PATH as a pre-commit signal — Git Bash always sets
// it, and CI runs the test step under it — and it also fires when the working directory is a
// git repository carrying a pre-commit hook, which this package's directory is. In that mode
// the requested format is replaced with pre-commit's text default, so --format json yields
// prose and the parse below fails on ONE platform for a reason unrelated to counting. A
// sibling test learned that the expensive way. The working directory is therefore a temp dir
// outside any repository, so `git rev-parse --git-dir` fails, and every trigger variable is
// emptied.
func runStats(t *testing.T, bin, dir string, extra ...string) (scanStats, string) {
	t.Helper()

	out := filepath.Join(t.TempDir(), "stats.json")
	args := append([]string{
		"--file", dir, "--recursive", "--config", os.DevNull,
		"--checks", "SSN", "--limit", "0", "--enable-preprocessors",
		"--format", "json", "--output", out,
	}, extra...)

	cmd := exec.Command(bin, args...)
	cmd.Dir = t.TempDir()
	// MSYSTEM and MINGW_PREFIX are the ones that matter in CI and the ones this list first
	// missed: Git Bash sets all three of MSYSTEM, MINGW_PREFIX and GIT_EXEC_PATH, and the
	// windows test step runs under it. With detection live, the json formatter returns an EMPTY
	// document when there are no findings, so --output received zero bytes and this test failed
	// on "unexpected end of JSON input" — nothing to do with counting.
	//
	// This inline list is deliberately NOT a copy of the shared helper added in #356; defining
	// precommitFreeEnv in two files in one package would not merge. Once #356 is in, this
	// becomes cmd.Env = precommitFreeEnv() and the list is covered by that PR's drift guard.
	cmd.Env = append(os.Environ(),
		"PRE_COMMIT=", "_PRE_COMMIT_RUNNING=", "PRE_COMMIT_HOME=",
		"PRE_COMMIT_HOOK=", "GIT_HOOK_TYPE=", "GIT_EXEC_PATH=", "GITHUB_DESKTOP=",
		"MSYSTEM=", "MINGW_PREFIX=",
	)
	var so, se strings.Builder
	cmd.Stdout, cmd.Stderr = &so, &se
	if err := cmd.Run(); err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			t.Fatalf("run: %v\nstderr: %s", err, se.String())
		}
		// A non-zero exit is expected for several of these fixtures (findings, or coverage
		// cut short). The artifact still has to be written and parseable.
	}

	raw, err := os.ReadFile(out) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatalf("no output artifact written: %v\nstderr: %s", err, se.String())
	}
	var doc struct {
		Stats scanStats `json:"stats"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("stats artifact is not parseable JSON: %v\nfirst 160 bytes: %q", err, raw[:min(160, len(raw))])
	}
	return doc.Stats, se.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// writeTextFile writes a small file carrying one SSN, so it is scanned and yields a finding.
func writeTextFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("Employee record\nSSN: 452-11-9384\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeOversizeUnprocessable writes a file past the 100MB gate whose bytes sniff as BINARY, so
// discovery refuses it as a SKIP rather than as a coverage loss. This is the only shape that
// produces #342's missing term.
//
// Sparse: NUL/0xFF bytes first so the sniffer classifies it, then Truncate extends it without
// occupying disk.
func writeOversizeUnprocessable(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(bytes.Repeat([]byte{0x00, 0xFF}, 64)); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Truncate(101 * 1024 * 1024); err != nil {
		_ = f.Close()
		t.Skipf("cannot create a sparse oversize fixture: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// writeMetaOnlyDocx writes a .docx whose BODY is empty but whose core properties carry an SSN.
//
// This is the deliberate overlap: the file produces a finding through the metadata channel, so
// it counts as scanned, and its body yielded no text, so it also counts as not-examined.
func writeMetaOnlyDocx(t *testing.T, path string) {
	t.Helper()

	const contentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
		`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
		`<Default Extension="xml" ContentType="application/xml"/>` +
		`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
		`<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>` +
		`</Types>`
	const rels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
		`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>` +
		`<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>` +
		`</Relationships>`
	const core = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" ` +
		`xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>SSN: 452-11-9384</dc:creator></cp:coreProperties>`
	const emptyBody = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
		`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body/></w:document>`

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, p := range []struct{ name, content string }{
		{"[Content_Types].xml", contentTypes},
		{"_rels/.rels", rels},
		{"word/document.xml", emptyBody},
		{"docProps/core.xml", core},
	} {
		w, err := zw.Create(p.name)
		if err != nil {
			t.Fatalf("create zip entry %s: %v", p.name, err)
		}
		if _, err := w.Write([]byte(p.content)); err != nil {
			t.Fatalf("write zip entry %s: %v", p.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSummaryCountersReconcileOnRealPipeline(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary and 100MB sparse fixtures")
	}
	bin := buildForExitTest(t)

	cases := []struct {
		name string
		// wantGap is the number of DELIBERATE overlaps the fixture contains, by construction.
		wantGap int
		build   func(t *testing.T, dir string)
	}{
		{
			name:    "plain files only",
			wantGap: 0,
			build: func(t *testing.T, dir string) {
				writeTextFile(t, filepath.Join(dir, "a.txt"))
				writeTextFile(t, filepath.Join(dir, "b.txt"))
			},
		},
		{
			// #342's own repro. This is the case that was off by one.
			name:    "one discovery-time skip",
			wantGap: 0,
			build: func(t *testing.T, dir string) {
				writeTextFile(t, filepath.Join(dir, "a.txt"))
				writeOversizeUnprocessable(t, filepath.Join(dir, "blob.bin"))
			},
		},
		{
			// The gap scaled with the number of skips, so more than one is worth pinning.
			name:    "three discovery-time skips",
			wantGap: 0,
			build: func(t *testing.T, dir string) {
				writeTextFile(t, filepath.Join(dir, "a.txt"))
				for i := 0; i < 3; i++ {
					writeOversizeUnprocessable(t, filepath.Join(dir, fmt.Sprintf("blob%d.bin", i)))
				}
			},
		},
		{
			name:    "one metadata-only file (deliberate overlap)",
			wantGap: 1,
			build: func(t *testing.T, dir string) {
				writeTextFile(t, filepath.Join(dir, "a.txt"))
				writeMetaOnlyDocx(t, filepath.Join(dir, "meta.docx"))
			},
		},
		{
			name:    "two metadata-only files",
			wantGap: 2,
			build: func(t *testing.T, dir string) {
				writeTextFile(t, filepath.Join(dir, "a.txt"))
				writeMetaOnlyDocx(t, filepath.Join(dir, "m1.docx"))
				writeMetaOnlyDocx(t, filepath.Join(dir, "m2.docx"))
			},
		},
		{
			// Both correction sources at once: the term that was missing and the term that is
			// deliberate. Only the deliberate one may remain.
			name:    "discovery skip and metadata-only together",
			wantGap: 1,
			build: func(t *testing.T, dir string) {
				writeTextFile(t, filepath.Join(dir, "a.txt"))
				writeOversizeUnprocessable(t, filepath.Join(dir, "blob.bin"))
				writeMetaOnlyDocx(t, filepath.Join(dir, "meta.docx"))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.build(t, dir)

			stats, stderr := runStats(t, bin, dir)

			if got := stats.gap(); got != tc.wantGap {
				t.Errorf("reconciliation gap = %+d, want %+d\n  %s\n"+
					"  identity: files_processed + files_skipped + files_not_examined "+
					"== total_files + overlaps\n"+
					"  A positive gap beyond the fixture's deliberate overlaps means a category is "+
					"counted in a sub-total but excluded from total_files, so the printed numbers "+
					"cannot be reconciled and an operator cannot use them to confirm coverage.\n"+
					"  stderr:\n%s", got, tc.wantGap, stats, indent(stderr))
			}

			// Sanity floors: a fixture that stopped producing the shape it describes would make
			// the assertion above vacuous.
			if stats.TotalFiles == 0 {
				t.Errorf("total_files = 0, so the identity is trivially satisfied: %s", stats)
			}
			if stats.TotalFindings == 0 {
				t.Errorf("no findings, so nothing in this fixture was actually scanned: %s", stats)
			}
		})
	}
}

// A file whose validator coverage is cut short is counted BOTH as processed and as
// not-examined. That overlap is real, is not mentioned in #342, and is not the defect fixed
// here — it is asserted so the identity's second term is pinned rather than assumed.
func TestCutShortCoverageIsTheOtherOverlapTerm(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary")
	}
	bin := buildForExitTest(t)
	dir := t.TempDir()

	// Large enough that the validators are still running when the budget expires. A tiny file
	// can finish first, which would make this measure nothing.
	var body strings.Builder
	for i := 0; i < 4000; i++ {
		fmt.Fprintf(&body, "record %d ssn 452-11-%04d ref %d\n", i, i%10000, i*7)
	}
	if err := os.WriteFile(filepath.Join(dir, "big.txt"), []byte(body.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	stats, stderr := runStats(t, bin, dir, "--validator-budget", "all=1ns")

	if stats.FilesNotExamined == 0 {
		t.Skipf("the validator budget did not expire on this machine, so there is no cut-short "+
			"file to reconcile: %s", stats)
	}
	if got, want := stats.gap(), stats.FilesNotExamined; got != want {
		t.Errorf("reconciliation gap = %+d, want %+d (one per cut-short file)\n  %s\n"+
			"  A cut-short file is counted in files_processed (the pool leaves Result.Error nil) "+
			"AND in files_not_examined, so the gap should equal the number of such files and "+
			"nothing more.\n  stderr:\n%s", got, want, stats, indent(stderr))
	}
	if !strings.Contains(strings.ToLower(stderr), "cut short") {
		t.Errorf("stderr does not disclose the cut-short coverage:\n%s", indent(stderr))
	}
}

func indent(s string) string {
	if s == "" {
		return "    (empty)"
	}
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i := range lines {
		lines[i] = "    " + lines[i]
	}
	return strings.Join(lines, "\n")
}

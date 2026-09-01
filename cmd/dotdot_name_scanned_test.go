// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A filename containing ".." is not a path traversal, and a file the tool refuses must say so.
//
// Eight sites in cmd tested strings.Contains(path, "..") where a path-SEGMENT test was meant.
// Measured on the shipped binary at a0e983c, two byte-identical files in one directory, each
// holding `SSN: 452-11-9384`:
//
//	invocation                                    findings   rc
//	--file <dir>/normal.txt                        1          0
//	--file <dir>/report..final.txt                 0          0    "No files to process"
//	  ... --fail-on-incomplete                     0          0
//	--format json --file <dir>                     1          0    total_files 1, skipped 0
//
// Only reported findings reach the redactor, so the SSN in the second file stayed in cleartext
// at a success exit code. The directory row is the sharper harm: the walk dropped the path with
// a bare `return nil`, so it entered neither the numerator NOR the denominator, and the printed
// numbers are internally consistent while describing a scan of a file set with a member missing.
//
// Every identifier in this file carries a t562 prefix. Four other test files were added to this
// package concurrently, and a duplicate top-level name merges cleanly and then fails to compile.
//
// See #562. The boundary chosen — post-Clean leading ".." — and why an absolute path outside the
// working directory is deliberately still accepted, are argued in cmd/path_traversal.go.

const t562SSN = "452-11-9384"
const t562OutsideSSN = "613-22-7451"

// t562WriteSSN writes a file whose one line yields exactly one SSN finding at confidence 100.
func t562WriteSSN(t *testing.T, path, ssn string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("SSN: "+ssn+"\n"), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// t562Doc is the JSON artifact this file reconciles: the stats block plus enough of each result
// to say WHICH file a finding came from.
type t562Doc struct {
	Stats struct {
		TotalFiles       int `json:"total_files"`
		FilesProcessed   int `json:"files_processed"`
		FilesSkipped     int `json:"files_skipped"`
		FilesNotExamined int `json:"files_not_examined"`
		TotalFindings    int `json:"total_findings"`
	} `json:"stats"`
	Results []struct {
		Filename string `json:"filename"`
		Type     string `json:"type"`
	} `json:"results"`
}

// t562Run scans target with the real binary and returns the parsed JSON artifact and exit code.
//
// buildForExitTest and precommitFreeEnv are reused rather than reimplemented; both encode
// platform lessons this test would otherwise have to relearn (precommitFreeEnv in particular —
// with detection live the json formatter emits an EMPTY document when there are no findings, so
// the parse below would fail on Windows only, for a reason unrelated to traversal).
//
// --output rather than stdout, because the not-examined report is written to stderr for every
// format and a text banner spliced into stdout is exactly what makes such an artifact unparseable.
func t562Run(t *testing.T, bin, target string, extra ...string) (t562Doc, int, string) {
	t.Helper()

	out := filepath.Join(t.TempDir(), "scan.json")
	args := append([]string{
		"--file", target, "--recursive", "--config", os.DevNull,
		"--checks", "SSN", "--limit", "0", "--enable-preprocessors",
		"--format", "json", "--output", out,
	}, extra...)

	cmd := exec.Command(bin, args...)
	cmd.Dir = t.TempDir()
	cmd.Env = precommitFreeEnv()
	var so, se strings.Builder
	cmd.Stdout, cmd.Stderr = &so, &se
	err := cmd.Run()
	rc := 0
	if ee, ok := err.(*exec.ExitError); ok {
		rc = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run: %v\nstderr: %s", err, se.String())
	}

	raw, readErr := os.ReadFile(out) // #nosec G304 -- test temp dir
	if readErr != nil {
		// The artifact must EXIST before anything is concluded from it. A missing file
		// greps clean, which would turn "the tool wrote nothing" into "no findings".
		return t562Doc{}, rc, se.String()
	}
	var doc t562Doc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("artifact is not parseable JSON: %v\nfirst 200 bytes: %q\nstderr: %s",
			err, raw[:t562Min(200, len(raw))], se.String())
	}
	return doc, rc, se.String()
}

func t562Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// t562FindingFiles returns the base names that produced at least one finding.
func t562FindingFiles(doc t562Doc) map[string]int {
	got := map[string]int{}
	for _, r := range doc.Results {
		got[filepath.Base(r.Filename)]++
	}
	return got
}

// TestT562DotDotNameIsScannedWhenNamedDirectly is the reported defect, end to end.
func TestT562DotDotNameIsScannedWhenNamedDirectly(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary")
	}
	bin := buildForExitTest(t)

	dir := t.TempDir()
	target := filepath.Join(dir, "report..final.txt")
	t562WriteSSN(t, target, t562SSN)

	doc, rc, stderr := t562Run(t, bin, target)

	// Non-zero findings FIRST: every assertion below is about a set that must not be empty,
	// and a zero here would make the rest pass vacuously.
	if doc.Stats.TotalFindings == 0 {
		t.Fatalf("total_findings = 0 for %s, want 1.\nThe file holds `SSN: %s`, which this tool "+
			"detects at confidence 100 — the identical bytes under the name normal.txt yield one "+
			"HIGH finding. A file that is never scanned is never redacted, so this is a cleartext "+
			"leak at rc %d.\nstderr: %s", filepath.Base(target), t562SSN, rc, stderr)
	}
	if got := t562FindingFiles(doc)["report..final.txt"]; got != 1 {
		t.Errorf("findings attributed to report..final.txt = %d, want 1; results = %+v",
			got, doc.Results)
	}
	if doc.Stats.FilesProcessed != 1 {
		t.Errorf("files_processed = %d, want 1", doc.Stats.FilesProcessed)
	}
	if doc.Stats.FilesSkipped != 0 {
		t.Errorf("files_skipped = %d, want 0: the file was scanned, so calling it skipped would "+
			"claim nobody expected a finding from it", doc.Stats.FilesSkipped)
	}
}

// TestT562DirectoryAccountingHasNoSilentThirdCategory is the accounting assertion the issue asks
// for: N files in, N accounted for, each one either processed or disclosed.
//
// The identity is asserted against the number of files ON DISK, not against total_files. Checking
// the printed numbers against each other cannot catch this defect — before the fix they were
// self-consistent (total 1, processed 1, skipped 0, one finding) and simply omitted a file from
// every term including the denominator.
func TestT562DirectoryAccountingHasNoSilentThirdCategory(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary")
	}
	bin := buildForExitTest(t)

	dir := t.TempDir()
	names := []string{
		"normal.txt",
		"report..final.txt",
		"2024..2025.txt",
		"notes...draft.txt",
	}
	for _, n := range names {
		t562WriteSSN(t, filepath.Join(dir, n), t562SSN)
	}

	doc, rc, stderr := t562Run(t, bin, dir)

	if doc.Stats.TotalFindings == 0 {
		t.Fatalf("total_findings = 0 over %d files each holding an SSN; nothing below can be "+
			"concluded from an empty scan.\nrc %d\nstderr: %s", len(names), rc, stderr)
	}
	if doc.Stats.TotalFiles != len(names) {
		t.Errorf("total_files = %d, want %d.\nThe DENOMINATOR is the defect: an entry the walk "+
			"dropped was absent from total_files too, so no arithmetic on the printed numbers "+
			"could reveal it and `files_skipped: 0` read as complete coverage.",
			doc.Stats.TotalFiles, len(names))
	}
	accounted := doc.Stats.FilesProcessed + doc.Stats.FilesSkipped + doc.Stats.FilesNotExamined
	if accounted != len(names) {
		t.Errorf("processed(%d) + skipped(%d) + not_examined(%d) = %d, want %d — %d file(s) are "+
			"in a silent fourth category",
			doc.Stats.FilesProcessed, doc.Stats.FilesSkipped, doc.Stats.FilesNotExamined,
			accounted, len(names), len(names)-accounted)
	}
	// And each file individually produced its finding, so "accounted for" means examined
	// rather than merely counted.
	got := t562FindingFiles(doc)
	for _, n := range names {
		if got[n] != 1 {
			t.Errorf("findings attributed to %s = %d, want 1; the file holds `SSN: %s` and an "+
				"unreported value is never handed to the redactor", n, got[n], t562SSN)
		}
	}
}

// TestT562GlobMatchHoldingTwoDotsIsScanned covers the glob branch of getFilesToProcess, which has
// its own gate and its own silent `continue`.
func TestT562GlobMatchHoldingTwoDotsIsScanned(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"normal.txt", "report..final.txt"} {
		t562WriteSSN(t, filepath.Join(dir, n), t562SSN)
	}

	res, err := getFilesToProcess(filepath.Join(dir, "*.txt"), false, nil, nil, true)
	if err != nil {
		t.Fatalf("getFilesToProcess(glob): %v", err)
	}
	if len(res.FilesToProcess) != 2 {
		t.Fatalf("glob queued %d files, want 2: %v\nA match dropped here reaches no counter at "+
			"all — the gate was `continue` with nothing recorded.", len(res.FilesToProcess), res.FilesToProcess)
	}
	queued := map[string]bool{}
	for _, p := range res.FilesToProcess {
		queued[filepath.Base(p)] = true
	}
	if !queued["report..final.txt"] {
		t.Errorf("report..final.txt was not queued by the glob; queued = %v", res.FilesToProcess)
	}
	if len(res.UnexaminedFiles) != 0 {
		t.Errorf("UnexaminedFiles = %+v, want empty: nothing here is a traversal", res.UnexaminedFiles)
	}
}

// TestT562WalkedDirectoryNameHoldingTwoDotsIsDescended covers the walk gate directly: a
// SUBDIRECTORY named with two dots hid every file beneath it, and how many is unknowable from the
// output.
func TestT562WalkedDirectoryNameHoldingTwoDotsIsDescended(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "2024..2025")
	if err := os.MkdirAll(sub, 0o750); err != nil {
		t.Fatal(err)
	}
	t562WriteSSN(t, filepath.Join(dir, "normal.txt"), t562SSN)
	t562WriteSSN(t, filepath.Join(sub, "budget.txt"), t562SSN)

	res, err := getFilesToProcess(dir, true, nil, nil, true)
	if err != nil {
		t.Fatalf("getFilesToProcess(dir): %v", err)
	}
	if len(res.FilesToProcess) != 2 {
		t.Fatalf("walk queued %d files, want 2: %v", len(res.FilesToProcess), res.FilesToProcess)
	}
	var found bool
	for _, p := range res.FilesToProcess {
		if filepath.Base(p) == "budget.txt" {
			found = true
		}
	}
	if !found {
		t.Errorf("the file under 2024..2025/ was not queued; queued = %v.\nA refused DIRECTORY "+
			"hides every descendant, and the count of them is absent from the report.",
			res.FilesToProcess)
	}
}

// TestT562GenuineEscapeIsRefusedDisclosedAndFailsTheBuild is the security half. The refusal must
// survive, and — the part that did not exist before — it must be VISIBLE and must reach the exit
// code of the flag whose purpose is to fail on incomplete coverage.
func TestT562GenuineEscapeIsRefusedDisclosedAndFailsTheBuild(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary")
	}
	bin := buildForExitTest(t)

	// Deliberately a path that need not exist: the gate fires before any filesystem access,
	// so the case is identical on Windows, where /etc/passwd is absent.
	const escape = "../../etc/passwd"

	doc, rc, stderr := t562Run(t, bin, escape, "--fail-on-incomplete")

	if doc.Stats.TotalFindings != 0 || doc.Stats.FilesProcessed != 0 {
		t.Fatalf("an escaping path was SCANNED: findings=%d processed=%d — narrowing the gate "+
			"must not remove it", doc.Stats.TotalFindings, doc.Stats.FilesProcessed)
	}
	if doc.Stats.FilesNotExamined != 1 {
		t.Errorf("files_not_examined = %d, want 1.\nA refusal nobody can see is indistinguishable "+
			"from a clean scan; before this change the run printed `No files to process` and "+
			"carried no files_not_examined key at all.", doc.Stats.FilesNotExamined)
	}
	if doc.Stats.TotalFiles != 1 {
		t.Errorf("total_files = %d, want 1: the refused path must be in the denominator it is "+
			"counted against", doc.Stats.TotalFiles)
	}
	if rc != exitCodeIncompleteCoverage {
		t.Errorf("--fail-on-incomplete exit = %d, want %d.\nThe whole purpose of the flag is to "+
			"turn incomplete coverage into a non-zero exit, and it returned 0 here because the "+
			"refused path never entered the coverage ledger.\nstderr: %s",
			rc, exitCodeIncompleteCoverage, stderr)
	}
	if !strings.Contains(stderr, "path refused as traversal") {
		t.Errorf("the not-examined report does not name the cause.\nstderr: %s", stderr)
	}
	// Positive control on the leak check above: the report must actually name the path, so
	// "no findings" is being read from a report that exists and has content.
	if !strings.Contains(stderr, "etc/passwd") && !strings.Contains(stderr, `etc\passwd`) {
		t.Errorf("the disclosure does not name the refused path, so an operator cannot act on "+
			"it.\nstderr: %s", stderr)
	}
}

// TestT562EscapingSymlinkIsStillRefusedWhileADotDotNameIsScanned is the combined case: the
// traversal gate is narrowed and the symlink containment check is untouched, in one run.
//
// It matters as a pair because the old substring gate ran BEFORE the symlink classifier, so a
// link whose NAME held two dots was dropped without ever being classified. Both properties have
// to hold at once: the ordinary name is scanned, and the escaping link is refused and disclosed.
func TestT562EscapingSymlinkIsStillRefusedWhileADotDotNameIsScanned(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()

	t562WriteSSN(t, filepath.Join(dir, "report..final.txt"), t562SSN)
	target := filepath.Join(outside, "secret.txt")
	t562WriteSSN(t, target, t562OutsideSSN)
	if err := os.Symlink(target, filepath.Join(dir, "escape..link.txt")); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}

	res, err := getFilesToProcess(dir, true, nil, nil, true)
	if err != nil {
		t.Fatalf("getFilesToProcess: %v", err)
	}

	queued := map[string]bool{}
	for _, p := range res.FilesToProcess {
		queued[filepath.Base(p)] = true
		if strings.HasPrefix(p, outside) {
			t.Errorf("a symlink escaping the scanned tree was queued as %s; the containment check "+
				"must survive the traversal-gate change", p)
		}
	}
	if !queued["report..final.txt"] {
		t.Errorf("report..final.txt was not queued; queued = %v", res.FilesToProcess)
	}
	if len(res.UnexaminedFiles) != 1 {
		t.Fatalf("UnexaminedFiles = %+v, want exactly the refused link. A refusal the classifier "+
			"never sees is a refusal nobody discloses.", res.UnexaminedFiles)
	}
	if got := res.UnexaminedFiles[0].Cause; got != causeNotFollowed {
		t.Errorf("cause = %v, want causeNotFollowed: it IS a symlink, and reporting it as a "+
			"traversal refusal or as unreadable would be a true disclosure under a false heading", got)
	}
}

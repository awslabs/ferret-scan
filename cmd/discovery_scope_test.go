// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Discovery-time coverage accounting has to get BOTH directions right: everything that was
// refused must be disclosed, and nothing that was never in scope may be reported as a loss.
//
// The first direction was fixed for #324 and #336. The second was broken BY those fixes, and
// the two failures need opposite corrections, so they are tested together to keep a later
// change from trading one for the other.

// pii is a value that must be found when a path is genuinely scanned, and must never appear
// in a disclosure string.
const pii = "SSN: 452-11-9384"

// A DIRECTORY matched by a glob pattern used to be dropped in silence.
//
// The glob branch tested info.Mode().IsRegular() and had no else, so a matched directory
// reached neither FilesToProcess nor either disclosure slice. --recursive was accepted and
// did nothing, because recursion lives in the directory branch that a glob never reaches.
//
// Measured on the shipped binary against a readable tree holding two values:
//
//	--file '<dir>/*' --recursive   ->  0 findings, total_files 1, exit 0, no disclosure
//	after this change              ->  2 findings, total_files 3
//
// A shell that expands the pattern itself hides this, because each match arrives as its own
// argument. It bites when the pattern is QUOTED, which is what the documentation asks for.
func TestGlobMatchedDirectoryIsScannedWhenRecursive(t *testing.T) {
	root := t.TempDir()
	deep := filepath.Join(root, "deep", "deeper")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "top.txt"), []byte("nothing here\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "deep", "pii.txt"), []byte(pii+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(deep, "more.txt"), []byte("Card: 4111111111111111\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := getFilesToProcess(filepath.Join(root, "*"), true, nil, nil, true)
	if err != nil {
		t.Fatalf("getFilesToProcess: %v", err)
	}

	var sawNested, sawDeepest bool
	for _, p := range res.FilesToProcess {
		switch filepath.Base(p) {
		case "pii.txt":
			sawNested = true
		case "more.txt":
			sawDeepest = true
		}
	}
	if !sawNested || !sawDeepest {
		t.Errorf("FilesToProcess = %v, want the files inside the matched directory. A glob that "+
			"matches a directory dropped it entirely, so --recursive was silently a no-op and "+
			"the PII inside was never scanned — which also means it is never redacted.",
			res.FilesToProcess)
	}
}

// Without --recursive the directory is genuinely out of scope, so it must be REPORTED as
// skipped rather than either scanned or dropped.
//
// Dropped is what it used to be: no counter, no message, nothing for the operator to notice
// that a matched path contributed nothing.
func TestGlobMatchedDirectoryIsDisclosedWhenNotRecursive(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "pii.txt"), []byte(pii+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "top.txt"), []byte("nothing\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := getFilesToProcess(filepath.Join(root, "*"), false, nil, nil, true)
	if err != nil {
		t.Fatalf("getFilesToProcess: %v", err)
	}

	for _, p := range res.FilesToProcess {
		if strings.Contains(p, "sub") {
			t.Errorf("%q was scanned without --recursive", p)
		}
	}

	var found *SkippedFile
	for i := range res.SkippedFiles {
		if strings.Contains(res.SkippedFiles[i].Path, "sub") {
			found = &res.SkippedFiles[i]
		}
	}
	if found == nil {
		t.Fatalf("the matched directory is in neither FilesToProcess nor SkippedFiles (%v) — a "+
			"pattern match that contributes nothing and says nothing is indistinguishable from "+
			"one that was scanned and was clean", pathsOf(res.SkippedFiles))
	}
	if found.Silent {
		t.Error("the skip is Silent, so nothing is printed; the operator asked for this path by " +
			"pattern and should be told --recursive is needed to descend into it")
	}
	if !strings.Contains(strings.ToLower(found.Reason), "recursive") {
		t.Errorf("reason = %q, want it to name --recursive as the remedy", found.Reason)
	}
	if strings.Contains(found.Reason, "452-11-9384") {
		t.Errorf("reason leaked file content: %q", found.Reason)
	}
}

// A subdirectory the user did not ask to descend into is NOT missing coverage.
//
// Go's filepath.Walk calls readDirNames before invoking the callback for a directory and
// passes that error in the SAME call, so an unreadable directory arrives at the error branch
// and never reaches the !recursive check below it. The result was exit 3 on a non-recursive
// scan, blaming the run for not reading something it was never asked to read.
//
// A flag that fires outside the requested scope is one people stop passing, which costs
// exactly the disclosures it exists to deliver.
func TestNonRecursiveScanDoesNotReportOutOfScopeSubdirectory(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(root, "secret")
	if err := os.MkdirAll(secret, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secret, "pii.txt"), []byte(pii+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "top.txt"), []byte("nothing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(secret, 0o000); err != nil {
		t.Skipf("cannot chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(secret, 0o755) })
	requireUnreadablePathsWork(t, secret)

	res, err := getFilesToProcess(root, false, nil, nil, true)
	if err != nil {
		t.Fatalf("getFilesToProcess: %v", err)
	}
	for _, u := range res.UnexaminedFiles {
		if strings.Contains(u.Path, "secret") {
			t.Errorf("a subdirectory was reported as unexamined on a NON-recursive scan: %q (%q). "+
				"Without --recursive its contents were never in scope, so nothing was lost and "+
				"--fail-on-incomplete must not exit 3.", u.Path, u.Reason)
		}
	}

	// The control: WITH --recursive the same directory IS a loss and must be reported. Without
	// this the test above would pass if disclosure were removed altogether.
	res2, err := getFilesToProcess(root, true, nil, nil, true)
	if err != nil {
		t.Fatalf("getFilesToProcess recursive: %v", err)
	}
	var reported bool
	for _, u := range res2.UnexaminedFiles {
		if strings.Contains(u.Path, "secret") {
			reported = true
		}
	}
	if !reported {
		t.Errorf("with --recursive the unreadable directory is NOT reported (%v) — scoping the "+
			"disclosure must not remove it where it belongs", pathsOf(res2.UnexaminedFiles))
	}
}

// A directory the user explicitly excluded is not missing coverage either.
func TestExcludedUnreadableDirectoryIsNotReported(t *testing.T) {
	root := t.TempDir()
	secret := filepath.Join(root, "secret")
	if err := os.MkdirAll(secret, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secret, "pii.txt"), []byte(pii+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "top.txt"), []byte("nothing\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(secret, 0o000); err != nil {
		t.Skipf("cannot chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(secret, 0o755) })
	requireUnreadablePathsWork(t, secret)

	res, err := getFilesToProcess(root, true, []string{"secret"}, nil, true)
	if err != nil {
		t.Fatalf("getFilesToProcess: %v", err)
	}
	for _, u := range res.UnexaminedFiles {
		if strings.Contains(u.Path, "secret") {
			t.Errorf("an --exclude'd directory was reported as unexamined: %q (%q). The user "+
				"asked for it not to be scanned; reporting lost coverage for it turns their own "+
				"instruction into a failing exit code.", u.Path, u.Reason)
		}
	}
}

// A path named directly on the command line that EXISTS but cannot be read is a coverage
// loss, and a path that does not exist is not.
//
// The unreadable case measured as one stderr line, "No files to process", total_files 0, no
// files_not_examined key, and --fail-on-incomplete exiting 0 — a complete scan of nothing,
// with an unread SSN at the named path.
//
// The nonexistent case is deliberately excluded. A typo is a usage error, and making
// --fail-on-incomplete fire on misspelled arguments is how people learn to stop passing it.
func TestNamedPathAccessFailureIsClassified(t *testing.T) {
	root := t.TempDir()
	locked := filepath.Join(root, "locked")
	if err := os.MkdirAll(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(locked, "pii.txt")
	if err := os.WriteFile(target, []byte(pii+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Skipf("cannot chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	requireUnreadablePathsWork(t, locked)

	// Both inputs fail, and they must be classified differently. getFilesToProcess returns an
	// error for each; the classification happens at the call site in main, so this asserts the
	// discriminator that call site uses rather than reaching into main itself.
	if _, err := getFilesToProcess(target, false, nil, nil, true); err == nil {
		t.Fatal("expected an error for a file inside an unreadable directory")
	}
	if !isAccessDenied(target) {
		t.Errorf("a file inside a mode-000 directory was not classified as access-denied, so it " +
			"reaches no counter and --fail-on-incomplete stays 0 while the value goes unread")
	}

	missing := filepath.Join(root, "no-such-file.txt")
	if isAccessDenied(missing) {
		t.Errorf("a nonexistent path was classified as access-denied; a typo would then be " +
			"reported as lost coverage and fail the build")
	}
}

// #9: a structured format must produce a parseable document even when every input was
// refused, which is precisely when it has something to disclose.
//
// Driven through the real binary because the defect is in an os.Exit path.
func TestMachineFormatEmitsValidJSONWhenEveryInputIsRefused(t *testing.T) {
	bin := buildForExitTest(t)
	dir := t.TempDir()

	// One oversize file, so discovery refuses it and no file reaches the scanner. Written as
	// real text first: past ~512 bytes the sniffer classifies it as text, and Truncate then
	// extends it sparsely so the fixture costs no disk.
	big := filepath.Join(dir, "big.txt")
	f, err := os.Create(big) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(strings.Repeat("Quarterly report text content.\n", 40)); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(105 * 1024 * 1024); err != nil {
		_ = f.Close()
		t.Skipf("cannot create a sparse oversize fixture: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	run := runForExit(t, bin, dir, nil, "--format", "json", "--fail-on-incomplete")

	if run.rc != 3 {
		t.Errorf("rc = %d, want 3: a refused processable file is lost coverage", run.rc)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(run.stdout), &doc); err != nil {
		t.Fatalf("--format json produced an unparseable document: %v\nfirst 120 bytes: %q\n"+
			"The no-files path printed a plain-text line on stdout, so `--format json > "+
			"report.json` yielded a file starting with 'N' — and it failed at the exact moment "+
			"the scan had a refusal to report.", err, truncateForMsg(run.stdout))
	}
	stats, ok := doc["stats"].(map[string]interface{})
	if !ok {
		t.Fatalf("the document carries no stats object: %q", truncateForMsg(run.stdout))
	}
	if got := stats["files_not_examined"]; got == nil {
		t.Errorf("stats = %v, want a files_not_examined count so the refusal is machine-readable "+
			"and not only an exit code", stats)
	}
}

// truncateForMsg keeps failure output readable.
func truncateForMsg(s string) string {
	if len(s) > 120 {
		return s[:120] + "..."
	}
	return s
}

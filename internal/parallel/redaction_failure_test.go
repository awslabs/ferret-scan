// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package parallel

import (
	"io"
	"path/filepath"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
	"github.com/awslabs/ferret-scan/v2/internal/redactors/plaintext"
)

// These tests lock the boundary between the SCAN result and the REDACTION
// artifact: a file whose findings could not be redacted must still report those
// findings and still be counted as processed. Redaction runs after the file has
// been read, extracted and validated, so it cannot invalidate what was found.
//
// The regression they guard is a silent one. Redaction failure used to be folded
// into Result.Error, whose branch in the result collector neither appends
// matches nor increments processedCount — so scanning a directory with
// --enable-redaction dropped every finding in every file whose extension has no
// registered redactor (.go, .py, ...) while still reporting "0 skipped" and
// exiting 0. A CI gate saw a clean pass over unredacted cleartext.

// newRedactionManagerWithPlaintextOnly builds a manager that can redact .txt but
// NOT .go — the real-world shape of the bug, since the default redactor set
// covers text/PDF/Office/image extensions and nothing else.
func newRedactionManagerWithPlaintextOnly(t *testing.T, outDir string) *redactors.RedactionManager {
	t.Helper()
	observer := observability.NewStandardObserver(observability.ObservabilityMetrics, io.Discard)
	om, err := redactors.NewOutputStructureManager(outDir, observer)
	if err != nil {
		t.Fatalf("output manager: %v", err)
	}
	mgr := redactors.NewRedactionManagerWithConfig(om, observer, &redactors.RedactionManagerConfig{
		DefaultStrategy: redactors.RedactionSimple,
		RetryAttempts:   1,
	})
	if err := mgr.RegisterRedactor(plaintext.NewPlainTextRedactor(om, observer)); err != nil {
		t.Fatalf("register plaintext redactor: %v", err)
	}
	return mgr
}

// TestRedaction_UnredactableFileKeepsItsMatches is the core guarantee: a file
// with no registered redactor still contributes its findings and is still
// counted, and the failure is reported as its own diagnostic rather than
// silently swallowed.
func TestRedaction_UnredactableFileKeepsItsMatches(t *testing.T) {
	dir := t.TempDir()
	txt := writeTxt(t, dir, "notes.txt", "alpha content")
	// .go has no registered redactor in the manager built above.
	gofile := writeTxt(t, dir, "creds.go", "package main // beta content")

	v := &batchStubValidator{}
	observer := observability.NewStandardObserver(observability.ObservabilityMetrics, io.Discard)
	pp := NewParallelProcessor(observer)
	fr := newTestFileRouter(t)
	mgr := newRedactionManagerWithPlaintextOnly(t, filepath.Join(dir, "out"))

	cfg := &JobConfig{EnableRedaction: true, RedactionStrategy: "simple"}
	matches, stats, err := pp.ProcessFilesWithProgress(
		[]string{txt, gofile}, []detector.Validator{v}, fr, cfg, mgr, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Both files' matches must be present. The stub emits one per file.
	byFile := map[string]int{}
	for _, m := range matches {
		byFile[filepath.Base(m.Filename)]++
	}
	if byFile["creds.go"] == 0 {
		t.Errorf("unredactable file's matches were DROPPED (the leak): got %v", byFile)
	}
	if byFile["notes.txt"] == 0 {
		t.Errorf("redactable file's matches missing: got %v", byFile)
	}

	// The unredactable file must still be counted as processed — a scan that
	// silently stops counting files is what makes "0 skipped" a lie.
	if stats.ProcessedFiles != 2 {
		t.Errorf("ProcessedFiles = %d, want 2 (both files were scanned)", stats.ProcessedFiles)
	}

	// ...and the redaction failure must be surfaced, naming the file.
	if len(stats.UnredactedFiles) != 1 {
		t.Fatalf("UnredactedFiles = %d, want 1: %+v", len(stats.UnredactedFiles), stats.UnredactedFiles)
	}
	if filepath.Base(stats.UnredactedFiles[0].FilePath) != "creds.go" {
		t.Errorf("wrong unredacted file: %q", stats.UnredactedFiles[0].FilePath)
	}
	if stats.UnredactedFiles[0].Reason == "" {
		t.Error("unredacted diagnostic carries no reason")
	}
}

// TestRedaction_FailureIsNotACoverageFailure keeps the two diagnostics distinct.
// A redaction failure means "the values were found but not masked anywhere";
// incomplete coverage means "findings may be missing". Conflating them would
// make --fail-on-incomplete fire on unredactable file types, and would tell an
// operator to re-scan when the scan was in fact complete.
func TestRedaction_FailureIsNotACoverageFailure(t *testing.T) {
	dir := t.TempDir()
	gofile := writeTxt(t, dir, "creds.go", "package main // beta content")

	v := &batchStubValidator{}
	observer := observability.NewStandardObserver(observability.ObservabilityMetrics, io.Discard)
	pp := NewParallelProcessor(observer)
	fr := newTestFileRouter(t)
	mgr := newRedactionManagerWithPlaintextOnly(t, filepath.Join(dir, "out"))

	cfg := &JobConfig{EnableRedaction: true, RedactionStrategy: "simple"}
	_, stats, err := pp.ProcessFilesWithProgress(
		[]string{gofile}, []detector.Validator{v}, fr, cfg, mgr, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(stats.UnredactedFiles) != 1 {
		t.Fatalf("UnredactedFiles = %d, want 1", len(stats.UnredactedFiles))
	}
	if len(stats.IncompleteFiles) != 0 {
		t.Errorf("a redaction failure must NOT be reported as incomplete coverage; got %+v",
			stats.IncompleteFiles)
	}
}

// TestRedaction_UnredactableFileIsNotAFailedFile pins the exit-code
// consequence, which is the sharpest edge of this bug. The CLI computes
// failedFiles = totalAttempted - ProcessedFiles and feeds that to the
// pre-commit exit code as hasErrors, where 2 ("system error") outranks 1
// ("blocking finding"). While unredactable files went uncounted, a pre-commit
// run over a repo of .go/.py sources exited 2 — a hook that treats 2 as
// infrastructure flakiness would retry or ignore it, letting a commit through
// with the secret still in it. Counting the file makes the exit code reflect
// the findings instead.
func TestRedaction_UnredactableFileIsNotAFailedFile(t *testing.T) {
	dir := t.TempDir()
	files := []string{
		writeTxt(t, dir, "notes.txt", "alpha content"),
		writeTxt(t, dir, "creds.go", "package main // beta content"),
		writeTxt(t, dir, "app.py", "# gamma content"),
	}

	v := &batchStubValidator{}
	observer := observability.NewStandardObserver(observability.ObservabilityMetrics, io.Discard)
	pp := NewParallelProcessor(observer)
	fr := newTestFileRouter(t)
	mgr := newRedactionManagerWithPlaintextOnly(t, filepath.Join(dir, "out"))

	cfg := &JobConfig{EnableRedaction: true, RedactionStrategy: "simple"}
	_, stats, err := pp.ProcessFilesWithProgress(files, []detector.Validator{v}, fr, cfg, mgr, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// This is the exact expression cmd/main.go uses for failedFiles/hasErrors.
	failedFiles := len(files) - stats.ProcessedFiles
	if failedFiles != 0 {
		t.Errorf("failedFiles = %d, want 0; %d unredactable file(s) must not read as system errors",
			failedFiles, len(stats.UnredactedFiles))
	}
	if len(stats.UnredactedFiles) != 2 {
		t.Errorf("UnredactedFiles = %d, want 2 (.go and .py)", len(stats.UnredactedFiles))
	}
}

// TestRedaction_SuccessReportsNoUnredactedFiles pins the happy path: when every
// file can be redacted, UnredactedFiles is empty, so a caller that only checks
// for the warning sees no change on a normal run.
func TestRedaction_SuccessReportsNoUnredactedFiles(t *testing.T) {
	dir := t.TempDir()
	a := writeTxt(t, dir, "a.txt", "alpha content")
	b := writeTxt(t, dir, "b.txt", "beta content")

	v := &batchStubValidator{}
	observer := observability.NewStandardObserver(observability.ObservabilityMetrics, io.Discard)
	pp := NewParallelProcessor(observer)
	fr := newTestFileRouter(t)
	mgr := newRedactionManagerWithPlaintextOnly(t, filepath.Join(dir, "out"))

	cfg := &JobConfig{EnableRedaction: true, RedactionStrategy: "simple"}
	matches, stats, err := pp.ProcessFilesWithProgress(
		[]string{a, b}, []detector.Validator{v}, fr, cfg, mgr, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(stats.UnredactedFiles) != 0 {
		t.Errorf("clean redaction run should report no unredacted files, got %+v", stats.UnredactedFiles)
	}
	if stats.ProcessedFiles != 2 {
		t.Errorf("ProcessedFiles = %d, want 2", stats.ProcessedFiles)
	}
	if len(matches) != 2 {
		t.Errorf("got %d matches, want 2", len(matches))
	}
}

// TestRedaction_DisabledLeavesDiagnosticEmpty confirms the field stays empty
// when redaction was never requested, so the no-redaction default path is
// byte-identical for every consumer of ProcessingStats.
func TestRedaction_DisabledLeavesDiagnosticEmpty(t *testing.T) {
	dir := t.TempDir()
	gofile := writeTxt(t, dir, "creds.go", "package main // beta content")

	v := &batchStubValidator{}
	observer := observability.NewStandardObserver(observability.ObservabilityMetrics, io.Discard)
	pp := NewParallelProcessor(observer)
	fr := newTestFileRouter(t)

	_, stats, err := pp.ProcessFilesWithProgress(
		[]string{gofile}, []detector.Validator{v}, fr, &JobConfig{}, nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(stats.UnredactedFiles) != 0 {
		t.Errorf("redaction disabled should leave UnredactedFiles empty, got %+v", stats.UnredactedFiles)
	}
	if stats.ProcessedFiles != 1 {
		t.Errorf("ProcessedFiles = %d, want 1", stats.ProcessedFiles)
	}
}

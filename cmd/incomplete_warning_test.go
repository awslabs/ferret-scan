// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/parallel"
)

// TestWriteIncompleteCoverageWarning_NoneIsSilent: a fully-complete scan (no
// incomplete files) must write nothing and report that nothing was written —
// this is the common path and must never emit a spurious warning.
func TestWriteIncompleteCoverageWarning_NoneIsSilent(t *testing.T) {
	var buf bytes.Buffer
	wrote := writeIncompleteCoverageWarning(&buf, nil, 5)
	if wrote {
		t.Error("expected no warning for a complete scan")
	}
	if buf.Len() != 0 {
		t.Errorf("expected empty output, got %q", buf.String())
	}
}

// TestWriteIncompleteCoverageWarning_SingleFile: one incomplete file names the
// file and its reason on the warning.
func TestWriteIncompleteCoverageWarning_SingleFile(t *testing.T) {
	var buf bytes.Buffer
	files := []parallel.FileDiagnostic{
		{FilePath: "big.json", Reason: "validator execution did not complete: context deadline exceeded"},
	}
	wrote := writeIncompleteCoverageWarning(&buf, files, 1)
	if !wrote {
		t.Fatal("expected a warning to be written")
	}
	out := buf.String()
	for _, want := range []string{"coverage incomplete", "1 of 1 file", "big.json", "context deadline exceeded", "findings may be missing"} {
		if !strings.Contains(out, want) {
			t.Errorf("warning missing %q; got:\n%s", want, out)
		}
	}
}

// TestWriteIncompleteCoverageWarning_MultipleFiles: the count reflects incomplete
// vs total, and every offending file is listed.
func TestWriteIncompleteCoverageWarning_MultipleFiles(t *testing.T) {
	var buf bytes.Buffer
	files := []parallel.FileDiagnostic{
		{FilePath: "a.txt", Reason: "validator match budget exceeded"},
		{FilePath: "b.txt", Reason: "context deadline exceeded"},
	}
	wrote := writeIncompleteCoverageWarning(&buf, files, 10)
	if !wrote {
		t.Fatal("expected a warning to be written")
	}
	out := buf.String()
	if !strings.Contains(out, "2 of 10 file") {
		t.Errorf("expected '2 of 10 file' count, got:\n%s", out)
	}
	if !strings.Contains(out, "a.txt") || !strings.Contains(out, "b.txt") {
		t.Errorf("expected both offending files listed, got:\n%s", out)
	}
}

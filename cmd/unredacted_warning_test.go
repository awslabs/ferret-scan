// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/parallel"
)

// TestWriteUnredactedFilesWarning_NoneIsSilent: a run where every file with
// findings was redacted (and every run without --enable-redaction) must write
// nothing, so the common path emits no spurious warning.
func TestWriteUnredactedFilesWarning_NoneIsSilent(t *testing.T) {
	var buf bytes.Buffer
	wrote := writeUnredactedFilesWarning(&buf, nil, 5)
	if wrote {
		t.Error("expected no warning when every file was redacted")
	}
	if buf.Len() != 0 {
		t.Errorf("expected empty output, got %q", buf.String())
	}
}

// TestWriteUnredactedFilesWarning_NamesFileAndCleartext: the warning must name
// the file, the reason, AND say the values are still in cleartext. The last part
// is the point — an operator who ran --enable-redaction believes an artifact was
// produced, and the count alone would not tell them otherwise.
func TestWriteUnredactedFilesWarning_NamesFileAndCleartext(t *testing.T) {
	var buf bytes.Buffer
	files := []parallel.FileDiagnostic{
		{FilePath: "src/creds.go", Reason: "failed to get redactor: no redactor registered for file type: .go"},
	}
	wrote := writeUnredactedFilesWarning(&buf, files, 5)
	if !wrote {
		t.Fatal("expected a warning to be written")
	}
	out := buf.String()
	for _, want := range []string{
		"redaction incomplete", "1 of 5 file", "src/creds.go",
		"no redactor registered", "cleartext",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("warning missing %q; got:\n%s", want, out)
		}
	}
}

// TestWriteUnredactedFilesWarning_MultipleFiles: every offending file is listed,
// not just a count — an operator needs to know which originals to handle.
func TestWriteUnredactedFilesWarning_MultipleFiles(t *testing.T) {
	var buf bytes.Buffer
	files := []parallel.FileDiagnostic{
		{FilePath: "a.go", Reason: "no redactor registered for file type: .go"},
		{FilePath: "b.py", Reason: "no redactor registered for file type: .py"},
	}
	wrote := writeUnredactedFilesWarning(&buf, files, 10)
	if !wrote {
		t.Fatal("expected a warning to be written")
	}
	out := buf.String()
	if !strings.Contains(out, "2 of 10 file") {
		t.Errorf("expected '2 of 10 file' count, got:\n%s", out)
	}
	if !strings.Contains(out, "a.go") || !strings.Contains(out, "b.py") {
		t.Errorf("expected both offending files listed, got:\n%s", out)
	}
}

// TestWriteUnredactedFilesWarning_DistinctFromIncompleteCoverage keeps the two
// warnings from being confused. They mean opposite things: incomplete coverage
// says findings may be MISSING (re-scan), unredacted says the findings were
// found and reported but nothing was masked (handle the original). A single
// merged message would send the operator down the wrong path.
func TestWriteUnredactedFilesWarning_DistinctFromIncompleteCoverage(t *testing.T) {
	files := []parallel.FileDiagnostic{{FilePath: "x.go", Reason: "no redactor registered for file type: .go"}}

	var unredacted, incomplete bytes.Buffer
	writeUnredactedFilesWarning(&unredacted, files, 1)
	writeIncompleteCoverageWarning(&incomplete, files, 1)

	if unredacted.String() == incomplete.String() {
		t.Fatal("the two warnings must not be identical")
	}
	if strings.Contains(unredacted.String(), "findings may be missing") {
		t.Error("unredacted warning must not claim findings are missing; the scan was complete")
	}
	if strings.Contains(incomplete.String(), "cleartext") {
		t.Error("incomplete-coverage warning must not claim a redaction outcome")
	}
}

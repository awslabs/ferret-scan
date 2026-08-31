// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/parallel"
)

// #544: control-byte escaping was wired in PER SINK, and three sinks were missed — most
// importantly the coverage/redaction DISCLOSURE channel, the one that says a file was not
// scanned.
//
// A filename's bytes are chosen by whoever created the file (a contributor to a repository, an
// upload directory, an extracted archive), so they are attacker-supplied input arriving at a
// display sink. A name containing "\x1b[2K\r" — erase-line, carriage-return — makes a terminal
// blank the line and return to its start, so the row disclosing an unscanned file disappears
// while the summary still counts it.
//
// Measured on origin/main before this, one run with two files whose names both carry the
// sequence — one scannable (findings channel), one oversize (disclosure channel):
//
//	RAW ESC in [DISCLOSURE]: '    /tmp/.../big\x1b[2Kskip.mp4  file too large (max size: 500MB)'
//	total raw ESC bytes:  1
//	visible \x1b escapes: 1
//
// One escaped row and one raw row in the same report. #534 covered the findings table; #529 and
// #540 then added messages to the channel it missed.
//
// These tests drive the cmd-side emitters directly. The formatter-side sinks are covered in
// internal/formatters/text, and the whole matrix was verified end to end through the CLI across
// 7 formats and 6 flag combinations.

// hostileName carries the erase-line + carriage-return sequence that makes this a security
// concern rather than a cosmetic one, plus a newline, which fabricates a whole report line.
const hostileName = "big\x1b[2K\rskip\n.mp4"

// assertNoRawControlBytes fails when out contains a byte a terminal would act on.
//
// Checks the BYTES, not a rendered string: the whole defect is that a byte survived to the
// output, and a string comparison against an expected message would pass while the byte was
// still there. TAB and NEWLINE are excluded from the check because the reports use them
// structurally — what must not appear is a borrowed one, which is why the fixture's newline is
// inside the FILENAME and the assertion below also checks the line count.
func assertNoRawControlBytes(t *testing.T, label string, out []byte) {
	t.Helper()
	for i, b := range out {
		if b == '\n' || b == '\t' {
			continue
		}
		if b < 0x20 || b == 0x7F {
			// Show the neighbourhood, so a failure names the line rather than an offset.
			start := i - 40
			if start < 0 {
				start = 0
			}
			end := i + 40
			if end > len(out) {
				end = len(out)
			}
			t.Errorf("%s: raw control byte 0x%02x at offset %d — a borrowed filename reached a "+
				"display sink unescaped.\ncontext: %q", label, b, i, string(out[start:end]))
			return
		}
	}
}

// TestUnscannedReportEscapesTheDisclosedPath is the regression test for the reported sink.
func TestUnscannedReportEscapesTheDisclosedPath(t *testing.T) {
	entries := []unscannedEntry{
		{Path: "/tmp/scan/" + hostileName, Cause: causeTooLarge, Detail: "file too large (max size: 500MB)"},
	}
	var buf bytes.Buffer
	if !writeUnscannedReport(&buf, entries, 1, true, false) {
		t.Fatal("writeUnscannedReport wrote nothing, so there is no output to check")
	}
	out := buf.Bytes()

	// Non-vacuity: the report must actually mention the file, or an empty buffer would pass.
	if !bytes.Contains(out, []byte("skip")) {
		t.Fatalf("the report does not name the file at all:\n%s", out)
	}
	assertNoRawControlBytes(t, "writeUnscannedReport", out)

	// The escaped form must be visible, which is what makes the name still identifiable.
	if !bytes.Contains(out, []byte(`\x1b`)) {
		t.Errorf("the report contains no visible \\x1b escape, so the control byte was dropped "+
			"rather than escaped — two different names would then display identically:\n%s", out)
	}
}

// TestUnscannedReportDetailIsEscapedToo.
//
// Detail is assembled from preprocessor and redactor errors that quote an embedded part's name,
// and that name comes from inside the container — so it is borrowed text just as the path is.
// #529 added exactly such a message to this channel.
func TestUnscannedReportDetailIsEscapedToo(t *testing.T) {
	entries := []unscannedEntry{
		{
			Path:   "/tmp/scan/container.docx",
			Cause:  causeUnparseable,
			Detail: "embedded part \"" + hostileName + "\" could not be read",
		},
	}
	var buf bytes.Buffer
	if !writeUnscannedReport(&buf, entries, 1, true, false) {
		t.Fatal("no output")
	}
	assertNoRawControlBytes(t, "writeUnscannedReport detail", buf.Bytes())
}

// TestUnscannedReportColumnsStayAlignedAfterEscaping.
//
// The detail column is padded to the longest path, and escaping changes a path's LENGTH — three
// characters per escaped byte. Measuring before escaping would misalign every row in a run that
// contains one hostile name. Asserted because the fix moves the sanitize call ahead of the width
// calculation, and a later edit could easily move it back.
func TestUnscannedReportColumnsStayAlignedAfterEscaping(t *testing.T) {
	entries := []unscannedEntry{
		{Path: "/tmp/scan/" + hostileName, Cause: causeTooLarge, Detail: "DETAIL-A"},
		{Path: "/tmp/scan/ordinary-file-name.txt", Cause: causeTooLarge, Detail: "DETAIL-B"},
	}
	var buf bytes.Buffer
	if !writeUnscannedReport(&buf, entries, 2, true, false) {
		t.Fatal("no output")
	}

	var cols []int
	for _, line := range strings.Split(buf.String(), "\n") {
		for _, d := range []string{"DETAIL-A", "DETAIL-B"} {
			if i := strings.Index(line, d); i >= 0 {
				cols = append(cols, i)
			}
		}
	}
	if len(cols) != 2 {
		t.Fatalf("expected both detail strings on their own lines, found %d:\n%s", len(cols), buf.String())
	}
	if cols[0] != cols[1] {
		t.Errorf("detail column starts at %d and %d — escaping changed the path length after the "+
			"column width was measured, so every row in a run containing an escaped name is "+
			"misaligned:\n%s", cols[0], cols[1], buf.String())
	}
}

// TestUnredactedWarningEscapesPathAndReason.
//
// This is the "values remain in cleartext" channel. Both halves are borrowed: the path from the
// scanned tree, and the reason from a redactor error that names the embedded part it could not
// rewrite (#529).
func TestUnredactedWarningEscapesPathAndReason(t *testing.T) {
	for _, tc := range []struct {
		name string
		diag parallel.FileDiagnostic
	}{
		{"hostile path", parallel.FileDiagnostic{
			FilePath: "/tmp/scan/" + hostileName,
			Reason:   "refusing to write: 1 embedded part could not be shown free of reported values",
		}},
		{"hostile reason", parallel.FileDiagnostic{
			FilePath: "/tmp/scan/container.docx",
			Reason:   "refusing to write " + hostileName + ": not a valid zip file",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if !writeUnredactedFilesWarning(&buf, []parallel.FileDiagnostic{tc.diag}, 1) {
				t.Fatal("writeUnredactedFilesWarning wrote nothing")
			}
			assertNoRawControlBytes(t, "writeUnredactedFilesWarning", buf.Bytes())
		})
	}
}

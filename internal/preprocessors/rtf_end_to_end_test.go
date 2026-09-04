// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRTFReachesThePreprocessorAndReportsSuccess pins the four registration points a new type has to
// satisfy, because getting three of them right still produces a file reported as unscannable.
//
// Measured while building this: omitting content.Success made files_processed go 1 -> 0 and reported
// "contents do not match the .rtf format" on a well-formed document — a fourth site beyond the three
// the SVG precedent suggested. A unit test on the extractor cannot see any of that.
func TestRTFReachesThePreprocessorAndReportsSuccess(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "doc.rtf")
	// A value split across formatting runs, which is the shape a real producer emits.
	body := "{\\rtf1\\ansi\\deff0\n{\\fonttbl{\\f0 Helvetica;}}\n" +
		"\\f0\\fs24 Employee SSN: 452-11-\\f1\\b 9384\\b0\\par\nEmail: bob@example.com\\par\n}\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	tp := NewTextPreprocessor()
	if !tp.CanProcess(p) {
		t.Fatal("CanProcess said no for .rtf; the extension is not registered in supportedExtensions")
	}
	got, err := tp.Process(p)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if !got.Success {
		t.Errorf("Success is false, so the scan reports files_processed=0 and the file reads as "+
			"unscannable. Error: %q", got.Error)
	}
	if !strings.Contains(got.Text, "452-11-9384") {
		t.Errorf("the split value did not survive the preprocessor; got %q", got.Text)
	}
	if !strings.Contains(got.Text, "bob@example.com") {
		t.Errorf("second value lost; got %q", got.Text)
	}
	if strings.Contains(got.Text, `\fs24`) || strings.Contains(got.Text, "Helvetica") {
		t.Errorf("RTF control words or the font table reached the text, so the plaintext path is still "+
			"claiming this file: %q", got.Text)
	}
}

// TestAMislabelledRTFStillGetsScanned. A file named .rtf that is NOT RTF must fall back to its raw
// bytes rather than being reported as a clean scan of nothing — a silent empty result is a false
// all-clear, which is the failure mode this whole change exists to remove.
func TestAMislabelledRTFStillGetsScanned(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "notreally.rtf")
	if err := os.WriteFile(p, []byte("Just plain text. SSN: 452-11-9384\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tp := NewTextPreprocessor()
	got, err := tp.Process(p)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if !got.Success {
		t.Errorf("a mislabelled .rtf was reported as a failure; it should fall back to raw bytes. "+
			"Error: %q", got.Error)
	}
	if !strings.Contains(got.Text, "452-11-9384") {
		t.Errorf("the value in a mislabelled .rtf was lost entirely — this is a silent all-clear on a "+
			"file that does contain PII. got %q", got.Text)
	}
}

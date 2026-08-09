// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"os"
	"path/filepath"
	"testing"
)

// A 0-byte file is not a failure. It is a file with nothing in it.
//
// Every preprocessor legitimately declines an empty file, and the fall-through then
// reported "all preprocessors failed", which the CLI surfaced as:
//
//	NOT EXAMINED: 1 of 1 file — contents were never read, so findings may be missing
//
// and which made --fail-on-incomplete exit 3. All of that is false: the contents
// WERE read, there are none, and an empty file cannot hold sensitive data.
//
// It matters because false alarms are how the warning that matters becomes noise an
// operator filters out — and the warning it shares a channel with is the one that
// says a file full of PII went unexamined.

func TestEmptyFileIsCleanNotAFailure(t *testing.T) {
	dir := t.TempDir()

	// Several extensions, because routing is extension-driven and an empty file
	// must be clean whatever it claims to be.
	for _, name := range []string{"empty.csv", "empty.txt", "empty.docx", "empty.pdf", "empty.json"} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(dir, name)
			if err := os.WriteFile(p, nil, 0o600); err != nil {
				t.Fatal(err)
			}

			fr := NewFileRouter(false)
			got, err := fr.ProcessFile(p, nil)

			if err != nil {
				t.Fatalf("empty %s returned an error (%v). An empty file is not a "+
					"processing failure; reporting one produces a false 'contents were "+
					"never read' warning and makes --fail-on-incomplete exit 3.", name, err)
			}
			if got == nil {
				t.Fatalf("empty %s returned nil content with no error", name)
			}
			if got.Text != "" {
				t.Errorf("empty %s extracted %q; want empty text", name, got.Text)
			}
			if !got.Success {
				t.Errorf("empty %s reported Success=false; it succeeded, there was just "+
					"nothing in it", name)
			}
		})
	}
}

// TestNonEmptyFailureStillFails is the control.
//
// Without it, a change that made EVERY unparseable file return clean would satisfy
// the test above and look correct — while silently converting real failures into
// clean bills of health, which is the most serious defect this tool can have.
func TestNonEmptyFailureStillFails(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "corrupt.docx")
	// A zip signature the archive reader cannot open: non-empty, genuinely broken.
	if err := os.WriteFile(p, []byte("PK\x03\x04truncated-not-a-real-zip"), 0o600); err != nil {
		t.Fatal(err)
	}

	fr := NewFileRouter(false)
	if _, err := fr.ProcessFile(p, nil); err == nil {
		t.Error("a corrupt non-empty .docx was reported as processed. The empty-file " +
			"exemption must be scoped to size 0 exactly, or a truncated document reads " +
			"as scanned-and-clean.")
	}
}

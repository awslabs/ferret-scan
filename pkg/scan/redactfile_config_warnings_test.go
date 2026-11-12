// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// RedactFileResult carries the configured values the redaction could not use (#903 box 6). Measured on
// main @ 3aa380e: core.RedactFile reported the warning, scan.RedactFile dropped it, so a library caller
// whose pattern RE2 rejected got a redacted copy that looked complete, with nothing to say a value its
// config meant to mask was never looked for.
func TestRedactFileCarriesConfigWarnings(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	file := write("notes.txt", "Ticket ref: CUSTOMID-482913\n")
	bad := write("bad.yaml", `validators: {cloud_resources: {custom_patterns: ['(?<=Ticket ref: )CUSTOMID-\d{6}']}}`+"\n")
	good := write("good.yaml", `validators: {cloud_resources: {custom_patterns: ['CUSTOMID-\d{6}']}}`+"\n")
	const want = "config value validators.cloud_resources.custom_patterns[0]: not a valid RE2 regular expression: "

	res, err := RedactFile(file, RedactFileOptions{OutputDir: filepath.Join(dir, "out-bad"),
		Checks: []string{"CLOUD_RESOURCES"}, ConfigPath: bad, LogWriter: io.Discard})
	if err != nil {
		t.Fatalf("RedactFile: %v", err)
	}
	if res.ConfigWarnings == nil || len(res.ConfigWarnings.Lines) != 1 ||
		!strings.HasPrefix(res.ConfigWarnings.Lines[0], want) {
		t.Fatalf("ConfigWarnings = %+v, want one line starting %q", res.ConfigWarnings, want)
	}
	if res.RedactionCount != 0 {
		t.Errorf("RedactionCount %d: the dropped pattern cannot have masked anything", res.RedactionCount)
	}

	// The valid twin: nil, and the value it configures is masked.
	res, err = RedactFile(file, RedactFileOptions{OutputDir: filepath.Join(dir, "out-good"),
		Checks: []string{"CLOUD_RESOURCES"}, ConfigPath: good, LogWriter: io.Discard})
	if err != nil {
		t.Fatalf("RedactFile (valid twin): %v", err)
	}
	if res.ConfigWarnings != nil {
		t.Errorf("valid twin: ConfigWarnings = %+v, want nil", res.ConfigWarnings)
	}
	if res.RedactionCount != 1 {
		t.Errorf("valid twin: RedactionCount %d, want 1 (the control that the pattern is live)", res.RedactionCount)
	}

	// Still comparable with a carrier set: the pointer compares by identity.
	withWarnings := RedactFileResult{ConfigWarnings: &RedactConfigWarnings{Lines: []string{"x"}}}
	if withWarnings == (RedactFileResult{}) {
		t.Error("a result with ConfigWarnings compares equal to the zero result")
	}
}

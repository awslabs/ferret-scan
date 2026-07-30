// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package email

import "testing"

// TestProsePunctuationIsNotURLStructure is the leak this file exists for.
//
// hasURLStructureAfter treated any ':' or '/' directly after the domain as URL
// structure and analyzeContextAt returns -100 on that, zeroing the confidence and
// deleting the finding. But a colon that ends a clause is ordinary prose, and
// dropping the finding means the address is never handed to the redactor -- a file
// with no findings has no redacted output written at all, so it survives in
// cleartext.
func TestProsePunctuationIsNotURLStructure(t *testing.T) {
	v := NewValidator()

	lines := []string{
		"Escalation owner schen@acmehealth.com: paged at 02:14 UTC",
		"Contact schen@acmehealth.com: see the runbook",
		"On-call: schen@acmehealth.com:",
		"Shared mailbox jchen@acmehealth.com/ backup is monitored",
	}

	for _, line := range lines {
		t.Run(line, func(t *testing.T) {
			matches, err := v.ValidateContent(line, "oncall.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) == 0 {
				t.Fatalf("prose punctuation after the domain deleted a real email: %s", line)
			}
		})
	}
}

// TestURLStructureStillSuppressed is the precision half, and the reason the fix
// keys on what FOLLOWS the separator rather than removing the check. These are
// the shapes hasURLStructureAfter exists to reject.
func TestURLStructureStillSuppressed(t *testing.T) {
	v := NewValidator()

	lines := []string{
		"git@github.com:user/repo cloned",
		"clone git@github.com:acme/app.git",
		"ssh user@host:22 connected",
		"deploy git@host:~/deploy",
		"Shared mailbox jchen@acmehealth.com/shared is monitored",
		"url https://acme.com/u/schen@acmehealth.com/profile",
		"sftp://user@host://path",
		"host user@@backup",
	}

	for _, line := range lines {
		t.Run(line, func(t *testing.T) {
			matches, err := v.ValidateContent(line, "infra.log")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) != 0 {
				t.Errorf("a URL/URI was reported as an email: %s (got %d)", line, len(matches))
			}
		})
	}
}

// TestHasURLStructureAfter pins the helper directly. The rule is structural: a
// URI never puts whitespace between the separator and the port, path or ref it
// introduces, and prose always does (or ends the line).
func TestHasURLStructureAfter(t *testing.T) {
	cases := []struct {
		after string
		want  bool
	}{
		// URI structure: separator followed immediately by what it introduces.
		{":user/repo cloned", true},
		{":22 connected", true},
		{":5432/db", true},
		{":~/deploy", true},
		{":3000/health", true},
		{":/var/spool", true},
		{":8080", true},
		{"/shared is monitored", true},
		{"/repo.git", true},
		{"/v2/manifests", true},
		{"/.git/config", true},
		{"://path", true},
		{"@host", true},
		{`\\share\dir`, true},
		{":paged", true}, // no space: ambiguous, stays conservative

		// Prose: separator then whitespace, or separator at end of line.
		{": paged at 02:14 UTC", false},
		{": see notes", false},
		{":\tpaged", false},
		{":\n", false},
		{":  double space", false},
		{":", false},
		{"/ backup mailbox", false},

		// Ordinary email terminators.
		{", paged", false},
		{" paged", false},
		{"; escalated", false},
		{").", false},
		{" (primary)", false},

		// Degenerate input must not panic.
		{"", false},
	}

	for _, c := range cases {
		if got := hasURLStructureAfter(c.after); got != c.want {
			t.Errorf("hasURLStructureAfter(%q) = %v, want %v", c.after, got, c.want)
		}
	}
}

// TestURLStructureRedactsWhatItReports is the sink check in test form: a finding
// that is reported must carry a usable span, since that span is what the redactor
// replaces. A recovered finding with a wrong span would leak just as surely as no
// finding at all.
func TestURLStructureRedactsWhatItReports(t *testing.T) {
	v := NewValidator()

	const line = "Escalation owner schen@acmehealth.com: paged at 02:14 UTC"
	matches, err := v.ValidateContent(line, "oncall.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("no finding to check")
	}

	// The reported text must be exactly the address -- not truncated at the colon,
	// and not extended over it.
	const want = "schen@acmehealth.com"
	for _, m := range matches {
		if m.Text != want {
			t.Errorf("reported text %q, want %q -- the span drives redaction", m.Text, want)
		}
	}
}

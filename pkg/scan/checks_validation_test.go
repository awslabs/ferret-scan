// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An unrecognized check name must be an error, never "scan for nothing".
//
// normalizeChecks used to pass the caller's slice through untouched, and
// core.ParseChecksToRun's loop has no else branch, so a name it does not recognise is
// discarded silently. A caller who misspelled one got zero validators, a nil error,
// and an empty finding list indistinguishable from a clean input. Measured before:
//
//	Checks=["BOGUS_CHECK"] -> 0 findings, err=nil
//	Checks=["ADDRESS"]     -> 0 findings, err=nil   (real id: PHYSICAL_ADDRESS)
//	Checks=["ssn"]         -> 0 findings, err=nil   (case-sensitive)
//	Checks=["ALL"]         -> 0 findings, err=nil   (only lowercase "all" was the sentinel)
//	Checks=[" all"]        -> 0 findings, err=nil   (what strings.Split leaves behind)
//	Checks=["all","SSN"]   -> 1 finding             (sentinel needs a 1-element list)
//
// pkg/redact already fails closed on the same mistake ("redact: no validators
// enabled"), so this brings the sibling package into line rather than inventing a
// policy.

const validationBody = "Employee SSN: 452-11-9384\nCard: 4111 1111 1111 1111\n"

func TestUnknownCheckIsAnError(t *testing.T) {
	for _, tc := range []struct {
		name  string
		check []string
		why   string
	}{
		{"bogus", []string{"BOGUS_CHECK"}, "a name no validator answers to"},
		{"plausible ADDRESS", []string{"ADDRESS"}, "the real id is PHYSICAL_ADDRESS"},
		{"plausible CARD", []string{"CARD"}, "the real id is CREDIT_CARD"},
		{"plausible NAME", []string{"NAME"}, "the real id is PERSON_NAME"},
		{"one bad in a list", []string{"SSN", "BOGUS"}, "half a list silently dropped is worse than an error"},
		{"all mixed with names", []string{"all", "SSN"}, "the sentinel used to select only the OTHER names"},
		{"ALL mixed with names", []string{"ALL", "ssn"}, "same, in the case that previously selected nothing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := ScanText(context.Background(), validationBody, TextOptions{Checks: tc.check})
			if err == nil {
				got := 0
				if r != nil {
					got = len(r.Findings)
				}
				t.Errorf("ScanText(Checks=%v) returned nil error and %d findings.\n%s\n"+
					"Silently running zero validators reports the input CLEAN.",
					tc.check, got, tc.why)
			}
		})
	}
}

// TestEveryCheckSpellingThatShouldWorkDoes is the recall half, and it matters more.
//
// A validation gate that rejects a legitimate name is worse than the fail-open it
// replaces: it stops a scan that would have found something.
func TestEveryCheckSpellingThatShouldWorkDoes(t *testing.T) {
	// The sentinel, in every shape a caller plausibly produces.
	for _, tc := range [][]string{
		nil,
		{},
		{"all"},
		{"ALL"},
		{" all"},
		{"all "},
		{""},
		{" "},
	} {
		r, err := ScanText(context.Background(), validationBody, TextOptions{Checks: tc})
		if err != nil {
			t.Errorf("ScanText(Checks=%#v) errored: %v — all of these mean \"every validator\"", tc, err)
			continue
		}
		if len(r.Findings) < 2 {
			t.Errorf("ScanText(Checks=%#v) found %d findings, want the same as nil (>=2). "+
				"This spelling silently selected nothing.", tc, len(r.Findings))
		}
	}

	// Every canonical name, in both cases.
	names := CheckNames()
	if len(names) == 0 {
		t.Fatal("CheckNames() is empty; this test would pass vacuously")
	}
	for _, n := range names {
		for _, spelling := range []string{n, strings.ToLower(n)} {
			if _, err := ScanText(context.Background(), validationBody,
				TextOptions{Checks: []string{spelling}}); err != nil {
				t.Errorf("ScanText(Checks=[%q]) rejected a name CheckNames() publishes: %v", spelling, err)
			}
		}
	}

	// And the whole published list at once.
	if _, err := ScanText(context.Background(), validationBody, TextOptions{Checks: names}); err != nil {
		t.Errorf("the full CheckNames() list was rejected: %v", err)
	}
}

// TestLowercaseCheckActuallySelectsTheValidator — normalizing must not be cosmetic.
//
// Accepting "ssn" without upper-casing it would pass the error-path test above while
// still selecting nothing, so assert the finding comes back.
func TestLowercaseCheckActuallySelectsTheValidator(t *testing.T) {
	upper, err := ScanText(context.Background(), validationBody, TextOptions{Checks: []string{"SSN"}})
	if err != nil {
		t.Fatal(err)
	}
	lower, err := ScanText(context.Background(), validationBody, TextOptions{Checks: []string{"ssn"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(upper.Findings) == 0 {
		t.Fatal(`Checks=["SSN"] found nothing; the fixture is broken`)
	}
	if len(lower.Findings) != len(upper.Findings) {
		t.Errorf(`Checks=["ssn"] found %d findings but ["SSN"] found %d: the name was accepted `+
			`but not canonicalized, so it still selects nothing`, len(lower.Findings), len(upper.Findings))
	}
}

// TestRedactFileRejectsUnknownCheckBeforeWriting is THE SINK, and the reason this is
// a leak rather than a nuisance.
//
// Measured before this change, with Checks=["BOGUS_CHECK"]:
//
//	err                            = nil
//	RedactionCount                 = 0
//	output byte-identical to input = true
//	cleartext SSN in output file   = TRUE
//
// The API's own doc comment describes that path as the redacted copy. A caller has
// nothing to branch on — RedactionCount 0 is also what a genuinely clean input
// produces — so they would hand the file on believing it was scrubbed.
func TestRedactFileRejectsUnknownCheckBeforeWriting(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.txt")
	if err := os.WriteFile(in, []byte(validationBody), 0o600); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "redacted")

	res, err := RedactFile(in, RedactFileOptions{OutputDir: outDir, Checks: []string{"BOGUS_CHECK"}})
	if err == nil {
		count := -1
		if res != nil {
			count = res.RedactionCount
		}
		t.Errorf("RedactFile(Checks=[BOGUS_CHECK]) returned nil error (RedactionCount=%d). "+
			"It previously wrote an output file byte-identical to the input, with the SSN "+
			"in cleartext, in a path the API calls the redacted copy.", count)
	}

	// Nothing may be written on the rejected path: a file that exists and is
	// unredacted is worse than no file, because the caller can ship it.
	var written []string
	_ = filepath.Walk(outDir, func(p string, fi os.FileInfo, walkErr error) error {
		if walkErr == nil && fi != nil && !fi.IsDir() {
			written = append(written, p)
		}
		return nil
	})
	for _, p := range written {
		b, readErr := os.ReadFile(p)
		if readErr != nil {
			continue
		}
		if strings.Contains(string(b), "452-11-9384") {
			t.Errorf("a file was written at %s containing the cleartext SSN despite the "+
				"rejected check name", p)
		}
	}
	if len(written) > 0 {
		t.Errorf("RedactFile wrote %d file(s) on the error path: %v", len(written), written)
	}
}

// TestRedactFileStillWorksWithAValidCheck — the fix must not break redaction.
func TestRedactFileStillWorksWithAValidCheck(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.txt")
	if err := os.WriteFile(in, []byte(validationBody), 0o600); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "redacted")

	for _, checks := range [][]string{nil, {"SSN"}, {"ssn"}, {"all"}} {
		res, err := RedactFile(in, RedactFileOptions{OutputDir: outDir, Checks: checks})
		if err != nil {
			t.Errorf("RedactFile(Checks=%#v) errored: %v", checks, err)
			continue
		}
		if res == nil || res.RedactionCount == 0 {
			t.Errorf("RedactFile(Checks=%#v) reported no redactions on content holding an SSN", checks)
			continue
		}
		var sawRedacted, sawCleartext bool
		_ = filepath.Walk(outDir, func(p string, fi os.FileInfo, walkErr error) error {
			if walkErr != nil || fi == nil || fi.IsDir() {
				return nil
			}
			b, readErr := os.ReadFile(p)
			if readErr != nil {
				return nil
			}
			if strings.Contains(string(b), "452-11-9384") {
				sawCleartext = true
			}
			if strings.Contains(string(b), "*") {
				sawRedacted = true
			}
			return nil
		})
		if sawCleartext {
			t.Errorf("Checks=%#v: the redacted output still contains the cleartext SSN", checks)
		}
		if !sawRedacted {
			t.Errorf("Checks=%#v: no redaction token found in the output", checks)
		}
	}
}

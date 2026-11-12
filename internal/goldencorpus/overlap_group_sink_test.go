// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package goldencorpus

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/olefixture"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// TestOverlapGroupSinkEveryFormat drives the issue's lines through the REAL file pipeline
// (core.RedactFile: scan, route, redact, verify) in every format a writer exists for and under every
// strategy, and asserts the artifact a user would hand on holds no byte of any member of an overlap
// group. #773 measured all three writers leaking differently on these lines: .txt stranded the head
// of the earlier span, .docx the tail of the later one, and legacy .doc/.xls/.ppt -- which had no
// overlap pass at all -- leaked even containment ("100 ****************** Blvd").
//
// The whole-value residue checks could not catch any of it: a partly rewritten value is no longer the
// value. So the assertion here is on the fragments a stranded member leaves.
//
// Every group is between two GENUINE findings, so a detector fix that stops a false positive cannot
// silently empty a case: a titled name read two ways (partial), a card inside its own track frame
// (contained), PASSPORT and SSN on the same digits (identical). The lines #773 used, a street read as a
// name and a list read as `Surname, Given`, were the false positives #935 and #936 remove.
//
// All values synthetic: Jane Ann Doe is the placeholder name and the UTF-8 names repo fixtures, the
// card has a computed Luhn digit, 512010001 is area 512.
func TestOverlapGroupSinkEveryFormat(t *testing.T) {
	var padded []string
	for i := 1; i <= 11; i++ {
		padded = append(padded, fmt.Sprintf("Contact %d: user%d@example.com", i, i))
	}
	cases := []struct {
		name      string
		lines     []string
		checks    []string
		forbidden []string // fragments of a member that must not survive
	}{
		// "Dr. Jane Ann" and "Jane Ann Doe" cross: the title's head and the surname's tail are each
		// outside the other member. synthetic keeps the title and draws "First M. Last" from the name
		// data, so the fragments are whole tokens it does not rebuild: "Ann" alone would match a drawn
		// "Anna". shortcut: a draw of exactly "Jane" (1 of 5,301 first names) or of the one last name
		// starting "Doe" (1 of 2,333) fails this subtest under synthetic; measured 1 failure in 400
		// synthetic runs. Upgrade (assert on the rendered tokens) if it flakes in CI.
		{"titled", []string{"Signed: Dr. Jane Ann Doe"},
			[]string{"PERSON_NAME"}, []string{"Jane Ann", "Ann Doe", "Jane ", " Doe"}},
		// synthetic keeps the PAN's issuer prefix by design (cardDigits), so the forbidden runs start after it.
		{"track", []string{"Track 1: %B4532015112830366^DOE/JANE^2912101000000000000000?"},
			[]string{"CREDIT_CARD"}, []string{"015112830366", "DOE/JANE", "29121010"}},
		{"names", []string{"Dr. Renée Müller García signed"},
			[]string{"PERSON_NAME"}, []string{"Renée", "Müller", "García"}},
		// 13 findings: above sort.Slice's insertion-sort threshold, where the SSN rendering used to win.
		{"passport13", append(append([]string(nil), padded...), "Passport number: 512010001"),
			[]string{"EMAIL", "PASSPORT", "SSN"}, []string{"0001", "512010"}},
	}
	formats := []string{".txt", ".docx", ".doc", ".xls", ".ppt"}
	strategies := []string{"simple", "format_preserving", "synthetic"}

	for _, c := range cases {
		for _, ext := range formats {
			if c.name == "names" && (ext == ".doc" || ext == ".xls" || ext == ".ppt") {
				// The issue's criterion for this line is .txt and .docx: a legacy body stream written as raw
				// UTF-8 is not decoded as such by the legacy extractor, so the names are never reported there.
				continue
			}
			for _, st := range strategies {
				t.Run(c.name+ext+"/"+st, func(t *testing.T) {
					dir := t.TempDir()
					in := filepath.Join(dir, "in"+ext)
					if err := os.WriteFile(in, overlapFixture(t, ext, c.lines), 0o600); err != nil {
						t.Fatal(err)
					}
					res, err := core.RedactFile(core.RedactConfig{
						FilePath: in, OutputDir: filepath.Join(dir, "out"), Strategy: st, Checks: c.checks,
						Config: config.LoadConfigOrDefault(""), LogWriter: io.Discard,
					})
					if st == "synthetic" && legacyOffice(ext) {
						// Legacy Office is rewritten in place at each value's own byte length, so it does
						// not offer synthetic, as the redaction guide says: the file is refused, naming the
						// strategy, and nothing is written (#863). It used to be written with a mask.
						if err == nil || !strings.Contains(err.Error(), "not synthetic") {
							t.Fatalf("RedactFile(%s, synthetic) = %v, want a refusal naming synthetic", ext, err)
						}
						if found := findRedactedArtifact(t, filepath.Join(dir, "out")); found != "" {
							t.Fatalf("a refused file was written at %s", found)
						}
						return
					}
					if err != nil {
						t.Fatalf("RedactFile: %v", err)
					}
					if len(res.Matches) == 0 {
						t.Fatalf("the fixture reported nothing; the case is not testing the overlap")
					}
					grouped := false
					for _, g := range redactors.ResolveOverlaps(res.Matches) {
						grouped = grouped || g.IsGroup()
					}
					if !grouped {
						t.Fatalf("the fixture's %d findings hold no overlap group; the case is not testing the overlap", len(res.Matches))
					}
					out := res.RedactedFilePath
					if out == "" {
						out = findRedactedArtifact(t, filepath.Join(dir, "out"))
					}
					var all []byte
					for _, body := range readAllParts(t, out) {
						all = append(all, body...)
					}
					for _, f := range c.forbidden {
						if bytes.Contains(all, []byte(f)) {
							t.Errorf("%q survived in the redacted %s (%s)", f, ext, st)
						}
					}
				})
			}
		}
	}
}

// legacyOffice reports whether ext is one of the legacy compound-file formats.
func legacyOffice(ext string) bool { return ext == ".doc" || ext == ".xls" || ext == ".ppt" }

// overlapFixture writes the lines in the given format: text, a one-paragraph-per-line .docx, or the
// main stream of a legacy compound file.
func overlapFixture(t *testing.T, ext string, lines []string) []byte {
	t.Helper()
	switch ext {
	case ".txt":
		return []byte(strings.Join(lines, "\n") + "\n")
	case ".docx":
		return BuildDOCX("", "", lines)
	case ".doc":
		return olefixture.LegacyDoc(strings.Join(lines, "\r")+"\r", nil)
	case ".xls":
		return olefixture.MustBuild([]olefixture.Stream{{Name: olefixture.StreamWorkbook, Data: []byte(strings.Join(lines, "\r") + "\r")}})
	case ".ppt":
		return olefixture.MustBuild([]olefixture.Stream{{Name: olefixture.StreamPowerPoint, Data: []byte(strings.Join(lines, "\r") + "\r")}})
	}
	t.Fatalf("no fixture for %s", ext)
	return nil
}

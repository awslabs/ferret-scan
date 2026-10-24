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
// All values synthetic: the names and addresses are repo fixtures, 512010001 is area 512.
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
		{"residence", []string{"Residence: 77 August Lane, Boise ID 83702"},
			[]string{"PHYSICAL_ADDRESS", "PERSON_NAME"}, []string{"77 August", "August Lane", "Lane,", ", Boise", "Boise ID"}},
		{"mlk", []string{"Located at 100 Martin Luther King Blvd"},
			[]string{"PHYSICAL_ADDRESS", "PERSON_NAME"}, []string{"at 100", "Martin", "King Blvd", "* Blvd"}},
		{"names", []string{"Renée Müller, José García, François Lefèvre"},
			[]string{"PERSON_NAME"}, []string{"Renée", "José", "García"}},
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
					if err != nil {
						t.Fatalf("RedactFile: %v", err)
					}
					if len(res.Matches) == 0 {
						t.Fatalf("the fixture reported nothing; the case is not testing the overlap")
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

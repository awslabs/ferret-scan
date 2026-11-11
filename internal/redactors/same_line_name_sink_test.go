// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors_test

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/goldencorpus"
	"github.com/awslabs/ferret-scan/v2/internal/olefixture"
)

// TestSameLineBareAndTitledNameSink is #966's sink check. A name that appears twice on one
// line, once bare and once inside a longer match ("Dr. John Smith"), used to be reported
// once: deduplicateMatches compared TEXTS, so the bare occurrence was dropped as "contained"
// in the longer match although it sat elsewhere on the line, and it survived redaction in
// clear under every strategy and in every format, with no warning. Driven through the real
// pipeline (core.RedactFile) in every format a writer exists for and under every strategy,
// asserting the artifact a user hands on holds no copy of either name.
//
// All values synthetic (the issue's fixture).
func TestSameLineBareAndTitledNameSink(t *testing.T) {
	forbidden := []string{"John Smith", "Maria Garcia"}

	// The issue's fixture; line 3 is its control (one occurrence, clean on main too).
	sameLineSink(t, "bare_first", []string{
		"Signed by John Smith, witnessed by Dr. John Smith.",
		"Approved by Maria Garcia; countersigned by Ms. Maria Garcia on Monday.",
		"Control: witnessed by Dr. John Smith only.",
	}, forbidden, false)

	// The titled occurrence FIRST. The bare name is now reported, and .txt is fully masked
	// (its completeness sweep removes every copy of a reported value). The OOXML and legacy
	// writers place a reported value on its first occurrence in the line, which here is the
	// one inside "Dr. John Smith", so the overlap pass folds it into that group and the bare
	// copy is not written; their residue floor then REFUSES the file, naming the type. That
	// is a disclosed refusal where main wrote the name in clear and reported success, and it
	// is pinned here so that a fix to the placement (outside this package's dedup, see #966)
	// has to flip it deliberately: allowRefusal is the only thing it may relax.
	sameLineSink(t, "titled_first", []string{
		"Witnessed by Dr. John Smith, signed by John Smith.",
		"Countersigned by Ms. Maria Garcia; approved by Maria Garcia on Monday.",
	}, forbidden, true)

	// Control: the same name twice, bare both times, is one finding and fully masked.
	sameLineSink(t, "repeated_bare", []string{
		"Signed by John Smith and again by John Smith today.",
	}, forbidden, false)
}

// sameLineSink redacts lines in every format and strategy and fails on any surviving copy of a
// forbidden value. With allowRefusal, a non-.txt format may instead refuse the file, provided
// it writes nothing: never a silent survivor.
func sameLineSink(t *testing.T, name string, lines, forbidden []string, allowRefusal bool) {
	for _, ext := range []string{".txt", ".docx", ".doc", ".xls", ".ppt"} {
		for _, st := range []string{"simple", "format_preserving", "synthetic"} {
			t.Run(name+ext+"/"+st, func(t *testing.T) {
				legacy := ext == ".doc" || ext == ".xls" || ext == ".ppt"
				if legacy && st == "synthetic" {
					t.Skip("legacy Office refuses synthetic (#863); TestOverlapGroupSinkEveryFormat pins the refusal")
				}
				dir := t.TempDir()
				in := filepath.Join(dir, "in"+ext)
				if err := os.WriteFile(in, sameLineFixture(t, ext, lines), 0o600); err != nil {
					t.Fatal(err)
				}
				outDir := filepath.Join(dir, "out")
				res, err := core.RedactFile(core.RedactConfig{
					FilePath: in, OutputDir: outDir, Strategy: st,
					Checks: []string{"PERSON_NAME"}, Config: config.LoadConfigOrDefault(""), LogWriter: io.Discard,
				})
				if err != nil {
					if !allowRefusal || ext == ".txt" || !strings.Contains(err.Error(), "PERSON_NAME") {
						t.Fatalf("RedactFile: %v", err)
					}
					if found := anyFile(t, outDir); found != "" {
						t.Fatalf("a refused file was written at %s", found)
					}
					return
				}
				if len(res.Matches) == 0 {
					t.Fatal("the fixture reported nothing; the case is not testing the dedup")
				}
				out := res.RedactedFilePath
				if out == "" {
					out = anyFile(t, outDir)
				}
				if out == "" {
					t.Fatalf("no redacted artifact under %s", outDir)
				}
				body := allParts(t, out)
				for _, f := range forbidden {
					if n := bytes.Count(body, []byte(f)); n > 0 {
						t.Errorf("%q survived %d time(s) in the redacted %s (%s)", f, n, ext, st)
					}
				}
			})
		}
	}
}

// sameLineFixture writes the lines as text, a one-paragraph-per-line .docx, or the main stream
// of a legacy compound file (the shapes TestOverlapGroupSinkEveryFormat uses).
func sameLineFixture(t *testing.T, ext string, lines []string) []byte {
	t.Helper()
	switch ext {
	case ".txt":
		return []byte(strings.Join(lines, "\n") + "\n")
	case ".docx":
		return goldencorpus.BuildDOCX("", "", lines)
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

// allParts returns the artifact's bytes, with every ZIP entry DECOMPRESSED for a container:
// grepping compressed bytes finds nothing and looks like a pass.
func allParts(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	zr, zerr := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if zerr != nil {
		return raw
	}
	var all []byte
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open %s: %v", f.Name, err)
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("read %s: %v", f.Name, err)
		}
		all = append(all, b...)
	}
	return all
}

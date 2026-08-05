// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scorecorpus

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/core"
)

// flattenContainer returns all text inside a redacted artifact.
//
// A container hides its payload: grepping the .docx bytes for an SSN finds nothing
// even when the SSN is present, because the parts are DEFLATE-compressed. So the
// only honest way to ask "did this value survive?" is to open the ZIP and read
// every part. A test that greps the raw file would pass on a live leak.
func flattenContainer(t *testing.T, path string) string {
	t.Helper()

	zr, err := zip.OpenReader(path)
	if err != nil {
		// Not a ZIP: read it as flat bytes.
		b, rerr := os.ReadFile(path) //nolint:gosec // test-controlled path
		if rerr != nil {
			t.Fatalf("read redacted artifact: %v", rerr)
		}
		return string(b)
	}
	defer func() { _ = zr.Close() }()

	var all strings.Builder
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open part %s: %v", f.Name, err)
		}
		b, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatalf("read part %s: %v", f.Name, err)
		}
		all.WriteString(f.Name)
		all.WriteString("\n")
		all.Write(b)
		all.WriteString("\n")
	}
	return all.String()
}

// TestContainerResidue is the half of the gate that a detection score cannot
// provide.
//
// Measured: reverting PR #250 leaves every detection number bit-for-bit identical
// (TP 111, FN 0, precision 0.7097) while a labelled SSN survives verbatim inside
// word/document.xml. A precision/recall gate reports PASS on a shipped cleartext
// leak; this test is what fails.
func TestContainerResidue(t *testing.T) {
	cfg, err := config.LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	for _, fc := range ContainerCases() {
		for _, strategy := range sinkStrategies {
			t.Run(fc.Name+"/"+strategy, func(t *testing.T) {
				dir := t.TempDir()
				src := filepath.Join(dir, fc.Basename)
				if err := os.WriteFile(src, fc.Build(), 0o600); err != nil {
					t.Fatalf("write fixture: %v", err)
				}

				outDir := filepath.Join(dir, "out")
				if err := os.MkdirAll(outDir, 0o700); err != nil {
					t.Fatalf("mkdir: %v", err)
				}

				res, err := core.RedactFile(core.RedactConfig{
					FilePath:  src,
					OutputDir: outDir,
					Strategy:  strategy,
					Checks:    fc.Checks,
					Config:    cfg,
					LogWriter: io.Discard,
				})
				if err != nil {
					t.Fatalf("RedactFile: %v", err)
				}

				flat := flattenContainer(t, res.RedactedFilePath)

				for _, leak := range fc.Leaks {
					if strings.Contains(flat, leak) {
						// Payload-free: name the case and the part, never the value.
						part := "unknown part"
						for _, p := range strings.Split(flat, "\n") {
							if strings.Contains(p, "/") && strings.HasSuffix(p, ".xml") {
								part = p
							}
						}
						t.Errorf("%s (%s): a labelled value SURVIVES inside the redacted "+
							"container (last part seen: %s).\n"+
							"Detection is unchanged when this breaks, so no precision or "+
							"recall number moves — the artifact is the only witness. This is "+
							"the PR #250 regression shape.",
							fc.Name, strategy, part)
					}
				}
			})
		}
	}
}

// TestContainerFixtureIsWellFormed proves the fixture is a real container that
// actually carries the value, so a PASS above means "redacted", not "the SSN was
// never there".
//
// This is the vacuity guard for the test above: a fixture that silently built an
// empty or unroutable document would make TestContainerResidue pass forever.
func TestContainerFixtureIsWellFormed(t *testing.T) {
	for _, fc := range ContainerCases() {
		raw := fc.Build()
		if len(raw) == 0 {
			t.Fatalf("%s: builder produced no bytes", fc.Name)
		}

		dir := t.TempDir()
		src := filepath.Join(dir, fc.Basename)
		if err := os.WriteFile(src, raw, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}

		// The unredacted document must contain the value, in a real ZIP part.
		flat := flattenContainer(t, src)
		for _, leak := range fc.Leaks {
			if !strings.Contains(flat, leak) {
				t.Fatalf("%s: the fixture does not contain the value it is supposed to "+
					"protect; TestContainerResidue would pass vacuously", fc.Name)
			}
		}
		if !strings.Contains(flat, "word/document.xml") {
			t.Errorf("%s: no word/document.xml part, so this does not route as a .docx", fc.Name)
		}
		if !strings.Contains(flat, "docProps/core.xml") {
			t.Errorf("%s: no docProps/core.xml part, so the metadata-vs-body interaction "+
				"that PR #250 fixed is not exercised", fc.Name)
		}

		// And the scanner must actually FIND it, or a redaction failure would be
		// indistinguishable from a detection failure.
		cfg, err := config.LoadConfig("")
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		// EnablePreprocessors is REQUIRED for a container: without it ScanFile returns
		// "file type not supported for processing" and never opens the ZIP. Omitting it
		// is how a container case silently becomes a no-op, which is precisely what this
		// well-formedness test exists to catch — it caught it here.
		res, err := core.ScanFile(core.ScanConfig{
			FilePath:            src,
			Checks:              fc.Checks,
			Config:              cfg,
			EnablePreprocessors: true,
			LogWriter:           io.Discard,
		})
		if err != nil {
			t.Fatalf("%s: ScanFile: %v", fc.Name, err)
		}
		found := 0
		for _, m := range res.Matches {
			for _, leak := range fc.Leaks {
				if strings.Contains(m.Text, leak) {
					found++
				}
			}
		}
		if found == 0 {
			t.Errorf("%s: the scanner does not detect the labelled value in the container, "+
				"so the residue assertion cannot distinguish a redaction bug from a "+
				"detection bug", fc.Name)
		}
	}
}

// TestContainerCaseWouldCatchTheLeak pins the geometry that makes the container
// case meaningful.
//
// Span subsumption only fires when the metadata span numerically CONTAINS the body
// span and is strictly wider. My first attempt used the author "Jane Smith", which
// is too short: the case PASSED under the reverted-PR-#250 mutation, i.e. it was
// vacuous and would have shipped a gate that certified a cleartext leak.
//
// This test fails if someone shortens the author or moves the SSN, instead of
// letting the container case quietly stop testing anything.
func TestContainerCaseWouldCatchTheLeak(t *testing.T) {
	authorLine := containerAuthorPfx + containerAuthor

	ssnStart := strings.Index(containerBodyLine, containerSSN)
	ssnEnd := ssnStart + len(containerSSN)
	authorStart := strings.Index(authorLine, containerAuthor)
	authorEnd := authorStart + len(containerAuthor)

	if ssnStart < 0 || authorStart < 0 {
		t.Fatalf("fixture strings are inconsistent: ssnStart=%d authorStart=%d", ssnStart, authorStart)
	}
	if !(authorStart <= ssnStart && ssnEnd <= authorEnd && (authorEnd-authorStart) > (ssnEnd-ssnStart)) {
		t.Fatalf("containment lost: the author span [%d,%d) must strictly contain the SSN "+
			"span [%d,%d), or TestContainerResidue passes no matter what the redactor does. "+
			"Measured: with a short author the case did NOT reproduce the PR #250 leak.",
			authorStart, authorEnd, ssnStart, ssnEnd)
	}

	// And the value the case claims to protect must be the one actually planted.
	if !strings.Contains(containerBodyLine, containerSSN) {
		t.Fatalf("the body line does not contain the SSN it is labelled with")
	}
	for _, fc := range ContainerCases() {
		for _, leak := range fc.Leaks {
			if leak != containerSSN {
				t.Errorf("%s: Leaks lists %q but the fixture plants %q; the assertion would "+
					"search for a value that is not there", fc.Name, leak, containerSSN)
			}
		}
	}
}

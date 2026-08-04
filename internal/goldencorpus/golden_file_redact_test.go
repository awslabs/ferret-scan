// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package goldencorpus

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
)

// TestGoldenFileRedactionSink closes the coverage gap that let every container
// redaction leak of the last several fixes hide.
//
// TestGoldenRedact iterates Cases (in-memory strings) through redact.Engine,
// whose Request takes Text — there is no file path, so no container ever reaches
// it. FileCases, which is where the .docx/.xlsx/.wav cases live, therefore had
// ZERO redaction coverage: `grep -ci redact` over the FileCases test path
// returned 0. Every leak in that area was found by hand, by unzipping an output
// and grepping the parts, and fixed the same way:
//
//   - #250: ResolveOverlaps compared offsets across different source texts, so a
//     metadata match silently dropped a body SSN from redaction
//   - the Office redactor writing a package with every part byte-identical
//   - a .docx inside a .docx whose inner body was never scanned
//
// None of those had a test that would have failed. This one would.
//
// It asserts the SINK, not a snapshot. A golden text file records what the
// formatter said; this checks the thing that actually matters — whether the
// sensitive bytes survive in the artifact handed to a third party. And it looks
// INSIDE containers, because an OOXML part is deflated: grepping the .docx
// bytes finds nothing whether or not redaction worked.
func TestGoldenFileRedactionSink(t *testing.T) {
	for _, fc := range FileCases {
		fc := fc
		t.Run(fc.Name, func(t *testing.T) {
			tmpDir := caseTempDir(t, fc)
			path := writeFixture(t, tmpDir, fc)

			outDir := filepath.Join(tmpDir, "redacted")

			// core.RedactFile, not core.ScanFile. ScanFile deliberately passes a
			// nil redaction manager and leaves the wiring to its caller (its doc
			// comment says so), so driving redaction through it silently produces
			// no artifact at all — which is exactly what happened on the first
			// version of this test: 11 of 12 cases "failed" for that reason rather
			// than for any real defect. RedactFile is the file-level entry point
			// that mirrors the CLI's wiring.
			res, err := core.RedactFile(core.RedactConfig{
				FilePath:  path,
				OutputDir: outDir,
				Strategy:  "simple",
				Checks:    fc.Checks,
				Config:    config.LoadConfigOrDefault(""),
				LogWriter: io.Discard,
			})
			if err != nil {
				// A file type with no registered redactor is a DISCLOSED
				// limitation, not a silent leak: the CLI already emits
				// "WARNING: redaction incomplete — ... the original values remain
				// in cleartext" and names the file. Verified on a .go file. So
				// there is nothing for this test to assert; the honesty of that
				// warning is covered by the unredacted-files diagnostic.
				//
				// Skipping keeps the sink assertion focused on the case it exists
				// for: a redactor that RAN and still left the value behind.
				if strings.Contains(err.Error(), "no redactor registered") {
					t.Skipf("no redactor for this file type (%v); the CLI discloses this as "+
						"redaction-incomplete rather than failing silently", err)
				}
				t.Fatalf("RedactFile for case %q: %v", fc.Name, err)
			}

			// Collect the matched values the scan reported. These are exactly the
			// strings the tool claims to have found, so they are exactly the
			// strings that must not survive in the redacted artifact. Deriving
			// them from the scan rather than hardcoding them keeps the assertion
			// honest as the corpus grows.
			var reported []string
			for _, m := range res.Matches {
				if v := strings.TrimSpace(m.Text); len(v) >= minRedactableLen {
					reported = append(reported, v)
				}
			}

			// The negative case legitimately has nothing to redact; it still
			// exercises "redaction is a no-op and does not corrupt the file".
			if len(reported) == 0 {
				if len(res.Matches) == 0 {
					return
				}
				t.Skipf("case reported %d findings but none long enough to assert on", len(res.Matches))
			}

			redacted := res.RedactedFilePath
			if redacted == "" {
				redacted = findRedactedArtifact(t, outDir)
			}
			if redacted == "" {
				t.Fatalf("case %q reported %d findings but produced NO redacted artifact under %s — "+
					"a scan that finds sensitive data and writes no redacted copy has silently "+
					"failed at the only job redaction has", fc.Name, len(reported), outDir)
			}

			// Check every part, decompressed. This is the container-format trap:
			// an OOXML part is deflated inside the package, so grepping the .docx
			// bytes finds nothing whether or not redaction worked.
			parts := readAllParts(t, redacted)
			if len(parts) == 0 {
				t.Fatalf("read no content at all from the redacted artifact %s", redacted)
			}
			for _, v := range reported {
				for name, body := range parts {
					if !bytes.Contains(body, []byte(v)) {
						continue
					}
					{
						t.Errorf("case %q: a REPORTED finding survives in the redacted output\n"+
							"  artifact: %s\n"+
							"  part:     %s\n"+
							"  value:    %d bytes, type withheld\n"+
							"The scan named this value, so redaction was asked to remove it and did "+
							"not. That is a cleartext leak in the artifact a user hands to someone "+
							"else, and it is the exact shape of the container leaks fixed by hand "+
							"in #250 and the Office repackaging fixes.",
							fc.Name, redacted, name, len(v))
					}
				}
			}
		})
	}
}

// findRedactedArtifact locates the redacted copy under outDir. The output layout
// mirrors the input path, so the file can be nested arbitrarily deep; find it by
// walking rather than by reconstructing the expected path.
func findRedactedArtifact(t *testing.T, outDir string) string {
	t.Helper()
	var found string
	_ = filepath.Walk(outDir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() || found != "" {
			return nil //nolint:nilerr // a missing outDir means "no artifact", handled by the caller
		}
		found = p
		return nil
	})
	return found
}

// readAllParts returns the artifact's content keyed by part name. For a ZIP
// container (docx/xlsx/pptx) that is every entry, DECOMPRESSED; for anything
// else it is the file itself under the key "<file>".
//
// Reading the parts is the whole point. A redaction bug that leaves a part
// byte-identical is invisible to a whole-file comparison, because zip
// re-compression changes the container bytes either way — which is how one of
// these leaks survived an md5 check that reported "differs".
func readAllParts(t *testing.T, path string) map[string][]byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read redacted artifact %s: %v", path, err)
	}

	out := map[string][]byte{}
	zr, zerr := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if zerr != nil {
		// Not a container: the file's own bytes are the only "part".
		out["<file>"] = raw
		return out
	}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("open zip entry %s in %s: %v", f.Name, path, err)
		}
		body, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("read zip entry %s in %s: %v", f.Name, path, err)
		}
		out[f.Name] = body
	}
	return out
}

// minRedactableLen skips values too short to assert on: a 1-2 character match
// would collide with ordinary bytes anywhere in a container's XML and produce a
// false failure.
const minRedactableLen = 6

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scorecorpus

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/core"
)

// writeUnscannedFixture materialises a case and returns its path.
func writeUnscannedFixture(t *testing.T, dir string, c UnscannedCase) string {
	t.Helper()

	p := filepath.Join(dir, c.Basename)
	if err := os.WriteFile(p, c.Build(), 0o600); err != nil {
		t.Fatalf("%s: write fixture: %v", c.Name, err)
	}
	if c.Unreadable {
		if err := os.Chmod(p, 0o000); err != nil {
			t.Fatalf("%s: chmod: %v", c.Name, err)
		}
		// Prove the chmod took effect. Without this the case can pass because the
		// file was READABLE, which is the opposite of what it tests.
		if _, err := os.ReadFile(p); err == nil { //nolint:gosec // fixture path
			t.Fatalf("%s: fixture is still readable after chmod 0o000, so this case "+
				"would pass for the wrong reason", c.Name)
		}
		// Restore write permission so t.TempDir() cleanup can remove it; without
		// this a 0o000 fixture leaks a directory on some platforms.
		t.Cleanup(func() { _ = os.Chmod(p, 0o600) })
	}
	return p
}

// TestUnscannedFilesAreNotReportedClean — the library must admit it did not read a
// file.
//
// "Admit" means either ScanResult.Incomplete is set OR ScanFile returns an error.
// Both are accepted because the two failure modes take genuinely different paths
// today: measured, an unreadable file errors out with "file type not supported for
// processing" (itself a misleading message for a permission problem, since .txt IS
// supported), while a corrupt or empty one returns successfully with Incomplete set.
//
// Accepting either is deliberate rather than lax: the assertion is about the
// OUTCOME the operator depends on — "this file was not examined" — not about which
// internal path produced it. A later change that unifies the two paths must not have
// to rewrite this test.
func TestUnscannedFilesAreNotReportedClean(t *testing.T) {
	cfg, err := config.LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	for _, c := range UnscannedCases {
		t.Run(c.Name, func(t *testing.T) {
			if runtimeSkipsMode(t, c) {
				return
			}

			path := writeUnscannedFixture(t, t.TempDir(), c)

			res, scanErr := core.ScanFile(core.ScanConfig{
				FilePath:            path,
				Checks:              c.Checks,
				Config:              cfg,
				EnablePreprocessors: true,
				LogWriter:           io.Discard,
			})

			admitted := scanErr != nil || (res != nil && res.Incomplete)

			switch {
			case c.MustNotBeReportedClean:
				if !admitted {
					t.Errorf("%s was NOT examined, yet the scan reported success with no "+
						"incomplete signal (err=%v, incomplete=%v). A file the tool never read "+
						"must never be indistinguishable from a file that was read and found "+
						"clean — a reviewer merges the change believing it was checked.",
						c.Name, scanErr, res != nil && res.Incomplete)
				}

			case c.IsGenuinelyClean:
				if !admitted {
					// The correct outcome. Nothing to assert beyond "no false alarm".
					return
				}
				t.Errorf("%s is genuinely clean but was reported as not-scanned "+
					"(err=%v, incomplete=%v). False alarms turn the warning that matters "+
					"into noise operators filter out.", c.Name, scanErr, res != nil && res.Incomplete)

			default:
				// The control: must scan, must not be flagged, must find something.
				if admitted {
					t.Errorf("control case %s should scan normally but was flagged "+
						"(err=%v, incomplete=%v)", c.Name, scanErr, res != nil && res.Incomplete)
					return
				}
				if len(res.Matches) == 0 {
					t.Errorf("control case %s produced no findings; the other cases in this "+
						"test would then pass vacuously — a change marking EVERY file unscanned "+
						"would look like success", c.Name)
				}
			}
		})
	}
}

// TestUnscannedFilesAreNotReportedCleanByTheCLI is the same contract at the
// EXECUTABLE layer, which is what a CI pipeline actually consumes.
//
// The library test above proves the information exists. This one asks the harder
// question: can an operator SEE it?
//
// Measured at HEAD, for both files that cannot be read:
//
//	stdout is an OBJECT carrying stats.files_not_examined = 1, results = []
//	rc = 0, plus a NOT FULLY EXAMINED block on stderr
//
// So machine output CAN now distinguish "nothing found" from "never looked", and this
// test asserts it. The prose here previously said the opposite — "rc=0 and `[]` on
// stdout for all three failure modes ... cannot distinguish" — which was true when it
// was written and stopped being true in 33b1f44 (#316). Stale prose in a test is worse
// than none: these are the sentences that get quoted, and a reader could reasonably
// re-file the fixed issue (#385).
//
// One caveat that is still accurate: stdout carries the COUNT, not the file list.
// Per-file detail remains stderr-only. The count is enough to tell the two situations
// apart, which is what the removed branch claimed was impossible.
//
// rc is still 0 here; --fail-on-incomplete raises it to 3 and remains opt-in.
func TestUnscannedFilesAreNotReportedCleanByTheCLI(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped under -short")
	}
	bin := buildCLI(t)

	for _, c := range UnscannedCases {
		if !c.MustNotBeReportedClean {
			continue
		}
		t.Run(c.Name, func(t *testing.T) {
			if runtimeSkipsMode(t, c) {
				return
			}
			path := writeUnscannedFixture(t, t.TempDir(), c)

			got := runCLI(t, bin, nil,
				"--file", path,
				"--config", os.DevNull,
				"--checks", strings.Join(c.Checks, ","),
				"--limit", "0",
				"--enable-preprocessors",
				"--format", "json",
			)

			// Whatever else happens, the operator must be told SOMETHING. Total
			// silence on both streams is the failure that shipped once already
			// (#193) and it is gated here, not merely logged.
			if len(got.stdout)+len(got.stderr) == 0 {
				t.Errorf("%s produced zero bytes on stdout AND stderr: the file was not "+
					"scanned and nothing said so", c.Name)
			}

			// The output must name the problem somewhere. Checked against a SET of
			// phrasings rather than one string: the wording is presentation and is
			// expected to be improved, but the OBLIGATION to say something is the
			// contract. An earlier version asserted only "not scanned"/"could not" and
			// went red when the renderer was reworded to "NOT EXAMINED" — a stale
			// assertion failing on an improvement, which teaches people to loosen tests.
			//
			// Both streams are accepted because the destination legitimately differs by
			// format: text renders it inside its summary block on stdout so a piped
			// report keeps a closed frame, while machine formats put it on stderr to
			// leave stdout parseable.
			combined := strings.ToLower(got.stdout + got.stderr)
			said := false
			for _, phrase := range []string{"not examined", "not scanned", "could not", "unreadable"} {
				if strings.Contains(combined, phrase) {
					said = true
					break
				}
			}
			if !said {
				t.Errorf("%s: neither stream explains that the file was not examined "+
					"(stdout %d bytes, stderr %d bytes). Without it the only signal is an "+
					"empty result set, which is what a clean scan also produces.",
					c.Name, len(got.stdout), len(got.stderr))
			}

			// The machine-readable half, now GATED rather than narrated.
			//
			// This branch used to be a t.Logf under `json.Unmarshal(stdout, &results) == nil
			// && len(results) == 0`, recording that a JSON consumer could not tell "nothing
			// found" from "never looked" and promising "when it lands, this becomes an
			// assertion". It landed in 33b1f44 (#316, "always emit stats in json and yaml"),
			// after which stdout is an OBJECT and unmarshalling it into a []json.RawMessage
			// errors — so the branch could never run again. Live one week, dead five (#385).
			//
			// This is what its own comment promised: assert the disclosure instead of
			// describing its absence. It passes at HEAD and would have failed before 33b1f44,
			// so it gates the behaviour rather than narrating a gap.
			var report struct {
				Stats struct {
					FilesNotExamined int `json:"files_not_examined"`
				} `json:"stats"`
				Results []json.RawMessage `json:"results"`
			}
			if err := json.Unmarshal([]byte(got.stdout), &report); err != nil {
				t.Fatalf("%s: stdout is not the JSON report this test depends on: %v\nstdout: %s",
					c.Name, err, got.stdout)
			}
			if len(report.Results) != 0 {
				t.Errorf("%s: expected no findings from a file that could not be read, got %d",
					c.Name, len(report.Results))
			}
			if report.Stats.FilesNotExamined < 1 {
				t.Errorf("%s: stats.files_not_examined = %d, want >= 1.\n"+
					"An empty results array is what a CLEAN scan produces too, so the count is "+
					"the only thing in machine output that separates 'nothing found' from "+
					"'never looked'.\nstdout: %s",
					c.Name, report.Stats.FilesNotExamined, got.stdout)
			}
		})
	}
}

// runtimeSkipsMode reports whether a case cannot be exercised on this platform.
//
// A 0o000 file is still readable by an elevated user, and Windows does not honour
// POSIX mode bits the same way, so the permission case would silently pass for the
// wrong reason there. Skipping loudly is better than a green test that proves
// nothing.
func runtimeSkipsMode(t *testing.T, c UnscannedCase) bool {
	t.Helper()
	if !c.Unreadable {
		return false
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: a 0o000 file is still readable, so this case cannot fail")
		return true
	}
	if !posixModesEnforced() {
		t.Skip("platform does not enforce POSIX mode bits for this case")
		return true
	}
	return false
}

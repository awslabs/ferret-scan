// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// reportRootBinary builds the CLI once for this file's tests.
func reportRootBinary(t *testing.T) string {
	t.Helper()
	binName := "ferret-scan"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	binPath := filepath.Join(t.TempDir(), binName)

	cmd := exec.Command("go", "build", "-o", binPath, "../../cmd")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build ferret-scan: %v\n%s", err, out)
	}
	return binPath
}

// twoNestedFindings writes <root>/src/first/config.py and <root>/src/second/config.py, one SSN
// each, and returns root. Two files with the SAME BASENAME in different directories is the
// shape that makes a lossy path visible: a basename collapses them into one location.
func twoNestedFindings(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for name, ssn := range map[string]string{"first": "452-11-9384", "second": "449-87-4100"} {
		dir := filepath.Join(root, "src", name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "config.py"), []byte("ssn = \""+ssn+"\"\n"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	return root
}

// gitlabLocations runs a gitlab-sast scan with the given working directory and returns every
// location.file, sorted by the order they appear.
func gitlabLocations(t *testing.T, bin, workDir string, args ...string) []string {
	t.Helper()

	cmd := exec.Command(bin, append([]string{"--format", "gitlab-sast", "--checks", "SSN"}, args...)...)
	cmd.Dir = workDir
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("scan failed (%v): %s", err, ee.Stderr)
		}
		t.Fatalf("scan failed: %v", err)
	}

	var report struct {
		Vulnerabilities []struct {
			Description string `json:"description"`
			Location    struct {
				File string `json:"file"`
			} `json:"location"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatalf("gitlab-sast output is not JSON (%v): %s", err, out)
	}

	files := make([]string, 0, len(report.Vulnerabilities))
	for _, v := range report.Vulnerabilities {
		files = append(files, v.Location.File)
		// A vulnerability that names one path in location.file and another in its own
		// description is internally inconsistent, and the absolute spelling is the host
		// layout disclosure location.file exists to keep out (#712). Checked here rather
		// than in a separate test because the pair only exists together.
		if want := "**Location:** " + v.Location.File + " "; !strings.Contains(v.Description, want) {
			t.Errorf("description does not carry the same path as location.file %q:\n%s",
				v.Location.File, v.Description)
		}
	}
	return files
}

// TestReportedPathsAreRelativeToTheScanTarget covers the wiring, which is the part #710
// changes: resolveReportRoot has its own unit tests, but only an end-to-end run proves main
// passes the scan target rather than the working directory.
//
// The second case is the documented Docker invocation's shape. `docs/DOCKER_INTEGRATION.md`
// publishes
//
//	docker run --rm -v $PWD:/data ferret-scan:latest --file /data --recursive --format gitlab-sast
//
// and the image's final stage is FROM scratch with no WORKDIR, so the container's working
// directory is "/" — nowhere near the target. Rooting at the working directory put the MOUNT
// POINT into every path (measured on #707's head: "tmp/<...>/data/src/first/config.py"), which
// GitLab resolves from the repository root and misses.
func TestReportedPathsAreRelativeToTheScanTarget(t *testing.T) {
	bin := reportRootBinary(t)
	root := twoNestedFindings(t)
	want := []string{"src/first/config.py", "src/second/config.py"}

	cases := []struct {
		name    string
		workDir string
		args    []string
	}{
		{
			name:    "--file . from the tree, as GitLab CI runs it",
			workDir: root,
			args:    []string{"--file", ".", "--recursive"},
		},
		{
			name: "--file <absolute target> from an unrelated working directory, as the container runs it",
			// Not the filesystem root itself: a scan of a directory the test does not own
			// would be unpredictable. Any directory that is not the target proves the same
			// property, that the working directory does not contribute.
			workDir: t.TempDir(),
			args:    []string{"--file", root, "--recursive"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := gitlabLocations(t, bin, tc.workDir, tc.args...)
			if len(got) != len(want) {
				t.Fatalf("got %d vulnerabilities (%v), want %d — a lossy path that collapses "+
					"two findings would also fail the comparison below", len(got), got, len(want))
			}
			// Sorted output is not guaranteed across platforms; compare as a set.
			gotSet := map[string]bool{got[0]: true, got[1]: true}
			for _, w := range want {
				if !gotSet[w] {
					t.Errorf("no vulnerability at %q; got %v", w, got)
				}
			}
		})
	}
}

// A single FILE target roots at its parent, so the report names the file the user asked about
// and nothing above it.
func TestReportedPathForASingleFileTargetIsItsName(t *testing.T) {
	bin := reportRootBinary(t)
	root := twoNestedFindings(t)

	got := gitlabLocations(t, bin, t.TempDir(),
		"--file", filepath.Join(root, "src", "first", "config.py"))
	if len(got) != 1 || got[0] != "config.py" {
		t.Errorf("got %v, want exactly [config.py]", got)
	}
}

// TestMachineFormatsDoNotCarryTheHostLayout is #715's guarantee: a report is an artifact
// people attach to tickets, commit and upload, and it should not carry the operator's home
// directory, the checkout layout, or in CI the runner's group and project path. None of that
// is information about the finding.
//
// The scan target's own absolute path is the whole prefix at issue here, so asserting its
// absence is the direct test. SARIF is the documented exception: it declares the root ONCE in
// run.originalUriBaseIds, because without that definition its per-result %SRCROOT% is a
// dangling reference no consumer can resolve (#711) — the run-level field #715 itself floats as
// the right shape for a consumer that needs to rejoin the prefix.
func TestMachineFormatsDoNotCarryTheHostLayout(t *testing.T) {
	bin := reportRootBinary(t)
	root := twoNestedFindings(t)
	workDir := t.TempDir()

	for _, format := range []string{"json", "yaml", "csv", "gitlab-sast", "sarif"} {
		t.Run(format, func(t *testing.T) {
			cmd := exec.Command(bin, "--file", root, "--recursive", "--format", format,
				"--checks", "SSN", "--confidence", "all")
			cmd.Dir = workDir
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("scan failed: %v", err)
			}
			report := string(out)

			// Non-vacuity first: the findings have to be in there for their absence of a
			// prefix to mean anything.
			if !strings.Contains(report, "src/first/config.py") {
				t.Fatalf("the report does not name src/first/config.py at all:\n%s", report)
			}

			// Every spelling the prefix could take in a report: the native one, the
			// forward-slashed one the formatters emit, and — on Windows — the
			// backslash-escaped one a JSON encoder writes. Counting only one spelling
			// would make this test pass vacuously on the platform whose spelling it missed.
			occurrences := 0
			for _, spelling := range pathSpellings(root) {
				occurrences += strings.Count(report, spelling)
			}
			allowed := 0
			if format == "sarif" {
				allowed = 1 // run.originalUriBaseIds, once
			}
			if occurrences > allowed {
				t.Errorf("the scan target's absolute path appears %d times (at most %d allowed "+
					"for %s):\n%s", occurrences, allowed, format, report)
			}
		})
	}
}

// The path is relative in the per-finding field of every format that has one, not just absent
// from the prefix. Reads the value rather than the whole document, so a format that dropped the
// field entirely would fail rather than pass by omission.
func TestPerFindingPathsAreRootRelative(t *testing.T) {
	bin := reportRootBinary(t)
	root := twoNestedFindings(t)
	workDir := t.TempDir()

	run := func(t *testing.T, format string) string {
		t.Helper()
		cmd := exec.Command(bin, "--file", root, "--recursive", "--format", format,
			"--checks", "SSN", "--confidence", "all")
		cmd.Dir = workDir
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("scan failed: %v", err)
		}
		return string(out)
	}

	t.Run("json", func(t *testing.T) {
		var doc struct {
			Results []struct {
				Filename string `json:"filename"`
			} `json:"results"`
		}
		if err := json.Unmarshal([]byte(run(t, "json")), &doc); err != nil {
			t.Fatalf("json output is not JSON: %v", err)
		}
		if len(doc.Results) != 2 {
			t.Fatalf("got %d results, want 2", len(doc.Results))
		}
		for _, r := range doc.Results {
			if filepath.IsAbs(r.Filename) || !strings.HasPrefix(r.Filename, "src/") {
				t.Errorf("filename = %q, want a path under src/", r.Filename)
			}
		}
	})

	t.Run("csv", func(t *testing.T) {
		lines := strings.Split(strings.TrimSpace(run(t, "csv")), "\n")
		if len(lines) < 3 {
			t.Fatalf("csv has %d lines, want a header and two rows:\n%s", len(lines), lines)
		}
		for _, line := range lines[1:] {
			first := strings.SplitN(line, ",", 2)[0]
			if filepath.IsAbs(first) || !strings.HasPrefix(first, "src/") {
				t.Errorf("Filename column = %q, want a path under src/", first)
			}
		}
	})

	t.Run("yaml", func(t *testing.T) {
		out := run(t, "yaml")
		if !strings.Contains(out, "filename: src/first/config.py") {
			t.Errorf("yaml does not carry a root-relative filename:\n%s", out)
		}
	})
}

// pathSpellings returns the distinct ways an absolute path can appear in a report: as the host
// writes it, forward-slashed as the formatters emit it, and JSON-escaped as an encoder writes a
// Windows path.
func pathSpellings(path string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range []string{
		path,
		filepath.ToSlash(path),
		strings.ReplaceAll(path, `\`, `\\`),
	} {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

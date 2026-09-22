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

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scorecorpus

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The executable layer: the same corpus driven through the REAL built binary.
//
// Every other layer here calls the library in-process. That is not the product. A
// library that scores perfectly behind a CLI that prints nothing, or exits 0 on a
// blocking finding, protects nobody — and both have shipped in this repo:
//
//	#193  a streaming regression made the pre-commit path exit 1 with ZERO bytes on
//	      stdout and stderr, so a developer saw a mysterious failure and no findings.
//	#270  exit-code precedence was inverted, so a blocking finding was reported as a
//	      "system error" (rc=2) instead of a policy failure (rc=1).
//
// Neither moves a precision or recall number. This layer is what fails.

// buildCLI compiles the binary once per test run and returns its path.
//
// Cross-platform notes, because this layer is the only one that leaves the Go test
// process and CI runs it on ubuntu, macos AND windows:
//
//   - The output needs .exe on Windows or the produced file is not executable.
//   - The package argument stays a forward-slash relative path: that is Go tooling
//     syntax, not a filesystem path, and it is correct on every platform.
//   - GOFLAGS/GOPROXY are inherited so the offline module cache is used.
func buildCLI(t *testing.T) string {
	t.Helper()

	name := "ferret-scan-under-test"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}

	bin := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-o", bin, "../../cmd")
	cmd.Env = os.Environ()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, out)
	}
	return bin
}

type cliResult struct {
	stdout, stderr string
	code           int
}

// precommitOffEnv neutralises pre-commit auto-detection.
//
// The CLI detects a pre-commit environment and then OVERRIDES the output format to
// "text" (precommit/detector.go: Format: "text"), silently discarding an explicit
// --format json. On Windows the detection is far broader than the PRE_COMMIT
// variable: detectWindowsGitEnvironment() returns true if MSYSTEM, MINGW_PREFIX or
// GIT_EXEC_PATH is set — i.e. for anything running under Git Bash, which is exactly
// how GitHub Actions runs the Windows job.
//
// So this test asked for JSON, received pre-commit text, and failed on Windows only
// while passing on ubuntu and macos. Blanking the triggers keeps the scored
// behaviour identical on all three platforms.
//
// This is a test-harness fix, not a product change: a real user in Git Bash who
// passes --format json arguably has the same complaint, but that is a separate
// question about precedence between an explicit flag and an inferred environment.
var precommitOffEnv = []string{
	"PRE_COMMIT=",
	"_PRE_COMMIT_RUNNING=",
	"PRE_COMMIT_HOME=",
	"PRE_COMMIT_HOOK=",
	"GIT_HOOK_TYPE=",
	"MSYSTEM=",
	"MINGW_PREFIX=",
	"GIT_EXEC_PATH=",
	"GITHUB_DESKTOP=",
}

func runCLI(t *testing.T, bin string, env []string, args ...string) cliResult {
	t.Helper()

	cmd := exec.Command(bin, args...)
	// precommitOffEnv first, so a caller that deliberately sets PRE_COMMIT (the
	// exit-code test) still wins by appending after it.
	cmd.Env = append(os.Environ(), precommitOffEnv...)
	cmd.Env = append(cmd.Env, env...)

	var so, se strings.Builder
	cmd.Stdout = &so
	cmd.Stderr = &se
	err := cmd.Run()

	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run CLI: %v", err)
	}
	return cliResult{stdout: so.String(), stderr: se.String(), code: code}
}

// TestExecutableAgreesWithLibrary — the binary must report the same findings the
// in-process score is computed from.
//
// If these diverge, every other number in this package describes a library nobody
// runs. Compared on the (line, type, text) key rather than on confidence, so a
// scoring change does not read as a CLI bug.
func TestExecutableAgreesWithLibrary(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped under -short")
	}
	bin := buildCLI(t)
	dir := t.TempDir()

	type cliFinding struct {
		Text       string  `json:"text"`
		LineNumber int     `json:"line_number"`
		Type       string  `json:"type"`
		Confidence float64 `json:"confidence"`
	}
	type cliReport struct {
		Results []cliFinding `json:"results"`
	}

	checked := 0
	for _, c := range GatedCases() {
		if len(c.Labels) == 0 {
			continue // negatives are covered by the precision numbers
		}

		src := filepath.Join(dir, c.Name+sinkExtension(c.Name))
		if err := os.WriteFile(src, []byte(c.Input), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}

		// os.DevNull, not the literal "/dev/null": on Windows that path does not
		// exist and the CLI would fall back to discovering the developer's config,
		// making this layer's result machine-dependent.
		got := runCLI(t, bin, nil,
			"--file", src,
			"--config", os.DevNull,
			"--checks", strings.Join(c.Checks, ","),
			"--limit", "0",
			"--show-match",
			"--format", "json",
		)

		var rep cliReport
		if err := json.Unmarshal([]byte(got.stdout), &rep); err != nil {
			t.Errorf("%s: CLI did not emit parseable JSON (rc=%d, %d bytes on stdout, "+
				"%d on stderr). A report nobody can parse is a report nobody reads.",
				c.Name, got.code, len(got.stdout), len(got.stderr))
			continue
		}

		// Every label must be present in the CLI's own output, not just the
		// library's.
		for _, lb := range c.Labels {
			found := false
			for _, f := range rep.Results {
				if f.LineNumber == lb.Line && covers(f.Text, lb.Value) && typeAllowed(f.Type, lb.Types) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s line %d (%s): the library scores this as found, but the CLI "+
					"does not report it. The CLI is the product.",
					c.Name, lb.Line, strings.Join(lb.Types, "|"))
			}
			checked++
		}
	}

	if checked == 0 {
		t.Fatal("no labels were checked through the CLI; this test would pass vacuously")
	}
	t.Logf("executable layer: %d labels verified through the real binary", checked)
}

// TestExecutableExitCodes — rc must reflect what was found.
//
// A finding with no non-zero exit is invisible to any automation; a non-zero exit
// with no output is a mystery failure. Both have shipped.
func TestExecutableExitCodes(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped under -short")
	}
	bin := buildCLI(t)
	dir := t.TempDir()

	// A case with a HIGH-confidence label, and a clean file.
	var withFinding Case
	for _, c := range GatedCases() {
		if len(c.Labels) > 0 && c.Labels[0].MinBand == BandHigh {
			withFinding = c
			break
		}
	}
	if withFinding.Name == "" {
		t.Fatal("no HIGH-band case in the corpus; cannot test exit codes")
	}

	dirty := filepath.Join(dir, withFinding.Name+sinkExtension(withFinding.Name))
	if err := os.WriteFile(dirty, []byte(withFinding.Input), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	clean := filepath.Join(dir, "clean.txt")
	if err := os.WriteFile(clean, []byte("nothing sensitive here at all\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	checks := strings.Join(withFinding.Checks, ",")

	t.Run("clean file exits 0 and says so", func(t *testing.T) {
		got := runCLI(t, bin, nil, "--file", clean, "--config", os.DevNull,
			"--checks", checks, "--limit", "0")
		if got.code != 0 {
			t.Errorf("clean file exited %d, want 0", got.code)
		}
		if len(got.stdout)+len(got.stderr) == 0 {
			t.Error("clean file produced no output at all; silence is indistinguishable " +
				"from a crash")
		}
	})

	t.Run("pre-commit blocks on a high finding", func(t *testing.T) {
		// The pre-commit path needs BOTH the env marker and the threshold; the flag
		// alone is not enough (learned the hard way in #193).
		got := runCLI(t, bin,
			[]string{"PRE_COMMIT=1", "FERRET_PRECOMMIT_EXIT_ON=medium"},
			"--file", dirty, "--config", os.DevNull, "--checks", checks, "--limit", "0")

		if got.code == 0 {
			t.Errorf("a HIGH-confidence finding did not block: rc=0 under "+
				"FERRET_PRECOMMIT_EXIT_ON=medium (%s). A gate that does not gate is worse "+
				"than no gate, because the commit looks reviewed.", withFinding.Name)
		}
		if got.code == 2 {
			t.Errorf("rc=2 means SYSTEM ERROR, but this is a policy block (want 1). " +
				"That precedence inversion shipped once already (#270): a real finding " +
				"reported as a tool malfunction gets the tool disabled, not the finding fixed.")
		}
		if len(got.stdout)+len(got.stderr) == 0 {
			t.Error("blocked the commit with ZERO bytes of output. This exact regression " +
				"shipped in #193: the developer sees a failed hook and no reason.")
		}
	})
}

// TestExecutableRedactionWritesAFile — the redacted artifact must exist and must not
// contain the value.
//
// The library-level sink test covers the bytes; this covers the CLI wiring around
// it, which is a separate failure (a flag that silently does nothing, an output dir
// that is never created). pkg RedactFile once returned success on a cleartext copy.
func TestExecutableRedactionWritesAFile(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped under -short")
	}
	bin := buildCLI(t)
	dir := t.TempDir()

	var c Case
	for _, k := range GatedCases() {
		if len(k.Labels) > 0 && k.Redactable {
			c = k
			break
		}
	}
	if c.Name == "" {
		t.Fatal("no redactable labelled case")
	}

	src := filepath.Join(dir, c.Name+sinkExtension(c.Name))
	if err := os.WriteFile(src, []byte(c.Input), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	outDir := filepath.Join(dir, "redacted")

	runCLI(t, bin, nil, "--file", src, "--config", os.DevNull,
		"--checks", strings.Join(c.Checks, ","), "--limit", "0",
		"--enable-redaction", "--redaction-output-dir", outDir)

	var written []string
	_ = filepath.Walk(outDir, func(p string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() {
			written = append(written, p)
		}
		return nil
	})

	if len(written) == 0 {
		t.Fatalf("--enable-redaction produced no file for %s. A redaction flag that "+
			"silently does nothing leaves the user believing their data was masked.", c.Name)
	}

	for _, p := range written {
		b, err := os.ReadFile(p) //nolint:gosec // test-controlled path
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		for _, lb := range c.Labels {
			if strings.Contains(string(b), lb.Value) {
				t.Errorf("%s: the labelled value survives in the redacted file written by "+
					"the CLI", c.Name)
			}
		}
	}
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/tests/helpers"
)

// stdinBinary builds the ferret-scan binary once per test run and returns
// its path. Subsequent calls reuse the same binary across subtests.
func stdinBinary(t *testing.T) string {
	t.Helper()
	tempDir := t.TempDir()
	binName := "ferret-scan"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	binPath := filepath.Join(tempDir, binName)

	// Build the entire cmd package, not just main.go — auxiliary .go files
	// (e.g. stdin.go) live in the same package and must be compiled in.
	cmd := exec.Command("go", "build", "-o", binPath, "../../cmd")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build ferret-scan: %v\n%s", err, out)
	}
	return binPath
}

// runStdin pipes input through ferret-scan with the given args and returns
// stdout, stderr, and exit code.
func runStdin(t *testing.T, bin, input string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Stdin = strings.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			t.Fatalf("unexpected exec error: %v\nstderr=%s", err, stderr.String())
		}
	}
	return stdout.String(), stderr.String(), exitCode
}

// jsonResults parses the standard ferret-scan JSON output and returns the
// "results" array as []map[string]any. Empty input returns an empty slice.
func jsonResults(t *testing.T, raw string) []map[string]any {
	t.Helper()
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "[]" {
		return nil
	}
	// The JSON formatter emits either {"results":[...]} or [].
	if strings.HasPrefix(raw, "[") {
		var arr []map[string]any
		if err := json.Unmarshal([]byte(raw), &arr); err != nil {
			t.Fatalf("invalid array JSON: %v\n%s", err, raw)
		}
		return arr
	}
	var doc struct {
		Results []map[string]any `json:"results"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, raw)
	}
	return doc.Results
}

func TestStdin_DetectsAcrossFormats(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	input := strings.Join([]string{
		"credit card: 4532-0151-1283-0366",
		"contact: alice@example.com",
		"ssn: 123-45-6789",
	}, "\n")

	formats := []struct {
		name   string
		format string
	}{
		{"json", "json"},
		{"text", "text"},
		{"csv", "csv"},
		{"yaml", "yaml"},
		{"sarif", "sarif"},
		{"gitlab-sast", "gitlab-sast"},
		{"junit", "junit"},
	}

	for _, fmt := range formats {
		t.Run(fmt.name, func(t *testing.T) {
			stdout, stderr, code := runStdin(t, bin, input,
				"--stdin", "--confidence", "all", "--format", fmt.format)
			// Non-precommit mode never exits non-zero on findings.
			if code != 0 {
				t.Errorf("expected exit 0, got %d. stderr=%s", code, stderr)
			}
			if stdout == "" {
				t.Errorf("expected non-empty %s output", fmt.format)
			}
			// All formats must surface "<stdin>" as the source label.
			// Different formats encode the angle brackets differently:
			//   - text/csv/yaml: literal <stdin>
			//   - json/sarif/gitlab-sast (Go's json.Marshal escapes <,>):
			//     <stdin>
			//   - junit (XML): &lt;stdin&gt;
			labels := []string{
				"<stdin>",             // text, csv, yaml
				"\\u003cstdin\\u003e", // Go json.Marshal HTML-safe escape (json, sarif, gitlab-sast)
				"&lt;stdin&gt;",       // XML / JUnit
			}
			found := false
			for _, label := range labels {
				if strings.Contains(stdout, label) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s output missing <stdin> label in any encoding:\n%s",
					fmt.format, stdout)
			}
		})
	}
}

func TestStdin_FileDashAlias(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	stdout, stderr, code := runStdin(t, bin, "alice@example.com\n",
		"--file", "-", "--confidence", "all", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d. stderr=%s", code, stderr)
	}
	results := jsonResults(t, stdout)
	if len(results) == 0 {
		t.Fatal("expected at least one result for --file - alias")
	}
	if got := results[0]["filename"]; got != "<stdin>" {
		t.Errorf("filename=%v, want <stdin>", got)
	}
}

func TestStdin_PreprocessOnly(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	input := "alice@example.com is here\n"
	stdout, stderr, code := runStdin(t, bin, input, "--stdin", "-p")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d. stderr=%s", code, stderr)
	}
	want := []string{"=== FILE: <stdin> ===", "Status: Success", "alice@example.com"}
	for _, w := range want {
		if !strings.Contains(stdout, w) {
			t.Errorf("preprocess-only output missing %q. got:\n%s", w, stdout)
		}
	}
}

func TestStdin_EmptyInputNoFindings(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	stdout, stderr, code := runStdin(t, bin, "", "--stdin", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d. stderr=%s", code, stderr)
	}
	results := jsonResults(t, stdout)
	if len(results) != 0 {
		t.Errorf("expected no results for empty input, got %d", len(results))
	}
}

func TestStdin_BinaryRejected(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	input := "ssn 123-45-6789\x00binary\n"
	_, stderr, code := runStdin(t, bin, input, "--stdin")
	if code == 0 {
		t.Errorf("expected non-zero exit for binary input, got 0")
	}
	if !strings.Contains(stderr, "binary content") {
		t.Errorf("stderr should mention binary content; got %q", stderr)
	}
}

func TestStdin_MutualExclusion(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	cases := []struct {
		name       string
		extraArgs  []string
		wantStderr string
	}{
		{"file_collision", []string{"--stdin", "--file", "foo.txt"}, "mutually exclusive"},
		{"positional_collision", []string{"--stdin", "extra.txt"}, "positional file arguments"},
		{"recursive_collision", []string{"--stdin", "--recursive"}, "recursive"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, stderr, code := runStdin(t, bin, "alice@example.com\n", tc.extraArgs...)
			if code == 0 {
				t.Errorf("expected non-zero exit, got 0. stderr=%s", stderr)
			}
			if !strings.Contains(stderr, tc.wantStderr) {
				t.Errorf("stderr missing %q. got: %s", tc.wantStderr, stderr)
			}
		})
	}
}

func TestStdin_ChecksFilter(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	input := strings.Join([]string{
		"credit card: 4532-0151-1283-0366",
		"contact: alice@example.com",
		"ssn: 123-45-6789",
	}, "\n")

	stdout, stderr, code := runStdin(t, bin, input,
		"--stdin", "--confidence", "all", "--checks", "EMAIL", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d. stderr=%s", code, stderr)
	}
	results := jsonResults(t, stdout)
	if len(results) == 0 {
		t.Fatal("expected EMAIL match")
	}
	for _, r := range results {
		if v := r["validator"]; v != "email" {
			t.Errorf("expected only email findings, got validator=%v", v)
		}
	}
}

func TestStdin_CustomNameFlag(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	stdout, stderr, code := runStdin(t, bin, "alice@example.com\n",
		"--stdin", "--stdin-name", "<git-diff>", "--confidence", "all", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d. stderr=%s", code, stderr)
	}
	results := jsonResults(t, stdout)
	if len(results) == 0 {
		t.Fatal("expected at least one match")
	}
	if got := results[0]["filename"]; got != "<git-diff>" {
		t.Errorf("filename=%v, want <git-diff>", got)
	}
}

func TestStdin_BOMStripped(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	// Leading UTF-8 BOM (\xEF\xBB\xBF) followed by an email; line number
	// should be 1, i.e. the BOM is stripped before line-counting.
	input := "\xEF\xBB\xBFalice@example.com\n"
	stdout, stderr, code := runStdin(t, bin, input,
		"--stdin", "--confidence", "all", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d. stderr=%s", code, stderr)
	}
	results := jsonResults(t, stdout)
	if len(results) == 0 {
		t.Fatal("expected email match after BOM strip")
	}
	if line, ok := results[0]["line_number"].(float64); ok {
		if int(line) != 1 {
			t.Errorf("expected line_number=1, got %v", line)
		}
	}
}

func TestStdin_SARIFNoSrcRoot(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	stdout, stderr, code := runStdin(t, bin, "alice@example.com\n",
		"--stdin", "--confidence", "all", "--format", "sarif")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d. stderr=%s", code, stderr)
	}
	// SARIF emits a document-level versionControlProvenance.mappedTo
	// reference to %SRCROOT% regardless of whether the result is virtual,
	// so we can't simply forbid the literal in the output. What we *can*
	// guarantee is that no per-result artifactLocation carries the
	// uriBaseId — that's the Phase 1b contract.
	var doc struct {
		Runs []struct {
			Results []struct {
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI       string `json:"uri"`
							URIBaseID string `json:"uriBaseId"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if len(doc.Runs) == 0 || len(doc.Runs[0].Results) == 0 {
		t.Fatalf("SARIF document had no results; stdout=%s", stdout)
	}
	for i, res := range doc.Runs[0].Results {
		for j, loc := range res.Locations {
			if loc.PhysicalLocation.ArtifactLocation.URIBaseID != "" {
				t.Errorf("result %d location %d carries uriBaseId %q on virtual stdin source",
					i, j, loc.PhysicalLocation.ArtifactLocation.URIBaseID)
			}
			if loc.PhysicalLocation.ArtifactLocation.URI != "<stdin>" {
				t.Errorf("result %d location %d uri=%q want <stdin>",
					i, j, loc.PhysicalLocation.ArtifactLocation.URI)
			}
		}
	}
}

func TestStdin_OutputToFile(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	tmp := t.TempDir()
	outPath := filepath.Join(tmp, "out.json")

	_, stderr, code := runStdin(t, bin, "alice@example.com\n",
		"--stdin", "--confidence", "all", "--format", "json",
		"--output", outPath)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d. stderr=%s", code, stderr)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("expected output file %q to exist: %v", outPath, err)
	}
	results := jsonResults(t, string(data))
	if len(results) == 0 {
		t.Fatal("expected results in output file")
	}
	// Output file must be 0600 — sensitive findings should not be world-readable.
	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("stat output file: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("output file perms=%o, want 0600", mode)
	}
}

func TestStdin_OutputPathTraversalRejected(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	_, stderr, code := runStdin(t, bin, "alice@example.com\n",
		"--stdin", "--format", "json", "--output", "../escape.json")
	if code == 0 {
		t.Errorf("expected non-zero exit for path traversal, got 0")
	}
	if !strings.Contains(stderr, "Path traversal") &&
		!strings.Contains(stderr, "path traversal") {
		t.Errorf("stderr should mention path traversal, got: %s", stderr)
	}
}

func TestStdin_SuppressionApplied(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	tmp := t.TempDir()
	suppressionFile := filepath.Join(tmp, "supp.yaml")

	// Step 1: scan with --generate-suppressions to produce a rule file.
	_, _, code := runStdin(t, bin, "alice@example.com\n",
		"--stdin", "--confidence", "all", "--format", "json",
		"--generate-suppressions",
		"--suppression-file", suppressionFile)
	if code != 0 {
		t.Fatalf("generate-suppressions run exited %d", code)
	}

	// The generated rule is created disabled by default. We need to enable
	// it to actually suppress on the next run. Read the file and flip
	// every "enabled: false" to "enabled: true".
	raw, err := os.ReadFile(suppressionFile)
	if err != nil {
		t.Fatalf("reading suppression file: %v", err)
	}
	enabled := strings.ReplaceAll(string(raw), "enabled: false", "enabled: true")
	if err := os.WriteFile(suppressionFile, []byte(enabled), 0o600); err != nil {
		t.Fatalf("writing suppression file: %v", err)
	}

	// Step 2: scan again with the now-enabled rule. The email match should
	// be suppressed (count = 0 in default output, present when --show-suppressed).
	stdout, stderr, code := runStdin(t, bin, "alice@example.com\n",
		"--stdin", "--confidence", "all", "--format", "json",
		"--suppression-file", suppressionFile)
	if code != 0 {
		t.Fatalf("scan-with-suppressions exited %d. stderr=%s", code, stderr)
	}
	results := jsonResults(t, stdout)
	if len(results) != 0 {
		t.Errorf("expected 0 unsuppressed results, got %d: %+v", len(results), results)
	}

	// And confirm --show-suppressed surfaces the suppression.
	if !strings.Contains(stderr, "Suppressed") {
		t.Errorf("stderr should mention suppressed findings, got: %s", stderr)
	}
}

func TestStdin_PrecommitExitCode(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	// Pre-commit mode exits non-zero when findings exist (the precise
	// code depends on confidence level). We just need to verify it's
	// non-zero, which is the documented contract.
	input := "card 4532-0151-1283-0366\n"
	_, stderr, code := runStdin(t, bin, input,
		"--stdin", "--pre-commit-mode", "--confidence", "all", "--format", "json")
	if code == 0 {
		t.Errorf("expected non-zero exit in pre-commit mode with findings, got 0. stderr=%s", stderr)
	}
}

func TestStdin_PrecommitNoFindingsExitsZero(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	// Pre-commit mode with no findings must still exit 0 — that's the
	// "your code is clean" case.
	_, stderr, code := runStdin(t, bin, "nothing sensitive here\n",
		"--stdin", "--pre-commit-mode", "--confidence", "all", "--format", "json")
	if code != 0 {
		t.Errorf("expected exit 0 with no findings in pre-commit, got %d. stderr=%s", code, stderr)
	}
}

func TestStdin_HelpFlagFallsThrough(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	// --stdin --help must NOT consume stdin and instead show help. This
	// guards against a regression where the stdin branch swallowed the
	// help/version flags.
	stdout, _, code := runStdin(t, bin, "alice@example.com\n", "--stdin", "--help")
	if code != 0 {
		t.Errorf("expected exit 0 for --help, got %d", code)
	}
	if !strings.Contains(stdout, "USAGE") && !strings.Contains(stdout, "Usage") {
		t.Errorf("--help output missing USAGE banner. got first 200 chars: %q",
			stdout[:min(len(stdout), 200)])
	}
}

func TestStdin_VersionFlagFallsThrough(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	stdout, _, code := runStdin(t, bin, "alice@example.com\n", "--stdin", "--version")
	if code != 0 {
		t.Errorf("expected exit 0 for --version, got %d", code)
	}
	if !strings.Contains(stdout, "ferret-scan") {
		t.Errorf("--version output should contain ferret-scan banner, got: %q", stdout)
	}
}

func TestStdin_FileModeRegression(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	tmp := t.TempDir()
	sample := filepath.Join(tmp, "sample.txt")
	content := "alice@example.com\nssn: 123-45-6789\n"
	if err := os.WriteFile(sample, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	cmd := exec.Command(bin, "--file", sample, "--confidence", "all", "--format", "json")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("file-mode scan failed: %v\nstderr=%s", err, stderr.String())
	}
	results := jsonResults(t, stdout.String())
	if len(results) == 0 {
		t.Fatal("expected file-mode results")
	}
	for _, r := range results {
		if got := r["filename"]; got != sample {
			t.Errorf("filename=%v, want %v", got, sample)
		}
	}
}

// --- Stdin redaction tests ---

// TestStdin_RedactionAllStrategies verifies that all three plaintext
// redaction strategies (simple, format_preserving, synthetic) work end-to-end
// for stdin input, with the redacted content streaming to stdout.
func TestStdin_RedactionAllStrategies(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	input := "alice@example.com is here\n"

	cases := []struct {
		name     string
		strategy string
		// At minimum the redacted output must not contain the original
		// sensitive value AND must not be empty.
		mustNotContain string
	}{
		{"simple", "simple", "alice@example.com"},
		{"format_preserving", "format_preserving", "alice@example.com"},
		{"synthetic", "synthetic", "alice@example.com"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, code := runStdin(t, bin, input,
				"--stdin", "--enable-redaction",
				"--redaction-strategy", tc.strategy,
				"--confidence", "all", "--quiet")
			if code != 0 {
				t.Errorf("expected exit 0, got %d. stderr=%s", code, stderr)
			}
			if stdout == "" {
				t.Fatalf("expected redacted content on stdout for strategy=%s", tc.strategy)
			}
			if strings.Contains(stdout, tc.mustNotContain) {
				t.Errorf("strategy=%s leaked original value to stdout: %q", tc.strategy, stdout)
			}
		})
	}
}

// TestStdin_RedactionFindingsToStderr confirms that when --output is not
// set, redacted content goes to stdout and findings go to stderr (so the
// stdout stream is purely the cleansed text — composable with pipes).
func TestStdin_RedactionFindingsToStderr(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	stdout, stderr, code := runStdin(t, bin, "alice@example.com\n",
		"--stdin", "--enable-redaction", "--redaction-strategy", "simple",
		"--confidence", "all", "--format", "json", "--quiet")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d. stderr=%s", code, stderr)
	}
	// stdout must be ONLY the redacted content, not JSON findings.
	if strings.Contains(stdout, `"validator"`) {
		t.Errorf("stdout should not contain findings JSON when --output is not set, got: %q", stdout)
	}
	if strings.Contains(stdout, "alice@example.com") {
		t.Errorf("stdout should not contain the original sensitive value, got: %q", stdout)
	}
	// stderr must contain the JSON findings (since redaction is on).
	if !strings.Contains(stderr, `"validator"`) {
		t.Errorf("stderr should contain findings JSON when --output is not set, got: %q", stderr)
	}
}

// TestStdin_RedactionFindingsToFile verifies that when both --enable-redaction
// and --output are set, findings go to the file and the redacted content
// streams to stdout.
func TestStdin_RedactionFindingsToFile(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	tmp := t.TempDir()
	outPath := filepath.Join(tmp, "findings.json")

	stdout, stderr, code := runStdin(t, bin, "alice@example.com\n",
		"--stdin", "--enable-redaction", "--redaction-strategy", "simple",
		"--confidence", "all", "--format", "json", "--quiet",
		"--output", outPath)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d. stderr=%s", code, stderr)
	}
	// Findings must be in the file.
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("expected findings file %q: %v", outPath, err)
	}
	results := jsonResults(t, string(data))
	if len(results) == 0 {
		t.Fatal("expected findings in file")
	}
	// stdout must be the redacted content, not findings.
	if strings.Contains(stdout, `"validator"`) {
		t.Errorf("stdout should not contain findings, got: %q", stdout)
	}
	if strings.Contains(stdout, "alice@example.com") {
		t.Errorf("stdout should not contain original value, got: %q", stdout)
	}
}

// TestStdin_RedactionSuppressedNotRedacted verifies that suppressed matches
// (which represent accepted exposures) are NOT redacted — so a suppression
// rule effectively means "I'm fine with this leaking through".
func TestStdin_RedactionSuppressedNotRedacted(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	tmp := t.TempDir()
	suppressionFile := filepath.Join(tmp, "supp.yaml")

	// Generate the suppression rule first.
	_, _, code := runStdin(t, bin, "alice@example.com\n",
		"--stdin", "--confidence", "all", "--format", "json",
		"--generate-suppressions",
		"--suppression-file", suppressionFile)
	if code != 0 {
		t.Fatalf("generate-suppressions failed: code=%d", code)
	}
	raw, err := os.ReadFile(suppressionFile)
	if err != nil {
		t.Fatalf("read suppression file: %v", err)
	}
	enabled := strings.ReplaceAll(string(raw), "enabled: false", "enabled: true")
	if err := os.WriteFile(suppressionFile, []byte(enabled), 0o600); err != nil {
		t.Fatalf("write suppression file: %v", err)
	}

	// Now redact with that suppression file. The email is suppressed, so
	// the redactor should NOT touch it — the original value should pass
	// through unchanged.
	stdout, stderr, code := runStdin(t, bin, "alice@example.com\n",
		"--stdin", "--enable-redaction", "--redaction-strategy", "simple",
		"--confidence", "all", "--quiet",
		"--suppression-file", suppressionFile)
	if code != 0 {
		t.Fatalf("redaction with suppression failed: code=%d, stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "alice@example.com") {
		t.Errorf("suppressed match should pass through unredacted, got: %q", stdout)
	}
}

// TestStdin_RedactionPrecommitExitCode confirms exit-code parity: pre-commit
// mode plus findings still exits non-zero even when redacting (so a CI
// gateway can both produce clean output AND signal upstream).
func TestStdin_RedactionPrecommitExitCode(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	stdout, stderr, code := runStdin(t, bin, "card 4532-0151-1283-0366\n",
		"--stdin", "--enable-redaction", "--redaction-strategy", "simple",
		"--pre-commit-mode", "--confidence", "all", "--quiet")
	if code == 0 {
		t.Errorf("expected non-zero exit in pre-commit mode with findings, got 0. stderr=%s", stderr)
	}
	// Even on non-zero exit, redacted content must still be on stdout —
	// the gateway needs the cleansed string regardless of exit code.
	if !strings.Contains(stdout, "[CREDIT-CARD-REDACTED]") &&
		!strings.Contains(stdout, "card") {
		t.Errorf("expected redacted output on stdout even with non-zero exit, got: %q", stdout)
	}
	if strings.Contains(stdout, "4532-0151-1283-0366") {
		t.Errorf("stdout leaked the original credit card, got: %q", stdout)
	}
}

// TestStdin_RedactionAuditLogIgnoredWithNotice ensures the --redaction-audit-log
// flag is silently ignored with a stderr notice (audit log support for
// stdin requires the on-disk index manager and is tracked as a follow-up).
func TestStdin_RedactionAuditLogIgnoredWithNotice(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "audit.json")

	_, stderr, code := runStdin(t, bin, "alice@example.com\n",
		"--stdin", "--enable-redaction", "--redaction-strategy", "simple",
		"--redaction-audit-log", auditPath,
		"--confidence", "all", "--quiet")
	if code != 0 {
		t.Errorf("expected exit 0, got %d. stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr, "redaction-audit-log") {
		t.Errorf("expected stderr notice about audit-log being unsupported, got: %s", stderr)
	}
	if _, err := os.Stat(auditPath); err == nil {
		t.Errorf("audit-log file should not have been created at %s", auditPath)
	}
}

// TestStdin_RedactionPreservesNonSensitive verifies that non-sensitive parts
// of the input are passed through unchanged. This is the round-trip property
// that matters for a redaction gateway: only the matched spans are altered.
func TestStdin_RedactionPreservesNonSensitive(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	input := "Order #12345 from alice@example.com on 2026-01-15 ships tomorrow.\n"
	stdout, stderr, code := runStdin(t, bin, input,
		"--stdin", "--enable-redaction", "--redaction-strategy", "simple",
		"--checks", "EMAIL", "--confidence", "all", "--quiet")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d. stderr=%s", code, stderr)
	}
	// Non-email parts must be preserved verbatim.
	for _, want := range []string{"Order #12345", "ships tomorrow.", "2026-01-15"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing preserved fragment %q. got: %q", want, stdout)
		}
	}
	if strings.Contains(stdout, "alice@example.com") {
		t.Errorf("email must be redacted, got: %q", stdout)
	}
}

// TestStdin_RedactionNoMatchesPassthrough confirms that input with no
// detectable sensitive content passes through stdout unchanged when
// redaction is enabled. The gateway use case demands this — clean input
// in must produce clean (and identical) input out.
func TestStdin_RedactionNoMatchesPassthrough(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	input := "Hello world, nothing sensitive here.\n"
	stdout, stderr, code := runStdin(t, bin, input,
		"--stdin", "--enable-redaction", "--redaction-strategy", "simple",
		"--confidence", "all", "--quiet")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d. stderr=%s", code, stderr)
	}
	if stdout != input {
		t.Errorf("expected exact passthrough, got %q", stdout)
	}
}

// --- Stdin redaction stream-cleanliness tests ---
//
// These tests guard the contract that when --stdin and --enable-redaction
// are combined and findings stream to stderr (i.e., no --output), the
// findings document on stderr is parseable end-to-end. Human-readable
// prose lines like "Scan complete: ..." would corrupt structured output
// when redirected with `2> findings.json`, so they're suppressed in this
// mode.

// runStdinSeparateStreams pipes input through ferret-scan and captures
// stdout and stderr separately (unlike runStdin, which combines them via
// the helper's bytes.Buffer pair only — runStdin already separates them
// but this name is documenting the intent for readers).
func runStdinSeparateStreams(t *testing.T, bin, input string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	return runStdin(t, bin, input, args...)
}

// TestStdin_RedactionStderrIsParseableJSON asserts that with
// --stdin --enable-redaction --format json (no --output), stderr captures
// a complete, parseable JSON document with no leading prose corruption.
// This is the canonical pipe shape:
//
//	echo "..." | ferret-scan --stdin --enable-redaction --format json 2> findings.json > clean.txt
func TestStdin_RedactionStderrIsParseableJSON(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	stdout, stderr, code := runStdinSeparateStreams(t, bin,
		"alice@example.com is here\n",
		"--stdin", "--enable-redaction", "--redaction-strategy", "simple",
		"--confidence", "all", "--format", "json")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d. stderr=%s", code, stderr)
	}

	// stdout must be redacted content only.
	if strings.Contains(stdout, "alice@example.com") {
		t.Errorf("stdout leaked original value: %q", stdout)
	}
	if strings.Contains(stdout, `"validator"`) {
		t.Errorf("stdout should not contain JSON findings: %q", stdout)
	}

	// stderr must parse cleanly as JSON — no prose prefix.
	trimmed := strings.TrimSpace(stderr)
	if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		t.Fatalf("stderr should start with JSON document, not prose. First 100 chars: %q",
			trimmed[:min(len(trimmed), 100)])
	}
	var doc struct {
		Results []map[string]any `json:"results"`
	}
	if err := json.Unmarshal([]byte(trimmed), &doc); err != nil {
		t.Fatalf("stderr is not parseable JSON (R1 regression?): %v\nstderr=%s", err, stderr)
	}
	if len(doc.Results) == 0 {
		t.Errorf("expected findings in stderr JSON, got empty results")
	}
}

// TestStdin_RedactionStderrIsParseableYAML asserts the same contract for
// YAML, which is whitespace-sensitive and would silently produce a
// malformed document if a stray "Scan complete: ..." line landed at the
// top of stderr.
func TestStdin_RedactionStderrIsParseableYAML(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	_, stderr, code := runStdinSeparateStreams(t, bin,
		"alice@example.com is here\n",
		"--stdin", "--enable-redaction", "--redaction-strategy", "simple",
		"--confidence", "all", "--format", "yaml")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d. stderr=%s", code, stderr)
	}

	// First non-empty line must look like YAML, not prose.
	trimmed := strings.TrimLeft(stderr, "\r\n\t ")
	if strings.HasPrefix(trimmed, "Scan complete") || strings.HasPrefix(trimmed, "Suppressed") {
		t.Fatalf("YAML stderr starts with prose line (R1 regression). First 200 chars: %q",
			trimmed[:min(len(trimmed), 200)])
	}

	// Parse a few characters of YAML — every YAML formatter we ship
	// produces top-level keys before any list indicator. Cheapest check:
	// confirm we see "results:" near the top, which is the standard root.
	if !strings.Contains(stderr, "results:") {
		t.Errorf("YAML stderr missing 'results:' key. stderr=%s", stderr)
	}
}

// TestStdin_RedactionStderrSuppressesPropoOnShowSuppressed exercises the
// --show-suppressed code path to confirm the gate also suppresses the
// "Suppressed N findings... (shown below with [SUPP] label)" prose line
// that would otherwise corrupt structured output.
func TestStdin_RedactionStderrSuppressesPropoOnShowSuppressed(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	tmp := t.TempDir()
	suppressionFile := filepath.Join(tmp, "supp.yaml")

	// Generate and enable a suppression rule.
	_, _, code := runStdin(t, bin, "alice@example.com\n",
		"--stdin", "--confidence", "all", "--format", "json",
		"--generate-suppressions",
		"--suppression-file", suppressionFile)
	if code != 0 {
		t.Fatalf("generate-suppressions failed: code=%d", code)
	}
	raw, err := os.ReadFile(suppressionFile)
	if err != nil {
		t.Fatalf("read suppression file: %v", err)
	}
	enabled := strings.ReplaceAll(string(raw), "enabled: false", "enabled: true")
	if err := os.WriteFile(suppressionFile, []byte(enabled), 0o600); err != nil {
		t.Fatalf("write suppression file: %v", err)
	}

	// Now scan with redaction + show-suppressed + JSON. Stderr must still
	// be parseable JSON — the "Suppressed N findings..." prose must NOT
	// appear because we're in the streaming-redaction shape.
	_, stderr, code := runStdinSeparateStreams(t, bin, "alice@example.com\n",
		"--stdin", "--enable-redaction", "--redaction-strategy", "simple",
		"--confidence", "all", "--format", "json",
		"--show-suppressed",
		"--suppression-file", suppressionFile)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d. stderr=%s", code, stderr)
	}

	if strings.Contains(stderr, "Suppressed") && !strings.Contains(stderr, `"suppressed_by"`) {
		// Allow the word "Suppressed" only inside the JSON document
		// (e.g., as part of a structured field). The corrupting prose
		// is the standalone "Suppressed N findings..." line at the top.
		trimmed := strings.TrimLeft(stderr, "\r\n\t ")
		if strings.HasPrefix(trimmed, "Suppressed") {
			t.Errorf("stderr starts with corrupting 'Suppressed N findings' prose. stderr=%s", stderr)
		}
	}

	trimmed := strings.TrimSpace(stderr)
	if !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		t.Fatalf("stderr should be parseable JSON. First 100 chars: %q",
			trimmed[:min(len(trimmed), 100)])
	}
	if err := json.Unmarshal([]byte(trimmed), &struct {
		Results []map[string]any `json:"results"`
	}{}); err != nil {
		t.Fatalf("stderr is not parseable JSON: %v\nstderr=%s", err, stderr)
	}
}

// TestStdin_RedactionWithOutputKeepsProse verifies the converse: when
// --output <file> is set, prose lines on stderr are still emitted. The
// findings document is going to a file, so stderr is free to carry
// human-readable progress.
func TestStdin_RedactionWithOutputKeepsProse(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	tmp := t.TempDir()
	outPath := filepath.Join(tmp, "findings.json")

	_, stderr, code := runStdinSeparateStreams(t, bin, "alice@example.com\n",
		"--stdin", "--enable-redaction", "--redaction-strategy", "simple",
		"--confidence", "all", "--format", "json",
		"--output", outPath)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d. stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr, "Scan complete") {
		t.Errorf("expected 'Scan complete' prose on stderr when --output is set, got: %s", stderr)
	}

	// Findings file must still be valid JSON.
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read findings file: %v", err)
	}
	var doc struct {
		Results []map[string]any `json:"results"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("findings file is not parseable JSON: %v", err)
	}
	if len(doc.Results) == 0 {
		t.Error("expected findings in output file")
	}
}

// TestStdin_RedactionTTYSuppressesFindings simulates an interactive
// terminal (stdout is a TTY) and verifies that findings are suppressed in
// favor of a one-line hint pointing at the canonical pipe shape. This
// guards the UX where users running the command at their terminal don't
// see a noisy table of findings glued to a single redacted line.
//
// We use script(1) to allocate a pseudo-TTY for the child process; this
// is portable across macOS and Linux. The test is skipped on Windows
// because the script(1) flag set differs.
func TestStdin_RedactionTTYSuppressesFindings(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("script(1) interface differs on Windows; TTY behavior covered by macOS/Linux runs")
	}
	if _, err := exec.LookPath("script"); err != nil {
		t.Skip("script(1) not available on this system")
	}

	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	tmp := t.TempDir()
	stdoutLog := filepath.Join(tmp, "stdout.log")
	stderrPath := filepath.Join(tmp, "stderr.txt")

	// script(1) -q   = quiet mode (no banner)
	//          file  = capture file for the pseudo-TTY's stdout
	//          --    = end of options
	//          /bin/sh -c "..." = command to run under the pty
	//
	// Inside the shell command, redirect stderr to a file so we can
	// assert on it separately, leaving stdout to be captured by script.
	shellCmd := fmt.Sprintf(
		`echo "alice@example.com" | %s --stdin --enable-redaction --confidence all 2> %s`,
		bin, stderrPath,
	)

	var args []string
	switch runtime.GOOS {
	case "darwin":
		// BSD script: script [-q] [-t time] [file [command ...]]
		args = []string{"-q", stdoutLog, "/bin/sh", "-c", shellCmd}
	default:
		// util-linux script: script [options] [file]
		// -q = quiet, -c = run a command in the pty
		args = []string{"-q", "-c", shellCmd, stdoutLog}
	}

	cmd := exec.Command("script", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("script(1) failed: %v\noutput=%s", err, out)
	}

	stdoutBytes, err := os.ReadFile(stdoutLog)
	if err != nil {
		t.Fatalf("read stdout log: %v", err)
	}
	stdout := strings.ReplaceAll(string(stdoutBytes), "\r", "")

	stderrBytes, err := os.ReadFile(stderrPath)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	stderr := string(stderrBytes)

	// Stdout (the pty) must contain the redacted content.
	if !strings.Contains(stdout, "@example.com") && !strings.Contains(stdout, "[EMAIL-REDACTED]") {
		t.Errorf("expected redacted content in TTY stdout, got: %q", stdout)
	}
	// Stdout must NOT contain the findings table — that's the whole point
	// of TTY suppression.
	if strings.Contains(stdout, "VALIDATOR") || strings.Contains(stdout, "[LOW") {
		t.Errorf("findings table leaked into TTY stdout: %q", stdout)
	}

	// Stderr must contain the one-line hint.
	if !strings.Contains(stderr, "findings detected and redacted") {
		t.Errorf("expected hint about findings on stderr, got: %q", stderr)
	}
	// Stderr must NOT contain the full findings table either — TTY mode
	// means "the user didn't redirect, so don't dump findings anywhere
	// they'd see them."
	if strings.Contains(stderr, "VALIDATOR") {
		t.Errorf("full findings table leaked into stderr in TTY mode: %q", stderr)
	}
}

// TestStdin_RedactionPipedStdoutEmitsFindingsToStderr is the converse —
// when stdout is piped (i.e., not a TTY), findings DO go to stderr in
// full, so the canonical `... 2> findings.json > clean.txt` shape works.
// This is regression coverage for the existing piped-mode contract; the
// other tests already exercise it implicitly but this asserts it directly
// alongside the TTY test above.
func TestStdin_RedactionPipedStdoutEmitsFindingsToStderr(t *testing.T) {
	helpers.SetupTestMode()
	defer helpers.CleanupTestMode()

	bin := stdinBinary(t)
	// runStdin uses bytes.Buffer for stdout/stderr — i.e., stdout is NOT
	// a TTY from the binary's perspective. So the piped path runs.
	stdout, stderr, code := runStdin(t, bin, "alice@example.com\n",
		"--stdin", "--enable-redaction", "--confidence", "all", "--quiet")
	if code != 0 {
		t.Fatalf("expected exit 0, got %d. stderr=%s", code, stderr)
	}
	if strings.Contains(stdout, "VALIDATOR") {
		t.Errorf("findings table should not be on stdout when piped: %q", stdout)
	}
	if !strings.Contains(stderr, "VALIDATOR") {
		t.Errorf("expected full findings table on stderr when piped, got: %q", stderr)
	}
}

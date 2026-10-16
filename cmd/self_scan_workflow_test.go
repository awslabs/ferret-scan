// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// #767: .github/workflows/ferret-scan.yml — this repository's self-scan, and the file
// docs/TEAM_SETUP_GUIDE.md and `make setup-team` tell teams to copy as a required check — counted
// findings with `select(.confidence == "HIGH")`. In ferret's JSON `confidence` is a NUMBER (the band
// is `confidence_level`), so every count was 0, the gate step never ran, and the PR comment said
// "No sensitive data detected" over thousands of HIGH findings. `jq … 2>/dev/null | wc -l || echo "0"`
// turned every other failure into a 0 as well. It had been dead since the initial commit.
//
// Two tests guard it. The first reads the workflow's text for the specific mechanisms. The second
// is the one that would have caught the bug: it runs the workflow's own scan and gate scripts, as a
// Linux runner runs a `run:` step with no `shell:` (`bash -e <script>`), against the binary this
// package builds, and checks the counts they record and whether the gate fails.

const selfScanWorkflowPath = "../.github/workflows/ferret-scan.yml"

// The steps are found by name. A renamed step fails here loudly rather than being skipped.
const (
	stepScanChangedFiles = "Run Ferret Scan on changed files"
	stepScanFullRepo     = "Run Ferret Scan on full repository"
	stepPRComment        = "Create PR comment"
	stepGate             = "Gate on scan result and high confidence findings"

	gateCondition = "always() && env.scan_ran == 'true'"
)

type workflowStep struct {
	Name string         `yaml:"name"`
	If   string         `yaml:"if"`
	Env  map[string]any `yaml:"env"`
	Run  string         `yaml:"run"`
	With map[string]any `yaml:"with"`
}

type selfScanWorkflow struct {
	Env  map[string]any `yaml:"env"`
	Jobs map[string]struct {
		Steps []workflowStep `yaml:"steps"`
	} `yaml:"jobs"`
}

func loadSelfScanWorkflow(t *testing.T) (selfScanWorkflow, string) {
	t.Helper()
	raw, err := os.ReadFile(selfScanWorkflowPath) // #nosec G304 -- the repo's own workflow at a fixed path
	if err != nil {
		t.Fatalf("read %s: %v", selfScanWorkflowPath, err)
	}
	var wf selfScanWorkflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatalf("parse %s: %v", selfScanWorkflowPath, err)
	}
	if len(wf.Jobs["ferret-scan"].Steps) == 0 {
		t.Fatalf("%s has no steps in job ferret-scan; the job was renamed or the parse found nothing",
			selfScanWorkflowPath)
	}
	return wf, string(raw)
}

func (wf selfScanWorkflow) step(t *testing.T, name string) workflowStep {
	t.Helper()
	for _, s := range wf.Jobs["ferret-scan"].Steps {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("%s has no step named %q in job ferret-scan", selfScanWorkflowPath, name)
	return workflowStep{}
}

// scriptCode returns a run: script without its whole-line comments, so a flag or command that is
// only mentioned in a comment does not count as present.
func scriptCode(run string) string {
	var kept []string
	for _, line := range strings.Split(run, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}

// TestSelfScanWorkflowCountsFromStatsAndFailsClosed checks the text for each mechanism #767 named.
func TestSelfScanWorkflowCountsFromStatsAndFailsClosed(t *testing.T) {
	wf, raw := loadSelfScanWorkflow(t)

	// The defect itself, anywhere in the file: a numeric score compared with a band name.
	if m := regexp.MustCompile(`\.confidence\s*==`).FindString(raw); m != "" {
		t.Errorf("%s compares `.confidence` with a value (%q). `confidence` is the numeric score; the "+
			"band is `confidence_level`, and counts come from `.stats` (#767)", selfScanWorkflowPath, m)
	}

	for _, name := range []string{stepScanChangedFiles, stepScanFullRepo} {
		code := scriptCode(wf.step(t, name).Run)
		for _, want := range []string{
			`jq -e '.stats.high | numbers'`,
			`jq -e '.stats.medium | numbers'`,
			`jq -e '.stats.files_not_examined // 0 | numbers'`,
			"--fail-on-incomplete",
			`echo "scan_ran=true" >> "$GITHUB_ENV"`,
		} {
			if !strings.Contains(code, want) {
				t.Errorf("step %q does not contain %s outside a comment", name, want)
			}
		}
	}

	// A count must not be able to fail into a number: `wc -l` succeeds on empty input, `|| echo "0"`
	// replaces any failure, and `2>/dev/null` hides the reason. Checked on every run: line of the job.
	devNull := regexp.MustCompile(`2>\s*/dev/null`)
	for _, s := range wf.Jobs["ferret-scan"].Steps {
		for i, line := range strings.Split(s.Run, "\n") {
			if strings.Contains(line, "wc -l") {
				t.Errorf("step %q run line %d counts with wc -l: %s", s.Name, i+1, strings.TrimSpace(line))
			}
			if (strings.Contains(line, "jq ") || strings.Contains(line, "ferret-scan")) && devNull.MatchString(line) {
				t.Errorf("step %q run line %d discards stderr: %s", s.Name, i+1, strings.TrimSpace(line))
			}
			if strings.Contains(line, `type == "array"`) {
				t.Errorf("step %q run line %d still handles a bare-array report, which #296 removed: %s",
					s.Name, i+1, strings.TrimSpace(line))
			}
		}
	}

	// GATE_MODE: block | report, `block` for every copy, `report` for this repository (#767).
	const wantMode = "${{ github.repository == 'awslabs/ferret-scan' && 'report' || 'block' }}"
	if got, _ := wf.Env["GATE_MODE"].(string); got != wantMode {
		t.Errorf("workflow env GATE_MODE = %q, want %q", got, wantMode)
	}
	gate := wf.step(t, stepGate)
	if gate.If != gateCondition {
		t.Errorf("gate step `if:` = %q, want %q: it must run whenever a scan started, failed or not", gate.If, gateCondition)
	}
	if !strings.Contains(gate.Run, "block|report)") {
		t.Errorf("gate step does not validate GATE_MODE against block|report")
	}

	// The comment prints the band, names the mode, and never defaults a missing count to '0'.
	script, _ := wf.step(t, stepPRComment).With["script"].(string)
	for _, want := range []string{"finding.confidence_level", "env.GATE_MODE", "No files were scanned"} {
		if !strings.Contains(script, want) {
			t.Errorf("PR comment script does not contain %s", want)
		}
	}
	for _, bad := range []string{"finding.confidence ||", "|| '0'"} {
		if strings.Contains(script, bad) {
			t.Errorf("PR comment script contains %q", bad)
		}
	}
}

// stepResult is what one run: script did: its exit code, its output, and GITHUB_ENV afterwards.
type stepResult struct {
	code   int
	output string
	env    map[string]string
}

var workflowExpr = regexp.MustCompile(`\$\{\{\s*(.*?)\s*\}\}`)

// runWorkflowScript runs a step's run: script in dir as a Linux runner runs a step with no `shell:`:
// `bash -e <script file>`, with GITHUB_ENV, GITHUB_OUTPUT and GITHUB_STEP_SUMMARY pointing at files.
// The step's env is resolved from exprs, and `env.NAME` from the GITHUB_ENV written so far; any
// other expression fails the test instead of reaching the script as literal text.
func runWorkflowScript(t *testing.T, s workflowStep, dir, ghEnvFile string, exprs map[string]string, extra ...string) stepResult {
	t.Helper()
	scratch := t.TempDir()
	script := filepath.Join(scratch, "step.sh")
	if err := os.WriteFile(script, []byte(s.Run), 0o600); err != nil {
		t.Fatal(err)
	}
	before := readGitHubEnv(t, ghEnvFile)
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + t.TempDir(), // no user config or suppressions reach the scan
		"GITHUB_ENV=" + ghEnvFile,
		"GITHUB_OUTPUT=" + filepath.Join(scratch, "output"),
		"GITHUB_STEP_SUMMARY=" + filepath.Join(scratch, "summary.md"),
	}
	for k, v := range s.Env {
		val := workflowExpr.ReplaceAllStringFunc(fmt.Sprint(v), func(m string) string {
			expr := workflowExpr.FindStringSubmatch(m)[1]
			if name, ok := strings.CutPrefix(expr, "env."); ok {
				return before[name] // an unset env value is '' in an expression
			}
			r, ok := exprs[expr]
			if !ok {
				t.Fatalf("step %q env %s uses ${{ %s }}, which this test does not model", s.Name, k, expr)
			}
			return r
		})
		env = append(env, k+"="+val)
	}
	env = append(env, extra...)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-e", script)
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok || ctx.Err() != nil {
			t.Fatalf("running step %q: %v (ctx: %v)\n%s", s.Name, err, ctx.Err(), out)
		}
		code = ee.ExitCode()
	}
	return stepResult{code: code, output: string(out), env: readGitHubEnv(t, ghEnvFile)}
}

// readGitHubEnv parses NAME=value lines; a later line for the same name wins, as on a runner.
func readGitHubEnv(t *testing.T, path string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- a file this test created
	if err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if line == "" {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("GITHUB_ENV line %q is not NAME=value", line)
		}
		vars[name] = value
	}
	return vars
}

// highFixture returns n distinct `password=` lines, each a HIGH finding: a 24-character mixed-case
// value with digits. Assembled from pieces so this source holds no credential-shaped literal.
func highFixture(n int) string {
	var b strings.Builder
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, "db_%03d:\n  %s=%s%04d%s\n", i, "pass"+"word", "Qz8Wm3Lp7Rk2"+"Tn6V", (i*37)%9973, "HjYc")
	}
	return b.String()
}

// TestSelfScanWorkflowScriptsGateOnRealCounts runs the workflow's scan and gate scripts for the
// cases #767 lists. Against the workflow as it was, "one HIGH finding" records high_findings=0.
func TestSelfScanWorkflowScriptsGateOnRealCounts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the workflow's run: scripts are bash and the job runs on ubuntu")
	}
	for _, tool := range []string{"bash", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s is not on PATH (%v); the workflow's scripts need it, and skipping would leave "+
				"the gate untested", tool, err)
		}
	}
	wf, _ := loadSelfScanWorkflow(t)
	ferret := buildForCLIContract(t)
	exprs := map[string]string{"steps.scope.outputs.confidence": "high,medium"}

	// checkout lays out what the scan steps see: a repository root holding bin/ferret-scan and the
	// files. bin/ferret-scan is a two-line shim that execs the built binary, so the full-repository
	// scan reads the fixtures and the shim rather than the binary itself.
	checkout := func(t *testing.T, shim string, files map[string]string, changed ...string) (dir, ghEnv string) {
		t.Helper()
		dir = t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o700); err != nil {
			t.Fatal(err)
		}
		if shim == "" {
			shim = "#!/bin/sh\nexec \"$FERRET_REAL_BIN\" \"$@\"\n"
		}
		if err := os.WriteFile(filepath.Join(dir, "bin", "ferret-scan"), []byte(shim), 0o700); err != nil { // #nosec G306 -- the step executes it
			t.Fatal(err)
		}
		for name, content := range files {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if len(changed) > 0 {
			list := strings.Join(changed, "\n") + "\n"
			if err := os.WriteFile(filepath.Join(dir, "changed_files.txt"), []byte(list), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		ghEnv = filepath.Join(t.TempDir(), "github_env")
		if err := os.WriteFile(ghEnv, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		return dir, ghEnv
	}
	realBin := "FERRET_REAL_BIN=" + ferret

	scan := func(t *testing.T, step, dir, ghEnv string) stepResult {
		t.Helper()
		return runWorkflowScript(t, wf.step(t, step), dir, ghEnv, exprs, realBin)
	}
	// gate evaluates the gate step's `if:` against GITHUB_ENV and runs it in mode; ran is false when
	// the condition skips it.
	gate := func(t *testing.T, dir, ghEnv, mode string) (ran bool, r stepResult) {
		t.Helper()
		g := wf.step(t, stepGate)
		if g.If != gateCondition {
			t.Fatalf("gate step `if:` is %q; this test models only %q", g.If, gateCondition)
		}
		if readGitHubEnv(t, ghEnv)["scan_ran"] != "true" {
			return false, stepResult{}
		}
		return true, runWorkflowScript(t, g, dir, ghEnv, exprs, "GATE_MODE="+mode)
	}
	expectEnv := func(t *testing.T, r stepResult, want map[string]string) {
		t.Helper()
		for k, v := range want {
			if got, ok := r.env[k]; !ok || got != v {
				t.Errorf("GITHUB_ENV %s = %q (set: %v), want %q", k, got, ok, v)
			}
		}
		if t.Failed() {
			t.Logf("scan step output:\n%s", r.output)
		}
	}
	expectGate := func(t *testing.T, dir, ghEnv, mode string, wantFail bool) {
		t.Helper()
		ran, r := gate(t, dir, ghEnv, mode)
		if !ran {
			t.Errorf("GATE_MODE=%s: the gate step was skipped (scan_ran is not 'true')", mode)
			return
		}
		if failed := r.code != 0; failed != wantFail {
			t.Errorf("GATE_MODE=%s: gate exit %d, want failure=%v\n%s", mode, r.code, wantFail, r.output)
		}
	}

	oneHigh := map[string]string{"app.conf": "db:\n  " + "pass" + "word=" + "Xq7Lm2Pz9Rt4" + "Vb8Nk3Jh6Wd5" + "\n"}
	clean := map[string]string{"notes.yaml": "the quick brown fox jumps over the lazy dog\n"}

	for _, scope := range []struct{ step, label string }{
		{stepScanChangedFiles, "changed-files"},
		{stepScanFullRepo, "full-repository"},
	} {
		t.Run(scope.label+"/one HIGH finding", func(t *testing.T) {
			dir, ghEnv := checkout(t, "", oneHigh, "app.conf")
			r := scan(t, scope.step, dir, ghEnv)
			if r.code != 0 {
				t.Fatalf("scan step exit %d\n%s", r.code, r.output)
			}
			expectEnv(t, r, map[string]string{
				"scan_ran": "true", "high_findings": "1", "medium_findings": "0",
				"files_not_examined": "0", "scan_exit_code": "0", "results_truncated": "false",
			})
			if !strings.Contains(r.output, "High confidence findings: 1") {
				t.Errorf("the log does not say `High confidence findings: 1`:\n%s", r.output)
			}
			expectGate(t, dir, ghEnv, "block", true)
			expectGate(t, dir, ghEnv, "report", false)
		})

		t.Run(scope.label+"/clean file", func(t *testing.T) {
			dir, ghEnv := checkout(t, "", clean, "notes.yaml")
			r := scan(t, scope.step, dir, ghEnv)
			if r.code != 0 {
				t.Fatalf("scan step exit %d\n%s", r.code, r.output)
			}
			expectEnv(t, r, map[string]string{
				"scan_ran": "true", "high_findings": "0", "medium_findings": "0",
				"files_not_examined": "0", "scan_exit_code": "0",
			})
			if n := r.env["files_scanned"]; n == "" || n == "0" {
				t.Errorf("files_scanned = %q; a clean verdict needs files that were actually examined", n)
			}
			expectGate(t, dir, ghEnv, "block", false)
			expectGate(t, dir, ghEnv, "report", false)
		})

		t.Run(scope.label+"/ferret output is not JSON", func(t *testing.T) {
			dir, ghEnv := checkout(t, "#!/bin/sh\necho 'this is not a report'\n", oneHigh, "app.conf")
			r := scan(t, scope.step, dir, ghEnv)
			if r.code == 0 {
				t.Errorf("the scan step exited 0 on output it could not read; a count must not read as 0\n"+
					"GITHUB_ENV: %v\n%s", r.env, r.output)
			}
			expectGate(t, dir, ghEnv, "block", true)
			expectGate(t, dir, ghEnv, "report", true)
		})
	}

	t.Run("changed-files/unreadable file", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads a mode-000 file, so it cannot be made unreadable")
		}
		dir, ghEnv := checkout(t, "", oneHigh, "app.conf")
		locked := filepath.Join(dir, "app.conf")
		if err := os.Chmod(locked, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(locked, 0o600) })
		r := scan(t, stepScanChangedFiles, dir, ghEnv)
		if r.code != 0 {
			t.Fatalf("scan step exit %d; it should record the failure for the gate\n%s", r.code, r.output)
		}
		expectEnv(t, r, map[string]string{
			"scan_ran": "true", "files_not_examined": "1", "scan_exit_code": "3", "high_findings": "0",
		})
		if !strings.Contains(r.output, "NOT FULLY EXAMINED") {
			t.Errorf("ferret's not-examined disclosure is missing from the log:\n%s", r.output)
		}
		expectGate(t, dir, ghEnv, "block", true)
		expectGate(t, dir, ghEnv, "report", true)
	})

	t.Run("changed-files/201 HIGH findings, past the default --limit", func(t *testing.T) {
		dir, ghEnv := checkout(t, "", map[string]string{"many.conf": highFixture(201)}, "many.conf")
		r := scan(t, stepScanChangedFiles, dir, ghEnv)
		if r.code != 0 {
			t.Fatalf("scan step exit %d\n%s", r.code, r.output)
		}
		expectEnv(t, r, map[string]string{"high_findings": "201", "results_truncated": "true"})
		expectGate(t, dir, ghEnv, "block", true)
	})

	t.Run("changed-files/HIGH and LOW files with high,medium requested", func(t *testing.T) {
		files := map[string]string{
			"app.conf": oneHigh["app.conf"],
			// AWS's documented example key, a LOW finding by design. Assembled from pieces.
			"aws.conf": "aws " + "AKIA" + "IOSFODNN7EXAMPLE" + "\n",
		}
		dir, ghEnv := checkout(t, "", files, "app.conf", "aws.conf")
		r := scan(t, stepScanChangedFiles, dir, ghEnv)
		if r.code != 0 {
			t.Fatalf("scan step exit %d\n%s", r.code, r.output)
		}
		// Non-vacuity: the LOW finding is in stats but not in results, which is exactly what a
		// comparison against total_findings would misread as truncation.
		var low struct {
			Stats   struct{ High, Medium, Low int } `json:"stats"`
			Results []json.RawMessage               `json:"results"`
		}
		b, err := os.ReadFile(filepath.Join(dir, "results", "aws.conf.json")) // #nosec G304 -- written by the step
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &low); err != nil {
			t.Fatal(err)
		}
		if low.Stats.Low < 1 || low.Stats.High != 0 || low.Stats.Medium != 0 || len(low.Results) != 0 {
			t.Fatalf("aws.conf report is %s; this case needs a LOW-only report with no results", b)
		}
		expectEnv(t, r, map[string]string{"high_findings": "1", "medium_findings": "0", "results_truncated": "false"})
	})

	t.Run("no relevant file changed", func(t *testing.T) {
		// The scan step is skipped by its own `if:`, so nothing writes GITHUB_ENV and the gate's
		// condition is false. The comment's "No files were scanned" branch is checked by the test above.
		if s := wf.step(t, stepScanChangedFiles); !strings.Contains(s.If, "steps.changed-files.outputs.has_files == 'true'") {
			t.Fatalf("the changed-files scan's `if:` is %q; this case assumes it requires has_files", s.If)
		}
		dir, ghEnv := checkout(t, "", nil)
		if ran, r := gate(t, dir, ghEnv, "block"); ran {
			t.Errorf("the gate ran with no scan (exit %d)\n%s", r.code, r.output)
		}
	})

	t.Run("unknown GATE_MODE fails", func(t *testing.T) {
		dir, ghEnv := checkout(t, "", clean, "notes.yaml")
		if r := scan(t, stepScanChangedFiles, dir, ghEnv); r.code != 0 {
			t.Fatalf("scan step exit %d\n%s", r.code, r.output)
		}
		expectGate(t, dir, ghEnv, "warn", true)
	})
}

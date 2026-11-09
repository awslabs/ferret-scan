// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
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

// #927: .github/workflows/ferret-scan.yml, this repository's self-scan, blocks on HIGH. The scan is
// scripts/self-scan.sh (docs/testing/SELF_SCAN.md): the committed profile .ferret-scan/selfscan.yaml,
// the reviewed suppression ledger it names, two gates (shippable files with every check, *_test.go
// with SECRETS only), counts from each report's `stats`. The workflow runs the script once per scope
// with --mode "$GATE_MODE", and its gate step reads the script's <out>/summary.env and fails closed.
//
// The workflow before it counted findings itself, and for a long time wrongly (#767): it selected
// `.confidence == "HIGH"`, a band name compared with a field that is a NUMBER, so every count was 0,
// the gate never ran and the PR comment said "No sensitive data detected" over thousands of HIGH
// findings; `jq … 2>/dev/null | wc -l || echo "0"` turned every other failure into a 0 as well.
//
// Two tests guard it. The first reads the workflow for the contract: GATE_MODE, the script and its
// arguments, no extension filter, the fail-closed shapes. The second runs the workflow's own step
// scripts, as a Linux runner runs a `run:` step with no `shell:` (`bash -e <script>`), in a git
// checkout holding the profile, an empty ledger, the script and each case's files, with the binary
// this package builds, and checks each step's exit status and the gate's verdict in both modes.

const selfScanWorkflowPath = "../.github/workflows/ferret-scan.yml"

// The steps are found by name. A renamed step fails here loudly rather than being skipped.
const (
	stepDownload         = "Download binary"
	stepChmod            = "Make binary executable"
	stepScope            = "Determine scan scope"
	stepChangedFiles     = "Get changed files (PR only)"
	stepScanChangedFiles = "Run Ferret Scan on changed files"
	stepScanFullRepo     = "Run Ferret Scan on full repository"
	stepPRComment        = "Create PR comment"
	stepUpload           = "Upload scan results"
	stepGate             = "Gate on scan result and high confidence findings"
)

// The `if:` conditions the second test evaluates. A step with any other condition fails it, so a
// changed condition is modelled before it is trusted.
const (
	ifChangedFiles     = "steps.scope.outputs.scope == 'changed-files'"
	ifScanChangedFiles = "steps.scope.outputs.scope == 'changed-files' && steps.changed-files.outputs.has_files == 'true'"
	ifScanFullRepo     = "steps.scope.outputs.scope == 'full-repository'"
	ifUpload           = "always() && env.scan_ran == 'true'"
	gateCondition      = "always()"
)

const (
	selfScanScript = "scripts/self-scan.sh"
	selfScanOut    = `--out "$RUNNER_TEMP/self-scan"`
	selfScanBin    = "bin/ferret-scan" // where the download step puts the build job's binary
)

type workflowStep struct {
	Name string         `yaml:"name"`
	ID   string         `yaml:"id"`
	If   string         `yaml:"if"`
	Env  map[string]any `yaml:"env"`
	Run  string         `yaml:"run"`
	With map[string]any `yaml:"with"`
}

type selfScanWorkflow struct {
	On          map[string]any    `yaml:"on"`
	Permissions map[string]string `yaml:"permissions"`
	Env         map[string]any    `yaml:"env"`
	Jobs        map[string]struct {
		Permissions map[string]string `yaml:"permissions"`
		Steps       []workflowStep    `yaml:"steps"`
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

// TestSelfScanWorkflowRunsTheScriptInBlockModeAndFailsClosed reads the workflow for the contract.
func TestSelfScanWorkflowRunsTheScriptInBlockModeAndFailsClosed(t *testing.T) {
	wf, raw := loadSelfScanWorkflow(t)

	// #767's defect, anywhere in the file: a numeric score compared with a band name.
	if m := regexp.MustCompile(`\.confidence\s*==`).FindString(raw); m != "" {
		t.Errorf("%s compares `.confidence` with a value (%q). `confidence` is the numeric score; the "+
			"band is `confidence_level`, and counts come from `.stats` (#767)", selfScanWorkflowPath, m)
	}

	// This repository blocks on HIGH (#927): a literal, with no repository condition.
	if got, _ := wf.Env["GATE_MODE"].(string); got != "block" {
		t.Errorf("workflow env GATE_MODE = %q, want the literal \"block\" (#927)", got)
	}

	// Every pull request is scanned. The trigger used to list nine extensions under `paths:`, so a
	// pull request that changed only other files never ran the scan at all.
	switch pr := wf.On["pull_request"].(type) {
	case nil:
		if _, ok := wf.On["pull_request"]; !ok {
			t.Errorf("%s has no pull_request trigger", selfScanWorkflowPath)
		}
	case map[string]any:
		for _, filter := range []string{"paths", "paths-ignore"} {
			if _, ok := pr[filter]; ok {
				t.Errorf("on.pull_request has a %s filter; every pull request must be scanned", filter)
			}
		}
	default:
		t.Errorf("on.pull_request is %#v; want the bare trigger or a map", pr)
	}

	// Read-only on the repository, plus pull-requests: write for the results comment; nothing wider.
	allowed := map[string]string{"contents": "read", "pull-requests": "write"}
	for where, perms := range map[string]map[string]string{
		"workflow":        wf.Permissions,
		"job ferret-scan": wf.Jobs["ferret-scan"].Permissions,
	} {
		for scope, level := range perms {
			if allowed[scope] != level {
				t.Errorf("%s permissions grant %s: %s; the job needs contents: read and pull-requests: write only",
					where, scope, level)
			}
		}
	}
	if jp := wf.Jobs["ferret-scan"].Permissions; jp["contents"] != "read" || jp["pull-requests"] != "write" {
		t.Errorf("job ferret-scan permissions = %v; want contents: read and pull-requests: write, set on the job", jp)
	}

	// The changed files are every file the pull request adds, copies, modifies or renames, against
	// the merge base. No extension filter: the old step piped the names through
	// `grep -E '\.(py|js|ts|go|java|json|yaml|yml|env|conf|config)$'` and dropped every *_test.go
	// with a second grep, so neither was ever scanned.
	cf := wf.step(t, stepChangedFiles)
	if cf.If != ifChangedFiles {
		t.Errorf("step %q `if:` = %q, want %q", stepChangedFiles, cf.If, ifChangedFiles)
	}
	cfCode := scriptCode(cf.Run)
	for _, want := range []string{"--diff-filter=ACMR", `"$BASE_SHA...$HEAD_SHA"`, "core.quotePath=false", "> changed_files.txt"} {
		if !strings.Contains(cfCode, want) {
			t.Errorf("step %q does not contain %s outside a comment", stepChangedFiles, want)
		}
	}
	for _, bad := range []string{"grep", " -- "} {
		if strings.Contains(cfCode, bad) {
			t.Errorf("step %q filters the changed files (%q); the script decides what to scan", stepChangedFiles, bad)
		}
	}

	// The download step puts the binary where the scan steps' FERRET_BIN points.
	if got := fmt.Sprint(wf.step(t, stepDownload).With["path"]); got != "bin/" {
		t.Errorf("step %q path = %q, want bin/ (FERRET_BIN is %s)", stepDownload, got, selfScanBin)
	}

	// Both scan steps are the script. The profile owns the excludes and the ledger and the script
	// owns the flags, so none is passed here; and nothing may turn its exit status into success or
	// hide its output.
	invocation := regexp.MustCompile(`^([A-Z_]+=\S+\s+)*` + regexp.QuoteMeta(selfScanScript) + `\s`)
	swallow := regexp.MustCompile(`\|\|\s*(true\b|:|exit\s+0\b)|\bset\s+\+e\b|>\s*/dev/null`)
	for _, sc := range []struct {
		name, cond string
		args       []string
	}{
		{stepScanChangedFiles, ifScanChangedFiles, []string{"--scope changed", "--files changed_files.txt"}},
		{stepScanFullRepo, ifScanFullRepo, []string{"--scope tree"}},
	} {
		s := wf.step(t, sc.name)
		if s.If != sc.cond {
			t.Errorf("step %q `if:` = %q, want %q", sc.name, s.If, sc.cond)
		}
		if got := fmt.Sprint(s.Env["FERRET_BIN"]); got != selfScanBin {
			t.Errorf("step %q env FERRET_BIN = %q, want %s (the downloaded build)", sc.name, got, selfScanBin)
		}
		code := scriptCode(s.Run)
		var calls []string
		for _, line := range strings.Split(code, "\n") {
			if strings.Contains(line, selfScanScript) {
				calls = append(calls, strings.TrimSpace(line))
			}
		}
		if len(calls) != 1 {
			t.Errorf("step %q runs %s %d times outside comments, want once: %q", sc.name, selfScanScript, len(calls), calls)
			continue
		}
		call := calls[0]
		if !invocation.MatchString(call) || strings.ContainsAny(call, "|&;<>!") {
			t.Errorf("step %q runs the script as %q; it must be a plain command, not in a pipeline, a list, "+
				"a negation or a redirect, so its exit status is the step's", sc.name, call)
		}
		for _, want := range append([]string{`--mode "$GATE_MODE"`, selfScanOut}, sc.args...) {
			if !strings.Contains(call, want) {
				t.Errorf("step %q does not pass %s to the script: %s", sc.name, want, call)
			}
		}
		for _, flag := range []string{"--confidence", "--fail-on-incomplete", "--checks", "--exclude",
			"--config", "--suppressions", "--suppression-file", "--regenerate"} {
			if strings.Contains(call, flag) {
				t.Errorf("step %q passes %s; the profile and the script own it: %s", sc.name, flag, call)
			}
		}
		if m := swallow.FindString(code); m != "" {
			t.Errorf("step %q contains %q, which swallows the script's exit status or output", sc.name, m)
		}
		// Recorded before the script runs, so the gate reads summary.env even when the script fails.
		at := strings.Index(code, selfScanScript)
		for _, want := range []string{
			`echo "scan_ran=true" >> "$GITHUB_ENV"`,
			`echo "self_scan_out=$RUNNER_TEMP/self-scan" >> "$GITHUB_ENV"`,
		} {
			if i := strings.Index(code, want); i < 0 || i > at {
				t.Errorf("step %q does not run `%s` before the script", sc.name, want)
			}
		}
	}

	// A count must not be able to fail into a number: `wc -l` succeeds on empty input, and
	// `2>/dev/null` hides the reason. Checked on every run: line of the job.
	devNull := regexp.MustCompile(`2>\s*/dev/null`)
	for _, s := range wf.Jobs["ferret-scan"].Steps {
		for i, line := range strings.Split(s.Run, "\n") {
			if strings.Contains(line, "wc -l") {
				t.Errorf("step %q run line %d counts with wc -l: %s", s.Name, i+1, strings.TrimSpace(line))
			}
			if (strings.Contains(line, "jq ") || strings.Contains(line, "ferret-scan") || strings.Contains(line, "self-scan")) &&
				devNull.MatchString(line) {
				t.Errorf("step %q run line %d discards stderr: %s", s.Name, i+1, strings.TrimSpace(line))
			}
		}
	}

	// The gate runs after every scan and when none ran; the second test runs what it decides.
	gate := wf.step(t, stepGate)
	if gate.If != gateCondition {
		t.Errorf("gate step `if:` = %q, want %q: it must run whether the scan passed, failed or never started",
			gate.If, gateCondition)
	}
	gateCode := scriptCode(gate.Run)
	for _, want := range []string{"block|report)", "summary.env", `exit "$fail"`} {
		if !strings.Contains(gateCode, want) {
			t.Errorf("gate step does not contain %s outside a comment", want)
		}
	}
	if m := regexp.MustCompile(`(?m)^\s*(\.|source|eval)\s`).FindString(gateCode); m != "" {
		t.Errorf("gate step runs %q; summary.env is read with sed, never sourced or evaluated", strings.TrimSpace(m))
	}

	// The upload is the script's out dir, whenever a scan started.
	up := wf.step(t, stepUpload)
	if up.If != ifUpload || fmt.Sprint(up.With["path"]) != "${{ env.self_scan_out }}" {
		t.Errorf("upload step `if:` = %q, path = %v; want %q and ${{ env.self_scan_out }}", up.If, up.With["path"], ifUpload)
	}

	// The comment names the mode, reads summary.env, shows HIGH, suppressed (a suppression is
	// visible as a suppression, TM-11) and not fully examined, points at the guide, and never
	// defaults a missing count to '0'.
	script, _ := wf.step(t, stepPRComment).With["script"].(string)
	for _, want := range []string{"env.GATE_MODE", "summary.env", "No files were scanned", "suppressed",
		"not fully examined", "docs/testing/SELF_SCAN.md"} {
		if !strings.Contains(script, want) {
			t.Errorf("PR comment script does not contain %s", want)
		}
	}
	for _, bad := range []string{"|| '0'", "?? '0'"} {
		if strings.Contains(script, bad) {
			t.Errorf("PR comment script contains %q", bad)
		}
	}
}

// stepResult is what one run: script did: its exit status, its output, GITHUB_ENV afterwards, and
// what it wrote to GITHUB_OUTPUT and GITHUB_STEP_SUMMARY.
type stepResult struct {
	code    int
	output  string
	env     map[string]string
	outputs map[string]string
	summary string
}

var workflowExpr = regexp.MustCompile(`\$\{\{\s*(.*?)\s*\}\}`)

// runWorkflowScript runs a step's run: script in dir as a Linux runner runs a step with no `shell:`:
// `bash -e <script file>`, with GITHUB_ENV, GITHUB_OUTPUT and GITHUB_STEP_SUMMARY pointing at files,
// and what earlier steps wrote to GITHUB_ENV in its environment. The step's env is resolved from
// exprs, and `env.NAME` from GITHUB_ENV; any other expression fails the test instead of reaching the
// script as literal text. extra comes last, so it overrides the step's env.
func runWorkflowScript(t *testing.T, s workflowStep, dir, ghEnvFile string, exprs map[string]string, extra ...string) stepResult {
	t.Helper()
	scratch := t.TempDir()
	script := filepath.Join(scratch, "step.sh")
	output := filepath.Join(scratch, "output")
	summary := filepath.Join(scratch, "summary.md")
	for path, content := range map[string]string{script: s.Run, output: "", summary: ""} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	before := readGitHubEnv(t, ghEnvFile)
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + t.TempDir(), // no user config or suppressions reach the scan
		"TMPDIR=" + t.TempDir(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GITHUB_ENV=" + ghEnvFile,
		"GITHUB_OUTPUT=" + output,
		"GITHUB_STEP_SUMMARY=" + summary,
	}
	for name, value := range before {
		env = append(env, name+"="+value)
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
	written, err := os.ReadFile(summary) // #nosec G304 -- a file this test created
	if err != nil {
		t.Fatal(err)
	}
	return stepResult{
		code:    code,
		output:  string(out),
		env:     readGitHubEnv(t, ghEnvFile),
		outputs: readGitHubEnv(t, output),
		summary: string(written),
	}
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

// selfScanCheckout is the repository the job runs in, and the base and head commits of the pull
// request it stands for.
type selfScanCheckout struct{ dir, base, head string }

// newSelfScanCheckout lays out the checkout the job sees: a git repository whose first commit holds
// the profile, an empty ledger at the path the profile names and scripts/self-scan.sh, from this
// tree, and whose second commit adds files. With no files there is no second commit: head is base,
// a pull request that changes nothing. The three files read HIGH 0 with an empty ledger, so a finding
// in one of them would show up in every push case.
func newSelfScanCheckout(t *testing.T, files map[string]string) selfScanCheckout {
	t.Helper()
	const profilePath = ".ferret-scan/selfscan.yaml"
	profile := readRepoFile(t, profilePath)
	var p struct {
		Suppressions struct {
			File string `yaml:"file"`
		} `yaml:"suppressions"`
	}
	if err := yaml.Unmarshal(profile, &p); err != nil || p.Suppressions.File == "" {
		t.Fatalf("%s names no suppressions.file (%v)", profilePath, err)
	}
	dir := t.TempDir()
	writeCheckoutFile(t, dir, profilePath, profile, 0o600)
	writeCheckoutFile(t, dir, p.Suppressions.File, emptyLedger(t, readRepoFile(t, p.Suppressions.File)), 0o600)
	writeCheckoutFile(t, dir, selfScanScript, readRepoFile(t, selfScanScript), 0o700)
	gitIn(t, dir, "init", "-q")
	gitIn(t, dir, "add", "-A")
	gitIn(t, dir, "commit", "-q", "-m", "base")
	co := selfScanCheckout{dir: dir, base: gitIn(t, dir, "rev-parse", "HEAD")}
	co.head = co.base
	if len(files) > 0 {
		for name, content := range files {
			writeCheckoutFile(t, dir, name, []byte(content), 0o600)
		}
		gitIn(t, dir, "add", "-A")
		gitIn(t, dir, "commit", "-q", "-m", "change")
		co.head = gitIn(t, dir, "rev-parse", "HEAD")
	}
	return co
}

// emptyLedger keeps the real ledger's settings up to its `rules:` line, so its format version is
// the one the repository uses, and no rule.
func emptyLedger(t *testing.T, ledger []byte) []byte {
	t.Helper()
	kept := []string{"# An empty ledger: no finding is suppressed.\n"}
	for _, line := range strings.SplitAfter(string(ledger), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		kept = append(kept, line)
		if strings.TrimRight(line, " \t\r\n") == "rules:" {
			return []byte(strings.Join(kept, ""))
		}
	}
	t.Fatalf("the ledger has no top-level `rules:` line")
	return nil
}

func readRepoFile(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", rel)) // #nosec G304 -- a fixed path in this repository
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeCheckoutFile(t *testing.T, dir, rel string, content []byte, mode os.FileMode) {
	t.Helper()
	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, mode); err != nil { // #nosec G306 -- the script is executed
		t.Fatal(err)
	}
}

// gitIn runs git in dir with no user or system configuration and returns its trimmed output.
func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "init.defaultBranch=main", "-c", "commit.gpgsign=false"}, args...)...) // #nosec G204 -- literal arguments from this test
	cmd.Dir = dir
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + t.TempDir(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=ferret-scan test", "GIT_AUTHOR_EMAIL=ferret-scan-test",
		"GIT_COMMITTER_NAME=ferret-scan test", "GIT_COMMITTER_EMAIL=ferret-scan-test",
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

// modelledSteps are the run: steps runJob runs. The chmod of the downloaded binary is the one it
// leaves out: here the binary is FERRET_BIN. A new run: step fails runJob until it is added.
var modelledSteps = map[string]bool{
	stepScope: true, stepChangedFiles: true, stepScanChangedFiles: true, stepScanFullRepo: true, stepGate: true,
}

// jobRun is what the job's run: steps did for one event, by step name. A step that did not run is
// absent.
type jobRun map[string]stepResult

// runJob runs the job's run: steps in workflow order for event (pull_request or push), as a runner
// does: each `if:` is evaluated from the step outputs so far, a failed step skips the later steps
// whose `if:` does not say always(), and GITHUB_ENV carries from step to step. GATE_MODE is mode,
// FERRET_BIN the built binary and RUNNER_TEMP a new directory; extra overrides any of them. The
// uses: steps are not run: the comment and the upload only read what the run: steps wrote.
func runJob(t *testing.T, wf selfScanWorkflow, ferret string, co selfScanCheckout, event, mode string, extra ...string) jobRun {
	t.Helper()
	ghEnv := filepath.Join(t.TempDir(), "github_env")
	if err := os.WriteFile(ghEnv, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	exprs := map[string]string{
		"github.event_name":                  event,
		"github.event.inputs.scan_scope":     "",
		"github.event.pull_request.base.sha": "",
		"github.event.pull_request.head.sha": "",
		// An output no step wrote is '' in an expression.
		"steps.scope.outputs.scope":             "",
		"steps.changed-files.outputs.has_files": "",
	}
	if event == "pull_request" {
		exprs["github.event.pull_request.base.sha"] = co.base
		exprs["github.event.pull_request.head.sha"] = co.head
	}
	env := append([]string{
		"GATE_MODE=" + mode,
		"FERRET_BIN=" + ferret,
		"RUNNER_TEMP=" + t.TempDir(),
		"GITHUB_SERVER_URL=https://github.com",
		"GITHUB_REPOSITORY=awslabs/ferret-scan",
		"GITHUB_SHA=" + co.head,
	}, extra...)

	run := jobRun{}
	failed := false
	for _, s := range wf.Jobs["ferret-scan"].Steps {
		if s.Run == "" || s.Name == stepChmod {
			continue
		}
		if !modelledSteps[s.Name] {
			t.Fatalf("run: step %q is not one this test models; add it to runJob", s.Name)
		}
		if !stepCondition(t, s, exprs, failed) {
			continue
		}
		r := runWorkflowScript(t, s, co.dir, ghEnv, exprs, env...)
		run[s.Name] = r
		if r.code != 0 {
			failed = true
		}
		if s.ID != "" {
			for name, value := range r.outputs {
				exprs["steps."+s.ID+".outputs."+name] = value
			}
		}
	}
	return run
}

// stepCondition evaluates a step's `if:` as the runner would, for the conditions this test knows.
// A condition without always() also needs every earlier step to have succeeded.
func stepCondition(t *testing.T, s workflowStep, exprs map[string]string, failed bool) bool {
	t.Helper()
	scope := exprs["steps.scope.outputs.scope"]
	switch s.If {
	case "":
		return !failed
	case ifChangedFiles:
		return !failed && scope == "changed-files"
	case ifScanChangedFiles:
		return !failed && scope == "changed-files" && exprs["steps.changed-files.outputs.has_files"] == "true"
	case ifScanFullRepo:
		return !failed && scope == "full-repository"
	case gateCondition:
		return true
	}
	t.Fatalf("step %q has `if: %s`, which this test does not model", s.Name, s.If)
	return false
}

// summaryEnv is the summary.env the scan step's script wrote, or nil when it wrote none.
func summaryEnv(t *testing.T, run jobRun) map[string]string {
	t.Helper()
	for _, name := range []string{stepScanChangedFiles, stepScanFullRepo} {
		r, ok := run[name]
		if !ok {
			continue
		}
		out := r.env["self_scan_out"]
		if out == "" {
			t.Errorf("step %q did not record self_scan_out in GITHUB_ENV", name)
			return nil
		}
		b, err := os.ReadFile(filepath.Join(out, "summary.env")) // #nosec G304 -- written by the step
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			t.Fatal(err)
		}
		vars := map[string]string{}
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			name, value, _ := strings.Cut(line, "=")
			vars[name] = value
		}
		return vars
	}
	return nil
}

// TestSelfScanWorkflowScriptsGateOnRealCounts runs the workflow's steps for each case, on a pull
// request and on a push where both apply, in block and in report mode, and checks the scan step's
// exit status, the summary.env the script wrote, and the gate's verdict.
func TestSelfScanWorkflowScriptsGateOnRealCounts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the workflow's run: scripts and scripts/self-scan.sh are bash, and the job runs on ubuntu")
	}
	for _, tool := range []string{"bash", "git", "jq", "tar"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s is not on PATH (%v); the workflow's scan needs it, and skipping would leave "+
				"the gate untested", tool, err)
		}
	}
	wf, _ := loadSelfScanWorkflow(t)
	ferret := buildForCLIContract(t)

	// outcome is what one job run must do: the scan step's exit status (the script's), whether the
	// gate fails, summary.env's high, exit and not_examined (exit "" means the script stopped before
	// writing one), and what the scan step's and the gate's logs must say.
	type outcome struct {
		scan        int
		fail        bool
		high, exit  string
		notExamined string
		scanSays    string
		gateSays    string
	}
	expect := func(t *testing.T, run jobRun, scanStep, scope, mode string, want outcome) {
		t.Helper()
		scan, ok := run[scanStep]
		if !ok {
			t.Fatalf("GATE_MODE=%s: step %q did not run", mode, scanStep)
		}
		if scan.code != want.scan {
			t.Errorf("GATE_MODE=%s: scan step exit %d, want %d\n%s", mode, scan.code, want.scan, scan.output)
		}
		if want.scanSays != "" && !strings.Contains(scan.output, want.scanSays) {
			t.Errorf("GATE_MODE=%s: the scan step's log does not say %q:\n%s", mode, want.scanSays, scan.output)
		}
		got := summaryEnv(t, run)
		switch {
		case want.exit == "" && got != nil:
			t.Errorf("GATE_MODE=%s: summary.env = %v; the script should have stopped before writing one", mode, got)
		case want.exit != "":
			for k, v := range map[string]string{"high": want.high, "suppressed": "0", "not_examined": want.notExamined,
				"exit": want.exit, "scope": scope, "mode": mode} {
				if got[k] != v {
					t.Errorf("GATE_MODE=%s: summary.env %s = %q, want %q (summary.env: %v)\n%s", mode, k, got[k], v, got, scan.output)
				}
			}
		}
		gate, ok := run[stepGate]
		if !ok {
			t.Fatalf("GATE_MODE=%s: the gate step did not run", mode)
		}
		if failed := gate.code != 0; failed != want.fail {
			t.Errorf("GATE_MODE=%s: gate exit %d, want failure=%v\n%s", mode, gate.code, want.fail, gate.output)
		}
		if want.gateSays != "" && !strings.Contains(gate.output, want.gateSays) {
			t.Errorf("GATE_MODE=%s: the gate's log does not say %q:\n%s", mode, want.gateSays, gate.output)
		}
	}

	clean := "the quick brown fox jumps over the lazy dog\n"
	green := outcome{scan: 0, fail: false, high: "0", exit: "0", notExamined: "0"}
	// SSN 100 under every check. Assembled from pieces, as is the key ID below.
	ssnLine := "package fixture\n\nvar ssn = \"" + "423-71-" + "5846" + "\"\n"
	// A synthetic AWS access key ID, AKIA and 16 characters: AWS_ACCESS_KEY 94. Not the documentation
	// example, which the validator demotes to LOW.
	keyLine := "package fixture\n\nconst awsKeyID = \"" + "AK" + "IA" + "ZQ4MX7RT" + "2VLK6HPN" + "\"\n"

	for _, sc := range []struct{ label, event, step, scope string }{
		{"pull request", "pull_request", stepScanChangedFiles, "changed"},
		{"push", "push", stepScanFullRepo, "tree"},
	} {
		inBoth := func(t *testing.T, co selfScanCheckout, block, report outcome) {
			t.Helper()
			expect(t, runJob(t, wf, ferret, co, sc.event, "block"), sc.step, sc.scope, "block", block)
			expect(t, runJob(t, wf, ferret, co, sc.event, "report"), sc.step, sc.scope, "report", report)
		}

		t.Run(sc.label+"/clean file", func(t *testing.T) {
			inBoth(t, newSelfScanCheckout(t, map[string]string{"notes.yaml": clean}), green, green)
		})

		t.Run(sc.label+"/HIGH in a shippable file", func(t *testing.T) {
			co := newSelfScanCheckout(t, map[string]string{"app.conf": highFixture(1)})
			inBoth(t, co,
				outcome{scan: 1, fail: true, high: "1", exit: "1", notExamined: "0", scanSays: "app.conf",
					gateSays: "Blocking merge: 1 HIGH"},
				outcome{scan: 0, fail: false, high: "1", exit: "0", notExamined: "0", scanSays: "app.conf",
					gateSays: "HIGH 1 (not suppressed)"})
		})

		t.Run(sc.label+"/SSN in a test file", func(t *testing.T) {
			// The tests gate checks SECRETS only: synthetic personal data in a test is the test's job.
			inBoth(t, newSelfScanCheckout(t, map[string]string{"ssn_test.go": ssnLine}), green, green)
			// Non-vacuity: the same file as shippable code blocks.
			run := runJob(t, wf, ferret, newSelfScanCheckout(t, map[string]string{"ssn.go": ssnLine}), sc.event, "block")
			expect(t, run, sc.step, sc.scope, "block", outcome{scan: 1, fail: true, high: "1", exit: "1", notExamined: "0"})
		})

		t.Run(sc.label+"/credential in a test file", func(t *testing.T) {
			co := newSelfScanCheckout(t, map[string]string{"aws_test.go": keyLine})
			inBoth(t, co,
				outcome{scan: 1, fail: true, high: "1", exit: "1", notExamined: "0", scanSays: "aws_test.go"},
				outcome{scan: 0, fail: false, high: "1", exit: "0", notExamined: "0", gateSays: "HIGH 1 (not suppressed)"})
		})

		t.Run(sc.label+"/unreadable file", func(t *testing.T) {
			if os.Geteuid() == 0 {
				t.Skip("root reads a mode-000 file, so it cannot be made unreadable")
			}
			co := newSelfScanCheckout(t, map[string]string{"app.conf": highFixture(1)})
			locked := filepath.Join(co.dir, "app.conf")
			if err := os.Chmod(locked, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(locked, 0o600) })
			failed := outcome{scan: 2, fail: true, high: "0", exit: "2", notExamined: "1",
				scanSays: "NOT FULLY EXAMINED", gateSays: "failed closed (exit 2)"}
			inBoth(t, co, failed, failed)
		})
	}

	t.Run("pull request/no file changed", func(t *testing.T) {
		co := newSelfScanCheckout(t, nil)
		for _, mode := range []string{"block", "report"} {
			run := runJob(t, wf, ferret, co, "pull_request", mode)
			if got := run[stepChangedFiles].outputs["has_files"]; got != "false" {
				t.Errorf("GATE_MODE=%s: has_files = %q, want false", mode, got)
			}
			for _, s := range []string{stepScanChangedFiles, stepScanFullRepo} {
				if r, ran := run[s]; ran {
					t.Errorf("GATE_MODE=%s: step %q ran with no file to scan\n%s", mode, s, r.output)
				}
			}
			gate, ran := run[stepGate]
			if !ran || gate.code != 0 || !strings.Contains(gate.output, "No files were scanned") ||
				!strings.Contains(gate.summary, "No files were scanned") {
				t.Errorf("GATE_MODE=%s: gate ran=%v exit %d; want a pass that says No files were scanned\n%s\nsummary:\n%s",
					mode, ran, gate.code, gate.output, gate.summary)
			}
		}
	})

	t.Run("pull request/unknown GATE_MODE", func(t *testing.T) {
		co := newSelfScanCheckout(t, map[string]string{"notes.yaml": clean})
		run := runJob(t, wf, ferret, co, "pull_request", "warn")
		expect(t, run, stepScanChangedFiles, "changed", "warn",
			outcome{scan: 2, fail: true, gateSays: "GATE_MODE is 'warn'"})
	})

	t.Run("pull request/the binary prints no report", func(t *testing.T) {
		shim := filepath.Join(t.TempDir(), "ferret-scan")
		if err := os.WriteFile(shim, []byte("#!/bin/sh\necho 'this is not a report'\n"), 0o700); err != nil { // #nosec G306 -- the script executes it
			t.Fatal(err)
		}
		co := newSelfScanCheckout(t, map[string]string{"app.conf": highFixture(1)})
		failed := outcome{scan: 2, fail: true, high: "0", exit: "2", notExamined: "0", gateSays: "failed closed (exit 2)"}
		for _, mode := range []string{"block", "report"} {
			expect(t, runJob(t, wf, ferret, co, "pull_request", mode, "FERRET_BIN="+shim),
				stepScanChangedFiles, "changed", mode, failed)
		}
	})

	t.Run("pull request/behind main, which deleted a file", func(t *testing.T) {
		// gone.md is at the branch point; main deletes it, the pull request adds notes.yaml, and the
		// checkout is the merge commit, as actions/checkout makes it for a pull_request event. A
		// two-dot diff against main's tip lists gone.md, which the checkout does not have.
		co := newSelfScanCheckout(t, map[string]string{"gone.md": "an old note\n"})
		branchPoint := co.head
		writeCheckoutFile(t, co.dir, "notes.yaml", []byte(clean), 0o600)
		gitIn(t, co.dir, "add", "-A")
		gitIn(t, co.dir, "commit", "-q", "-m", "pull request")
		prHead := gitIn(t, co.dir, "rev-parse", "HEAD")
		gitIn(t, co.dir, "checkout", "-q", "--detach", branchPoint)
		gitIn(t, co.dir, "rm", "-q", "gone.md")
		gitIn(t, co.dir, "commit", "-q", "-m", "main deletes gone.md")
		mainTip := gitIn(t, co.dir, "rev-parse", "HEAD")
		gitIn(t, co.dir, "merge", "-q", "--no-edit", prHead)
		co.base, co.head = mainTip, prHead

		run := runJob(t, wf, ferret, co, "pull_request", "block")
		listed, err := os.ReadFile(filepath.Join(co.dir, "changed_files.txt")) // #nosec G304 -- written by the step
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimSpace(string(listed)); got != "notes.yaml" {
			t.Errorf("changed_files.txt = %q, want notes.yaml: only what the pull request changed", got)
		}
		expect(t, run, stepScanChangedFiles, "changed", "block", green)
	})

	t.Run("gate reads summary.env and fails closed", func(t *testing.T) {
		g := wf.step(t, stepGate)
		const ok = "high=0\nsuppressed=0\nnot_examined=0\nscope=changed\nmode=block\nexit=0\n"
		with := func(pairs ...string) string { return strings.NewReplacer(pairs...).Replace(ok) }
		for _, c := range []struct {
			name, mode, summary string // summary "" writes no summary.env
			fails               bool
			says                string
		}{
			{"a clean run", "block", ok, false, "HIGH 0 (not suppressed), suppressed 0, not fully examined 0"},
			{"HIGH in report mode", "report", with("high=0", "high=2", "mode=block", "mode=report"), false,
				"2 HIGH finding(s) reported; GATE_MODE=report"},
			{"HIGH in block mode", "block", with("high=0", "high=2", "exit=0", "exit=1"), true, "Blocking merge: 2 HIGH"},
			{"no summary.env", "block", "", true, "summary.env is missing"},
			{"an empty summary.env", "block", "\n", true, "high is ''"},
			{"high is not a number", "block", with("high=0", "high=many"), true, "high is 'many'"},
			{"high is missing", "block", with("high=0\n", ""), true, "high is ''"},
			{"high is written twice", "block", ok + "high=0\n", true, "not a count"},
			// `[ 99999999999999999999 -gt 0 ]` is an error, which an `if` reads as false: HIGH > 0
			// would pass.
			{"high overflows a shell integer", "block", with("high=0", "high=99999999999999999999"), true,
				"high is '99999999999999999999'"},
			{"exit 2 with HIGH 0", "block", with("exit=0", "exit=2"), true, "failed closed (exit 2)"},
			{"a file not fully examined", "block", with("not_examined=0", "not_examined=1"), true,
				"1 file(s) were not fully examined"},
			{"the scan ran in report mode", "block", with("mode=block", "mode=report"), true, "ran in mode 'report'"},
			{"unknown GATE_MODE", "warn", ok, true, "GATE_MODE is 'warn'"},
			{"a value that is a command", "block", with("high=0", "high=$(touch pwned)"), true, "not a count"},
		} {
			t.Run(c.name, func(t *testing.T) {
				out, dir := t.TempDir(), t.TempDir()
				if c.summary != "" {
					if err := os.WriteFile(filepath.Join(out, "summary.env"), []byte(c.summary), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				ghEnv := filepath.Join(t.TempDir(), "github_env")
				if err := os.WriteFile(ghEnv, []byte("scan_ran=true\nself_scan_out="+out+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				r := runWorkflowScript(t, g, dir, ghEnv, map[string]string{"steps.changed-files.outputs.has_files": "true"},
					"GATE_MODE="+c.mode)
				if failed := r.code != 0; failed != c.fails || !strings.Contains(r.output, c.says) {
					t.Errorf("gate exit %d, want failure=%v and a log that says %q:\n%s", r.code, c.fails, c.says, r.output)
				}
				for _, d := range []string{dir, out} {
					if _, err := os.Stat(filepath.Join(d, "pwned")); err == nil {
						t.Errorf("the gate ran a command from summary.env")
					}
				}
				if c.name == "a clean run" {
					for _, want := range []string{"**passed**", "| 0 | 0 | 0 | changed | 0 |", "docs/testing/SELF_SCAN.md"} {
						if !strings.Contains(r.summary, want) {
							t.Errorf("the job summary does not say %q:\n%s", want, r.summary)
						}
					}
				}
			})
		}

		t.Run("no scan ran, and the change was not empty", func(t *testing.T) {
			ghEnv := filepath.Join(t.TempDir(), "github_env")
			if err := os.WriteFile(ghEnv, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			r := runWorkflowScript(t, g, t.TempDir(), ghEnv, map[string]string{"steps.changed-files.outputs.has_files": ""},
				"GATE_MODE=block")
			if r.code == 0 || !strings.Contains(r.output, "No scan ran") {
				t.Errorf("gate exit %d with no scan and no empty change; want a failure that says No scan ran:\n%s", r.code, r.output)
			}
		})
	})
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package formatters_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/core"
)

// The scope block end to end, through the built CLI (#904): every narrowing source the issue measured,
// on both input paths, against the full-scope controls that must stay silent.
//
// Here rather than in cmd/ because the contract is the formats' and this package owns them; the fill
// itself lives in cmd/stdin.go and cmd/main.go, which is why the binary is built. Measured on main at
// 5fecf59 before this change: every row below that expects a scope produced a report identical to a
// clean full scan of a neutral file, in all seven formats.

// scopeCLIEnv neutralises pre-commit auto-detection, which on Windows fires from Git Bash variables
// alone (see internal/scorecorpus's precommitOffEnv), and points the user config dir at an empty one.
func scopeCLIEnv(cfgDir string, extra ...string) []string {
	env := os.Environ()
	env = append(env, "PRE_COMMIT=", "_PRE_COMMIT_RUNNING=", "PRE_COMMIT_HOOK=", "GIT_HOOK_TYPE=",
		"MSYSTEM=", "MINGW_PREFIX=", "GIT_EXEC_PATH=", "GITHUB_DESKTOP=", "FERRET_DEBUG=",
		"FERRET_CONFIG_DIR="+cfgDir)
	return append(env, extra...)
}

type scopeCLIRun struct {
	stdout, stderr string
	rc             int
}

func runScopeCLI(t *testing.T, bin, dir string, env []string, stdin string, args ...string) scopeCLIRun {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	cmd.Env = env
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	rc := 0
	if ee, ok := err.(*exec.ExitError); ok {
		rc = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("running %v: %v", args, err)
	}
	return scopeCLIRun{stdout: out.String(), stderr: errb.String(), rc: rc}
}

func buildScopeCLI(t *testing.T) string {
	t.Helper()
	name := "ferret-scan-scope-under-test"
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

func writeScopeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func notRunGiven(run []string) []string {
	skip := map[string]bool{}
	for _, r := range run {
		skip[r] = true
	}
	var out []string
	for _, c := range core.CheckNames() {
		if !skip[c] {
			out = append(out, c)
		}
	}
	return out
}

func TestNarrowedRunsAreNamedEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the CLI")
	}
	bin := buildScopeCLI(t)
	dir := t.TempDir()
	cfgDir := t.TempDir()
	env := scopeCLIEnv(cfgDir)

	// The issue's fixtures: two findings (copyright MEDIUM, email LOW), and a neutral file.
	writeScopeFile(t, filepath.Join(dir, "narrowed.txt"),
		"Copyright (c) 2024 Example Corp. All rights reserved.\nContact: jane.example@example.com\n")
	writeScopeFile(t, filepath.Join(dir, "clean.txt"),
		"Meeting notes: the quarterly review is on Tuesday.\nNothing else to report.\n")
	writeScopeFile(t, filepath.Join(dir, "cfgs", "narrow.yaml"), "defaults:\n  checks: SSN\n")
	writeScopeFile(t, filepath.Join(dir, "cfgs", "profile.yaml"),
		"profiles:\n  ci:\n    checks: DATE_OF_BIRTH\n    description: synthetic test profile\n")
	writeScopeFile(t, filepath.Join(dir, "cfgs", "ipoff.yaml"),
		"validators:\n  intellectual_property:\n    disabled_types:\n      - copyright\n")

	precommitChecks := strings.Split(config.BuiltinPrecommitChecks, ",")
	sort.Strings(precommitChecks)

	type row struct {
		name       string
		env        []string
		args       []string
		checksRun  []string
		levels     []string
		profile    map[string]any
		config     string
		textScoped bool // pre-commit text carries no scope line
	}
	rows := []row{
		{name: "--checks SSN", args: []string{"--checks", "SSN"}, checksRun: []string{"SSN"},
			levels: []string{"high", "medium", "low"}, config: "built-in", textScoped: true},
		{name: "defaults.checks in --config", args: []string{"--config", "cfgs/narrow.yaml"}, checksRun: []string{"SSN"},
			levels: []string{"high", "medium", "low"}, config: "explicit", textScoped: true},
		{name: "--profile ci from --config", args: []string{"--config", "cfgs/profile.yaml", "--profile", "ci"},
			checksRun: []string{"DATE_OF_BIRTH"}, levels: []string{"high", "medium", "low"},
			profile: map[string]any{"name": "ci", "selected_by": "--profile"}, config: "explicit", textScoped: true},
		{name: "--profile precommit", args: []string{"--profile", "precommit"}, checksRun: precommitChecks,
			levels:  []string{"high", "medium"},
			profile: map[string]any{"name": "precommit", "selected_by": "--profile"}, config: "built-in", textScoped: true},
		{name: "PRE_COMMIT=1", env: []string{"PRE_COMMIT=1"}, checksRun: precommitChecks,
			levels:  []string{"high", "medium"},
			profile: map[string]any{"name": "precommit", "selected_by": "pre-commit mode"}, config: "built-in"},
	}

	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			runEnv := append(append([]string{}, env...), r.env...)
			out := func(format string) scopeCLIRun {
				t.Helper()
				path := filepath.Join(dir, "out."+format)
				_ = os.Remove(path)
				args := append([]string{"--file", "narrowed.txt", "--format", format, "--no-color", "--output", path}, r.args...)
				res := runScopeCLI(t, bin, dir, runEnv, "", args...)
				if res.rc != 0 {
					t.Fatalf("%s rc=%d stderr=%s", format, res.rc, res.stderr)
				}
				body, err := os.ReadFile(path) // #nosec G304 -- test temp dir
				if err != nil {
					t.Fatalf("%s: no --output file: %v", format, err)
				}
				res.stdout = string(body)
				return res
			}

			var doc map[string]any
			if err := json.Unmarshal([]byte(out("json").stdout), &doc); err != nil {
				t.Fatalf("json: %v", err)
			}
			scan, ok := doc["scan"].(map[string]any)
			if !ok {
				t.Fatalf("json has no scan block, so this narrowed run reads like a clean full scan: %v", doc)
			}
			if got := toStrings(scan["checks_run"]); !reflect.DeepEqual(got, r.checksRun) {
				t.Errorf("checks_run = %v, want %v", got, r.checksRun)
			}
			if got := toStrings(scan["checks_not_run"]); !reflect.DeepEqual(got, notRunGiven(r.checksRun)) {
				t.Errorf("checks_not_run = %v, want core.CheckNames() minus checks_run = %v", got, notRunGiven(r.checksRun))
			}
			if got := toStrings(scan["confidence_levels"]); !reflect.DeepEqual(got, r.levels) {
				t.Errorf("confidence_levels = %v, want %v", got, r.levels)
			}
			if got, _ := scan["profile"].(map[string]any); !reflect.DeepEqual(got, r.profile) {
				t.Errorf("profile = %v, want %v", scan["profile"], r.profile)
			}
			if cfg, _ := scan["config"].(map[string]any); cfg["source"] != r.config {
				t.Errorf("config = %v, want source %q", scan["config"], r.config)
			}

			if y := out("yaml").stdout; !strings.Contains(y, "checks_not_run:") {
				t.Errorf("yaml has no scan block:\n%s", y)
			}
			if j := out("junit").stdout; !strings.Contains(j, `name="ferret-scan.checks_not_run"`) {
				t.Errorf("junit has no scope properties:\n%s", j)
			}
			assertOneChecksNotification(t, out("sarif").stdout)
			if g := out("gitlab-sast").stdout; !strings.Contains(g, "checks not run for this scan") {
				t.Errorf("gitlab-sast has no scope message:\n%s", g)
			}
			text := out("text").stdout
			if n := strings.Count(text, "Scope: "); r.textScoped && n != 1 || !r.textScoped && n != 0 {
				t.Errorf("%d Scope lines in text, want %v:\n%s", n, r.textScoped, text)
			}
		})
	}

	t.Run("full scope stays silent in every format", func(t *testing.T) {
		for _, input := range []string{"narrowed.txt", "clean.txt"} {
			for _, format := range []string{"json", "yaml", "junit", "sarif", "gitlab-sast", "text", "csv"} {
				res := runScopeCLI(t, bin, dir, env, "", "--file", input, "--format", format, "--no-color")
				markers := []string{"checks_not_run", "<properties>", "ferretScan", "checks not run", "Scope:"}
				if format == "gitlab-sast" {
					// Its schema has a scan object of its own; the scope would arrive as messages.
					markers = append(markers, `"messages"`)
				} else {
					markers = append(markers, `"scan"`)
				}
				for _, marker := range markers {
					if strings.Contains(res.stdout, marker) {
						t.Errorf("%s %s: a full-scope report carries %q:\n%s", input, format, marker, res.stdout)
					}
				}
			}
		}
	})

	t.Run("stdin: stats always, the scope when narrowed, METADATA not applicable", func(t *testing.T) {
		input := "Copyright (c) 2024 Example Corp. All rights reserved.\nMeeting notes: nothing else.\n"

		var full map[string]any
		res := runScopeCLI(t, bin, dir, env, input, "--stdin", "--format", "json")
		if err := json.Unmarshal([]byte(res.stdout), &full); err != nil {
			t.Fatalf("stdin json: %v\n%s", err, res.stdout)
		}
		stats, ok := full["stats"].(map[string]any)
		if !ok || stats["total_files"] != float64(1) || stats["total_findings"] != float64(1) {
			t.Errorf("stdin json stats = %v, want total_files 1 and the one finding counted", full["stats"])
		}
		if _, ok := full["scan"]; ok {
			t.Errorf("a full-scope stdin run carries a scan block: %v", full["scan"])
		}

		var narrowed map[string]any
		res = runScopeCLI(t, bin, dir, env, input, "--stdin", "--format", "json", "--checks", "all", "--confidence", "high")
		if err := json.Unmarshal([]byte(res.stdout), &narrowed); err != nil {
			t.Fatalf("stdin json: %v", err)
		}
		scan, _ := narrowed["scan"].(map[string]any)
		if got := toStrings(scan["checks_not_applicable"]); !reflect.DeepEqual(got, []string{"METADATA"}) {
			t.Errorf("checks_not_applicable = %v, want [METADATA]", got)
		}
		for _, c := range toStrings(scan["checks_run"]) {
			if c == "METADATA" {
				t.Errorf("METADATA listed as run on stdin, where core.ScanContent cannot run it")
			}
		}

		var ipoff map[string]any
		res = runScopeCLI(t, bin, dir, env, input, "--stdin", "--format", "json", "--config", "cfgs/ipoff.yaml")
		if err := json.Unmarshal([]byte(res.stdout), &ipoff); err != nil {
			t.Fatalf("stdin json: %v", err)
		}
		st, _ := ipoff["stats"].(map[string]any)
		if !reflect.DeepEqual(st["disabled_detection_types"], map[string]any{"INTELLECTUAL_PROPERTY": []any{"copyright"}}) {
			t.Errorf("stdin stats.disabled_detection_types = %v", st["disabled_detection_types"])
		}
		if !strings.Contains(res.stderr, "Note: config disabled 1 INTELLECTUAL_PROPERTY") {
			t.Errorf("stdin printed no disabled-types note: %q", res.stderr)
		}
	})

	t.Run("stdin pre-commit --output writes the document --file writes", func(t *testing.T) {
		clean := "Meeting notes: the quarterly review is on Tuesday.\nNothing else to report.\n"
		stdinOut := filepath.Join(dir, "pc-stdin.json")
		fileOut := filepath.Join(dir, "pc-file.json")
		a := runScopeCLI(t, bin, dir, env, clean, "--stdin", "--pre-commit-mode", "--format", "json", "--output", stdinOut)
		b := runScopeCLI(t, bin, dir, env, "", "--file", "clean.txt", "--pre-commit-mode", "--format", "json", "--output", fileOut)
		if a.rc != 0 || b.rc != 0 {
			t.Fatalf("rc stdin=%d file=%d", a.rc, b.rc)
		}
		keys := func(path string) []string {
			raw, err := os.ReadFile(path) // #nosec G304 -- test temp dir
			if err != nil || len(raw) == 0 {
				t.Fatalf("%s is empty or missing (%v): an --output file the caller asked for must be written", path, err)
			}
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			var out []string
			for k := range m {
				out = append(out, k)
			}
			sort.Strings(out)
			return out
		}
		if ka, kb := keys(stdinOut), keys(fileOut); !reflect.DeepEqual(ka, kb) {
			t.Errorf("stdin document keys %v, --file document keys %v", ka, kb)
		}
	})

	t.Run("the working-directory provenance note names the checks the config limited", func(t *testing.T) {
		wd := t.TempDir()
		writeScopeFile(t, filepath.Join(wd, ".ferret-scan.yaml"), "defaults:\n  checks: EMAIL\n")
		writeScopeFile(t, filepath.Join(wd, "doc.txt"), "Contact: jane.example@example.com\n")
		res := runScopeCLI(t, bin, wd, env, "", "--file", "doc.txt", "--format", "json")
		total := len(core.CheckNames())
		want := "it limits checks to EMAIL (" + strconv.Itoa(total-1) + " of " + strconv.Itoa(total) + " not run)"
		if !strings.Contains(res.stderr, want) {
			t.Errorf("--file note = %q, want it to contain %q", res.stderr, want)
		}
		res = runScopeCLI(t, bin, wd, env, "", "--file", "doc.txt", "--format", "json", "--checks", "SSN")
		if !strings.Contains(res.stderr, "it can disable detection types") || strings.Contains(res.stderr, "limits checks") {
			t.Errorf("with --checks choosing, the note must not credit the config: %q", res.stderr)
		}
		res = runScopeCLI(t, bin, wd, env, "Contact: jane.example@example.com\n", "--stdin", "--format", "json")
		// METADATA cannot run on piped content, so the note names it rather than leave the counts short.
		want = "it limits checks to EMAIL (" + strconv.Itoa(total-2) + " of " + strconv.Itoa(total) +
			" not run, METADATA not applicable)"
		if !strings.Contains(res.stderr, want) {
			t.Errorf("--stdin note = %q, want it to contain %q", res.stderr, want)
		}
	})
}

func toStrings(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, e := range list {
		s, _ := e.(string)
		out = append(out, s)
	}
	return out
}

func assertOneChecksNotification(t *testing.T, sarifDoc string) {
	t.Helper()
	var doc struct {
		Runs []struct {
			Invocations []struct {
				ExecutionSuccessful bool `json:"executionSuccessful"`
				Notifications       []struct {
					Descriptor struct{ ID string }   `json:"descriptor"`
					Message    struct{ Text string } `json:"message"`
				} `json:"toolExecutionNotifications"`
			} `json:"invocations"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(sarifDoc), &doc); err != nil {
		t.Fatalf("sarif: %v", err)
	}
	if len(doc.Runs) != 1 || len(doc.Runs[0].Invocations) != 1 || !doc.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Fatalf("want one run with one successful invocation:\n%s", sarifDoc)
	}
	n := 0
	for _, note := range doc.Runs[0].Invocations[0].Notifications {
		if note.Descriptor.ID == "ferret-scan/detection-disabled-by-config" && strings.Contains(note.Message.Text, "Checks not run") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d checks-not-run notifications, want 1:\n%s", n, sarifDoc)
	}
}

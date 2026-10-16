// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// An enum-valued input the tool does not recognise must be refused, not turned into its default.
//
// # What it looked like (#772)
//
// `--redaction-strategy SIMPLE` -- or `simpel`, `" simple"`, `bogus` -- redacted with
// format_preserving at exit 0 with an empty stderr: `SSN: ***-**-8901` where `simple` writes
// `SSN: [SSN-REDACTED]`. A config file's `strategy: simple` was discarded by a typo on the flag. An
// auto-discovered `.ferret-scan.yaml` saying `strategy: simpel` was applied as format_preserving,
// because only an explicit --config ran the schema, and the schema itself let `" simple "`,
// `"simple,"` and `"simple,synthetic"` through to a parser that matched none of them. And
// `FERRET_PRECOMMIT_EXIT_ON=MEDIUM` left the pre-commit gate at "high", so a commit holding one MEDIUM
// finding went through at exit 0 where `medium` blocks it: a gate failing OPEN on a typo.
//
// # Why these are CLI tests
//
// The parsers are unit-tested in their packages. What this file adds is the consequence at the
// binary: that the exit code is non-zero, that it happens BEFORE any output or output directory,
// that the message names the value, the valid names and the source it came from, and that the
// canonical spellings still produce exactly what they produced before. A unit test on a parser
// passes with the parser unwired, which is how --confidence (#689) and --checks (#299) shipped.

// strategyFixture is a small file with three findings the two deterministic strategies render
// differently, so "the strategy was applied" is observable in the redacted bytes.
const strategyFixture = "Customer record\nCard number: 4929 1234 5678 9015\nContact email: jane.doe@example.org\nSSN: 345-67-8901\n"

// isolatedEnv is an environment in which no config can be auto-discovered from the developer's
// machine and no pre-commit signal leaks in: HOME, XDG_CONFIG_HOME and FERRET_CONFIG_DIR all point at
// empty directories, and nothing else is inherited but PATH.
func isolatedEnv(t *testing.T, dir string, extra ...string) []string {
	t.Helper()
	env := []string{"PATH=" + os.Getenv("PATH")}
	for _, name := range []string{"HOME", "XDG_CONFIG_HOME", "FERRET_CONFIG_DIR"} {
		d := filepath.Join(dir, "iso-"+strings.ToLower(name))
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
		env = append(env, name+"="+d)
	}
	return append(env, extra...)
}

type cliRun struct {
	rc     int
	stdout string
	stderr string
}

func runCLI(t *testing.T, bin, dir string, env []string, stdin string, args ...string) cliRun {
	t.Helper()
	c := exec.Command(bin, args...)
	c.Dir = dir
	c.Env = env
	if stdin != "" {
		c.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	c.Stdout, c.Stderr = &out, &errb
	_ = c.Run()
	return cliRun{rc: c.ProcessState.ExitCode(), stdout: out.String(), stderr: errb.String()}
}

// redactedSSNLine returns the SSN line of the redacted copy under outDir, or "" when no copy exists.
func redactedSSNLine(t *testing.T, outDir string) string {
	t.Helper()
	var line string
	_ = filepath.Walk(outDir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || filepath.Base(p) != "pii.txt" {
			return nil
		}
		b, _ := os.ReadFile(p)
		for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			if strings.HasPrefix(l, "SSN:") {
				line = l
			}
		}
		return nil
	})
	return line
}

// refusedStrategySpellings are the values #772 measured as silently becoming format_preserving.
var refusedStrategySpellings = []string{"simpel", "SIMPLE", "Simple", " simple", "synthetc", "format-preserving", "none", "bogus", "  "}

// TestAnUnusableRedactionStrategyIsRefusedOnEveryChannel runs the refused spellings through the five
// channels a strategy can arrive by, and the canonical names as controls.
func TestAnUnusableRedactionStrategyIsRefusedOnEveryChannel(t *testing.T) {
	bin := buildScanner(t)
	dir := t.TempDir()
	in := filepath.Join(dir, "pii.txt")
	if err := os.WriteFile(in, []byte(strategyFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	env := isolatedEnv(t, dir)

	// Non-vacuity: the two deterministic strategies must render the fixture differently, or a
	// "wrong strategy applied" could never be observed.
	simpleOut := filepath.Join(dir, "red-simple")
	fpOut := filepath.Join(dir, "red-fp")
	rs := runCLI(t, bin, dir, env, "", "--file", in, "--config", os.DevNull, "--enable-redaction",
		"--redaction-output-dir", simpleOut, "--redaction-strategy", "simple", "--quiet")
	rf := runCLI(t, bin, dir, env, "", "--file", in, "--config", os.DevNull, "--enable-redaction",
		"--redaction-output-dir", fpOut, "--redaction-strategy", "format_preserving", "--quiet")
	if rs.rc != 0 || rf.rc != 0 {
		t.Fatalf("canonical names must exit 0: simple rc=%d (%s) format_preserving rc=%d (%s)", rs.rc, rs.stderr, rf.rc, rf.stderr)
	}
	simpleSSN, fpSSN := redactedSSNLine(t, simpleOut), redactedSSNLine(t, fpOut)
	if simpleSSN == "" || fpSSN == "" || simpleSSN == fpSSN {
		t.Fatalf("the two strategies must render the SSN line differently: simple=%q format_preserving=%q", simpleSSN, fpSSN)
	}
	if simpleSSN != "SSN: [SSN-REDACTED]" || fpSSN != "SSN: ***-**-8901" {
		t.Errorf("canonical output changed: simple=%q format_preserving=%q (v2.5.4 wrote [SSN-REDACTED] and ***-**-8901)", simpleSSN, fpSSN)
	}

	assertRefused := func(t *testing.T, r cliRun, value, sourceFragment string) {
		t.Helper()
		if r.rc != 1 {
			t.Errorf("rc=%d, want 1 (stderr: %q)", r.rc, r.stderr)
		}
		if !strings.Contains(r.stderr, fmt.Sprintf("%q", value)) {
			t.Errorf("stderr does not quote the value %q: %q", value, r.stderr)
		}
		for _, name := range []string{"simple", "format_preserving", "synthetic"} {
			if !strings.Contains(r.stderr, name) {
				t.Errorf("stderr does not name the valid value %q: %q", name, r.stderr)
			}
		}
		if sourceFragment != "" && !strings.Contains(r.stderr, sourceFragment) {
			t.Errorf("stderr does not name the source %q: %q", sourceFragment, r.stderr)
		}
	}

	t.Run("--file flag", func(t *testing.T) {
		for _, v := range refusedStrategySpellings {
			out := filepath.Join(dir, "red-"+fmt.Sprintf("%x", []byte(v)))
			r := runCLI(t, bin, dir, env, "", "--file", in, "--config", os.DevNull, "--enable-redaction",
				"--redaction-output-dir", out, "--redaction-strategy", v, "--quiet")
			assertRefused(t, r, v, "--redaction-strategy")
			if _, err := os.Stat(out); err == nil {
				t.Errorf("[%s] the output directory was created before the strategy was refused", v)
			}
			if r.stdout != "" {
				t.Errorf("[%s] stdout is not empty: %q", v, r.stdout)
			}
		}
	})

	t.Run("--stdin flag", func(t *testing.T) {
		for _, v := range []string{"SIMPLE", "simpel", "bogus"} {
			r := runCLI(t, bin, dir, env, strategyFixture, "--stdin", "--config", os.DevNull, "--enable-redaction", "--redaction-strategy", v)
			assertRefused(t, r, v, "--redaction-strategy")
			if len(r.stdout) != 0 {
				t.Errorf("[%s] --stdin wrote %d bytes to stdout; a refused strategy must write nothing", v, len(r.stdout))
			}
		}
		// Control: the canonical name on --stdin still redacts to stdout.
		r := runCLI(t, bin, dir, env, strategyFixture, "--stdin", "--config", os.DevNull, "--enable-redaction", "--redaction-strategy", "simple")
		if r.rc != 0 || !strings.Contains(r.stdout, "[SSN-REDACTED]") {
			t.Errorf("--stdin with simple: rc=%d stdout=%q", r.rc, r.stdout)
		}
	})

	t.Run("explicit --config defaults", func(t *testing.T) {
		// These reach the schema, which now applies the parser's exact rule. Before #772 the schema
		// trimmed and comma-split, so every one of these passed it and fell back downstream.
		for _, v := range []string{"simpel", `" simple "`, `"simple,"`, `"simple,synthetic"`, `"  "`} {
			cfg := filepath.Join(dir, "cfg.yaml")
			if err := os.WriteFile(cfg, []byte("redaction:\n  strategy: "+v+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			raw := strings.Trim(v, `"`)
			r := runCLI(t, bin, dir, env, "", "--file", in, "--config", cfg, "--enable-redaction",
				"--redaction-output-dir", filepath.Join(dir, "red-cfg"), "--quiet")
			assertRefused(t, r, raw, "redaction.strategy")
		}
	})

	t.Run("explicit --config profile", func(t *testing.T) {
		cfg := filepath.Join(dir, "cfg-profile.yaml")
		if err := os.WriteFile(cfg, []byte("profiles:\n  share:\n    redaction:\n      strategy: Simple\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		r := runCLI(t, bin, dir, env, "", "--file", in, "--config", cfg, "--profile", "share", "--enable-redaction",
			"--redaction-output-dir", filepath.Join(dir, "red-prof"), "--quiet")
		assertRefused(t, r, "Simple", `profile "share"`)
	})

	t.Run("a valid config value is not rescued from an invalid flag", func(t *testing.T) {
		// The flag wins the precedence and is invalid; before #772 the config's `simple` was thrown
		// away and the hard default format_preserving was applied, at exit 0.
		cfg := filepath.Join(dir, "cfg-ok.yaml")
		if err := os.WriteFile(cfg, []byte("redaction:\n  strategy: simple\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		r := runCLI(t, bin, dir, env, "", "--file", in, "--config", cfg, "--enable-redaction",
			"--redaction-output-dir", filepath.Join(dir, "red-mix"), "--redaction-strategy", "bogus", "--quiet")
		assertRefused(t, r, "bogus", "--redaction-strategy")
	})

	t.Run("auto-discovered .ferret-scan.yaml", func(t *testing.T) {
		// No --config, so the lenient loader is used and the schema never runs: the strategy helper
		// is the only thing standing between `simpel` and format_preserving, and its message must
		// say the file was auto-discovered (#293).
		auto := filepath.Join(dir, "auto")
		if err := os.MkdirAll(auto, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(auto, ".ferret-scan.yaml"), []byte("redaction:\n  strategy: simpel\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(auto, "pii.txt"), []byte(strategyFixture), 0o600); err != nil {
			t.Fatal(err)
		}
		r := runCLI(t, bin, auto, env, "", "--file", "pii.txt", "--enable-redaction", "--redaction-output-dir", "red", "--quiet")
		assertRefused(t, r, "simpel", "auto-discovered")
		if _, err := os.Stat(filepath.Join(auto, "red")); err == nil {
			t.Error("the output directory was created before the strategy was refused")
		}
	})

	t.Run("an invalid strategy is refused even when nothing is redacted", func(t *testing.T) {
		// Validation is unconditional: redaction can be enabled by a config or a profile the operator
		// does not see on the command line, so the value handed to the redactor is checked whether or
		// not this run redacts. The stated cost: a run that does not redact but carries a typo exits 1.
		r := runCLI(t, bin, dir, env, "", "--file", in, "--config", os.DevNull, "--redaction-strategy", "bogus", "--quiet")
		assertRefused(t, r, "bogus", "--redaction-strategy")
	})
}

// TestPreCommitExitOnIsRefusedWhenMisspelled pins FERRET_PRECOMMIT_EXIT_ON: the four names keep
// their exit codes on a MEDIUM-only and a HIGH-only fixture, every other value exits 1 before
// scanning on both paths with a message naming the variable and no "commit blocked" text, and
// outside pre-commit mode an invalid value has no effect.
func TestPreCommitExitOnIsRefusedWhenMisspelled(t *testing.T) {
	bin := buildScanner(t)
	dir := t.TempDir()
	med := filepath.Join(dir, "med.txt")
	high := filepath.Join(dir, "high.txt")
	if err := os.WriteFile(med, []byte("SSN: 345-67-8901\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(high, []byte("Visa card number 4929123456789015 exp 12/29\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := isolatedEnv(t, dir)
	rcWith := func(value string, set bool, file string) cliRun {
		env := base
		if set {
			env = append(append([]string{}, base...), "FERRET_PRECOMMIT_EXIT_ON="+value)
		}
		return runCLI(t, bin, dir, env, "", "--pre-commit-mode", "--file", file, "--config", os.DevNull)
	}

	// The documented names, and their v2.5.4 exit codes: MEDIUM fixture / HIGH fixture.
	valid := []struct {
		value     string
		set       bool
		med, high int
	}{
		{"", false, 0, 1}, {"", true, 0, 1}, {"high", true, 0, 1}, {"medium", true, 1, 1}, {"low", true, 1, 1}, {"none", true, 0, 0},
	}
	for _, v := range valid {
		m, h := rcWith(v.value, v.set, med), rcWith(v.value, v.set, high)
		if m.rc != v.med || h.rc != v.high {
			t.Errorf("FERRET_PRECOMMIT_EXIT_ON=%q (set=%v): medium fixture rc=%d want %d, high fixture rc=%d want %d",
				v.value, v.set, m.rc, v.med, h.rc, v.high)
		}
	}
	// Non-vacuity of the fixtures: medium must block only from `medium` down, high must block at `high`.
	if rcWith("high", true, med).rc != 0 || rcWith("medium", true, med).rc != 1 {
		t.Fatal("the MEDIUM fixture does not separate high from medium; every refused-value row below would be vacuous")
	}

	for _, v := range []string{"Medium", "MEDIUM", "meduim", " medium", "medium ", "LOW", "None", "NONE", "off", "nonee"} {
		for _, f := range []string{med, high} {
			r := rcWith(v, true, f)
			if r.rc != 1 {
				t.Errorf("FERRET_PRECOMMIT_EXIT_ON=%q on %s: rc=%d, want 1", v, filepath.Base(f), r.rc)
			}
			if !strings.Contains(r.stderr, "FERRET_PRECOMMIT_EXIT_ON") || !strings.Contains(r.stderr, fmt.Sprintf("%q", v)) {
				t.Errorf("FERRET_PRECOMMIT_EXIT_ON=%q: stderr does not name the variable and quote the value: %q", v, r.stderr)
			}
			if strings.Contains(strings.ToLower(r.stderr), "commit blocked") {
				t.Errorf("FERRET_PRECOMMIT_EXIT_ON=%q: a usage error must not read as a blocked commit: %q", v, r.stderr)
			}
			if r.stdout != "" {
				t.Errorf("FERRET_PRECOMMIT_EXIT_ON=%q: stdout is not empty, so a scan ran before the refusal: %q", v, r.stdout)
			}
		}
	}

	// --stdin --pre-commit-mode takes the same refusal.
	r := runCLI(t, bin, dir, append(append([]string{}, base...), "FERRET_PRECOMMIT_EXIT_ON=MEDIUM"), "SSN: 345-67-8901\n",
		"--stdin", "--pre-commit-mode", "--config", os.DevNull)
	if r.rc != 1 || !strings.Contains(r.stderr, "FERRET_PRECOMMIT_EXIT_ON") {
		t.Errorf("--stdin --pre-commit-mode with MEDIUM: rc=%d stderr=%q, want 1 and the variable named", r.rc, r.stderr)
	}

	// Outside pre-commit mode the variable is not acted on, so an invalid value has no effect.
	r = runCLI(t, bin, dir, append(append([]string{}, base...), "FERRET_PRECOMMIT_EXIT_ON=MEDIUM"), "",
		"--file", med, "--config", os.DevNull, "--quiet")
	if r.rc != 0 {
		t.Errorf("outside pre-commit mode FERRET_PRECOMMIT_EXIT_ON=MEDIUM changed the exit code to %d: %q", r.rc, r.stderr)
	}
}

// TestEveryEnumValuedInputRejectsAnOutOfDomainValue is the derived class guard. It selects every
// --flag whose registered usage text lists its values, and every FERRET_* variable whose row in the
// pre-commit docs' environment table lists option values, and requires each to exit non-zero on an
// out-of-domain value. The set is DERIVED -- from cmd/main.go's flag.String calls via go/ast and from
// the docs table -- never hand-kept, so a new enum-valued input is selected the day it is added, and
// an exemption whose input is no longer selected fails the test rather than lingering.
//
// Before #772 this test selected eight inputs and two of them failed: --redaction-strategy and
// FERRET_PRECOMMIT_EXIT_ON, the two this issue is about.
func TestEveryEnumValuedInputRejectsAnOutOfDomainValue(t *testing.T) {
	// Exemptions must name an input the derivation selects, and carry the reason.
	exemptFlags := map[string]string{
		"disable-ip-types": "a bad sub-type warns on stderr and detection keeps running (disclosed, fail-safe); the --stdin half is a sibling audit item",
	}
	exemptEnv := map[string]string{
		"FERRET_PRECOMMIT_EXIT_ON_FIRST": "parsed but nothing reads ExitOnFirst; a dead setting owned by a sibling audit item",
		"FERRET_PRECOMMIT":               "an unrecognised opt-out leaves the gate ON, which is the safe direction",
	}

	flags := flagsWhoseUsageListsValues(t, "main.go")
	envs := envVarsWhoseDocsRowListsValues(t, filepath.Join("..", "docs", "PRE_COMMIT_INTEGRATION.md"))
	if len(flags) < 4 || len(envs) < 2 {
		t.Fatalf("derivation is vacuous: flags=%v envs=%v", flags, envs)
	}
	for name := range exemptFlags {
		if !containsString(flags, name) {
			t.Errorf("stale exemption: --%s is no longer an enum-valued flag by the derivation; remove it", name)
		}
	}
	for name := range exemptEnv {
		if !containsString(envs, name) {
			t.Errorf("stale exemption: %s is no longer in the docs' environment table; remove it", name)
		}
	}
	t.Logf("derived flags: %v", flags)
	t.Logf("derived env vars: %v", envs)

	bin := buildScanner(t)
	dir := t.TempDir()
	in := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(in, []byte("SSN: 345-67-8901\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := isolatedEnv(t, dir)

	for _, name := range flags {
		if why, ok := exemptFlags[name]; ok {
			t.Logf("--%s exempt: %s", name, why)
			continue
		}
		r := runCLI(t, bin, dir, env, "", "--file", in, "--config", os.DevNull, "--"+name, "bogus", "--quiet")
		if r.rc == 0 {
			t.Errorf("--%s bogus exited 0; an enum-valued flag must refuse a value outside its domain (stderr: %q)", name, r.stderr)
		}
	}
	for _, name := range envs {
		if why, ok := exemptEnv[name]; ok {
			t.Logf("%s exempt: %s", name, why)
			continue
		}
		r := runCLI(t, bin, dir, append(append([]string{}, env...), name+"=bogus"), "", "--pre-commit-mode", "--file", in, "--config", os.DevNull)
		if r.rc == 0 {
			t.Errorf("%s=bogus exited 0 in pre-commit mode; an enum-valued variable must refuse a value outside its domain (stderr: %q)", name, r.stderr)
		}
	}
}

// valueList matches a usage text that enumerates values after a colon: at least three lowercase
// tokens separated by commas, e.g. "Output format: text, json, csv" or "to disable: a,b,c". Uppercase
// lists (units: B, KB, MB) and parenthesised examples (days (30), weeks (4w)) are deliberately not
// matched; they describe a syntax, not a closed set of names.
var valueList = regexp.MustCompile(`: ?(?:[a-z][a-z_-]*, ?){2,}[a-z][a-z_-]*`)

// flagsWhoseUsageListsValues parses the flag.String registrations in file and returns the names
// whose usage text enumerates values. A usage built with strings.Join over a name list counts: the
// join IS a value list (that is how --checks is registered).
func flagsWhoseUsageListsValues(t *testing.T, file string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", file, err)
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 3 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "String" {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "flag" {
			return true
		}
		nameLit, ok := call.Args[0].(*ast.BasicLit)
		if !ok {
			return true
		}
		name := strings.Trim(nameLit.Value, `"`)
		usage, hasJoin := renderUsage(call.Args[2])
		if hasJoin || valueList.MatchString(usage) {
			out = append(out, name)
		}
		return true
	})
	sort.Strings(out)
	return out
}

// renderUsage folds a usage expression's string literals into one string and reports whether a
// strings.Join call is part of it.
func renderUsage(e ast.Expr) (string, bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		s := x.Value
		if len(s) >= 2 && (s[0] == '"' || s[0] == '`') {
			s = s[1 : len(s)-1]
		}
		return s, false
	case *ast.BinaryExpr:
		l, lj := renderUsage(x.X)
		r, rj := renderUsage(x.Y)
		return l + r, lj || rj
	case *ast.CallExpr:
		if sel, ok := x.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Join" {
			return "<list>", true
		}
		return "", false
	case *ast.ParenExpr:
		return renderUsage(x.X)
	}
	return "", false
}

// docsEnvRow matches a row of the docs' environment table whose second cell lists two or more
// backticked option values: | `FERRET_X` | `a`, `b` | ... |
var docsEnvRow = regexp.MustCompile("^\\| `(FERRET_[A-Z_]+)` \\| ((?:`[^`]*`[, ]*){2,}) \\|")

func envVarsWhoseDocsRowListsValues(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		if m := docsEnvRow.FindStringSubmatch(line); m != nil {
			out = append(out, m[1])
		}
	}
	sort.Strings(out)
	return out
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

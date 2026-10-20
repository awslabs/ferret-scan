// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// The built-in precommit profile must yield to what a config wrote (#768).
//
// Measured on v2.5.3, and on main at 46e2918: under --pre-commit-mode, any of the four hook
// environment variables, or the published hook's --profile precommit, the built-in profile's checks,
// confidence_levels, redaction.strategy and redaction.output_dir replaced the config's. A config
// naming PASSPORT got six other types, so a HIGH passport passed the hook at exit 0 with no output,
// and `--stdin` with `strategy: simple` returned it in cleartext beside `***-**-0001`. Every route,
// both input paths and every config source reproduced it; only a config's own profiles.precommit
// escaped. A second member reached every profile: an unbackfilled fail_on_incomplete gave exit 0
// where the config asked for 3.
//
// These run the real binary because the defect is in how three layers combine (config load, profile
// selection, resolveConfiguration) and a unit test of any one of them passes with the others wrong.

const (
	// Synthetic values only: an SSN in a valid-shaped but unissued range and a placeholder passport.
	profileInTxt   = "SSN: 234-56-0001\nPassport number: X00000001\n"
	profilePPTxt   = "Passport number: X00000001\n"
	profileRedYAML = "redaction:\n  enabled: true\n  strategy: simple\ndefaults:\n  checks: PASSPORT,SSN\n"
)

// profileRoute is one way a run comes to use the precommit profile.
type profileRoute struct {
	name string
	env  []string
	args []string
	// gate is true when the route is pre-commit mode, whose exit code reports findings.
	gate bool
}

func precommitProfileRoutes() []profileRoute {
	routes := []profileRoute{{name: "--pre-commit-mode", args: []string{"--pre-commit-mode"}, gate: true}}
	for _, v := range precommitTriggers {
		routes = append(routes, profileRoute{name: v + "=1", env: []string{v + "=1"}, gate: true})
	}
	return append(routes, profileRoute{name: "--profile precommit", args: []string{"--profile", "precommit"}})
}

// profileWorkdir is a working directory beside an isolated HOME, XDG and user config dir, so the user
// config dir is outside the working directory as it is on a real machine.
func profileWorkdir(t *testing.T) (work, userCfgDir string, env []string) {
	t.Helper()
	base := t.TempDir()
	env = isolatedEnv(t, base)
	work = filepath.Join(base, "work")
	if err := os.MkdirAll(work, 0o750); err != nil {
		t.Fatal(err)
	}
	return work, filepath.Join(base, "iso-ferret_config_dir"), env
}

func writeFixture(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// redactedCopy returns the content of the redacted copy of name under dir, or "" when there is none.
func redactedCopy(t *testing.T, dir, name string) string {
	t.Helper()
	var body string
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && filepath.Base(p) == name {
			b, _ := os.ReadFile(p) // #nosec G304 -- test temp dir
			body = string(b)
		}
		return nil
	})
	return body
}

// TestBuiltinPrecommitProfileYieldsOnEveryRoute is the binary matrix: 6 routes x 2 input paths x 5
// config sources, plus an ordinary run per source as the control. The config asks for PASSPORT and
// SSN and the simple strategy; every run must mask both values with simple's markers.
func TestBuiltinPrecommitProfileYieldsOnEveryRoute(t *testing.T) {
	bin := buildScanner(t)
	sources := []string{"--config", "config.yaml", "ferret.yaml", ".ferret-scan.yaml", "user config dir"}
	routes := append([]profileRoute{{name: "no profile"}}, precommitProfileRoutes()...)
	for _, source := range sources {
		work, userCfg, env := profileWorkdir(t)
		writeFixture(t, filepath.Join(work, "in.txt"), profileInTxt)
		var cfgArgs []string
		switch source {
		case "--config":
			writeFixture(t, filepath.Join(work, "red.yaml"), profileRedYAML)
			cfgArgs = []string{"--config", "red.yaml"}
		case "user config dir":
			writeFixture(t, filepath.Join(userCfg, "config.yaml"), profileRedYAML)
		default:
			writeFixture(t, filepath.Join(work, source), profileRedYAML)
		}
		for _, route := range routes {
			args := append(append([]string{}, cfgArgs...), route.args...)
			wantRC := 0
			if route.gate {
				wantRC = 1
			}

			r := runCLI(t, bin, work, append(append([]string{}, env...), route.env...), profileInTxt, append(args, "--stdin")...)
			assertSimpleMasked(t, source+" / "+route.name+" / --stdin", r.stdout)
			if r.rc != wantRC {
				t.Errorf("%s / %s / --stdin: rc = %d, want %d", source, route.name, r.rc, wantRC)
			}

			_ = os.RemoveAll(filepath.Join(work, "redacted"))
			r = runCLI(t, bin, work, append(append([]string{}, env...), route.env...), "", append(args, "--file", "in.txt")...)
			assertSimpleMasked(t, source+" / "+route.name+" / --file", redactedCopy(t, filepath.Join(work, "redacted"), "in.txt"))
			if r.rc != wantRC {
				t.Errorf("%s / %s / --file: rc = %d, want %d (stderr %q)", source, route.name, r.rc, wantRC, r.stderr)
			}
		}
	}
}

func assertSimpleMasked(t *testing.T, label, out string) {
	t.Helper()
	if !strings.Contains(out, "SSN: [SSN-REDACTED]") || !strings.Contains(out, "Passport number: [PASSPORT-REDACTED]") {
		t.Errorf("%s: redacted output %q, want both values masked with the config's simple strategy. "+
			"The built-in precommit profile's format_preserving and six checks replaced what the config wrote",
			label, out)
	}
	if strings.Contains(out, "X00000001") {
		t.Errorf("%s: the passport the config asked for is in cleartext: %q", label, out)
	}
}

// TestPrecommitHookReportsThePassportTheConfigNamed: a config naming PASSPORT gets one PASSPORT HIGH
// finding on every route, and the published hook blocks on it.
func TestPrecommitHookReportsThePassportTheConfigNamed(t *testing.T) {
	bin := buildScanner(t)
	work, _, env := profileWorkdir(t)
	writeFixture(t, filepath.Join(work, "pp.txt"), profilePPTxt)
	writeFixture(t, filepath.Join(work, "pp.yaml"), "defaults:\n  checks: PASSPORT,SSN\n")
	for _, cfgBody := range []string{"pp.yaml", "other.yaml", "empty.yaml", "null.yaml"} {
		switch cfgBody {
		case "other.yaml":
			writeFixture(t, filepath.Join(work, cfgBody), "defaults:\n  checks: PASSPORT,SSN\nprofiles:\n  ci:\n    checks: SSN\n")
		case "empty.yaml":
			writeFixture(t, filepath.Join(work, cfgBody), "defaults:\n  checks: PASSPORT,SSN\nprofiles: {}\n")
		case "null.yaml":
			writeFixture(t, filepath.Join(work, cfgBody), "defaults:\n  checks: PASSPORT,SSN\nprofiles:\n")
		}
		for _, route := range precommitProfileRoutes() {
			out := filepath.Join(work, "o.json")
			_ = os.Remove(out)
			args := append([]string{"--config", cfgBody, "--file", "pp.txt", "--format", "json", "--output", out}, route.args...)
			r := runCLI(t, bin, work, append(append([]string{}, env...), route.env...), "", args...)
			got := jsonFindings(t, out)
			if len(got) != 1 || got[0] != "PASSPORT:HIGH" {
				t.Errorf("%s / %s: findings %v, want exactly [PASSPORT:HIGH]: the config named PASSPORT and "+
					"the built-in profile's six checks replaced it", cfgBody, route.name, got)
			}
			if route.gate && r.rc != 1 {
				t.Errorf("%s / %s: rc = %d, want 1: a HIGH finding the config asked for passed the hook", cfgBody, route.name, r.rc)
			}
		}
	}

	// The published hook's own arguments, text output.
	r := runCLI(t, bin, work, env, "", "--config", "pp.yaml", "--file", "pp.txt", "--pre-commit-mode", "--profile", "precommit", "--respect-gitignore")
	if r.rc != 1 || !strings.Contains(r.stdout, "1 high confidence issues found") || !strings.Contains(r.stdout, "Passport number detected") {
		t.Errorf("published hook args: rc %d stdout %q, want rc 1 naming one passport", r.rc, r.stdout)
	}
}

func jsonFindings(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var doc struct {
		Results []struct {
			Type            string `json:"type"`
			ConfidenceLevel string `json:"confidence_level"`
		} `json:"results"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("%s is not JSON: %v", path, err)
	}
	var out []string
	for _, r := range doc.Results {
		out = append(out, r.Type+":"+r.ConfidenceLevel)
	}
	sort.Strings(out)
	return out
}

// TestBuiltinPrecommitProfileDecoys pins what #768 must NOT change. They pass on main by design.
func TestBuiltinPrecommitProfileDecoys(t *testing.T) {
	bin := buildScanner(t)
	work, _, env := profileWorkdir(t)
	writeFixture(t, filepath.Join(work, "pp.txt"), profilePPTxt)
	writeFixture(t, filepath.Join(work, "ssn.txt"), "SSN: 234-56-0001\n")
	writeFixture(t, filepath.Join(work, "own.yaml"), "defaults:\n  checks: PASSPORT,SSN\nprofiles:\n  precommit:\n    description: own\n")

	// No config: exactly the six, and pp.txt is clean and silent.
	r := runCLI(t, bin, work, env, "", "--pre-commit-mode", "--file", "pp.txt", "--debug")
	if !strings.Contains(r.stderr, "Validators to run: CREDIT_CARD,SECRETS,SSN,EMAIL,PHONE,IP_ADDRESS\n") {
		t.Errorf("no config: the debug log does not show the six checks:\n%s", r.stderr)
	}
	r = runCLI(t, bin, work, env, "", "--pre-commit-mode", "--file", "pp.txt")
	if r.rc != 0 || r.stdout != "" || r.stderr != "" {
		t.Errorf("no config, pp.txt: rc %d stdout %q stderr %q, want 0 and silent", r.rc, r.stdout, r.stderr)
	}
	// A config's own precommit profile: as before.
	out := filepath.Join(work, "o.json")
	r = runCLI(t, bin, work, env, "", "--config", "own.yaml", "--pre-commit-mode", "--file", "pp.txt", "--format", "json", "--output", out)
	if got := jsonFindings(t, out); r.rc != 1 || len(got) != 1 || got[0] != "PASSPORT:HIGH" {
		t.Errorf("own precommit profile: rc %d findings %v, want 1 [PASSPORT:HIGH]", r.rc, got)
	}
	// FERRET_PRECOMMIT=0 opts out of pre-commit mode: an ordinary run.
	_ = os.Remove(out)
	r = runCLI(t, bin, work, append(append([]string{}, env...), "PRE_COMMIT=1", "FERRET_PRECOMMIT=0"), "",
		"--config", "own.yaml", "--file", "pp.txt", "--format", "json", "--output", out)
	if got := jsonFindings(t, out); r.rc != 0 || len(got) != 1 {
		t.Errorf("FERRET_PRECOMMIT=0: rc %d findings %v, want 0 [PASSPORT:HIGH]", r.rc, got)
	}
	// A planted project config cannot narrow the hook (#293): defaults.checks EMAIL still finds the SSN.
	writeFixture(t, filepath.Join(work, ".ferret-scan.yaml"), "defaults:\n  checks: EMAIL\n")
	r = runCLI(t, bin, work, env, "", "--pre-commit-mode", "--file", "ssn.txt")
	if r.rc != 1 || !strings.Contains(r.stdout, "Social Security Number detected") {
		t.Errorf("planted defaults.checks: EMAIL: rc %d stdout %q, want rc 1 with the SSN", r.rc, r.stdout)
	}
}

// TestBuiltinPrecommitChecksAllIsDisclosedOnce: the one override the built-in profile keeps -- a
// config's `defaults.checks: all` runs the six in a hook -- is named on one stderr line, and only
// where stderr is a human channel.
func TestBuiltinPrecommitChecksAllIsDisclosedOnce(t *testing.T) {
	bin := buildScanner(t)
	work, _, env := profileWorkdir(t)
	writeFixture(t, filepath.Join(work, "pp.txt"), profilePPTxt)
	writeFixture(t, filepath.Join(work, "in.txt"), profileInTxt)
	writeFixture(t, filepath.Join(work, "all.yaml"), "defaults:\n  checks: all\n")
	writeFixture(t, filepath.Join(work, "allred.yaml"), "redaction:\n  enabled: true\n  strategy: simple\ndefaults:\n  checks: all\n")
	writeFixture(t, filepath.Join(work, "nochecks.yaml"), "defaults:\n  format: text\n")

	disclosure := func(stderr string) []string {
		var lines []string
		for _, l := range strings.Split(stderr, "\n") {
			if strings.Contains(l, "profiles.precommit.checks") {
				lines = append(lines, l)
			}
		}
		return lines
	}

	r := runCLI(t, bin, work, env, "", "--config", "all.yaml", "--pre-commit-mode", "--file", "pp.txt")
	lines := disclosure(r.stderr)
	if r.rc != 0 || len(lines) != 1 || strings.Count(r.stderr, "\n") != 1 {
		t.Fatalf("checks: all, --file: rc %d stderr %q, want rc 0 and exactly one line naming "+
			"profiles.precommit.checks", r.rc, r.stderr)
	}
	for _, want := range append(strings.Split("CREDIT_CARD,SECRETS,SSN,EMAIL,PHONE,IP_ADDRESS", ","), "built-in precommit profile", "all.yaml") {
		if !strings.Contains(lines[0], want) {
			t.Errorf("disclosure %q does not name %q", lines[0], want)
		}
	}

	r = runCLI(t, bin, work, env, profilePPTxt, "--config", "all.yaml", "--pre-commit-mode", "--stdin")
	if got := disclosure(r.stderr); len(got) != 1 {
		t.Errorf("checks: all, --stdin: %d disclosure lines in %q, want 1", len(got), r.stderr)
	}
	// stderr is the findings document here; nothing else may be written to it.
	r = runCLI(t, bin, work, env, profileInTxt, "--config", "allred.yaml", "--pre-commit-mode", "--stdin")
	if got := disclosure(r.stderr); len(got) != 0 {
		t.Errorf("--stdin --enable-redaction without --output: the disclosure corrupts the findings document on stderr: %q", r.stderr)
	}
	for _, c := range [][]string{
		{"--config", "all.yaml", "--pre-commit-mode", "--checks", "SSN", "--file", "pp.txt"},
		{"--config", "nochecks.yaml", "--pre-commit-mode", "--file", "pp.txt"},
		{"--pre-commit-mode", "--file", "pp.txt"},
	} {
		if r = runCLI(t, bin, work, env, "", c...); len(disclosure(r.stderr)) != 0 {
			t.Errorf("%v: unexpected disclosure %q", c, r.stderr)
		}
	}
}

// TestConfigOutputDirAndConfidenceApplyUnderPrecommit: the two other values the built-in profile
// used to replace.
func TestConfigOutputDirAndConfidenceApplyUnderPrecommit(t *testing.T) {
	bin := buildScanner(t)
	work, _, env := profileWorkdir(t)
	writeFixture(t, filepath.Join(work, "ssn.txt"), "SSN: 234-56-0001\n")
	writeFixture(t, filepath.Join(work, "em.txt"), "contact user@example.com\n")
	cfgOut := filepath.Join(work, "cfgout")
	writeFixture(t, filepath.Join(work, "od.yaml"), "redaction:\n  enabled: true\n  output_dir: "+filepath.ToSlash(cfgOut)+"\n")
	writeFixture(t, filepath.Join(work, "ca.yaml"), "defaults:\n  confidence_levels: all\n")

	_ = runCLI(t, bin, work, env, "", "--config", "od.yaml", "--pre-commit-mode", "--file", "ssn.txt")
	if redactedCopy(t, cfgOut, "ssn.txt") == "" || redactedCopy(t, filepath.Join(work, "redacted"), "ssn.txt") != "" {
		t.Errorf("the redacted copy did not land in the config's output_dir %s under pre-commit mode", cfgOut)
	}

	r := runCLI(t, bin, work, env, "", "--config", "ca.yaml", "--pre-commit-mode", "--quiet=false", "--file", "em.txt")
	if !strings.Contains(r.stdout, "LOW") || strings.Contains(r.stdout, "No matches found") {
		t.Errorf("confidence_levels: all under pre-commit mode: stdout %q, want the LOW email finding listed", r.stdout)
	}
	if r.rc != 0 {
		t.Errorf("confidence_levels is a display filter; the gate must not change: rc %d", r.rc)
	}
}

// TestProfileBoolsInheritTheConfigAtTheBinary: fail_on_incomplete under the built-in profile, a
// config's own precommit profile and any other profile, and the suppressions block's bools under a
// profile.
func TestProfileBoolsInheritTheConfigAtTheBinary(t *testing.T) {
	bin := buildScanner(t)
	work, _, env := profileWorkdir(t)
	writeFixture(t, filepath.Join(work, "ssn.txt"), "SSN: 234-56-0001\n")

	if os.Geteuid() != 0 && runtime.GOOS != "windows" {
		writeFixture(t, filepath.Join(work, "ok.txt"), "nothing here\n")
		locked := filepath.Join(work, "locked.txt")
		writeFixture(t, locked, "SSN: 234-56-0001\n")
		if err := os.Chmod(locked, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(locked, 0o600) })
		writeFixture(t, filepath.Join(work, "foi.yaml"), "defaults:\n  fail_on_incomplete: true\n")
		writeFixture(t, filepath.Join(work, "foiown.yaml"), "defaults:\n  fail_on_incomplete: true\nprofiles:\n  precommit:\n    description: own\n  other:\n    description: other\n")
		for _, c := range [][]string{
			{"--config", "foi.yaml", "--pre-commit-mode"},
			{"--config", "foi.yaml", "--profile", "precommit"},
			{"--config", "foiown.yaml", "--pre-commit-mode"},
			{"--config", "foiown.yaml", "--profile", "other"},
		} {
			if r := runCLI(t, bin, work, env, "", append(c, "ok.txt", "locked.txt")...); r.rc != exitCodeIncompleteCoverage {
				t.Errorf("%v with an unreadable file: rc %d, want %d: the profile switched off the config's "+
					"fail_on_incomplete: true", c, r.rc, exitCodeIncompleteCoverage)
			}
		}
	}

	// suppressions.generate_on_scan under --profile other writes a rule.
	gen := filepath.Join(work, "gen.yaml")
	writeFixture(t, filepath.Join(work, "gen.cfg.yaml"), "suppressions:\n  file: "+filepath.ToSlash(gen)+
		"\n  generate_on_scan: true\nprofiles:\n  other:\n    description: other\n")
	_ = runCLI(t, bin, work, env, "", "--config", "gen.cfg.yaml", "--profile", "other", "--file", "ssn.txt")
	if b, _ := os.ReadFile(gen); !strings.Contains(string(b), "hash:") { // #nosec G304 -- test temp dir
		t.Errorf("suppressions.generate_on_scan: true under --profile other wrote no rule (%q)", b)
	}

	// suppressions.show_suppressed under --profile other lists the suppressed finding.
	supp := filepath.Join(work, "supp.yaml")
	writeFixture(t, filepath.Join(work, "mk.cfg.yaml"), "suppressions:\n  file: "+filepath.ToSlash(supp)+"\n")
	_ = runCLI(t, bin, work, env, "", "--config", "mk.cfg.yaml", "--file", "ssn.txt", "--generate-suppressions")
	b, err := os.ReadFile(supp) // #nosec G304 -- test temp dir
	if err != nil || !strings.Contains(string(b), "enabled: false") {
		t.Fatalf("could not generate a suppression rule to enable: %v %q", err, b)
	}
	writeFixture(t, supp, strings.Replace(string(b), "enabled: false", "enabled: true", 1))
	writeFixture(t, filepath.Join(work, "ss.cfg.yaml"), "suppressions:\n  file: "+filepath.ToSlash(supp)+
		"\n  show_suppressed: true\nprofiles:\n  other:\n    description: other\n")
	r := runCLI(t, bin, work, env, "", "--config", "ss.cfg.yaml", "--profile", "other", "--file", "ssn.txt", "--format", "json")
	var doc struct {
		Suppressed []json.RawMessage `json:"suppressed"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &doc); err != nil || len(doc.Suppressed) != 1 {
		t.Errorf("suppressions.show_suppressed: true under --profile other: %d suppressed entries (%v), want 1: "+
			"the profile switched the config's setting off", len(doc.Suppressed), err)
	}
}

// TestActiveProfileIsNamed: --list-profiles reads the loaded config, auto-discovered included, and
// marks the built-in profile; --debug names the active profile on both input paths.
func TestActiveProfileIsNamed(t *testing.T) {
	bin := buildScanner(t)
	work, _, env := profileWorkdir(t)
	writeFixture(t, filepath.Join(work, "in.txt"), profileInTxt)
	writeFixture(t, filepath.Join(work, "pp.yaml"), "defaults:\n  checks: PASSPORT,SSN\n")
	writeFixture(t, filepath.Join(work, "own.yaml"), "profiles:\n  precommit:\n    checks: SSN\n")

	writeFixture(t, filepath.Join(work, ".ferret-scan.yaml"), "profiles:\n  ci:\n    checks: SSN\n")
	r := runCLI(t, bin, work, env, "", "--list-profiles")
	if !strings.Contains(r.stdout, "  - ci\n") || !strings.Contains(r.stdout, "  - precommit (built-in): ") {
		t.Errorf("--list-profiles with an auto-discovered config: %q, want its ci profile and the built-in precommit", r.stdout)
	}
	_ = os.Remove(filepath.Join(work, ".ferret-scan.yaml"))
	if r = runCLI(t, bin, work, env, "", "--config", "own.yaml", "--list-profiles"); strings.Contains(r.stdout, "built-in") {
		t.Errorf("a config's own precommit profile is listed as built-in: %q", r.stdout)
	}

	for _, input := range [][]string{{"--file", "in.txt"}, {"--stdin"}} {
		stdin := ""
		if input[0] == "--stdin" {
			stdin = profileInTxt
		}
		r = runCLI(t, bin, work, env, stdin, append([]string{"--config", "pp.yaml", "--pre-commit-mode", "--debug"}, input...)...)
		for _, want := range []string{
			`active profile "precommit" (built-in), selected because --pre-commit-mode was passed`,
			"checks=CREDIT_CARD,SECRETS,SSN,EMAIL,PHONE,IP_ADDRESS,PASSPORT",
		} {
			if !strings.Contains(r.stderr, want) {
				t.Errorf("%v --debug: stderr does not contain %q", input, want)
			}
		}
		r = runCLI(t, bin, work, append(append([]string{}, env...), "PRE_COMMIT=1"), stdin, append([]string{"--config", "own.yaml", "--debug"}, input...)...)
		if !strings.Contains(r.stderr, `active profile "precommit" defined in own.yaml, selected because a pre-commit hook environment was detected`) {
			t.Errorf("%v --debug with the config's own profile: the record does not name it", input)
		}
	}
}

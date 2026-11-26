// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// cleanConfig is a config that sets a value every validator can use, so a run over it has nothing to report.
const cleanConfig = "defaults:\n  format: text\n"

// TestCheckConfig is the table of #1086: which config a run would use, and everything configured that
// would not take effect, answered without scanning. Each case asserts stdout, the exit code and an
// empty stderr (a load failure and a rejected value are the command's answer, not the binary failing).
func TestCheckConfig(t *testing.T) {
	bin := buildScanner(t)
	cases := []struct {
		name     string
		where    string // "", "cwd", "userdir" or "explicit"
		body     string
		env      []string
		args     []string
		wantRC   int
		want     []string
		wantNone []string
	}{
		{name: "no config", wantRC: 0,
			want:     []string{"config: none found (built-in defaults)", "profile: none", "config check: OK"},
			wantNone: []string{"pre-commit:"}},
		{name: "clean config in cwd", where: "cwd", body: cleanConfig, wantRC: 0,
			want: []string{"config: config.yaml (working directory)", "config check: OK"}},
		{name: "PCRE lookbehind", where: "cwd", body: badPatternConfig, wantRC: 1,
			want: []string{"Warning: config value validators.social_media.platform_patterns.twitter[0]: not a valid RE2 regular expression",
				"config check: 1 problem(s)"}},
		{name: "unknown key", where: "cwd", body: "bogus_key: 1\n", wantRC: 1,
			want: []string{`Warning: unknown config key "bogus_key"`, "config check: 1 problem(s)"}},
		{name: "unrecognised disabled type", where: "cwd",
			body:   "validators:\n  intellectual_property:\n    disabled_types: [nope]\n",
			wantRC: 1, want: []string{"sub-type(s) nope", "config check: 1 problem(s)"}},
		{name: "recognised disabled type is a note, not a problem", where: "cwd",
			body:   "validators:\n  intellectual_property:\n    disabled_types: [copyright]\n",
			wantRC: 0, want: []string{"disabled 1 INTELLECTUAL_PROPERTY detection sub-type(s)", "config check: OK"}},
		{name: "malformed YAML", where: "cwd", body: "defaults: [\n", wantRC: 1,
			want:     []string{"config load failed: error parsing config file", "config check: 1 problem(s)"},
			wantNone: []string{"profile:"}},
		{name: "--config path", where: "explicit", body: cleanConfig, wantRC: 0,
			want: []string{"(--config)", "config check: OK"}, wantNone: []string{"pre-commit:"}},
		{name: "--config path with a bad value", where: "explicit", body: badPatternConfig, wantRC: 1,
			want: []string{"(--config)", "not a valid RE2 regular expression"}},
		{name: "config in the user config dir", where: "userdir", body: cleanConfig, wantRC: 0,
			want: []string{"(user config dir)", "config check: OK"}, wantNone: []string{"pre-commit:"}},
		{name: "discovered config names the pre-commit refusal", where: "cwd", body: cleanConfig, wantRC: 0,
			want: []string{"pre-commit: config.yaml was found in the working directory", "--allow-project-config", "config check: OK"}},
		{name: "PRE_COMMIT=1 with a discovered config is not refused", where: "cwd", body: cleanConfig,
			env: []string{"PRE_COMMIT=1"}, wantRC: 0,
			want:     []string{"config: config.yaml (working directory)", "profile: precommit (built-in", "config check: OK"},
			wantNone: []string{"Error:"}},
		{name: "--profile that does not exist", where: "cwd", body: cleanConfig, args: []string{"--profile", "nosuch"}, wantRC: 1,
			want: []string{"profile: nosuch not found", "config check: 1 problem(s)"}},
		{name: "--profile that exists", where: "cwd", body: "profiles:\n  mine:\n    checks: EMAIL\n", args: []string{"--profile", "mine"}, wantRC: 0,
			want: []string{"profile: mine (defined in the config)", "config check: OK"}},
		{name: "--stdin --check-config reads no stdin", where: "cwd", body: cleanConfig, args: []string{"--stdin"}, wantRC: 0,
			want: []string{"config check: OK"}, wantNone: []string{"No matches", "findings"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			work, userCfgDir, env := profileWorkdir(t)
			args := []string{"--check-config"}
			switch c.where {
			case "cwd":
				writeFixture(t, filepath.Join(work, "config.yaml"), c.body)
			case "userdir":
				writeFixture(t, filepath.Join(userCfgDir, "config.yaml"), c.body)
			case "explicit":
				path := filepath.Join(t.TempDir(), "named.yaml")
				writeFixture(t, path, c.body)
				args = append(args, "--config", path)
			}
			args = append(args, c.args...)
			stdin := ""
			if len(c.args) > 0 && c.args[0] == "--stdin" {
				stdin = "078-05-1120\n"
			}
			r := runCLI(t, bin, work, append(append([]string{}, env...), c.env...), stdin, args...)
			if r.rc != c.wantRC {
				t.Fatalf("rc %d, want %d\nstdout:\n%s\nstderr:\n%s", r.rc, c.wantRC, r.stdout, r.stderr)
			}
			if r.stderr != "" {
				t.Errorf("stderr must be empty, got:\n%s", r.stderr)
			}
			for _, w := range c.want {
				if !strings.Contains(r.stdout, w) {
					t.Errorf("stdout lacks %q:\n%s", w, r.stdout)
				}
			}
			for _, w := range c.wantNone {
				if strings.Contains(r.stdout, w) {
					t.Errorf("stdout must not contain %q:\n%s", w, r.stdout)
				}
			}
			if last := lastLine(r.stdout); !strings.HasPrefix(last, "config check: ") {
				t.Errorf("the last line must be the summary, got %q", last)
			}
		})
	}
}

// TestCheckConfigIsRefusedWithWeb pins the web side of #1086: the web loads config only from --config
// and has no run to exit from, so the flag is refused at startup like --list-profiles.
func TestCheckConfigIsRefusedWithWeb(t *testing.T) {
	bin := buildScanner(t)
	work, _, env := profileWorkdir(t)
	r := runCLI(t, bin, work, env, "", "--web", "--check-config")
	if r.rc != 1 || !strings.Contains(r.stderr, "--check-config") || !strings.Contains(r.stderr, "Troubleshooting") {
		t.Fatalf("rc %d, want 1 naming --check-config\nstdout:\n%s\nstderr:\n%s", r.rc, r.stdout, r.stderr)
	}
}

func lastLine(s string) string {
	s = strings.TrimRight(s, "\n")
	return s[strings.LastIndex(s, "\n")+1:]
}

// TestHelpListsCheckConfig pins that --help names the flag, beside --list-profiles and in the
// CONFIGURATION section.
func TestHelpListsCheckConfig(t *testing.T) {
	bin := buildScanner(t)
	work, _, env := profileWorkdir(t)
	r := runCLI(t, bin, work, env, "", "--help")
	if r.rc != 0 || strings.Count(r.stdout, "--check-config") < 2 {
		t.Fatalf("--help must list --check-config as an option and in CONFIGURATION (rc %d):\n%s", r.rc, r.stdout)
	}
	if !strings.Contains(r.stdout, "Check the config a run would use: ferret-scan --check-config") {
		t.Errorf("--help lacks the CONFIGURATION sentence:\n%s", r.stdout)
	}
}

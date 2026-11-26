// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// badPatternConfig is a config whose one configured regex RE2 rejects (a PCRE lookbehind) and whose
// precommit profile narrows the hook, so it exercises both the config-value warning (#903) and the
// pre-commit refusal (#293) when a scan runs.
const badPatternConfig = "validators:\n  social_media:\n    platform_patterns:\n      twitter:\n" +
	"        - \"(?<!\\\\w)twitter\"\nprofiles:\n  precommit:\n    checks: EMAIL\n"

// TestVersionAndHelpDoNotReadTheConfig pins #1085: --version and --help are answered before the scan's
// front half, so a config file in the working directory or the user config dir cannot put a warning
// above the version line, and a hook environment cannot turn `--version` into the TM-13 refusal.
// Measured before the fix on v2.6.2: `--version` beside such a config printed the RE2 warning first
// (rc 0), and with #293's refusal in place `PRE_COMMIT=1 ferret-scan --version` exited 1 with no version.
func TestVersionAndHelpDoNotReadTheConfig(t *testing.T) {
	bin := buildScanner(t)
	cases := []struct {
		name       string
		where      string // "cwd" or "userdir"
		env        []string
		args       []string
		wantStdout string
	}{
		{name: "--version, config in cwd", where: "cwd", args: []string{"--version"}, wantStdout: "ferret-scan "},
		{name: "--version, config in user dir", where: "userdir", args: []string{"--version"}, wantStdout: "ferret-scan "},
		{name: "--version, config in cwd, PRE_COMMIT=1", where: "cwd", env: []string{"PRE_COMMIT=1"}, args: []string{"--version"}, wantStdout: "ferret-scan "},
		{name: "--version --pre-commit-mode, config in cwd", where: "cwd", args: []string{"--version", "--pre-commit-mode"}, wantStdout: "ferret-scan "},
		{name: "--help, config in cwd, PRE_COMMIT=1", where: "cwd", env: []string{"PRE_COMMIT=1"}, args: []string{"--help"}, wantStdout: "USAGE:"},
		{name: "--help SSN, config in cwd", where: "cwd", args: []string{"--help", "SSN"}, wantStdout: "SSN"},
		{name: "--help checks, config in user dir", where: "userdir", args: []string{"--help", "checks"}, wantStdout: "SSN"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			work, userCfgDir, env := profileWorkdir(t)
			switch c.where {
			case "cwd":
				writeFixture(t, filepath.Join(work, "config.yaml"), badPatternConfig)
			case "userdir":
				writeFixture(t, filepath.Join(userCfgDir, "config.yaml"), badPatternConfig)
			}
			r := runCLI(t, bin, work, append(append([]string{}, env...), c.env...), "", c.args...)
			if r.rc != 0 {
				t.Fatalf("rc %d, want 0\nstdout:\n%s\nstderr:\n%s", r.rc, r.stdout, r.stderr)
			}
			if r.stderr != "" {
				t.Errorf("stderr must be empty for an informational flag, got:\n%s", r.stderr)
			}
			if !strings.Contains(r.stdout, c.wantStdout) {
				t.Errorf("stdout lacks %q:\n%s", c.wantStdout, r.stdout)
			}
			if c.args[0] == "--version" && strings.Count(strings.TrimSpace(r.stdout), "\n") != 0 {
				t.Errorf("--version must print exactly one line, got:\n%s", r.stdout)
			}
		})
	}
}

// TestScanStillWarnsAboutTheConfigValue is the regression guard for #903: moving --version and --help
// ahead of the front half must not move the warning itself. A scan beside the same config still says,
// once, which configured value it could not use.
func TestScanStillWarnsAboutTheConfigValue(t *testing.T) {
	bin := buildScanner(t)
	work, _, env := profileWorkdir(t)
	writeFixture(t, filepath.Join(work, "config.yaml"), badPatternConfig)
	writeFixture(t, filepath.Join(work, "in.txt"), "nothing here\n")
	r := runCLI(t, bin, work, env, "", "--file", "in.txt")
	if r.rc != 0 {
		t.Fatalf("rc %d, want 0\nstderr:\n%s", r.rc, r.stderr)
	}
	if n := strings.Count(r.stderr, "Warning: config value validators.social_media.platform_patterns.twitter[0]"); n != 1 {
		t.Errorf("the scan must warn about the rejected pattern exactly once, got %d:\n%s", n, r.stderr)
	}
}

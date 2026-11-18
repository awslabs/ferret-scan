// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// The validators' Configure-time [DEBUG] lines under --debug, on --file and --stdin, and the profile
// label on a config-value warning, through the built binary (#903).
//
// Measured on main @ 3b9780b: `--debug` printed 0 of "Cloud Resource Validator initialized" and the
// internal-URL pattern lines on both paths, and `--profile zz` printed the warning path as
// validators.cloud_resources.custom_patterns[0] with no profile in it.
func TestConfigureTimeDebugLinesAreWritten(t *testing.T) {
	bin := buildScanner(t)
	work, _, env := profileWorkdir(t)
	cfg := filepath.Join(work, "dbg.yaml")
	writeFixture(t, cfg, "validators:\n  cloud_resources:\n    custom_patterns: ['bucket-[a-z]+']\n"+
		"  intellectual_property:\n    internal_urls: ['corp\\.example\\.test']\n")
	writeFixture(t, filepath.Join(work, "c.txt"), "reach me at jordan.sample@example.com\n")

	file := runCLI(t, bin, work, env, "", "--config", cfg, "--file", "c.txt", "--debug", "--format", "json")
	stdin := runCLI(t, bin, work, env, "reach me at jordan.sample@example.com\n", "--config", cfg, "--stdin", "--debug", "--format", "json")
	for label, stderr := range map[string]string{"--file": file.stderr, "--stdin": stdin.stderr} {
		for _, want := range []string{"Cloud Resource Validator initialized: ", "1 custom patterns", "Successfully loaded 1 internal URL patterns"} {
			if !strings.Contains(stderr, want) {
				t.Errorf("%s --debug stderr lacks %q", label, want)
			}
		}
	}

	// Control: no --debug, none of them.
	quiet := runCLI(t, bin, work, env, "", "--config", cfg, "--file", "c.txt", "--format", "json")
	if strings.Contains(quiet.stderr, "Cloud Resource Validator initialized") {
		t.Errorf("a run without --debug printed the validator's debug line:\n%s", quiet.stderr)
	}
}

func TestConfigValueWarningNamesTheProfile(t *testing.T) {
	bin := buildScanner(t)
	work, _, env := profileWorkdir(t)
	cfg := filepath.Join(work, "bad.yaml")
	const bad = "custom_patterns: ['(?<=bucket-)[a-z]+']"
	writeFixture(t, cfg, "validators:\n  cloud_resources:\n    "+bad+"\n"+
		"profiles:\n  zz:\n    checks: CLOUD_RESOURCES\n    validators:\n      cloud_resources:\n        "+bad+"\n")
	writeFixture(t, filepath.Join(work, "c.txt"), "bucket s3://my-bucket-1\n")

	for _, tc := range []struct {
		name string
		run  func(args ...string) cliRun
	}{
		{"--file", func(a ...string) cliRun {
			return runCLI(t, bin, work, env, "", append([]string{"--file", "c.txt"}, a...)...)
		}},
		{"--stdin", func(a ...string) cliRun {
			return runCLI(t, bin, work, env, "bucket s3://my-bucket-1\n", append([]string{"--stdin"}, a...)...)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			with := tc.run("--config", cfg, "--profile", "zz", "--format", "json")
			if got := len(cfgWarnLines(with.stderr, "config value validators.cloud_resources.custom_patterns[0]")); got != 1 {
				t.Errorf("want 1 global-block warning, got %d:\n%s", got, with.stderr)
			}
			if got := len(cfgWarnLines(with.stderr, "config value profiles.zz.validators.cloud_resources.custom_patterns[0]")); got != 1 {
				t.Errorf("want 1 warning naming profiles.zz, got %d:\n%s", got, with.stderr)
			}
			without := tc.run("--config", cfg, "--format", "json")
			if l := cfgWarnLines(without.stderr, "config value"); len(l) != 1 || strings.Contains(l[0], "profiles.") {
				t.Errorf("no --profile: want the one bare-path warning, got %q", l)
			}
		})
	}
}

func cfgWarnLines(stderr, sub string) []string {
	var out []string
	for _, l := range strings.Split(stderr, "\n") {
		if strings.Contains(l, sub) {
			out = append(out, l)
		}
	}
	return out
}

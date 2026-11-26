// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// refusalText is the part of the refusal every row looks for.
const refusalText = "was found in the working directory and is not used in pre-commit mode"

// narrowingConfig redefines the built-in precommit profile as EMAIL only: the plant of #293. The scanned
// file holds an SSN, so a hook that used it passes a commit it should block.
const narrowingConfig = "profiles:\n  precommit:\n    checks: EMAIL\n"

const refusalInput = "Employee SSN: 456-45-6789\n"

// TestPrecommitDiscoveredConfig is the table for #293 direction 2 (THREAT_MODEL TM-13): in pre-commit mode
// a config discovered in the working directory is refused unless --allow-project-config was typed. It runs
// the built binary on both input paths, because the defect was in the caller's gate and not in a function
// a unit test could reach, and it covers every way into pre-commit mode: the flag and each of the four
// environment variables the detector reads.
//
// Before the change, a planted config.yaml with this content made the shipped hook arguments exit 0 with
// 0 bytes on stdout and a 117-byte note on stderr that pre-commit does not show for a passing hook.
func TestPrecommitDiscoveredConfig(t *testing.T) {
	bin := buildScanner(t)

	triggers := []struct {
		name string
		env  []string
		args []string
		pre  bool
	}{
		{name: "--pre-commit-mode", args: []string{"--pre-commit-mode"}, pre: true},
		{name: "neither"},
	}
	for _, v := range precommitTriggers {
		triggers = append(triggers, struct {
			name string
			env  []string
			args []string
			pre  bool
		}{name: v + "=1", env: []string{v + "=1"}, pre: true})
	}

	configs := []struct {
		name  string
		plant string // file name planted in the working directory, "" for none
		extra []string
		// wantRefused is true when a pre-commit run must refuse.
		wantRefused bool
		// wantRC is the exit code of a pre-commit run that is not refused.
		wantRC int
	}{
		{name: "no config", wantRC: 1},
		{name: "config.yaml planted", plant: "config.yaml", wantRefused: true},
		{name: ".ferret-scan.yaml planted", plant: ".ferret-scan.yaml", wantRefused: true},
		{name: "planted + --allow-project-config", plant: "config.yaml", extra: []string{"--allow-project-config"}, wantRC: 0},
		{name: "planted + --config <empty file>", plant: "config.yaml", extra: []string{"--config", "empty.yaml"}, wantRC: 1},
	}

	for _, path := range []string{"file", "stdin"} {
		for _, tr := range triggers {
			for _, c := range configs {
				t.Run(path+"/"+tr.name+"/"+c.name, func(t *testing.T) {
					work, _, env := profileWorkdir(t)
					writeFixture(t, filepath.Join(work, "in.txt"), refusalInput)
					writeFixture(t, filepath.Join(work, "empty.yaml"), "")
					if c.plant != "" {
						writeFixture(t, filepath.Join(work, c.plant), narrowingConfig)
					}
					args := append(append(append([]string{}, tr.args...), c.extra...), "--profile", "precommit")
					stdin := ""
					if path == "file" {
						args = append(args, "--file", "in.txt")
					} else {
						args = append(args, "--stdin", "--stdin-name", "in.txt")
						stdin = refusalInput
					}
					r := runCLI(t, bin, work, append(append([]string{}, env...), tr.env...), stdin, args...)

					refused := tr.pre && c.wantRefused
					got := strings.Contains(r.stderr, refusalText)
					if got != refused {
						t.Fatalf("refusal on stderr = %v, want %v (rc %d)\nstderr:\n%s", got, refused, r.rc, r.stderr)
					}
					if refused {
						if r.rc != 1 || r.stdout != "" {
							t.Errorf("refused run: rc %d stdout %q, want rc 1 and no stdout", r.rc, r.stdout)
						}
						if !strings.Contains(r.stderr, c.plant) || !strings.Contains(r.stderr, "TM-13") ||
							!strings.Contains(r.stderr, "--allow-project-config") || !strings.Contains(r.stderr, "--config <path>") {
							t.Errorf("the error must name the file, TM-13 and both ways out:\n%s", r.stderr)
						}
						return
					}
					if tr.pre && r.rc != c.wantRC {
						t.Errorf("rc %d, want %d\nstderr:\n%s", r.rc, c.wantRC, r.stderr)
					}
					// With the flag the behaviour is today's, provenance note included.
					if tr.pre && c.name == "planted + --allow-project-config" && !strings.Contains(r.stderr, "project config "+c.plant) {
						t.Errorf("an allowed project config is no longer named on stderr:\n%s", r.stderr)
					}
				})
			}
		}
	}
}

// TestPrecommitRefusalCannotBeSetFromTheFile: the flag is CLI-only. A config that carried it would unlock
// itself, so neither a defaults key, a profile key, nor an environment variable may allow the run.
func TestPrecommitRefusalCannotBeSetFromTheFile(t *testing.T) {
	bin := buildScanner(t)
	for _, tc := range []struct{ name, config string }{
		{"defaults key", "defaults:\n  allow_project_config: true\n" + narrowingConfig},
		{"profile key", "profiles:\n  precommit:\n    checks: EMAIL\n    allow_project_config: true\n"},
	} {
		for _, path := range []string{"file", "stdin"} {
			t.Run(tc.name+"/"+path, func(t *testing.T) {
				work, _, env := profileWorkdir(t)
				writeFixture(t, filepath.Join(work, "in.txt"), refusalInput)
				writeFixture(t, filepath.Join(work, "config.yaml"), tc.config)
				args, stdin := []string{"--pre-commit-mode", "--file", "in.txt"}, ""
				if path == "stdin" {
					args, stdin = []string{"--pre-commit-mode", "--stdin"}, refusalInput
				}
				env = append(env, "FERRET_ALLOW_PROJECT_CONFIG=1", "ALLOW_PROJECT_CONFIG=true")
				r := runCLI(t, bin, work, env, stdin, args...)
				if r.rc != 1 || !strings.Contains(r.stderr, refusalText) {
					t.Errorf("a config key or environment variable lifted the refusal: rc %d\n%s", r.rc, r.stderr)
				}
			})
		}
	}
}

// TestPrecommitRefusalSurvivesQuietAndRedaction: the refusal is an error, not progress, so --quiet does not
// withhold it, and with --enable-redaction and no --output (stderr carries the findings document) it is
// still the only thing written to stderr and nothing is written to stdout.
func TestPrecommitRefusalSurvivesQuietAndRedaction(t *testing.T) {
	bin := buildScanner(t)
	for _, extra := range [][]string{{"--quiet"}, {"--enable-redaction"}, {"--quiet", "--enable-redaction"}} {
		t.Run(strings.Join(extra, " "), func(t *testing.T) {
			work, _, env := profileWorkdir(t)
			writeFixture(t, filepath.Join(work, ".ferret-scan.yaml"), narrowingConfig)
			r := runCLI(t, bin, work, env, refusalInput, append([]string{"--stdin", "--pre-commit-mode"}, extra...)...)
			if r.rc != 1 || r.stdout != "" || !strings.HasPrefix(r.stderr, "Error: .ferret-scan.yaml "+refusalText) {
				t.Errorf("rc %d stdout %q stderr %q, want rc 1, no stdout and the refusal alone on stderr", r.rc, r.stdout, r.stderr)
			}
			if strings.Count(r.stderr, "\n") != 1 {
				t.Errorf("the refusal must be one line, got:\n%s", r.stderr)
			}
		})
	}
}

// TestUserConfigDirIsNotRefusedInPrecommit: a config from the user config dir is the developer's own, not a
// file discovered in the tree under review.
func TestUserConfigDirIsNotRefusedInPrecommit(t *testing.T) {
	bin := buildScanner(t)
	work, userCfg, env := profileWorkdir(t)
	writeFixture(t, filepath.Join(work, "in.txt"), refusalInput)
	writeFixture(t, filepath.Join(userCfg, "config.yaml"), "defaults:\n  checks: SSN\n")
	r := runCLI(t, bin, work, env, "", "--pre-commit-mode", "--file", "in.txt")
	if strings.Contains(r.stderr, refusalText) || r.rc != 1 {
		t.Errorf("a user-config-dir config was refused or the SSN was missed: rc %d\n%s", r.rc, r.stderr)
	}
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --quiet and the two TM-13 Notes (#1008 item 3): "Note: using project config … found in the working
// directory" and "Note: config disabled N … detection sub-type(s)".
//
// Measured on main @ a73c55d6, a .ferret-scan.yaml in the working directory disabling copyright, on
// --file and --stdin, all seven formats: `--quiet` leaves both Notes on stderr (495 B with the config
// that also names a sub-type that does not exist), exactly as without it. #1007 made every format but
// csv carry the same two facts in its own document (the scope block), so the stderr copy is duplication
// for six formats and the only channel for csv.
//
// The rule, pinned here:
//   - a --quiet typed on the command line withholds both Notes, except under --format csv;
//   - the pre-commit default, --quiet=false and a config file's `quiet: true` do not: a config shipped in
//     a pull request can disable detection, and it must not be able to silence the Note naming it (TB-7);
//   - the Warning for a `disabled_types` entry that named nothing stays: that config had NO effect;
//   - the document carries both facts whether or not the Notes print.

const tm13Config = "validators:\n  intellectual_property:\n    disabled_types:\n      - copyright\n      - copyrite\n"

const tm13Input = "Copyright (c) 2026 Acme Corporation. All rights reserved.\n"

var tm13Formats = []string{"text", "json", "yaml", "csv", "junit", "gitlab-sast", "sarif"}

// tm13Run runs the scanner in a fresh directory holding .ferret-scan.yaml = config and notice.txt, on
// --file or --stdin, and returns what it wrote.
func tm13Run(t *testing.T, bin, config, path string, args ...string) cliRun {
	t.Helper()
	dir := t.TempDir()
	writeFixture(t, filepath.Join(dir, ".ferret-scan.yaml"), config)
	writeFixture(t, filepath.Join(dir, "notice.txt"), tm13Input)
	if err := os.MkdirAll(filepath.Join(dir, "emptycfg"), 0o750); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "FERRET_CONFIG_DIR="+filepath.Join(dir, "emptycfg"))
	base := []string{"--checks", "INTELLECTUAL_PROPERTY"}
	if path == "file" {
		return runCLI(t, bin, dir, env, "", append(append([]string{"--file", "notice.txt"}, base...), args...)...)
	}
	return runCLI(t, bin, dir, env, tm13Input,
		append(append([]string{"--stdin", "--stdin-name", "notice.txt"}, base...), args...)...)
}

func tm13Notes(stderr string) (provenance, disabled, warning bool) {
	return strings.Contains(stderr, "Note: using project config .ferret-scan.yaml found in the working directory"),
		strings.Contains(stderr, "Note: config disabled 1 INTELLECTUAL_PROPERTY detection sub-type(s)"),
		strings.Contains(stderr, "Warning: config asked to disable INTELLECTUAL_PROPERTY sub-type(s) copyrite")
}

func TestQuietWithholdsTheTM13Notes(t *testing.T) {
	bin := buildScanner(t)
	for _, path := range []string{"file", "stdin"} {
		for _, format := range tm13Formats {
			t.Run(path+"/"+format, func(t *testing.T) {
				// Without --quiet: both Notes and the Warning, so every row below can fail.
				plain := tm13Run(t, bin, tm13Config, path, "--format", format)
				if p, d, w := tm13Notes(plain.stderr); !p || !d || !w {
					t.Fatalf("no --quiet: provenance %v, disabled %v, warning %v, want all three:\n%s", p, d, w, plain.stderr)
				}

				quiet := tm13Run(t, bin, tm13Config, path, "--format", format, "--quiet")
				p, d, w := tm13Notes(quiet.stderr)
				wantNotes := format == "csv" // no scope block, so stderr stays the channel
				if p != wantNotes || d != wantNotes {
					t.Errorf("--quiet: provenance %v, disabled %v, want both %v:\n%s", p, d, wantNotes, quiet.stderr)
				}
				if !w {
					t.Errorf("--quiet withheld the Warning for a disabled_types entry that matched nothing:\n%s", quiet.stderr)
				}
				if quiet.rc != plain.rc {
					t.Errorf("exit code moved with --quiet: %d, want %d", quiet.rc, plain.rc)
				}

				// The document names both facts either way; csv names neither, which is why it keeps the Notes.
				carries := strings.Contains(quiet.stdout, ".ferret-scan.yaml") && strings.Contains(quiet.stdout, "copyright")
				if carries == wantNotes {
					t.Errorf("--quiet document carries the config source and the disabled sub-type = %v, "+
						"but the Notes are withheld = %v: they must be exact opposites\n%s", carries, !wantNotes, quiet.stdout)
				}

				// quiet=false is no --quiet.
				if p, d, _ := tm13Notes(tm13Run(t, bin, tm13Config, path, "--format", format, "--quiet=false").stderr); !p || !d {
					t.Errorf("--quiet=false: provenance %v, disabled %v, want both", p, d)
				}
			})
		}
	}
}

// TestTM13NotesSurviveWhatAConfigFileCanSet: `quiet: true` in the discovered config, or the pre-commit
// default, must not withhold the Notes. A config that can both disable a detection type and silence
// the Note naming it is the TB-7 hole TM-13 closed.
func TestTM13NotesSurviveWhatAConfigFileCanSet(t *testing.T) {
	bin := buildScanner(t)
	quietConfig := "defaults:\n  quiet: true\n" + tm13Config
	for _, path := range []string{"file", "stdin"} {
		t.Run(path, func(t *testing.T) {
			for _, tc := range []struct {
				name, config string
				args         []string
			}{
				{"defaults.quiet: true", quietConfig, []string{"--format", "json"}},
				{"--pre-commit-mode", tm13Config, []string{"--pre-commit-mode"}},
				{"--pre-commit-mode, quiet config", quietConfig, []string{"--pre-commit-mode"}},
			} {
				r := tm13Run(t, bin, tc.config, path, tc.args...)
				if p, d, _ := tm13Notes(r.stderr); !p || !d {
					t.Errorf("%s: provenance %v, disabled %v, want both:\n%s", tc.name, p, d, r.stderr)
				}
			}
			// With the flag typed as well, the operator has asked for it.
			r := tm13Run(t, bin, tm13Config, path, "--pre-commit-mode", "--quiet")
			if p, d, _ := tm13Notes(r.stderr); p || d {
				t.Errorf("--pre-commit-mode --quiet: provenance %v, disabled %v, want neither:\n%s", p, d, r.stderr)
			}
		})
	}
}

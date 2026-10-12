// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The #753 lexical gate takes the file type from the NAME on every channel, and this pins that
// through the real binary. A unit test of sourceLanguageFor cannot catch a channel that stops
// passing the name through -- stdin mode routes through core.ScanContent with --stdin-name as the
// virtual path, not through the file router -- so the contract is asserted where a user meets it.
//
// The bytes are the #753 contrast: `token: AuthToken` is a type annotation in TypeScript and may be
// a value in YAML. Gated, both lines drop; ungated, both report, exactly as before the gate.
func TestSourceGateFollowsTheNameOnEveryCLIChannel(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	bin := buildForCLIContract(t)
	const body = "token: AuthToken\npassword: MixedCaseNoDigits\n"

	dir := t.TempDir()
	for _, name := range []string{"models.ts", "settings.yaml"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	cases := []struct {
		name string
		args []string
		want int
	}{
		{"--stdin-name x.ts is gated", []string{"--stdin", "--stdin-name", "x.ts"}, 0},
		{"--stdin-name with no extension is not", []string{"--stdin", "--stdin-name", "notes"}, 2},
		{"bare --stdin (<stdin>) is not", []string{"--stdin"}, 2},
		{"--stdin-name x.yaml is not", []string{"--stdin", "--stdin-name", "x.yaml"}, 2},
		{"a .ts path is gated", []string{"--file", filepath.Join(dir, "models.ts")}, 0},
		{"a .yaml path is not", []string{"--file", filepath.Join(dir, "settings.yaml")}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append(tc.args, "--checks", "SECRETS", "--format", "json", "--config", os.DevNull,
				"--quiet", "--no-color", "--limit", "0")
			cmd := exec.Command(bin, args...)
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "FERRET_PRECOMMIT=0"}
			cmd.Dir = dir
			cmd.Stdin = strings.NewReader(body)
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("%v: %v\n%s", args, err, out)
			}
			var doc struct {
				Results []struct {
					LineNumber int     `json:"line_number"`
					Confidence float64 `json:"confidence"`
				} `json:"results"`
			}
			if err := json.Unmarshal(out, &doc); err != nil {
				t.Fatalf("unparseable JSON: %v\n%s", err, out)
			}
			if len(doc.Results) != tc.want {
				t.Errorf("%v: %d findings, want %d", args, len(doc.Results), tc.want)
			}
		})
	}
}

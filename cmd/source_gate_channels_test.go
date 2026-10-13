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
	// A React component saved as .js: JSX text is neither code nor a JS string, so the file fails
	// the gate open and reports both lines, through the file path and through --stdin-name alike.
	// Written with no credential-shaped literal in this file: the two values are the same bytes as
	// above, inside JSX children.
	const jsxBody = "export default () => (\n  <pre>\n    token: AuthToken\n" +
		"    password: MixedCaseNoDigits\n  </pre>\n);\n"
	if err := os.WriteFile(filepath.Join(dir, "Help.js"), []byte(jsxBody), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "plain.js"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	// A value pasted between quotes no grammar here accepts is not valid source, so the file fails
	// the gate open and reports both lines: Windows-1252 smart quotes (raw 0x93/0x94 bytes, which
	// the file and stdin paths both decode to U+0093/U+0094) and guillemets.
	const smartBody = "token: AuthToken\npassword = \x93MixedCaseNoDigits\x94\n"
	const guillBody = "token: AuthToken\npassword = \u00abMixedCaseNoDigits\u00bb\n"
	if err := os.WriteFile(filepath.Join(dir, "smart.py"), []byte(smartBody), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "guill.py"), []byte(guillBody), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		args  []string
		stdin string
		want  int
	}{
		{"--stdin-name x.ts is gated", []string{"--stdin", "--stdin-name", "x.ts"}, "", 0},
		{"--stdin-name with no extension is not", []string{"--stdin", "--stdin-name", "notes"}, "", 2},
		{"bare --stdin (<stdin>) is not", []string{"--stdin"}, "", 2},
		{"--stdin-name x.yaml is not", []string{"--stdin", "--stdin-name", "x.yaml"}, "", 2},
		{"a .ts path is gated", []string{"--file", filepath.Join(dir, "models.ts")}, "", 0},
		{"a .yaml path is not", []string{"--file", filepath.Join(dir, "settings.yaml")}, "", 2},
		{"a .js path of plain code is gated", []string{"--file", filepath.Join(dir, "plain.js")}, "", 0},
		{"a .js path holding JSX fails open", []string{"--file", filepath.Join(dir, "Help.js")}, "", 2},
		{"--stdin-name x.js with JSX fails open", []string{"--stdin", "--stdin-name", "x.js"}, jsxBody, 2},
		{"a .py path with cp1252 smart quotes fails open", []string{"--file", filepath.Join(dir, "smart.py")}, "", 2},
		{"--stdin-name x.py with cp1252 smart quotes fails open", []string{"--stdin", "--stdin-name", "x.py"}, smartBody, 2},
		{"a .py path with guillemets fails open", []string{"--file", filepath.Join(dir, "guill.py")}, "", 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append(tc.args, "--checks", "SECRETS", "--format", "json", "--config", os.DevNull,
				"--quiet", "--no-color", "--limit", "0")
			cmd := exec.Command(bin, args...)
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "FERRET_PRECOMMIT=0"}
			cmd.Dir = dir
			in := body
			if tc.stdin != "" {
				in = tc.stdin
			}
			cmd.Stdin = strings.NewReader(in)
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

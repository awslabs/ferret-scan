// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// The "Warning: config value …" line (#903) on both input paths, and in the report.
//
// #917 made the validators record a configured value they cannot use and removed their raw stderr
// writes; core.ScanContent reports the lines, but runStdinScan printed none of them. Measured on main
// @ 2fb4719 with a custom pattern RE2 rejects: --file prints the warning, --stdin prints 0 bytes of it in
// default mode, --quiet and --pre-commit-mode, and the --stdin gateway's findings document (stderr under
// --enable-redaction without --output) has no field for it. A pattern that silently stopped detecting
// is a value the gateway passes through in clear.

// configWarningSample is reported by cloud_resources whatever the custom pattern does, so every row has
// a finding and the gateway rows write a findings document. The ARN is assembled from pieces so this
// source holds no ARN-shaped literal.
var configWarningSample = "Deployment role: arn:aws:iam::" + "210987654321" + ":role/deploy-runner\n" +
	"Ticket ref: CUSTOMID-482913\n"

// lookbehindConfig is the issue's c-lookbehind row: RE2 has no lookbehind, so the pattern is dropped.
const lookbehindConfig = "validators: {cloud_resources: {custom_patterns: ['(?<=Ticket ref: )CUSTOMID-\\d{6}']}}\n"

// usableConfig is its valid twin.
const usableConfig = "validators: {cloud_resources: {custom_patterns: ['CUSTOMID-\\d{6}']}}\n"

func configWarningLines(stderr string) []string {
	var out []string
	for _, line := range strings.Split(stderr, "\n") {
		if strings.HasPrefix(line, "Warning: config value ") {
			out = append(out, line)
		}
	}
	return out
}

func statsConfigWarnings(t *testing.T, label, doc string) (warnings []string, present bool) {
	t.Helper()
	var parsed struct {
		Stats map[string]json.RawMessage `json:"stats"`
	}
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		t.Fatalf("%s: the findings document does not parse (%v):\n%s", label, err, doc)
	}
	raw, ok := parsed.Stats["config_warnings"]
	if !ok {
		return nil, false
	}
	if err := json.Unmarshal(raw, &warnings); err != nil {
		t.Fatalf("%s: stats.config_warnings is not a list of strings (%v): %s", label, err, raw)
	}
	return warnings, true
}

// TestStdinPrintsConfigValueWarningsAsFileDoes: the same config through --file and --stdin prints the
// same warning lines, in every mode the file path prints them in, with the same exit code.
func TestStdinPrintsConfigValueWarningsAsFileDoes(t *testing.T) {
	bin := buildScanner(t)
	work, _, env := profileWorkdir(t)
	writeFixture(t, filepath.Join(work, "cloud.txt"), configWarningSample)
	writeFixture(t, filepath.Join(work, "bad.yaml"), lookbehindConfig)

	base := []string{"--config", "bad.yaml", "--checks", "CLOUD_RESOURCES", "--format", "json"}
	for _, tc := range []struct {
		name string
		env  []string
		args []string
	}{
		{"plain", nil, nil},
		{"--quiet", nil, []string{"--quiet"}},
		{"--pre-commit-mode", nil, []string{"--pre-commit-mode"}},
		{"PRE_COMMIT=1", []string{"PRE_COMMIT=1"}, nil},
		{"--enable-redaction --output", nil, []string{"--enable-redaction", "--output", "report.json"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runEnv := append(append([]string{}, env...), tc.env...)
			file := runCLI(t, bin, work, runEnv, "", append(append([]string{"--file", "cloud.txt"}, base...), tc.args...)...)
			stdin := runCLI(t, bin, work, runEnv, configWarningSample,
				append(append([]string{"--stdin", "--stdin-name", "cloud.txt"}, base...), tc.args...)...)
			fw, sw := configWarningLines(file.stderr), configWarningLines(stdin.stderr)
			if len(fw) != 1 || !strings.Contains(fw[0], "validators.cloud_resources.custom_patterns[0]") {
				t.Fatalf("--file printed %q, want the one custom_patterns[0] warning, so the comparison is vacuous:\n%s", fw, file.stderr)
			}
			if len(sw) != 1 || sw[0] != fw[0] {
				t.Errorf("--stdin printed %q, want --file's %q\nstdin stderr:\n%s", sw, fw[0], stdin.stderr)
			}
			if file.rc != stdin.rc {
				t.Errorf("rc --file %d, --stdin %d", file.rc, stdin.rc)
			}
		})
	}
}

// TestConfigValueWarningsRideInTheReport: stats.config_warnings carries the lines the warning prints,
// without its "Warning: " prefix, on --file and --stdin; SARIF carries them in
// toolConfigurationNotifications; and on the gateway, where stderr IS the findings document, the
// document still parses and is the warning's channel.
func TestConfigValueWarningsRideInTheReport(t *testing.T) {
	bin := buildScanner(t)
	work, _, env := profileWorkdir(t)
	writeFixture(t, filepath.Join(work, "cloud.txt"), configWarningSample)
	writeFixture(t, filepath.Join(work, "bad.yaml"), lookbehindConfig)
	base := []string{"--config", "bad.yaml", "--checks", "CLOUD_RESOURCES"}

	file := runCLI(t, bin, work, env, "", append([]string{"--file", "cloud.txt", "--format", "json"}, base...)...)
	printed := configWarningLines(file.stderr)
	if len(printed) != 1 {
		t.Fatalf("--file printed %d config warnings, want 1:\n%s", len(printed), file.stderr)
	}
	want := strings.TrimPrefix(printed[0], "Warning: ")

	check := func(label, doc string) {
		t.Helper()
		got, present := statsConfigWarnings(t, label, doc)
		if !present || len(got) != 1 || got[0] != want {
			t.Errorf("%s: stats.config_warnings = %q (present %v), want [%q]", label, got, present, want)
		}
	}
	check("--file json", file.stdout)
	stdin := runCLI(t, bin, work, env, configWarningSample, append([]string{"--stdin", "--format", "json"}, base...)...)
	check("--stdin json", stdin.stdout)

	t.Run("gateway: stderr is the findings document", func(t *testing.T) {
		r := runCLI(t, bin, work, env, configWarningSample,
			append([]string{"--stdin", "--format", "json", "--enable-redaction"}, base...)...)
		if r.rc != 0 {
			t.Fatalf("rc %d\n%s", r.rc, r.stderr)
		}
		// statsConfigWarnings fails the test when the document does not parse, which is what a prose line
		// ahead of it would cause.
		check("--stdin --enable-redaction stderr", r.stderr)
	})

	t.Run("sarif", func(t *testing.T) {
		r := runCLI(t, bin, work, env, "", append([]string{"--file", "cloud.txt", "--format", "sarif"}, base...)...)
		var doc struct {
			Runs []struct {
				Invocations []struct {
					ToolConfigurationNotifications []struct {
						Message struct {
							Text string `json:"text"`
						} `json:"message"`
					} `json:"toolConfigurationNotifications"`
				} `json:"invocations"`
			} `json:"runs"`
		}
		if err := json.Unmarshal([]byte(r.stdout), &doc); err != nil {
			t.Fatalf("the SARIF report does not parse: %v\n%s", err, r.stdout)
		}
		var got []string
		for _, run := range doc.Runs {
			for _, inv := range run.Invocations {
				for _, n := range inv.ToolConfigurationNotifications {
					got = append(got, n.Message.Text)
				}
			}
		}
		if len(got) != 1 || got[0] != want {
			t.Errorf("toolConfigurationNotifications = %q, want [%q]", got, want)
		}
	})
}

// TestAUsableConfigNamesNoConfigValue is the precision half: the valid twin prints no warning on either
// path and adds no key to any report, so a run whose configuration is usable keeps every byte.
func TestAUsableConfigNamesNoConfigValue(t *testing.T) {
	bin := buildScanner(t)
	work, _, env := profileWorkdir(t)
	writeFixture(t, filepath.Join(work, "cloud.txt"), configWarningSample)
	writeFixture(t, filepath.Join(work, "good.yaml"), usableConfig)
	base := []string{"--config", "good.yaml", "--checks", "CLOUD_RESOURCES"}

	for _, tc := range []struct {
		name  string
		stdin string
		args  []string
		doc   func(cliRun) string
	}{
		{"--file json", "", []string{"--file", "cloud.txt", "--format", "json"}, func(r cliRun) string { return r.stdout }},
		{"--file sarif", "", []string{"--file", "cloud.txt", "--format", "sarif"}, func(r cliRun) string { return r.stdout }},
		{"--stdin json", configWarningSample, []string{"--stdin", "--format", "json"}, func(r cliRun) string { return r.stdout }},
		{"--stdin gateway json", configWarningSample, []string{"--stdin", "--format", "json", "--enable-redaction"}, func(r cliRun) string { return r.stderr }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := runCLI(t, bin, work, env, tc.stdin, append(tc.args, base...)...)
			if lines := configWarningLines(r.stderr); len(lines) != 0 {
				t.Errorf("a usable config printed %q", lines)
			}
			doc := tc.doc(r)
			// CLOUD_RESOURCE_ID is the type the custom pattern reports; the scope block names only the check.
			if !strings.Contains(doc, "CLOUD_RESOURCE_ID") {
				t.Fatalf("the valid custom pattern found nothing, so this control is vacuous:\n%s", doc)
			}
			for _, banned := range []string{"config_warnings", "toolConfigurationNotifications"} {
				if strings.Contains(doc, banned) {
					t.Errorf("a usable config gained %q in the report:\n%s", banned, doc)
				}
			}
		})
	}
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

// The "Warning: config value …" disclosure on --stdin --enable-redaction when the input has no finding
// (#903, the zero-findings edge left by #955).
//
// Measured on main @ a73c55d6, config with a custom pattern RE2 rejects, input with no finding, every
// format: stderr 0 bytes, so a gateway reading stderr as the findings document got an empty stream and
// the warning appeared nowhere. With one finding on the input json/yaml/sarif carry the warning in the
// document (#955); text, csv, junit and gitlab-sast have no place for it.

// noFindingInput holds nothing CLOUD_RESOURCES reports.
const noFindingInput = "Meeting notes: nothing to see here.\n"

func TestZeroFindingGatewayDisclosesConfigWarnings(t *testing.T) {
	bin := buildScanner(t)
	work, _, env := profileWorkdir(t)
	writeFixture(t, filepath.Join(work, "bad.yaml"), lookbehindConfig)
	writeFixture(t, filepath.Join(work, "good.yaml"), usableConfig)
	base := []string{"--stdin", "--enable-redaction", "--checks", "CLOUD_RESOURCES"}

	for _, format := range []string{"text", "json", "yaml", "csv", "junit", "sarif", "gitlab-sast"} {
		t.Run(format, func(t *testing.T) {
			r := runCLI(t, bin, work, env, noFindingInput, append(base, "--format", format, "--config", "bad.yaml")...)
			if r.rc != 0 {
				t.Fatalf("rc %d, want 0 (a dropped pattern is a disclosure, not a failure)\n%s", r.rc, r.stderr)
			}
			if r.stdout != noFindingInput {
				t.Errorf("the redacted stream changed: %q", r.stdout)
			}
			if !strings.Contains(r.stderr, "custom_patterns[0]") {
				t.Fatalf("stderr does not name the dropped pattern (%d bytes):\n%s", len(r.stderr), r.stderr)
			}
			// The valid twin writes nothing, as before: empty stderr still means a clean run.
			twin := runCLI(t, bin, work, env, noFindingInput, append(base, "--format", format, "--config", "good.yaml")...)
			if twin.stderr != "" {
				t.Errorf("valid twin: %d bytes on stderr, want 0:\n%s", len(twin.stderr), twin.stderr)
			}
			if statsCarryConfigWarnings(format) {
				// The document, not prose ahead of it: json must still parse.
				if format == "json" {
					got, present := statsConfigWarnings(t, format, r.stderr)
					if !present || len(got) != 1 {
						t.Errorf("stats.config_warnings = %q (present %v), want the one warning", got, present)
					}
				}
				if len(configWarningLines(r.stderr)) != 0 {
					t.Errorf("a prose Warning line sits in the %s document:\n%s", format, r.stderr)
				}
				return
			}
			if n := len(configWarningLines(r.stderr)); n != 1 {
				t.Errorf("%s: %d Warning lines, want 1:\n%s", format, n, r.stderr)
			}
		})
	}
}

// TestStatsCarryConfigWarningsMatchesTheFormatters: statsCarryConfigWarnings is a list, and the list is
// true only while each formatter agrees. A formatter that starts or stops writing Stats.ConfigWarnings
// fails here rather than leaving the gateway with the wrong channel.
func TestStatsCarryConfigWarningsMatchesTheFormatters(t *testing.T) {
	const marker = "config value validators.example[0]: marker-for-the-test"
	for _, name := range []string{"text", "json", "yaml", "csv", "junit", "sarif", "gitlab-sast"} {
		f, ok := formatters.Get(name)
		if !ok {
			t.Fatalf("no formatter %q", name)
		}
		out, err := f.Format(nil, nil, formatters.FormatterOptions{
			Stats: &formatters.ScanStats{TotalFiles: 1, FilesProcessed: 1, ConfigWarnings: []string{marker}},
		})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := strings.Contains(out, "marker-for-the-test"); got != statsCarryConfigWarnings(name) {
			t.Errorf("%s: the document carries the warning = %v, statsCarryConfigWarnings = %v",
				name, got, statsCarryConfigWarnings(name))
		}
	}
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readFileForTest(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path) // #nosec G304 -- a path the test created
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// expiredSample has two findings the built-in precommit profile also scans for (a card and an email), so
// the pre-commit rows exercise the warning rather than a scan that found nothing. Synthetic values: the
// card is a patterned body plus its Luhn digit, the domain is invented.
const expiredSample = "Contact: jane.roe@contoso-example.net\ncard number: 4539000000123457\n"

func expiredWarningLines(stderr string) []string {
	var out []string
	for _, line := range strings.Split(stderr, "\n") {
		if strings.Contains(line, "suppression rule has EXPIRED") {
			out = append(out, line)
		}
	}
	return out
}

// TestStdinWarnsAboutExpiredRules is the --stdin half of #696's warning (#866). The file path has said
// "N finding(s) are reported because their suppression rule has EXPIRED" since #699; --stdin said nothing,
// and `--stdin --pre-commit-mode` blocked a commit with 0 bytes on stderr. It is a disclosure about what
// governed the run, so like the config-provenance note it is withheld only where stderr IS the findings
// document: --enable-redaction without --output.
func TestStdinWarnsAboutExpiredRules(t *testing.T) {
	bin := buildScanner(t)
	work, _, env := profileWorkdir(t)
	writeFixture(t, filepath.Join(work, "sample.txt"), expiredSample)
	gen := filepath.Join(work, "gen.yaml")
	if r := runCLI(t, bin, work, env, "", "--file", "sample.txt", "--generate-suppressions", "--suppression-file", gen); r.rc != 0 {
		t.Fatalf("generating rules: rc %d\n%s", r.rc, r.stderr)
	}
	raw := readFileForTest(t, gen)
	expired := strings.ReplaceAll(strings.ReplaceAll(raw, "enabled: false", "enabled: true"),
		"enabled: true\n", "enabled: true\n      expires_at: 2020-01-01T00:00:00Z\n")
	if strings.Count(expired, "expires_at: 2020-01-01") != 2 {
		t.Fatalf("expected two expired rules, got:\n%s", expired)
	}
	writeFixture(t, filepath.Join(work, "expired.yaml"), expired)

	base := []string{"--format", "json", "--suppression-file", "expired.yaml"}
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
			file := runCLI(t, bin, work, runEnv, "", append(append([]string{"--file", "sample.txt"}, base...), tc.args...)...)
			stdin := runCLI(t, bin, work, runEnv, expiredSample,
				append(append([]string{"--stdin", "--stdin-name", "sample.txt"}, base...), tc.args...)...)
			fw, sw := expiredWarningLines(file.stderr), expiredWarningLines(stdin.stderr)
			if len(fw) != 1 {
				t.Fatalf("--file printed %d EXPIRED warnings, want 1, so the comparison is vacuous:\n%s", len(fw), file.stderr)
			}
			if len(sw) != 1 || sw[0] != fw[0] {
				t.Errorf("--stdin's EXPIRED warning %q, want --file's %q\nstdin stderr:\n%s", sw, fw[0], stdin.stderr)
			}
			if !strings.Contains(fw[0], "WARNING: 2 finding(s)") || !strings.Contains(fw[0], "oldest expired 2020-01-01") {
				t.Errorf("the warning does not count both findings and date the oldest rule: %q", fw[0])
			}
			if file.rc != stdin.rc {
				t.Errorf("rc --file %d, --stdin %d", file.rc, stdin.rc)
			}
		})
	}

	t.Run("gateway: stderr is the findings document", func(t *testing.T) {
		r := runCLI(t, bin, work, env, expiredSample, "--stdin", "--stdin-name", "sample.txt", "--format", "json",
			"--suppression-file", "expired.yaml", "--enable-redaction")
		if len(expiredWarningLines(r.stderr)) != 0 {
			t.Errorf("the warning was written into the findings document on stderr:\n%s", r.stderr)
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(r.stderr), &doc); err != nil {
			t.Errorf("stderr is not the JSON findings document (%v):\n%s", err, r.stderr)
		}
	})
}

// TestTheExpiredWarningNamesOnlyRemediesAReleaseHas: the remedy used to be `ferret-scan-suppress --action
// cleanup`, a binary no release builds (.goreleaser.yml builds ./cmd, as ferret-scan), and "regenerate the
// rules", which re-running --generate-suppressions on the file does not do: it keeps an expired rule's
// expires_at.
func TestTheExpiredWarningNamesOnlyRemediesAReleaseHas(t *testing.T) {
	var b strings.Builder
	writeExpiredRulesWarning(&b, 3, nil)
	got := b.String()
	for _, banned := range []string{"ferret-scan-suppress", "ferret-suppress", "--action"} {
		if strings.Contains(got, banned) {
			t.Errorf("the warning names %q, which no release ships:\n%s", banned, got)
		}
	}
	for _, want := range []string{"WARNING: 3 finding(s)", "expires_at", "web UI's bulk expiration control", "delete the expired rules and regenerate them"} {
		if !strings.Contains(got, want) {
			t.Errorf("the warning lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "oldest expired") {
		t.Errorf("no date was given, but the warning prints one:\n%s", got)
	}
	b.Reset()
	writeExpiredRulesWarning(&b, 0, nil)
	if b.Len() != 0 {
		t.Errorf("no expired skips, yet the warning printed %q", b.String())
	}
}

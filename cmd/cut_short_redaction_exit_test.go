// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestCutShortRedactionFollowsTheFileRule is #770's matrix A at the CLI: on a cut-short input both
// redaction paths follow --file's rule -- output never beyond --file's, disclosure always, exit 3
// under --fail-on-incomplete and 0 without it. Before the fix --stdin --enable-redaction exited 0
// under the flag, and in pre-commit mode printed no disclosure at all.
//
// Both triggers are clock-independent: CLOUD_RESOURCES declines anything over 5 MiB, and a 1ns
// PHONE budget over about 1 MB of filler is still being polled when the timer fires on any clock
// (#797 measured PHONE's pass over it at 400-600 ms).
func TestCutShortRedactionFollowsTheFileRule(t *testing.T) {
	bin := buildForExitTest(t)
	dir := t.TempDir()
	env := isolatedEnv(t, dir)

	var log strings.Builder
	log.WriteString("notify ops-oncall.example@example.org on failure\n")
	log.WriteString("put arn:aws:s3:::synthetic-bucket-q7x2/logs ok\n")
	for log.Len() <= 5<<20 {
		log.WriteString("heartbeat ok, queue depth nominal, all well\n")
	}
	overCap := writeCutShortFile(t, dir, "infra.log", []byte(log.String()))
	budget := writeCutShortFile(t, dir, "budget.txt", []byte(strings.Join(cutShortBudgetParas(), "\n")+"\n"))
	address := regexp.MustCompile(`(ops-oncall\.example|user\d{5})@example\.(org|com)`)

	run := func(t *testing.T, stdin string, args ...string) cliRun {
		t.Helper()
		c := exec.Command(bin, append(args, "--config", os.DevNull)...)
		c.Dir, c.Env = dir, env
		if stdin != "" {
			f, err := os.Open(stdin)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			c.Stdin = f
		}
		var out, errb bytes.Buffer
		c.Stdout, c.Stderr = &out, &errb
		_ = c.Run()
		return cliRun{rc: c.ProcessState.ExitCode(), stdout: out.String(), stderr: errb.String()}
	}

	for _, fail := range []bool{false, true} {
		wantRC := 0
		flag := []string{}
		if fail {
			wantRC, flag = 3, []string{"--fail-on-incomplete"}
		}
		name := map[bool]string{false: "without flag", true: "with --fail-on-incomplete"}[fail]

		t.Run("size cap, "+name, func(t *testing.T) {
			out := filepath.Join(dir, "red-"+strings.ReplaceAll(name, " ", "-"))
			file := run(t, "", append([]string{"--file", overCap, "--checks", "CLOUD_RESOURCES,EMAIL", "--enable-redaction",
				"--redaction-output-dir", out, "--format", "json", "--output", filepath.Join(out, "f.json")}, flag...)...)
			if file.rc != wantRC {
				t.Errorf("--file rc %d, want %d\nstderr: %s", file.rc, wantRC, file.stderr)
			}
			var copyPath string
			_ = filepath.Walk(out, func(p string, info os.FileInfo, err error) error {
				if err == nil && !info.IsDir() && strings.HasSuffix(p, "infra.log") {
					copyPath = p
				}
				return nil
			})
			copyBytes, err := os.ReadFile(copyPath)
			if err != nil {
				t.Fatalf("--file wrote no partial copy: %v", err)
			}

			stdin := run(t, overCap, append([]string{"--stdin", "--checks", "CLOUD_RESOURCES,EMAIL", "--enable-redaction",
				"--format", "json", "--output", filepath.Join(dir, "stdin-findings.json")}, flag...)...)
			if stdin.rc != wantRC {
				t.Errorf("--stdin --enable-redaction rc %d, want %d (the --file rule)\nstderr: %s", stdin.rc, wantRC, stdin.stderr)
			}
			if stdin.stdout != string(copyBytes) {
				t.Errorf("--stdin stdout (%d B) differs from the --file copy (%d B): the two paths must emit the same text",
					len(stdin.stdout), len(copyBytes))
			}
			if address.MatchString(stdin.stdout) {
				t.Errorf("the address the partial scan found is in the --stdin stream")
			}
			if !strings.Contains(stdin.stderr, "scan coverage incomplete") || !strings.Contains(stdin.stderr, "coverage cut short") {
				t.Errorf("--stdin stderr does not disclose the cut-short:\n%s", stdin.stderr)
			}
		})

		t.Run("budget, "+name, func(t *testing.T) {
			stdin := run(t, budget, append([]string{"--stdin", "--checks", "EMAIL,PHONE", "--validator-budget", "PHONE=1ns",
				"--enable-redaction", "--format", "json", "--output", filepath.Join(dir, "budget-findings.json")}, flag...)...)
			if stdin.rc != wantRC {
				t.Errorf("rc %d, want %d\nstderr: %s", stdin.rc, wantRC, stdin.stderr)
			}
			if n := len(address.FindAllString(stdin.stdout, -1)); n != 0 {
				t.Errorf("%d addresses in clear on stdout; PHONE's budget never touched EMAIL", n)
			}
		})

		t.Run("pre-commit, "+name, func(t *testing.T) {
			for _, redact := range []bool{false, true} {
				args := []string{"--stdin", "--pre-commit-mode", "--checks", "CLOUD_RESOURCES"}
				if redact {
					args = append(args, "--enable-redaction")
				}
				r := run(t, overCap, append(args, flag...)...)
				if r.rc != wantRC {
					t.Errorf("redaction=%v: rc %d, want %d\nstderr: %s", redact, r.rc, wantRC, r.stderr)
				}
				if !strings.Contains(r.stderr, "NOT fully examined (coverage cut short)") {
					t.Errorf("redaction=%v: pre-commit stderr has no cut-short notice (it printed 0 B):\n%q", redact, r.stderr)
				}
			}
		})
	}
}

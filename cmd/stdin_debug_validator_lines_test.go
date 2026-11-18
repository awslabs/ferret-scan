// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"strings"
	"testing"
)

// `--stdin --debug` prints the validators' own debug lines, as `--file --debug` does (#887 row 11).
// Measured on main @ 3aa380e over a one-line copyright notice: --file --debug printed the
// intellectual-property validator's 3-line "[DEBUG] Legal Notice Processing Summary" (and the file
// pipeline's "[DEBUG] Parallel processing" line, which stdin has no pipeline for); --stdin --debug and
// --file - --debug printed none, because core.ScanContent never gave its validators an observer.
func TestStdinDebugPrintsTheValidatorDebugLines(t *testing.T) {
	bin := buildScanner(t)
	work, _, env := profileWorkdir(t)
	var clean []string
	for _, kv := range env {
		if !strings.HasPrefix(kv, "FERRET_DEBUG=") {
			clean = append(clean, kv)
		}
	}
	const notice = "Copyright (c) 2024 Example Corp. All rights reserved.\nMeeting notes: nothing else.\n"
	const summary = "[DEBUG] Legal Notice Processing Summary:"

	for _, args := range [][]string{
		{"--stdin", "--debug"},
		{"--file", "-", "--debug"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			r := runCLI(t, bin, work, clean, notice, append(args, "--config", os.DevNull)...)
			if r.rc != 0 {
				t.Fatalf("rc %d\n%s", r.rc, r.stderr)
			}
			if !strings.Contains(r.stderr, summary) {
				t.Errorf("stderr lacks %q, which --file --debug prints:\n%s", summary, r.stderr)
			}
			if !strings.Contains(r.stderr, "intellectualproperty: Legal notice processing complete") {
				t.Errorf("stderr lacks the validator's observer detail line:\n%s", r.stderr)
			}
		})
	}

	t.Run("control: without --debug no validator debug line", func(t *testing.T) {
		r := runCLI(t, bin, work, clean, notice, "--stdin", "--config", os.DevNull)
		if strings.Contains(r.stderr, "[DEBUG]") || strings.Contains(r.stderr, "intellectualproperty:") {
			t.Errorf("a non-debug run printed debug lines:\n%s", r.stderr)
		}
	})
}

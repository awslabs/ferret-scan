// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package parallel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// verifyWrittenOutput is THE FLOOR at the top-level dispatch point. #459's thesis is that verification
// was per-redactor POLICY, so omission was a way to skip it — and #449 was the case where one redactor
// forgot and shipped a file containing a reported SSN with Success: true at exit 0.
//
// These drive the floor directly rather than through a redactor, because the property under test is
// "the dispatch point checks regardless of what the redactor claims".

func floorMatch(text, typ string) []detector.Match {
	return []detector.Match{{Text: text, Type: typ}}
}

func TestFloorRefusesAnOutputStillHoldingAReportedValue(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out.txt")
	if err := os.WriteFile(out, []byte("ssn: 452-11-9384\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := &redactors.RedactionResult{Success: true, RedactedFilePath: out}

	err := verifyWrittenOutput(res, out, floorMatch("452-11-9384", "SSN"))
	if err == nil {
		t.Fatal("the floor accepted a file that still contains the reported value; a redactor claiming " +
			"Success is the exact evidence #449 proved worthless")
	}
	if !strings.Contains(err.Error(), "SSN") {
		t.Errorf("the refusal does not name the leaked TYPE: %v", err)
	}
	if strings.Contains(err.Error(), "452-11-9384") {
		t.Errorf("the refusal reprints the VALUE, which must never reach a message: %v", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Error("the leaky output was left on disk. A file that looks redacted and is not must not " +
			"survive for something downstream to consume.")
	}
}

func TestFloorAcceptsACorrectlyRedactedOutput(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out.txt")
	if err := os.WriteFile(out, []byte("ssn: ***-**-****\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := &redactors.RedactionResult{Success: true, RedactedFilePath: out}
	if err := verifyWrittenOutput(res, out, floorMatch("452-11-9384", "SSN")); err != nil {
		t.Errorf("the floor refused a correctly redacted file: %v", err)
	}
	if _, statErr := os.Stat(out); statErr != nil {
		t.Errorf("a clean output was removed: %v", statErr)
	}
}

// TestFloorPrefersTheRedactorsOwnPath: a redactor may choose its output name. Trusting our guess would
// read the WRONG file — and a file that does not exist reads as clean, so the check would pass vacuously
// on every such redactor.
func TestFloorPrefersTheRedactorsOwnPath(t *testing.T) {
	dir := t.TempDir()
	guess := filepath.Join(dir, "guess.txt")
	actual := filepath.Join(dir, "actual.txt")
	if err := os.WriteFile(guess, []byte("ssn: ***-**-****\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(actual, []byte("ssn: 452-11-9384\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res := &redactors.RedactionResult{Success: true, RedactedFilePath: actual}
	if err := verifyWrittenOutput(res, guess, floorMatch("452-11-9384", "SSN")); err == nil {
		t.Error("the floor checked the guessed path instead of the path the redactor reported writing, " +
			"so a redactor that renames its output is never verified")
	}
}

// TestFloorTreatsAMissingOutputAsNotItsBusiness: pdf refuses outright and writes nothing. That is a
// legitimate outcome with its own error path, and there are no bytes to verify — but the reasoning has
// to be explicit, because "file absent => clean" is how a check silently stops running.
func TestFloorTreatsAMissingOutputAsNotItsBusiness(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "never-written.txt")
	res := &redactors.RedactionResult{Success: true, RedactedFilePath: missing}
	if err := verifyWrittenOutput(res, missing, floorMatch("452-11-9384", "SSN")); err != nil {
		t.Errorf("a redactor that wrote nothing produced a floor error: %v", err)
	}
}

// TestFloorIgnoresAFailedRedaction: the caller's existing failure handling owns that case, and running
// the floor on it would report a residual leak for a redaction that never happened.
func TestFloorIgnoresAFailedRedaction(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out.txt")
	if err := os.WriteFile(out, []byte("ssn: 452-11-9384\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyWrittenOutput(&redactors.RedactionResult{Success: false, RedactedFilePath: out},
		out, floorMatch("452-11-9384", "SSN")); err != nil {
		t.Errorf("the floor second-guessed a redaction that already reported failure: %v", err)
	}
	if err := verifyWrittenOutput(nil, out, floorMatch("452-11-9384", "SSN")); err != nil {
		t.Errorf("a nil result produced a floor error: %v", err)
	}
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/coverage"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/execguard"
)

// These tests pin #770 in core: ScanContent and ScanFile take the caller's ctx, every member of the
// cut-short family is reported, and RedactFile reports a file it did not fully examine instead of
// passing it through as clean.

// withStubCheck registers a validator constructor under name for the length of the test, so a stub
// runs through the real ParseChecksToRun -> BuildValidatorSet -> facade path. No test in this
// package runs in parallel, so the shared map is not observed half-updated.
func withStubCheck(t *testing.T, name string, ctor func() detector.Validator) {
	t.Helper()
	if _, exists := validatorConstructors[name]; exists {
		t.Fatalf("%s is already a real check", name)
	}
	validatorConstructors[name] = ctor
	t.Cleanup(func() { delete(validatorConstructors, name) })
}

// cancellingValidator finds n values, then cancels the caller's context -- the cancellation lands
// mid-scan by construction, with no clock involved -- and returns what it found with ctx.Err(), as a
// validator polling execguard.LineLoopCancelled does.
type cancellingValidator struct {
	cancel context.CancelFunc
	n      int
}

func (cancellingValidator) Validate(string) ([]detector.Match, error)             { return nil, nil }
func (cancellingValidator) CalculateConfidence(string) (float64, map[string]bool) { return 0, nil }
func (cancellingValidator) AnalyzeContext(string, detector.ContextInfo) float64   { return 0 }
func (cancellingValidator) ValidateContent(string, string) ([]detector.Match, error) {
	return nil, nil
}
func (v cancellingValidator) ValidateContentCtx(ctx context.Context, _, path string) ([]detector.Match, error) {
	out := make([]detector.Match, v.n)
	for i := range out {
		out[i] = detector.Match{Type: "STUB", Text: fmt.Sprintf("found%d", i), LineNumber: i + 1, Validator: "STUB", Filename: path}
	}
	v.cancel()
	<-ctx.Done()
	return out, ctx.Err()
}

// TestScanContentCtxKeepsWhatWasFoundWhenTheCallerCancelsMidScan is items 5 and 7: the caller's
// ctx reaches the validators, what they found before it fired comes back, and the input is named in
// NotExamined as "coverage cut short". ScanContent used to root its ceiling on
// context.Background(), so no caller could stop it, and it never filled NotExamined.
func TestScanContentCtxKeepsWhatWasFoundWhenTheCallerCancelsMidScan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	withStubCheck(t, "ZZ_STUB_CANCEL", func() detector.Validator { return cancellingValidator{cancel: cancel, n: 3} })

	res, err := ScanContentCtx(ctx, "line one\nline two\nline three\n", ContentScanConfig{
		VirtualPath: "<text>", Checks: []string{"ZZ_STUB_CANCEL"}, LogWriter: io.Discard,
	})
	if err != nil {
		t.Fatalf("ScanContentCtx: %v (a cut-short is reported in the result, not as an error)", err)
	}
	if len(res.Matches) != 3 {
		t.Errorf("got %d matches, want the 3 found before the cancellation", len(res.Matches))
	}
	if !res.Incomplete {
		t.Errorf("Incomplete = false after a mid-scan cancellation")
	}
	if len(res.NotExamined) != 1 || res.NotExamined[0].Cause != coverage.CauseCutShort || res.NotExamined[0].Path != "<text>" {
		t.Errorf("NotExamined = %+v, want one <text> entry with cause %q", res.NotExamined, coverage.CauseCutShort)
	}
}

// panickingValidator panics on every input.
type panickingValidator struct{}

func (panickingValidator) Validate(string) ([]detector.Match, error)             { return nil, nil }
func (panickingValidator) CalculateConfidence(string) (float64, map[string]bool) { return 0, nil }
func (panickingValidator) AnalyzeContext(string, detector.ContextInfo) float64   { return 0 }
func (panickingValidator) ValidateContent(string, string) ([]detector.Match, error) {
	panic("boom")
}

// TestScanContentReportsARecoveredPanic is item 12's defect: ScanContent's hand-written chain of
// errors.Is tests omitted ErrValidatorPanicked, so a validator that panicked on the whole input
// reported a complete scan. One predicate covers it.
func TestScanContentReportsARecoveredPanic(t *testing.T) {
	withStubCheck(t, "ZZ_STUB_PANIC", func() detector.Validator { return panickingValidator{} })
	res, err := ScanContent("anything\n", ContentScanConfig{VirtualPath: "<text>", Checks: []string{"ZZ_STUB_PANIC"}, LogWriter: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Incomplete || len(res.NotExamined) != 1 {
		t.Fatalf("Incomplete=%v NotExamined=%+v after a recovered panic; the validator examined nothing, "+
			"so the scan must not read as complete", res.Incomplete, res.NotExamined)
	}
	if !strings.Contains(res.IncompleteReason, "panicked") {
		t.Errorf("IncompleteReason %q does not say the validator panicked", res.IncompleteReason)
	}
}

// overCapText is just over CLOUD_RESOURCES's 5 MiB cap, with one ARN-shaped line, so the validator
// declines it -- deterministically, on any clock.
func overCapText() string {
	var b strings.Builder
	b.WriteString("put arn:aws:s3:::synthetic-bucket-q7x2/logs ok\n")
	line := "heartbeat ok, queue depth nominal, all well\n"
	for b.Len() <= 5<<20 {
		b.WriteString(line)
	}
	return b.String()
}

// TestScanContentNamesASizeCapOnceAndInNotExamined is item 7's other half: the reason states the
// guard once (it read "validator declined oversize content: validator declined oversize content:
// …"), and NotExamined is filled.
func TestScanContentNamesASizeCapOnceAndInNotExamined(t *testing.T) {
	res, err := ScanContent(overCapText(), ContentScanConfig{VirtualPath: "<text>", Checks: []string{"CLOUD_RESOURCES"}, LogWriter: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Incomplete {
		t.Fatal("a declined oversize input must be Incomplete")
	}
	if n := strings.Count(res.IncompleteReason, execguard.ErrContentTooLarge.Error()); n != 1 {
		t.Errorf("IncompleteReason names the guard %d times, want once: %q", n, res.IncompleteReason)
	}
	if len(res.NotExamined) != 1 || res.NotExamined[0].Cause != coverage.CauseCutShort {
		t.Errorf("NotExamined = %+v, want one entry with cause %q", res.NotExamined, coverage.CauseCutShort)
	}
}

// TestRedactFileReportsAFileItDidNotFullyExamine is item 2 in core: no passthrough copy for a file
// that was not fully examined, and an error wrapping ErrRedactionIncomplete with the result.
func TestRedactFileReportsAFileItDidNotFullyExamine(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name, file string
		content    []byte
		checks     []string
		cause      coverage.Cause
	}{
		{"unparseable pdf", "broken.pdf", []byte("%PDF-1.7\nCustomer SSN 521-33-4567 on file\n"), []string{"SSN"}, coverage.CauseUnparseable},
		{"log over the CLOUD_RESOURCES cap", "infra.log", []byte(overCapText()), []string{"CLOUD_RESOURCES"}, coverage.CauseCutShort},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := filepath.Join(dir, c.file)
			if err := os.WriteFile(src, c.content, 0o600); err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(dir, "out-"+c.file)
			res, err := RedactFile(RedactConfig{FilePath: src, OutputDir: out, Checks: c.checks,
				Config: config.LoadConfigOrDefault(""), LogWriter: io.Discard})
			if !errors.Is(err, ErrRedactionIncomplete) {
				t.Fatalf("err = %v, want ErrRedactionIncomplete", err)
			}
			if res == nil || !res.Incomplete || res.RedactedFilePath != "" {
				t.Fatalf("result %+v: want Incomplete and no output path", res)
			}
			if len(res.NotExamined) == 0 || res.NotExamined[0].Cause != c.cause {
				t.Errorf("NotExamined = %+v, want cause %q", res.NotExamined, c.cause)
			}
			if !strings.Contains(err.Error(), c.cause.String()) {
				t.Errorf("the error does not name the cause %q: %v", c.cause, err)
			}
			files := 0
			_ = filepath.Walk(out, func(_ string, info os.FileInfo, err error) error {
				if err == nil && !info.IsDir() {
					files++
				}
				return nil
			})
			if files != 0 {
				t.Errorf("%d file(s) written under %s for a file that was not fully examined; the clean-file "+
					"passthrough copied it as if it were clean", files, out)
			}
		})
	}
}

// TestRedactFileCtxWithADoneContextWritesNothing: a ctx done before the scan starts creates no
// output, not even the output directory, and its error is reachable through errors.Is.
func TestRedactFileCtxWithADoneContextWritesNothing(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "one.txt")
	if err := os.WriteFile(src, []byte("caller verified SSN 517-17-1007\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out := filepath.Join(dir, "out")
	res, err := RedactFileCtx(ctx, RedactConfig{FilePath: src, OutputDir: out, Checks: []string{"SSN"},
		Config: config.LoadConfigOrDefault(""), LogWriter: io.Discard})
	if !errors.Is(err, ErrRedactionIncomplete) || !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want ErrRedactionIncomplete and context.Canceled", err)
	}
	if res == nil || !res.Incomplete || res.RedactedFilePath != "" {
		t.Fatalf("result %+v: want Incomplete and no output path", res)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Errorf("output directory exists (%v) for a redaction that never started", statErr)
	}
}

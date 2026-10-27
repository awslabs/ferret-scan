// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// These tests pin #770 at the pkg/scan boundary: ScanText and ScanFile honour their ctx, and
// RedactFile reports a file it did not fully examine instead of copying it out as clean.

// filler1MB is about 1 MB of neutral prose, one address up front. PHONE's pass over it takes
// hundreds of milliseconds (#797 measured 400-600 ms on the dev host), so a caller deadline of a few
// tens of milliseconds fires while the scan is running, on any clock including Windows's coarse
// one; nothing in it is reported but the address.
func filler1MB() string {
	para := strings.Repeat("the quarterly report covers routine operational matters for the period under review ", 14)[:1150]
	var b strings.Builder
	b.WriteString("Contact user00001@example.com for the record.\n")
	for i := 0; i < 900; i++ {
		b.WriteString(para + "\n")
	}
	return b.String()
}

// overCapLog is just over CLOUD_RESOURCES's 5 MiB cap, so the validator declines it on any clock,
// with one ARN line and, when mail is set, one address the EMAIL check can still mask.
func overCapLog(mail bool) string {
	var b strings.Builder
	if mail {
		b.WriteString("notify ops-oncall.example@example.org on failure\n")
	}
	b.WriteString("put arn:aws:s3:::synthetic-bucket-q7x2/logs ok\n")
	for b.Len() <= 5<<20 {
		b.WriteString("heartbeat ok, queue depth nominal, all well\n")
	}
	return b.String()
}

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestScanTextAndScanFileReturnTheCtxErrorAtEntry: a ctx that is done before the scan starts gives
// (nil, ctx.Err()). Both functions took `_ context.Context` and scanned regardless: a pre-cancelled
// ctx over 10,000 records returned all 30,000 findings, Incomplete=false.
func TestScanTextAndScanFileReturnTheCtxErrorAtEntry(t *testing.T) {
	path := writeFile(t, t.TempDir(), "one.txt", "reach j7.example@example.org\n")
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	past, cancel2 := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel2()

	for name, c := range map[string]struct {
		ctx  context.Context
		want error
	}{"pre-cancelled": {cancelled, context.Canceled}, "past deadline": {past, context.DeadlineExceeded}} {
		t.Run(name, func(t *testing.T) {
			res, err := ScanText(c.ctx, "reach j7.example@example.org\n", TextOptions{DisableConfigDiscovery: true})
			if res != nil || !errors.Is(err, c.want) {
				t.Errorf("ScanText: res=%v err=%v; want nil, %v", res, err, c.want)
			}
			res, err = ScanFile(c.ctx, path, FileOptions{DisableConfigDiscovery: true})
			if res != nil || !errors.Is(err, c.want) {
				t.Errorf("ScanFile: res=%v err=%v; want nil, %v", res, err, c.want)
			}
		})
	}
}

// TestScanTextAndScanFileReturnThePartialResultWhenTheCtxFiresMidScan: the deadline reaches the
// validators, the partial result comes back marked Incomplete with the input in NotExamined, AND
// the error wraps ctx.Err(), so a caller that checks only err stops.
func TestScanTextAndScanFileReturnThePartialResultWhenTheCtxFiresMidScan(t *testing.T) {
	body := filler1MB()
	path := writeFile(t, t.TempDir(), "filler.txt", body)
	for name, scan := range map[string]func(context.Context) (*Result, error){
		"ScanText": func(ctx context.Context) (*Result, error) {
			return ScanText(ctx, body, TextOptions{Checks: []string{"EMAIL", "PHONE"}, DisableConfigDiscovery: true})
		},
		"ScanFile": func(ctx context.Context) (*Result, error) {
			return ScanFile(ctx, path, FileOptions{Checks: []string{"EMAIL", "PHONE"}, DisableConfigDiscovery: true})
		},
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			res, err := scan(ctx)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("err = %v, want one wrapping context.DeadlineExceeded", err)
			}
			if res == nil || !res.Incomplete {
				t.Fatalf("res = %+v, want the partial result with Incomplete set", res)
			}
			if len(res.NotExamined) != 1 || res.NotExamined[0].Cause != "coverage cut short" {
				t.Errorf("NotExamined = %+v, want one entry with Cause \"coverage cut short\"", res.NotExamined)
			}
		})
	}
}

// TestAnEngineGuardIsNotTheCallersCancellation keeps the #391 detection contract: a size cap inside
// the engine is (Result{Incomplete}, nil), with NotExamined filled and the guard named once.
func TestAnEngineGuardIsNotTheCallersCancellation(t *testing.T) {
	res, err := ScanText(context.Background(), overCapLog(false), TextOptions{Checks: []string{"CLOUD_RESOURCES"}, DisableConfigDiscovery: true})
	if err != nil {
		t.Fatalf("err = %v; an engine guard is reported in the result, not as an error", err)
	}
	if !res.Incomplete || len(res.NotExamined) != 1 || res.NotExamined[0].Cause != "coverage cut short" {
		t.Fatalf("Incomplete=%v NotExamined=%+v; want true and one \"coverage cut short\" entry", res.Incomplete, res.NotExamined)
	}
	if n := strings.Count(res.IncompleteReason, "validator declined oversize content"); n != 1 {
		t.Errorf("IncompleteReason names the guard %d times: %q", n, res.IncompleteReason)
	}
}

// TestWithCallerCancellation is the rule that tells the two apart, on its own.
func TestWithCallerCancellation(t *testing.T) {
	done, cancel := context.WithCancel(context.Background())
	cancel()
	live := context.Background()
	for _, c := range []struct {
		name       string
		ctx        context.Context
		incomplete bool
		wantErr    bool
	}{
		{"incomplete, caller cancelled", done, true, true},
		{"incomplete, caller alive (an engine guard)", live, true, false},
		{"complete, ctx expired after the last validator", done, false, false},
		{"complete, caller alive", live, false, false},
	} {
		res, err := withCallerCancellation(c.ctx, &Result{Incomplete: c.incomplete})
		if res == nil || (err != nil) != c.wantErr || (c.wantErr && !errors.Is(err, context.Canceled)) {
			t.Errorf("%s: res=%v err=%v; want an error: %v", c.name, res, err, c.wantErr)
		}
	}
}

// outputFiles lists the regular files under dir.
func outputFiles(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			out = append(out, p)
		}
		return nil
	})
	return out
}

// TestRedactFileReportsAFileItDidNotFullyExamine is items 2 and 7 for RedactFile: each case returned
// err == nil before the fix, with the original copied out as "the redacted copy" (broken.pdf
// byte-identical; the log with every ARN in clear).
func TestRedactFileReportsAFileItDidNotFullyExamine(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name, file, body string
		checks           []string
		cause            string
		wantCopy         bool
	}{
		{"unparseable pdf", "broken.pdf", "%PDF-1.7\nCustomer SSN 521-33-4567 on file\n", []string{"SSN"}, "cannot parse", false},
		{"log over the cap, CLOUD_RESOURCES only", "infra.log", overCapLog(false), []string{"CLOUD_RESOURCES"}, "coverage cut short", false},
		// The partial copy is kept, as --file keeps it: the address is masked, and the error says
		// the ARNs were never looked for.
		{"log over the cap plus an address", "infra-mail.log", overCapLog(true), []string{"CLOUD_RESOURCES", "EMAIL"}, "coverage cut short", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := writeFile(t, dir, c.file, c.body)
			out := filepath.Join(dir, "out-"+c.file)
			res, err := RedactFile(src, RedactFileOptions{OutputDir: out, Checks: c.checks, DisableConfigDiscovery: true})
			if !errors.Is(err, ErrIncomplete) {
				t.Fatalf("err = %v, want one wrapping ErrIncomplete", err)
			}
			if !strings.Contains(err.Error(), c.cause) {
				t.Errorf("err does not name the cause %q: %v", c.cause, err)
			}
			if res == nil || res.Coverage == nil || !res.Coverage.Incomplete {
				t.Fatalf("res = %+v: want Coverage.Incomplete alongside the error", res)
			}
			if len(res.Coverage.NotExamined) == 0 || res.Coverage.NotExamined[0].Path != src || res.Coverage.NotExamined[0].Cause != c.cause {
				t.Errorf("Coverage.NotExamined = %+v, want %s with cause %q", res.Coverage.NotExamined, src, c.cause)
			}
			files := outputFiles(t, out)
			switch {
			case !c.wantCopy && (len(files) != 0 || res.RedactedFilePath != ""):
				t.Errorf("wrote %v (RedactedFilePath %q) for a file that was not fully examined and had nothing masked",
					files, res.RedactedFilePath)
			case c.wantCopy:
				if len(files) != 1 || res.RedactedFilePath != files[0] {
					t.Fatalf("partial copy: files %v, RedactedFilePath %q; want the one copy", files, res.RedactedFilePath)
				}
				b, _ := os.ReadFile(files[0])
				if strings.Contains(string(b), "ops-oncall.example@example.org") {
					t.Errorf("the address the partial scan found is still in the partial copy")
				}
			}
		})
	}
}

// TestRedactFileContextWithADoneContextWritesNothing: no output and no output directory, and the
// error reaches context.Canceled as well as ErrIncomplete.
func TestRedactFileContextWithADoneContextWritesNothing(t *testing.T) {
	dir := t.TempDir()
	src := writeFile(t, dir, "one.txt", "caller verified SSN 517-17-1007\n")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out := filepath.Join(dir, "out")
	res, err := RedactFileContext(ctx, src, RedactFileOptions{OutputDir: out, Checks: []string{"SSN"}, DisableConfigDiscovery: true})
	if !errors.Is(err, ErrIncomplete) || !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want ErrIncomplete and context.Canceled", err)
	}
	if res == nil || res.Coverage == nil || res.RedactedFilePath != "" {
		t.Fatalf("res = %+v, want Coverage set and no output path", res)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Errorf("the output directory was created (%v) by a redaction that never started", statErr)
	}
}

// TestCompleteRedactFileHasNoCoverage: a fully examined file keeps the historical result, with
// Coverage nil, and the clean-file passthrough still runs for one with no findings.
func TestCompleteRedactFileHasNoCoverage(t *testing.T) {
	dir := t.TempDir()
	for _, body := range []string{"caller verified SSN 517-17-1007\n", "nothing to see here\n"} {
		src := writeFile(t, dir, "in.txt", body)
		out := filepath.Join(dir, "out", strings.Fields(body)[0])
		res, err := RedactFile(src, RedactFileOptions{OutputDir: out, Checks: []string{"SSN"}, DisableConfigDiscovery: true})
		if err != nil || res.Coverage != nil {
			t.Fatalf("%q: err=%v Coverage=%+v; want nil, nil", body, err, res.Coverage)
		}
		if _, err := os.Stat(res.RedactedFilePath); err != nil {
			t.Errorf("%q: no output at %s: %v", body, res.RedactedFilePath, err)
		}
	}
}

// TestRedactFileResultStaysComparable: Coverage is a pointer so the struct stays usable as a map key
// and with ==, as it was before the field existed. Slice fields would break both.
func TestRedactFileResultStaysComparable(t *testing.T) {
	if !reflect.TypeOf(RedactFileResult{}).Comparable() {
		t.Fatal("RedactFileResult is no longer comparable; existing map-key and == callers stop compiling")
	}
	seen := map[RedactFileResult]bool{{RedactedFilePath: "a"}: true}
	if !seen[RedactFileResult{RedactedFilePath: "a"}] {
		t.Fatal("equal results without Coverage must compare equal")
	}
}

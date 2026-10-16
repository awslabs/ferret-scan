// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The pkg/scan half of #772: a strategy name a caller got from a user is parsed strictly, an
// out-of-range RedactStrategy is refused before anything is written, and a pinned ConfigPath that
// exists but fails the strict load surfaces as an error instead of silently becoming the defaults.

func TestParseStrategyStrictIsExactAndParseStrategyIsUnchanged(t *testing.T) {
	for name, want := range map[string]RedactStrategy{
		"simple": StrategySimple, "format_preserving": StrategyFormatPreserving, "synthetic": StrategySynthetic,
	} {
		got, err := ParseStrategyStrict(name)
		if err != nil || got != want {
			t.Errorf("ParseStrategyStrict(%q) = %v, %v; want %v, nil", name, got, err, want)
		}
	}
	for _, v := range []string{"", "  ", "SIMPLE", "simpel", "Simple", " simple", "bogus", "simple,synthetic"} {
		if got, err := ParseStrategyStrict(v); err == nil {
			t.Errorf("ParseStrategyStrict(%q) = %v with no error; want an error", v, got)
		} else if !strings.Contains(err.Error(), `"`+v+`"`) {
			t.Errorf("ParseStrategyStrict(%q): error does not quote the value: %v", v, err)
		}
	}
	if _, err := ParseStrategyStrict("SIMPLE"); err == nil || !strings.Contains(err.Error(), `did you mean "simple"`) {
		t.Errorf("ParseStrategyStrict(\"SIMPLE\") should hint at \"simple\": %v", err)
	}
	// The deprecated parser keeps its documented fallback for the callers written against it.
	if ParseStrategy("simpel") != StrategyFormatPreserving || ParseStrategy("") != StrategyFormatPreserving {
		t.Error("ParseStrategy's fallback to format_preserving must be unchanged; it is deprecated, not altered")
	}
}

func TestRedactTextRejectsAnOutOfRangeStrategy(t *testing.T) {
	text := "SSN: 452-11-9384\n"
	r, err := ScanText(context.Background(), text, TextOptions{Checks: []string{"SSN"}, DisableConfigDiscovery: true})
	if err != nil || len(r.Findings) == 0 {
		t.Fatalf("fixture produced no SSN finding (err=%v); the rejection below would be vacuous", err)
	}
	out, err := RedactText(text, r.Findings, RedactStrategy(7))
	if err == nil {
		t.Fatalf("RedactText(RedactStrategy(7)) returned nil error and %q; before #772 the value was mapped to format_preserving", out.Text)
	}
	if !strings.Contains(err.Error(), "7") {
		t.Errorf("the error does not name the value: %v", err)
	}
	// Control: every defined strategy still works.
	for _, s := range []RedactStrategy{StrategySimple, StrategyFormatPreserving, StrategySynthetic} {
		if _, err := RedactText(text, r.Findings, s); err != nil {
			t.Errorf("RedactText(%v): %v", s, err)
		}
	}
}

func TestRedactFileRejectsAnOutOfRangeStrategyBeforeWriting(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.txt")
	if err := os.WriteFile(in, []byte("SSN: 452-11-9384\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "redacted")
	res, err := RedactFile(in, RedactFileOptions{OutputDir: outDir, Strategy: RedactStrategy(7), DisableConfigDiscovery: true})
	if err == nil {
		t.Fatalf("RedactFile(Strategy=RedactStrategy(7)) returned nil error (Strategy=%q); before #772 it wrote a format_preserving copy", res.Strategy)
	}
	if _, statErr := os.Stat(outDir); statErr == nil {
		t.Error("the output directory was created before the strategy was refused; nothing may be written on the error path")
	}
}

// TestASchemaRejectedPinnedConfigPathIsAnError is the sequencing guard: a ConfigPath that exists but
// fails the strict load must make ScanText, ScanFile and RedactFile return an error. Before #772
// resolveConfig replaced the whole file with built-in defaults and returned nil, so a pinned config
// holding a custom pattern plus a newly refused `strategy: " simple "` went from 1 finding to 0 with
// err=nil -- which is what made the schema unsafe to tighten. A MISSING path keeps the #317
// fall-back (TestUnreadableConfigPathFallsBackToDefaultsRatherThanCrashing).
func TestASchemaRejectedPinnedConfigPathIsAnError(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "pinned.yaml")
	// Only defect: a strategy spelling the exact schema refuses and the lenient one accepted.
	if err := os.WriteFile(cfg, []byte("redaction:\n  strategy: \" simple \"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	in := filepath.Join(dir, "in.txt")
	if err := os.WriteFile(in, []byte("SSN: 452-11-9384\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wantErr := func(t *testing.T, what string, err error) {
		t.Helper()
		if err == nil {
			t.Errorf("%s with a schema-rejected ConfigPath returned nil error; the pinned file was silently replaced by defaults", what)
			return
		}
		if !strings.Contains(err.Error(), "redaction.strategy") {
			t.Errorf("%s: the error does not name the rejected field: %v", what, err)
		}
	}
	_, err := ScanText(context.Background(), "SSN: 452-11-9384\n", TextOptions{ConfigPath: cfg})
	wantErr(t, "ScanText", err)
	_, err = ScanFile(context.Background(), in, FileOptions{ConfigPath: cfg})
	wantErr(t, "ScanFile", err)
	_, err = RedactFile(in, RedactFileOptions{OutputDir: filepath.Join(dir, "red"), Strategy: StrategySimple, ConfigPath: cfg})
	wantErr(t, "RedactFile", err)

	// Control: the same file with the exact spelling loads, and the scan runs.
	if err := os.WriteFile(cfg, []byte("redaction:\n  strategy: simple\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := ScanText(context.Background(), "SSN: 452-11-9384\n", TextOptions{ConfigPath: cfg})
	if err != nil || len(r.Findings) == 0 {
		t.Fatalf("control: exact spelling must load and detect: err=%v findings=%d", err, len(r.Findings))
	}
}

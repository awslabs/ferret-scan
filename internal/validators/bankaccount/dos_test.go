// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package bankaccount

import (
	stdctx "context"
	"strings"
	"testing"
	"time"
)

// TestSingleLongLine_NotQuadratic is a regression guard for the O(n^2)
// CPU-exhaustion DoS (security finding HIGH-5). Before the per-line hoisting of
// AnalyzeContext / hasStrongNegativeContext / hasBankingKeywords, a single ~36KB
// line packed with banking tokens took ~5.6s (quadratic in line length). After
// the fix it is linear and completes in tens of milliseconds.
func TestSingleLongLine_NotQuadratic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DoS timing regression in -short mode")
	}

	var b strings.Builder
	b.Grow(48*1024 + 64)
	b.WriteString("routing account bank wire ach ")
	for b.Len() < 48*1024 {
		b.WriteString("021000021 GB29NWBK60161331926819 DEUTDEFF 123456789012 ")
	}
	content := b.String()
	if strings.Contains(content, "\n") {
		t.Fatalf("worst-case input must be a single line")
	}

	const ceiling = 2 * time.Second
	start := time.Now()
	matches, err := NewValidator().ValidateContent(content, "worstcase.txt")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ValidateContent() error = %v", err)
	}
	if raceEnabled {
		t.Logf("processed %d-byte single line, %d matches (timing assertion skipped under -race)", len(content), len(matches))
		return
	}
	if elapsed > ceiling {
		t.Fatalf("ValidateContent on a %d-byte single line took %s, exceeding the %s ceiling (likely an O(n^2) regression)",
			len(content), elapsed, ceiling)
	}
}

// TestGroupedIBANLine_NotQuadratic is the same guard for the display-form IBAN scan (#862), which
// tries a candidate at every head and re-tries inside a rejected span. The unit packs every path
// it has into one line: a spaced IBAN before a BIC, a hyphen-grouped one, a rejected head before
// a real one, a near miss that is read in full and rejected by the structure gate, and a
// '_'-joined value whose label check reads the identifier around it. A second line is nothing but
// '_'-joined valid IBANs, the worst case for that label check. Each start reads at most 34
// characters and the label check at most underscoreLabelWindow bytes a side, so both stay linear.
func TestGroupedIBANLine_NotQuadratic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping DoS timing regression in -short mode")
	}
	units := map[string]struct {
		unit    string
		perUnit int // IBAN findings each repetition must contribute
	}{
		"mixed display forms": {
			unit:    "iban ES91 2100 0418 4502 0005 1332 BIC: EXMPESMM DE89-3704-0044-0532-0130-00 Ref AB12 GB29 NWBK 6016 1331 9268 19 BE16 KEYE XAMP LE00 bank_iban_NL91ABNA0417164300 ",
			perUnit: 4,
		},
		"underscore-joined run": {
			unit:    "iban_DE89370400440532013000_",
			perUnit: 1,
		},
	}
	for name, u := range units {
		t.Run(name, func(t *testing.T) {
			var b strings.Builder
			b.Grow(48*1024 + len(u.unit))
			for b.Len() < 48*1024 {
				b.WriteString(u.unit)
			}
			content := b.String()
			reps := strings.Count(content, u.unit)

			const ceiling = 2 * time.Second
			start := time.Now()
			matches, err := NewValidator().ValidateContent(content, "grouped.txt")
			elapsed := time.Since(start)
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			ibans := 0
			for _, m := range matches {
				if m.Type == "IBAN" {
					ibans++
				}
			}
			// Non-vacuity: the scan must actually find the values, or a fast run proves nothing.
			if name == "mixed display forms" && ibans != reps*u.perUnit {
				t.Fatalf("%d IBAN findings for %d repetitions, want %d", ibans, reps, reps*u.perUnit)
			}
			if name == "underscore-joined run" && ibans == 0 {
				t.Fatal("no IBAN found on the '_'-joined line; the label check was never exercised")
			}
			if raceEnabled {
				t.Logf("%d-byte line, %d IBANs in %s (timing assertion skipped under -race)", len(content), ibans, elapsed)
				return
			}
			if elapsed > ceiling {
				t.Fatalf("%d-byte line took %s, over the %s ceiling (likely an O(n^2) regression)", len(content), elapsed, ceiling)
			}
		})
	}
}

// TestSingleLongLine_Cancellable verifies the per-match ctx polling makes a
// single pathological line interruptible mid-scan (before the fix, ctx was only
// checked between lines, so one giant line ignored the deadline entirely).
func TestSingleLongLine_Cancellable(t *testing.T) {
	var b strings.Builder
	b.Grow(1<<20 + 64)
	b.WriteString("routing account bank ")
	for b.Len() < 1<<20 {
		b.WriteString("021000021 GB29NWBK60161331926819 123456789012 ")
	}

	ctx, cancel := stdctx.WithCancel(stdctx.Background())
	cancel() // already cancelled: the loop must bail promptly

	start := time.Now()
	_, err := NewValidator().ValidateContentCtx(ctx, b.String(), "cancel.txt")
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("cancelled scan took %s; per-match ctx polling not effective", elapsed)
	}
	if err == nil {
		t.Log("scan returned nil error (finished before first poll); acceptable if fast")
	}
}

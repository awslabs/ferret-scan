// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phone

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// internationalLine builds one line (no '\n') of at least n bytes packed with distinct "+CC" and
// "00CC" numbers, the forms #889's grammar and E.164 gate read. Every number is distinct (area
// 161 3xx-8xx, any subscriber), so per-line dedup cannot pin the match count and hide a per-match
// cost, and none is in an Ofcom drama block.
func internationalLine(n int) string {
	var b strings.Builder
	b.Grow(n + 32)
	b.WriteString("contacts ")
	for i := 0; b.Len() < n; i++ {
		area := 300 + (i/10000)%600
		if i%2 == 0 {
			fmt.Fprintf(&b, "+44 161 %03d %04d ", area, i%10000)
		} else {
			fmt.Fprintf(&b, "0044 161 %03d %04d ", area, i%10000)
		}
	}
	return b.String()
}

// TestInternationalLineScalesLinearly is #889's complexity row: a 1 MiB single line of international
// numbers, measured at 256 KiB, 512 KiB and 1 MiB. It asserts the measurement is not vacuous (findings
// at every size, growing with it), a ceiling on the 1 MiB scan, and that 4x the input costs at most
// maxIntlGrowth x the time, which a per-match rescan of the line (quadratic) cannot meet. Wall clock,
// best of three per size; the name is in the load skip list (docs/testing/TEST_PLAN.md dimension 2),
// so a loaded whole-module run skips it and it is run alone.
//
// shortcut: this lives in the phone package because internal/goldencorpus/complexity_guard_test.go
// (TestValidatorComplexityIsSubQuadratic) is not this change's to edit; its phone row there could
// take an international generator instead.
func TestInternationalLineScalesLinearly(t *testing.T) {
	if testing.Short() {
		t.Skip("timing guard skipped in -short mode")
	}
	const maxIntlGrowth = 8.0
	// Generous on purpose: at host load 150 the 1 MiB scan took 7.1 s. The ratio below is what
	// catches a quadratic path; the ceiling only catches a hang.
	const ceiling = 30 * time.Second
	v := NewValidator()
	measure := func(content string) (time.Duration, int) {
		best, n := time.Duration(1<<62), 0
		for r := 0; r < 3; r++ {
			start := time.Now()
			ms, err := v.ValidateContent(content, "intl-1mib.txt")
			d := time.Since(start)
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if d < best {
				best = d
			}
			n = len(ms)
		}
		return best, n
	}
	sizes := []int{256 << 10, 512 << 10, 1 << 20}
	var times []time.Duration
	var counts []int
	for _, size := range sizes {
		line := internationalLine(size)
		if strings.Contains(line, "\n") {
			t.Fatal("the input must be a single line")
		}
		d, n := measure(line)
		t.Logf("%7d bytes: %d findings in %v", len(line), n, d)
		times, counts = append(times, d), append(counts, n)
	}
	for i := range sizes {
		if counts[i] == 0 || (i > 0 && counts[i] <= counts[i-1]) {
			t.Fatalf("vacuous measurement: findings %v must be non-zero and grow with the input", counts)
		}
	}
	if raceEnabled {
		t.Logf("timing assertions skipped under -race (it inflates wall clock 5-20x)")
		return
	}
	if times[2] > ceiling {
		t.Errorf("1 MiB international line took %v, want under %v", times[2], ceiling)
	}
	if ratio := float64(times[2]) / float64(times[0]); ratio > maxIntlGrowth {
		t.Errorf("4x the input took %.1fx the time (%v -> %v), want at most %.0fx: super-linear", ratio, times[0], times[2], maxIntlGrowth)
	}
}

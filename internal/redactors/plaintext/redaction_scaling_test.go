// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package plaintext

import (
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// scalingFixture is n lines, each holding one distinct email (and a second on every 3rd line, so
// writes also land left of an earlier write on the same line), with the matches a scan reports.
func scalingFixture(n int) (string, []detector.Match) {
	var doc strings.Builder
	var ms []detector.Match
	for i := 0; i < n; i++ {
		a := fmt.Sprintf("user%06d.x%d@corp%d.example.org", i, (i*7919)%100000, i%97)
		line := fmt.Sprintf("line %d contact %s for details", i, a)
		vals := []string{a}
		if i%3 == 0 {
			b := fmt.Sprintf("second%06d@other.example.net", i)
			line += " cc " + b
			vals = append(vals, b)
		}
		doc.WriteString(line + "\n")
		for _, v := range vals {
			ms = append(ms, detector.Match{Text: v, Type: "EMAIL", LineNumber: i + 1, Confidence: 90,
				Context: detector.ContextInfo{FullLine: line}})
		}
	}
	return doc.String(), ms
}

func processCPU() time.Duration {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

// cpuOf is the least CPU time over reps runs of f: the minimum is the reading the least scheduler and
// collector noise sits on. CPU time and not wall time because the host this runs on is shared.
func cpuOf(reps int, f func()) time.Duration {
	best := time.Duration(1<<63 - 1)
	for i := 0; i < reps; i++ {
		runtime.GC()
		before := processCPU()
		f()
		if d := processCPU() - before; d < best {
			best = d
		}
	}
	return best
}

// Redacting N distinct values must cost about twice what N/2 costs. The pass used to rebuild the whole
// document string and re-copy it into the position correlator for every match, so doubling the values
// roughly tripled the time (#1005: 0.31, 0.60, 1.68, 4.29 s at 1k, 2k, 4k, 8k values; the in-process
// ratio from 4k to 8k was 2.7 to 3.0 and rose with N).
//
// What is timed is redactPositional, the pass this package owns. The completeness sweep that follows
// it (redactverify.SweepRemaining) is not timed here: it is 90% of the time
// from 4k values up and would hide the pass (measured in the PR for #1005).
//
// Ratio bound: linear is 2.0 and a per-match whole-document cost is above 3 at these sizes; the bound
// sits between, tighter than the noise on a quiet host is wide, so it is asserted on the least of
// several runs. The fixture's value-count is a MINIMUM, not a ceiling: findings must be > 0 and
// distinct at both sizes or the ratio measures nothing.
//
// shortcut: redactverify.SweepRemaining scans the document once per value (redactverify.go:234, :239,
// :278, :305) and is still quadratic; it is outside this package, so no guard here can cover it. When
// it is made linear, add a whole-RedactString row at 16k/32k beside this one.
func TestRedactionCPUTimeIsLinearInDistinctValues(t *testing.T) {
	const small, big = 8000, 16000
	const maxRatio = 2.6
	for _, tc := range []struct {
		name        string
		correlation bool
	}{{"position-correlation", true}, {"text-search", false}} {
		t.Run(tc.name, func(t *testing.T) {
			ptr := NewPlainTextRedactor(nil, nil)
			ptr.SetPositionCorrelationEnabled(tc.correlation)
			run := func(n int) time.Duration {
				doc, ms := scalingFixture(n)
				distinct := map[string]bool{}
				for _, m := range ms {
					distinct[m.Text] = true
				}
				if len(distinct) != len(ms) || len(ms) < n {
					t.Fatalf("fixture: %d matches, %d distinct for n=%d", len(ms), len(distinct), n)
				}
				text, _, mapping, err := ptr.redactPositional(doc, ms, redactors.RedactionSimple, nil)
				if err != nil {
					t.Fatal(err)
				}
				out := text.String()
				if len(mapping) != len(ms) || strings.Contains(out, "@corp") || strings.Contains(out, "@other") {
					t.Fatalf("n=%d: %d of %d redacted, values left: %v", n, len(mapping), len(ms), strings.Contains(out, "@corp"))
				}
				return cpuOf(3, func() { _, _, _, _ = ptr.redactPositional(doc, ms, redactors.RedactionSimple, nil) })
			}
			a, b := run(small), run(big)
			ratio := float64(b) / float64(a)
			t.Logf("%d values: %v CPU, %d values: %v CPU, ratio %.2f (bound %.2f)", small, a, big, b, ratio, maxRatio)
			if ratio > maxRatio {
				t.Fatalf("CPU time grew %.2fx for %dx the values; want <= %.2f (linear is 2.0)", ratio, big/small, maxRatio)
			}
		})
	}
}

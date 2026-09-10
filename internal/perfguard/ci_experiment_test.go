// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package perfguard

import (
	"fmt"
	"os"
	"testing"
	"time"
)

// TestCIExperiment619CycleClock answers #619 with measurements that cannot be taken on a developer
// machine: windows-latest advances its CPU clock in 15.625ms steps, and whether the cycle counter #624
// landed is a usable replacement depends on properties only that runner can report.
//
// MEASUREMENT ONLY. Every finding is logged and nothing is asserted, so this can never redden CI. It is
// gated on FERRET_CI_EXPERIMENT so it costs other branches nothing.
//
// The four properties #624 said one Windows run would settle, plus the one it did not ask:
//
//  1. does the counter advance, and never go backwards
//  2. its smallest non-zero delta, against the 15.625ms of the CPU clock
//  3. is SLEEPING charged -- the property a raw invariant TSC would lose, and the whole reason the CPU
//     statistic exists rather than a wall-clock one
//  4. does a 4x workload read ~4x and a quadratic ~16x on it
//  5. NEW: how do all three clocks compare on the SAME workload, in one run? #619 assumed the choice was
//     between a finer CPU clock and giving up; #645 has since moved windows onto its wall clock, so the
//     honest question is whether cycles beat what is already shipping.
func TestCIExperiment619CycleClock(t *testing.T) {
	if os.Getenv("FERRET_CI_EXPERIMENT") == "" {
		t.Skip("set FERRET_CI_EXPERIMENT=1 to run the #619 measurement")
	}

	cpuTick, wallTick := ClockResolution()
	t.Logf("EXP619 platform: cpuTick=%v wallTick=%v MinTicks=%d cyclesSupported=%v",
		cpuTick, wallTick, MinTicks, CyclesSupported())
	t.Logf("EXP619 MinTicks costs: cpu=%v wall=%v (budget %v)",
		time.Duration(MinTicks)*cpuTick, time.Duration(MinTicks)*wallTick, MinTicksBudget)

	if !CyclesSupported() {
		t.Log("EXP619 cycle counter unsupported on this platform; properties 1-4 are windows-only")
	} else {
		// 1 + 2: advance, monotonicity, and the smallest non-zero delta.
		var smallest uint64 = 1 << 62
		backwards := 0
		prev, err := ProcessCPUCycles()
		if err != nil {
			t.Logf("EXP619 ProcessCPUCycles error: %v", err)
		} else {
			for i := 0; i < 200_000; i++ {
				cur, err := ProcessCPUCycles()
				if err != nil {
					t.Logf("EXP619 ProcessCPUCycles error mid-loop: %v", err)
					break
				}
				switch {
				case cur < prev:
					backwards++
				case cur > prev:
					if d := cur - prev; d < smallest {
						smallest = d
					}
				}
				prev = cur
			}
			t.Logf("EXP619 cycle counter: smallestNonZeroDelta=%d cycles, wentBackwards=%d times",
				smallest, backwards)
		}

		// 3: is sleeping charged? A counter that charges sleep is a wall clock wearing a hat, and would
		// reintroduce the contention sensitivity this package exists to remove.
		before, _ := ProcessCPUCycles()
		time.Sleep(100 * time.Millisecond)
		after, _ := ProcessCPUCycles()
		sleepCharged := after - before
		busyBefore, _ := ProcessCPUCycles()
		burnCycles(8_000_000)
		busyAfter, _ := ProcessCPUCycles()
		busyCharged := busyAfter - busyBefore
		t.Logf("EXP619 100ms SLEEP charged %d cycles; 8M-step BUSY loop charged %d cycles (ratio busy/sleep=%s)",
			sleepCharged, busyCharged, ratioStr(busyCharged, sleepCharged))
	}

	// 4 + 5: the same two workloads read on all three clocks, in one run.
	//
	// Read together rather than in separate Measure calls, so contention cannot differ between the
	// clocks being compared -- comparing a cpu ratio from one run against a wall ratio from another is
	// how this repo previously convinced itself of the wrong thing.
	for _, c := range []struct {
		name       string
		base, big  func()
		wantApprox string
	}{
		{"linear 4x", func() { burnCycles(8_000_000) }, func() { burnCycles(32_000_000) }, "~4x"},
		{"quadratic 16x", func() { burnQuadratic(12_000_000) }, func() { burnQuadratic(48_000_000) }, "~16x"},
	} {
		cpuR, wallR, cycR := threeClockRatio(t, c.base, c.big)
		t.Logf("EXP619 %-14s want %-4s  cpu=%s  wall=%s  cycles=%s", c.name, c.wantApprox, cpuR, wallR, cycR)
	}
}

// threeClockRatio times base and big twice each, taking minimums, and reports the growth ratio each clock
// gives for the same readings.
func threeClockRatio(t *testing.T, base, big func()) (cpuRatio, wallRatio, cycleRatio string) {
	t.Helper()

	type reading struct {
		cpu, wall time.Duration
		cycles    uint64
	}
	take := func(fn func()) reading {
		cpuBefore, _ := ProcessCPUTime()
		cycBefore, _ := ProcessCPUCycles()
		start := time.Now()
		fn()
		wall := time.Since(start)
		cpuAfter, _ := ProcessCPUTime()
		cycAfter, _ := ProcessCPUCycles()
		return reading{cpu: cpuAfter - cpuBefore, wall: wall, cycles: cycAfter - cycBefore}
	}

	var bases, bigs []reading
	WithGCOff(func() {
		for i := 0; i < DefaultPairs; i++ {
			bases = append(bases, take(base))
			bigs = append(bigs, take(big))
		}
	})

	minCPU := func(rs []reading) time.Duration {
		m := rs[0].cpu
		for _, r := range rs[1:] {
			if r.cpu < m {
				m = r.cpu
			}
		}
		return m
	}
	minWall := func(rs []reading) time.Duration {
		m := rs[0].wall
		for _, r := range rs[1:] {
			if r.wall < m {
				m = r.wall
			}
		}
		return m
	}
	minCyc := func(rs []reading) uint64 {
		m := rs[0].cycles
		for _, r := range rs[1:] {
			if r.cycles < m {
				m = r.cycles
			}
		}
		return m
	}

	bc, gc := minCPU(bases), minCPU(bigs)
	bw, gw := minWall(bases), minWall(bigs)
	by, gy := minCyc(bases), minCyc(bigs)

	cpuRatio = durRatio(bc, gc)
	wallRatio = durRatio(bw, gw)
	cycleRatio = ratioStr(gy, by)
	return cpuRatio, wallRatio, cycleRatio
}

func durRatio(base, big time.Duration) string {
	if base <= 0 {
		return "base=0 (unmeasurable)"
	}
	n := float64(big) / float64(base)
	ticksNote := ""
	cpuTick, wallTick := ClockResolution()
	_ = wallTick
	if cpuTick > 0 {
		ticksNote = " base=" + base.String()
	}
	return sprintf("%.2fx%s", n, ticksNote)
}

func ratioStr(big, base uint64) string {
	if base == 0 {
		return "base=0"
	}
	return sprintf("%.2fx (base=%d)", float64(big)/float64(base), base)
}

func sprintf(format string, a ...any) string { return fmt.Sprintf(format, a...) }

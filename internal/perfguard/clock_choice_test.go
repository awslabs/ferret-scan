// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package perfguard

import (
	"testing"
	"time"
)

// Measured platform granularities, so these cases are the real thing rather than round numbers.
//
//	windows-latest  CPU clock steps 15.625ms exactly; wall clock measured at 355.7µs and 722.7µs on
//	                different runs, so the coarser of the two is used here — it is the harder case.
//	darwin/arm64    CPU 1µs, wall 41ns (measured by ClockResolution on this repo's dev machine).
const (
	winCPUTick  = 15625 * time.Microsecond
	winWallTick = 7227 * time.Microsecond / 10
	macCPUTick  = 1 * time.Microsecond
	macWallTick = 41 * time.Nanosecond
)

// TestTheCoarseClockIsNotChosenWhenTheFineOneCanResolveTheWorkload is the regression this file exists
// for.
//
// On windows-latest the CPU clock was chosen for a base reading of ONE 15.625ms tick, and the guard
// then declined to assert on it — 15 of 18 goldencorpus targets, in one measured run, every one of
// which had an amply divisible wall reading. Choosing a clock that cannot resolve the workload while a
// clock that can sits unused is the whole defect.
func TestTheCoarseClockIsNotChosenWhenTheFineOneCanResolveTheWorkload(t *testing.T) {
	// bankaccount from the measured windows run: CPU base quantised to a single tick, wall base 13.2543ms.
	const bankaccountWallBase = 13254 * time.Microsecond
	got := clockForRatio(winCPUTick, bankaccountWallBase, winCPUTick, winWallTick, true)
	if got != "wall" {
		t.Errorf("clock = %q for a 1-tick CPU base (%v, tick %v) with a %v wall base (tick %v, = %.0f "+
			"ticks); want wall. The CPU clock cannot divide a single tick, so choosing it here is what "+
			"made the guard silently stop asserting on this platform",
			got, winCPUTick, winCPUTick, bankaccountWallBase, winWallTick,
			float64(bankaccountWallBase)/float64(winWallTick))
	}
}

// TestTheCPUClockIsStillPreferredWhereItResolves guards the other direction. The CPU clock's immunity
// to contention is why this package replaced a wall-clock statistic, so a change that quietly moved
// every measurement onto the wall clock would undo that even while every test above passed.
func TestTheCPUClockIsStillPreferredWhereItResolves(t *testing.T) {
	// The historical fixture on darwin: base=4 spin units, ~3.9ms, which is ~3,900 CPU ticks there.
	if got := clockForRatio(3943*time.Microsecond, 3943*time.Microsecond, macCPUTick, macWallTick, true); got != "cpu" {
		t.Errorf("clock = %q on darwin numbers (CPU base 3.943ms at a 1µs tick = 3,943 ticks); want cpu. "+
			"The CPU clock resolves this workload nearly 500x over, and preferring the wall clock here "+
			"would reintroduce exactly the contention sensitivity this package exists to remove", got)
	}
	// And on windows once the fixture is big enough for its coarse clock: 8 ticks is 125ms.
	if got := clockForRatio(125*time.Millisecond, 120*time.Millisecond, winCPUTick, winWallTick, true); got != "cpu" {
		t.Errorf("clock = %q for a 125ms CPU base at a 15.625ms tick (exactly the %d ticks required); "+
			"want cpu", got, MinTicks)
	}
}

func TestClockChoiceTable(t *testing.T) {
	cases := []struct {
		name                    string
		minBaseCPU, minBaseWall time.Duration
		cpuRes, wallRes         time.Duration
		cpuMeasurable           bool
		want                    string
		why                     string
	}{{
		name: "below MinMeasurableCPU falls back to wall, unchanged",
		// The one question MinMeasurableCPU still answers. Preserved exactly.
		minBaseCPU: 1 * time.Millisecond, minBaseWall: 10 * time.Millisecond,
		cpuRes: macCPUTick, wallRes: macWallTick, cpuMeasurable: false,
		want: "wall",
		why:  "a CPU reading under MinMeasurableCPU is certainly useless",
	}, {
		name:       "windows, CPU base one tick, wall base ample -> wall",
		minBaseCPU: winCPUTick, minBaseWall: 57 * time.Millisecond,
		cpuRes: winCPUTick, wallRes: winWallTick, cpuMeasurable: true,
		want: "wall",
		why:  "ssn's measured readings; 1 CPU tick versus 78 wall ticks",
	}, {
		name:       "windows, NEITHER clock resolves -> cpu, keeping the existing disclosure",
		minBaseCPU: winCPUTick, minBaseWall: 2 * time.Millisecond,
		cpuRes: winCPUTick, wallRes: winWallTick, cpuMeasurable: true,
		want: "cpu",
		why:  "2ms is 2.8 wall ticks, also under MinTicks, so there is nothing better to move to",
	}, {
		name:       "darwin, CPU resolves -> cpu",
		minBaseCPU: 4 * time.Millisecond, minBaseWall: 4 * time.Millisecond,
		cpuRes: macCPUTick, wallRes: macWallTick, cpuMeasurable: true,
		want: "cpu",
		why:  "4,000 CPU ticks; the preferred clock works",
	}, {
		name:       "tick measurement failed on both clocks -> cpu, not a fabricated verdict",
		minBaseCPU: 50 * time.Millisecond, minBaseWall: 50 * time.Millisecond,
		cpuRes: 0, wallRes: 0, cpuMeasurable: true,
		want: "cpu",
		why:  "ticksAt reports zero ticks for a zero resolution rather than +Inf; neither branch may claim success",
	}, {
		name:       "wall tick measurement failed, CPU resolves -> cpu",
		minBaseCPU: 125 * time.Millisecond, minBaseWall: 100 * time.Millisecond,
		cpuRes: winCPUTick, wallRes: 0, cpuMeasurable: true,
		want: "cpu",
		why:  "the CPU clock is fine here; a broken wall probe must not matter",
	}, {
		name:       "CPU tick measurement failed, wall resolves -> wall",
		minBaseCPU: 125 * time.Millisecond, minBaseWall: 100 * time.Millisecond,
		cpuRes: 0, wallRes: winWallTick, cpuMeasurable: true,
		want: "wall",
		why:  "an unmeasurable CPU tick cannot support a ratio, and the wall clock demonstrably can",
	}, {
		name:       "zero wall base with a working wall tick -> cpu, no division by a zero reading",
		minBaseCPU: winCPUTick, minBaseWall: 0,
		cpuRes: winCPUTick, wallRes: winWallTick, cpuMeasurable: true,
		want: "cpu",
		why:  "a clock too coarse to register the workload at all reports 0, which is not a small reading",
	}}

	for _, c := range cases {
		got := clockForRatio(c.minBaseCPU, c.minBaseWall, c.cpuRes, c.wallRes, c.cpuMeasurable)
		if got != c.want {
			t.Errorf("%s: clock = %q, want %q — %s\n  (cpu base=%v tick=%v, wall base=%v tick=%v, cpuMeasurable=%v)",
				c.name, got, c.want, c.why, c.minBaseCPU, c.cpuRes, c.minBaseWall, c.wallRes, c.cpuMeasurable)
		}
	}
}

// TestTheChoiceActuallyDiffersFromTheOldRule is the non-vacuity floor for this whole change.
//
// The old rule was "CPU whenever every base reading clears MinMeasurableCPU". If the new rule agreed
// with it on windows' measured numbers, this change would be a no-op dressed up as a fix — and every
// other test in this file would still pass, because they assert the new rule's outputs rather than the
// difference. So the difference itself is asserted.
func TestTheChoiceActuallyDiffersFromTheOldRule(t *testing.T) {
	// The 15 measured windows base readings that declined to assert, paired with their wall readings.
	wallBases := []time.Duration{
		57022 * time.Microsecond,  // ssn
		30564 * time.Microsecond,  // email
		23950 * time.Microsecond,  // phone
		13494 * time.Microsecond,  // creditcard
		34084 * time.Microsecond,  // address
		13254 * time.Microsecond,  // bankaccount
		4260 * time.Microsecond,   // cloudresources  <- the one that does not clear 8 wall ticks
		18735 * time.Microsecond,  // driverslicense
		31230 * time.Microsecond,  // intellectualproperty
		12229 * time.Microsecond,  // medicalid
		41558 * time.Microsecond,  // passport
		19927 * time.Microsecond,  // personname
		68779 * time.Microsecond,  // secrets
		102608 * time.Microsecond, // socialmedia
		18891 * time.Microsecond,  // vin
	}

	movedToWall := 0
	for _, wall := range wallBases {
		// Every one of these cleared MinMeasurableCPU (2ms) and so was measured on the CPU clock, at
		// one to four 15.625ms ticks. One tick is the case here.
		oldRule := "cpu" // what the old code chose for all 15
		newRule := clockForRatio(winCPUTick, wall, winCPUTick, winWallTick, true)
		if newRule != oldRule {
			movedToWall++
		}
	}

	// At the coarser of the two measured windows wall ticks (722.7µs), 8 ticks costs 5.78ms, which the
	// 4.26ms cloudresources reading alone does not clear. So 14 of 15, not all 15 — stated as measured
	// rather than rounded up.
	if movedToWall != 14 {
		t.Errorf("%d of %d measured windows readings moved off the unusable CPU clock, want 14. If this "+
			"is 0 the change is a no-op and the guard is still silently not asserting on that platform",
			movedToWall, len(wallBases))
	}
}

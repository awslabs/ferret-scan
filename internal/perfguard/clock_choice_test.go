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

// TestBaseUnitsForSizesTheFixtureToTheClockThatWillMeasureIt covers the arithmetic that no darwin run
// exercises: there the floor is returned every time.
func TestBaseUnitsForSizesTheFixtureToTheClockThatWillMeasureIt(t *testing.T) {
	// One spin unit costs ~985µs, measured on this repo's dev machine.
	const oneUnit = 986 * time.Microsecond

	cases := []struct {
		name            string
		cpuRes, wallRes time.Duration
		oneUnit         time.Duration
		want            int
		why             string
	}{{
		name:   "darwin: the finer clock resolves MinTicks in 328ns, so the floor stands",
		cpuRes: macCPUTick, wallRes: macWallTick, oneUnit: oneUnit,
		want: historicalBaseUnits,
		why:  "8 x 41ns is far below one spin unit; the fixture must not SHRINK below what the tests were written against",
	}, {
		name:   "windows: sized against the 722.7µs WALL tick, not the 15.625ms CPU tick",
		cpuRes: winCPUTick, wallRes: winWallTick, oneUnit: oneUnit,
		want: 6,
		why:  "8 x 722.7µs = 5.78ms, which needs 6 units at ~986µs each. Sizing against the CPU tick would demand 127",
	}, {
		name:   "a platform with no usable wall clock is sized against its CPU tick",
		cpuRes: winCPUTick, wallRes: winCPUTick, oneUnit: oneUnit,
		want: 127,
		why:  "8 x 15.625ms = 125ms; expensive, but the alternative is a ratio of two integers",
	}, {
		name:   "failed unit calibration keeps the historical fixture",
		cpuRes: winCPUTick, wallRes: winWallTick, oneUnit: 0,
		want: historicalBaseUnits,
		why:  "dividing by a zero unit cost yields a nonsense size; the tests' original fixture is the safe answer",
	}, {
		name:   "failed tick probe keeps the historical fixture",
		cpuRes: 0, wallRes: 0, oneUnit: oneUnit,
		want: historicalBaseUnits,
		why:  "no measured tick to size against",
	}, {
		name:   "a wall-tick-only probe failure still keeps the historical fixture",
		cpuRes: macCPUTick, wallRes: 0, oneUnit: oneUnit,
		want: historicalBaseUnits,
		why:  "clockForRatio may still choose either clock, so a half-measured platform is not a basis to resize on",
	}, {
		name:   "rounds UP: a fraction of a spin unit buys no ticks",
		cpuRes: 1000 * time.Nanosecond, wallRes: 1000 * time.Nanosecond, oneUnit: 3 * time.Microsecond,
		want: historicalBaseUnits,
		why:  "8µs needs 2.67 units, rounded up to 3, which is then raised to the floor of 4",
	}, {
		name:   "rounds up above the floor too",
		cpuRes: 2 * time.Millisecond, wallRes: 2 * time.Millisecond, oneUnit: 3 * time.Millisecond,
		want: 6,
		why:  "8 x 2ms = 16ms over 3ms units is 5.33, and 5 units would fall 1ms short of MinTicks",
	}}

	for _, c := range cases {
		if got := baseUnitsFor(c.cpuRes, c.wallRes, c.oneUnit); got != c.want {
			t.Errorf("%s: baseUnitsFor(cpu=%v, wall=%v, unit=%v) = %d, want %d — %s",
				c.name, c.cpuRes, c.wallRes, c.oneUnit, got, c.want, c.why)
		}
	}
}

// TestTheCalibratedFixtureActuallyClearsTheGateHere is the non-vacuity floor: on this machine the
// sizer must produce a fixture the local clock can resolve, or every gated assertion above is skipped
// and the suite proves nothing.
func TestTheCalibratedFixtureActuallyClearsTheGateHere(t *testing.T) {
	base := calibratedBaseUnits()
	g, err := Measure(DefaultPairs, func() { spin(base) }, func() { spin(4 * base) })
	if err != nil {
		t.Fatalf("Measure with %d calibrated units: %v", base, err)
	}
	n, ok := g.Ticks()
	t.Logf("%d calibrated units -> %s; %s", base, g, g.ResolutionNote())
	if !ok {
		t.Errorf("the calibrated fixture spans only %.1f ticks, under the %d required, so every gated "+
			"assertion in this package is being SKIPPED on this platform rather than run. %s",
			n, MinTicks, g.ResolutionNote())
	}
}

// TestTheCalibratedFixtureClearsMinTicksAtEveryObservedWindowsWallTick is the proof that sizing the
// fixture from the measured tick closes the failure a hardcoded spin(4) could not.
//
// windows-latest does not have "a" wall tick. Across this repo's CI logs it has been observed at twenty
// distinct values from 320µs to 1.7107ms — a 5.3x spread, because the platform's timer resolution depends
// on what else has raised it. A fixed fixture cannot be right across that: spin(4) is ~7.34ms there, which
// is 22.9 ticks at the fine end and 4.29 at the coarse end, and the coarse end is what made
// TestTicksIsSufficientOnThisPlatformForATypicalFixture Errorf on roughly 1 windows run in 17.
//
// Driven by the pure sizer, so a developer on darwin can check the windows outcome. The unit cost is
// windows-latest's own measured spin(1) figure, not this machine's.
func TestTheCalibratedFixtureClearsMinTicksAtEveryObservedWindowsWallTick(t *testing.T) {
	// Measured on windows-latest: Measure(2, spin(4), spin(16)) reported min base=7.3437ms, so one spin
	// unit costs 1.836ms there. Deliberately NOT this Mac's 986µs — a laptop's unit cost would understate
	// the fixture windows builds and hide the very case this test covers.
	const winUnitCost = 1836 * time.Microsecond

	observed := []time.Duration{
		320_000, 332_500, 335_900, 336_100, 372_600, 383_100, 399_400, 473_800, 482_100, 484_500,
		505_300, 513_700, 518_900, 522_200, 532_200, 546_600, 622_500, 764_800, 951_000, 1_710_700,
	}

	for _, wallTick := range observed {
		wallTick *= time.Nanosecond
		units := baseUnitsFor(winCPUTick, wallTick, winUnitCost)
		base := time.Duration(units) * winUnitCost

		// The clock the ratio will be divided on: the CPU tick is 15.625ms there, so a base of this size
		// can never span MinTicks of it, and clockForRatio moves to the wall clock when the wall clock
		// resolves. That is the path this fixture must satisfy.
		got := clockForRatio(base, base, winCPUTick, wallTick, true)
		if got != "wall" {
			t.Errorf("wall tick %v: clock = %q for a %v base, want wall — the CPU clock needs %v and "+
				"cannot be satisfied by any fixture this repo ships",
				wallTick, got, base, time.Duration(MinTicks)*winCPUTick)
			continue
		}

		n, sufficient := ticksAt(base, wallTick)
		if !sufficient {
			t.Errorf("wall tick %v: a calibrated base of %v (%d units) spans only %.2f ticks, under the "+
				"%d required — this is the failure the hardcoded spin(4) produced, still open",
				wallTick, base, units, n, MinTicks)
		}
	}
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package perfguard

import "time"

// clockForRatio picks which clock a growth RATIO will be divided on.
//
// The CPU clock is preferred because contention only ever inflates wall time, so a descheduled sample
// cannot fake a quadratic there. That asymmetry is the reason this package exists.
//
// Preferring it UNCONDITIONALLY is how the guard went quiet on windows-latest. MinMeasurableCPU is 2ms
// and that platform's CPU clock steps in 15.625ms, so a single-tick reading cleared the floor, the CPU
// clock was chosen, and Ticks then correctly refused to divide a 1-tick base. Measured on one windows
// run: 15 of the 18 goldencorpus targets declined to assert, and every one of the 15 had a wall base
// between 4.26ms and 102.6ms — 6 to 288 wall ticks, amply divisible. The finer clock was available in
// every single case the coarser one gave up on.
//
// So the order is: use the CPU clock while it can actually resolve the workload; fall back to the wall
// clock only where the wall clock demonstrably can; otherwise keep the historical choice, so that Ticks
// still reports an unusable reading as unusable rather than this function inventing a verdict.
//
// PURE, and takes both ticks as parameters, for the same reason ticksAt does: the case that matters is
// on a platform the developer cannot run. On darwin the CPU tick is 1µs, so the first branch is taken
// every time and no local run exercises the fallback at all.
func clockForRatio(minBaseCPU, minBaseWall, cpuRes, wallRes time.Duration, cpuMeasurable bool) string {
	// Below MinMeasurableCPU the CPU reading is certainly useless, which is the one question that
	// constant still answers. Preserved exactly as it was.
	if !cpuMeasurable {
		return "wall"
	}
	if _, ok := ticksAt(minBaseCPU, cpuRes); ok {
		return "cpu"
	}
	// The CPU clock cannot resolve this workload. Move to the wall clock only on evidence that the wall
	// clock can — never merely because it is a different clock.
	if _, ok := ticksAt(minBaseWall, wallRes); ok {
		return "wall"
	}
	// Neither clock can carry a ratio. Returning "cpu" keeps the pre-existing disclosure: Ticks and
	// ResolutionNote then report the CPU-clock tick shortfall, which is the more informative of the two
	// and the message this platform has always produced.
	return "cpu"
}

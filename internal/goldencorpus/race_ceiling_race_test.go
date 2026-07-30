// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build race

package goldencorpus

// raceDetectorEnabled is true in this file, which is only compiled with -race.
// The two build-tagged files are how Go exposes the race detector to a test at
// compile time; there is no runtime API for it.
const raceDetectorEnabled = true

// raceCeilingMultiplier scales the absolute timing ceilings when the race
// detector is active.
//
// 8x is derived from measurement, not chosen for comfort. The socialmedia target
// takes 0.33s without -race and 4.97s with it — a 15x instrumentation cost — and
// the same suite runs on CI hardware roughly 2-3x slower than a developer
// machine. A ceiling at 8x the normal value keeps the guard meaningful (a genuine
// quadratic on these inputs is 16x per 4x of input and blows past any of these
// numbers) while not reporting the instrumentation itself as a regression.
//
// The ratio check is unaffected either way: -race inflates the base and the 4x
// measurement equally, so the growth factor it asserts on is preserved. That
// check, not this ceiling, is what actually detects quadratic scaling.
const raceCeilingMultiplier = 8

func raceNote() string { return ", scaled 8x for -race" }

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build !race

package goldencorpus

// raceDetectorEnabled is false in this file, which is compiled for ordinary
// (non -race) runs. See race_ceiling_race_test.go for why the pair exists and how
// the multiplier was derived.
const raceDetectorEnabled = false

// raceCeilingMultiplier is 1 without the race detector: the thresholds declared
// per target apply exactly as written.
const raceCeilingMultiplier = 1

func raceNote() string { return "" }

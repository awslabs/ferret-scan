// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build !race

package textextractofficetextlib

// raceDetectorEnabled is false in this file, which is compiled for ordinary (non -race) runs.
// See race_alloc_race_test.go for why the pair exists and how the numbers were derived.
const raceDetectorEnabled = false

// maxAllocGrowth: 4x input allocates ~3.9x on one pass and ~15x on a per-match rescan, so 8.0
// sits between them with 2.05x below and 1.88x above.
const maxAllocGrowth = 8.0

// baseAllocCeiling: one pass allocates 3.19MB for the base fixture, a per-match rescan 72.89MB.
// 20MB is 6.3x above the correct reading and 3.6x below the regressed one.
const baseAllocCeiling = 20 << 20

func raceAllocNote() string { return "" }

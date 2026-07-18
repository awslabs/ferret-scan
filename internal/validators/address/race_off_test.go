// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build !race

package address

// raceEnabled reports whether the binary was built with the race detector. The
// race detector adds large (5-20x), variable wall-clock overhead, so the DoS
// timing regression test uses it to skip its wall-clock ceiling (the scan still
// runs, so -race can still detect data races in the per-line hoisted state).
const raceEnabled = false

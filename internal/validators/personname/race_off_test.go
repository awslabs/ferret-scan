// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build !race

package personname

// raceEnabled reports whether the binary was built with the race detector. The
// race detector adds large (5-20x), variable wall-clock overhead, so timing-based
// regression tests use this to relax or skip their wall-clock ceiling.
const raceEnabled = false

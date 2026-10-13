// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build race

package perfguard

// raceEnabled is true when built with -race. Runner() reports it, because the race detector
// compresses growth ratios (#509 measured ~1.24x), so a margin read under it is a different
// population from the plain one and must not be pooled with it.
const raceEnabled = true

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build race

package textextractofficetextlib

// raceDetectorEnabled is true in this file, which is only compiled with -race. The two
// build-tagged files are how Go exposes the race detector to a test at compile time; there is no
// runtime API for it.
const raceDetectorEnabled = true

// The race detector allocates its own shadow state, and it is NOT neutral to an allocation
// ratio. This is the same trap #509 found in the timing guard's comment — "-race inflates both
// measurements equally, so the growth factor is preserved" — reappearing for a different
// instrument, and it was caught only because dimension 13 of the PR checklist runs the whole
// module under -race.
//
// Measured on this fixture:
//
//	                    base        big       ratio
//	one pass           3.16MB     12.35MB     3.91x
//	one pass, -race   58.07MB     73.39MB     1.26x
//	per-match        72.93MB   1095.76MB     15.02x
//	per-match, -race 127.4MB    1157.6MB      9.06x
//
// The detector adds roughly a CONSTANT — about 55MB to the base and 61MB to the big term — so it
// does not scale the two ends equally: it swamps the small base and barely moves the large big
// term, compressing the ratio. That is the opposite direction from the timing guard, where -race
// inflated the base MORE, but the lesson is the same: an instrument's behaviour under -race has
// to be measured, not assumed.
//
// The ratio still separates cleanly under -race — 1.26x correct against 9.06x regressed — so the
// guard is live in CI rather than skipped. 4.0 gives 3.17x below and 2.26x above.
const maxAllocGrowth = 4.0

// The absolute floor is raised past the detector's own overhead. Correct reads 58.07MB and
// regressed 127.4MB, so 90MB sits 1.55x above one and 1.42x below the other. Thinner than the
// non-race pair, which is inherent: a near-constant addend of 55MB compresses an absolute
// comparison whose correct value is 3MB. The ratio above is the stronger assertion here.
const baseAllocCeiling = 90 << 20

func raceAllocNote() string { return " (under -race)" }

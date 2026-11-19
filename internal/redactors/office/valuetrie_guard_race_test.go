// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build race

package office

// Under -race the trie's map lookups are instrumented and strings.Index (assembly) is not, so the
// ratio compresses from ~14x to 2.3x at 8,000 values (docs/testing/TEST_PLAN.md: "-race does not
// preserve a growth ratio"). The reference grows quadratically, so a larger input restores it.
//
// Measured linux/amd64, load 9-19: correct 4.18x and 4.43x (per pair 3.77 - 4.43x), regressed 0.7x
// (the per-value loop is the reference, so about 1x by construction). Bound 2.5: 4.18/2.5 = 1.67x
// above it (worst pair 3.77/2.5 = 1.5x), 2.5/1.0 = 2.5x below it.
const (
	guardValues    = 16000
	locateAllBound = 2.5
)

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build !race

package office

// guardValues is the distinct-value count of the locateAll cost guard, and locateAllBound is how many
// times the per-value implementation must cost what locateAll costs on that SAME input.
//
// Measured linux/amd64, 16 CPUs, load 9-19, Go 1.27.4: correct 14.5 - 16.0x (per pair 12.3 - 16.0x),
// regressed (locateAll replaced by the per-value loop) 0.72x. Margins: 14.5/3.0 = 4.8x above the
// bound, 3.0/0.72 = 4.2x below it.
const (
	guardValues    = 8000
	locateAllBound = 3.0
)

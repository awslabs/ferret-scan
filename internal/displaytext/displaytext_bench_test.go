// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package displaytext

import (
	"strings"
	"testing"
)

// SanitizeDisplayText runs on every filename of every finding, so its cost is worth a
// number rather than a wall-clock CLI comparison. Measuring it through the CLI was the wrong
// instrument: over seven repetitions the ratio scattered from 0.76x to 1.40x with no
// consistent direction, because process startup, the filesystem walk and validation dominate
// and vary far more than this function costs.
//
// The clean path is the one that matters — nearly every real filename takes it — and
// needsSanitizing exists to make it allocation-free.

var benchPaths = []string{
	"/home/user/Documents/quarterly-report.txt",
	"report.txt",
	"rapport-café.txt",
}

func BenchmarkSanitizeDisplayTextClean(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for _, p := range benchPaths {
			_ = SanitizeDisplayText(p)
		}
	}
}

func BenchmarkSanitizeDisplayTextHostile(b *testing.B) {
	hostile := "quarterly-report.txt\x1b[2K\r"
	for i := 0; i < b.N; i++ {
		_ = SanitizeDisplayText(hostile)
	}
}

func BenchmarkSanitizeDisplayTextLongClean(b *testing.B) {
	long := "/" + strings.Repeat("segment/", 40) + "file-name-that-is-quite-long.txt"
	b.SetBytes(int64(len(long)))
	for i := 0; i < b.N; i++ {
		_ = SanitizeDisplayText(long)
	}
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package intellectualproperty

import (
	stdctx "context"
	"strconv"
	"strings"
	"testing"
)

// multiLineIPContent has one IP notice per line so every line becomes a distinct
// key in processLineMatches' lineMatches map. Ranging that map directly rotated
// the whole file's findings differently on every run.
const multiLineIPContent = "Copyright (c) 2024 Acme Corp. All rights reserved.\n" +
	"Patent No. 9,876,543 pending application.\n" +
	"ACME(TM) is a trademark of Acme Corp.\n" +
	"CONFIDENTIAL AND PROPRIETARY trade secret information.\n" +
	"Copyright 2023 Widget Inc.\n"

// lineSignature renders the emitted line numbers in emit order.
func lineSignature(t *testing.T, content string) string {
	t.Helper()
	v := NewValidator()
	matches, err := v.ValidateContentCtx(stdctx.Background(), content, "/test/notice.txt")
	if err != nil {
		t.Fatalf("ValidateContentCtx: %v", err)
	}
	parts := make([]string, 0, len(matches))
	for _, m := range matches {
		parts = append(parts, strconv.Itoa(m.LineNumber))
	}
	return strings.Join(parts, ",")
}

// TestEmitOrderIsAscendingByLine pins the emit order to document order. Before
// the fix the emitted sequence was a random rotation of the file's lines.
func TestEmitOrderIsAscendingByLine(t *testing.T) {
	v := NewValidator()
	matches, err := v.ValidateContentCtx(stdctx.Background(), multiLineIPContent, "/test/notice.txt")
	if err != nil {
		t.Fatalf("ValidateContentCtx: %v", err)
	}
	if len(matches) < 3 {
		t.Fatalf("expected at least 3 findings across 5 notice lines, got %d", len(matches))
	}
	prev := -1
	for i, m := range matches {
		if m.LineNumber < prev {
			t.Fatalf("finding %d is on line %d, after a finding on line %d: emit order is not ascending (%s)",
				i, m.LineNumber, prev, lineSignature(t, multiLineIPContent))
		}
		prev = m.LineNumber
	}
}

// TestEmitOrderStableAcrossRuns is the anti-flake guard: Go randomizes map
// iteration per range statement, so one call can be ordered by luck.
func TestEmitOrderStableAcrossRuns(t *testing.T) {
	seen := make(map[string]int)
	for i := 0; i < 200; i++ {
		seen[lineSignature(t, multiLineIPContent)]++
	}
	if len(seen) != 1 {
		t.Fatalf("emit order varied across 200 runs: %d distinct orders %v", len(seen), seen)
	}
}

// TestEmitOrderKeepsEveryLinesFindings guards against the sort dropping a line.
// A silently dropped line is an undetected IP notice, which is worse than a
// randomly ordered one.
func TestEmitOrderKeepsEveryLinesFindings(t *testing.T) {
	v := NewValidator()
	lineMatches := v.detectPatternsByLine(stdctx.Background(), multiLineIPContent, "/test/notice.txt")
	linesWithMatches := 0
	for _, ms := range lineMatches {
		if len(ms) > 0 {
			linesWithMatches++
		}
	}
	if linesWithMatches == 0 {
		t.Fatal("fixture produced no per-line matches; the test would not prove anything")
	}
	emitted := v.processLineMatches(lineMatches)
	seenLines := make(map[int]bool, len(emitted))
	for _, m := range emitted {
		seenLines[m.LineNumber] = true
	}
	// Reconstruction can merge several matches on one line into one finding, so
	// the count can shrink — but no line that had matches may vanish entirely.
	for lineNum, ms := range lineMatches {
		if len(ms) == 0 {
			continue
		}
		if !seenLines[ms[0].LineNumber] {
			t.Fatalf("line key %d had %d matches but contributed no finding (line %d missing from output)",
				lineNum, len(ms), ms[0].LineNumber)
		}
	}
}

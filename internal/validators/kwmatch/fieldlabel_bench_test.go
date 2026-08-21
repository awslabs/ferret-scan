// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kwmatch

import "testing"

// benchKeywords mirrors the real medicalid vocabulary, the largest list LooksLikeFieldLabel is called
// with, so the per-keyword cost is measured at the size it actually runs at.
var benchKeywords = []string{
	"insurance", "member id", "member number", "subscriber", "policy number", "group number",
	"health plan", "enrollee", "covered", "copay", "deductible", "claims",
	"member identification", "subscriber identification", "policyholder",
	"rxbin", "rxpcn", "rxgrp", "rx bin", "rx group", "medical record", "patient id",
	"patient number", "record number", "chart number", "admission number", "patient account",
	"patient identification", "patient identification number", "medical record number",
}

// These exist because LooksLikeFieldLabel runs on EVERY line of every scanned document, so a constant
// factor here is not a micro-optimization — and because the sub-quadratic complexity guard in
// internal/goldencorpus is a RATIO test that cannot see one.
//
// BenchmarkLooksLikeFieldLabelMiss is the one to watch: ordinary prose is the common case, and it
// pays the full keyword scan before failing. Measured when the concatenated-label support was added
// (#409): the miss path went 507ns -> 534ns (+5%) with allocations unchanged, and a first draft that
// built the concatenation with a strings.Builder cost +1 alloc/op and +12% on ManyWords until it was
// rewritten to compare incrementally.
func BenchmarkLooksLikeFieldLabelMiss(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = LooksLikeFieldLabel("The quarterly report was circulated", benchKeywords)
	}
}

func BenchmarkLooksLikeFieldLabelHit(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = LooksLikeFieldLabel("Member ID (primary)", benchKeywords)
	}
}

// The concatenated spelling, which is what #409 added.
func BenchmarkLooksLikeFieldLabelConcatenated(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = LooksLikeFieldLabel("memberId:", benchKeywords)
	}
}

// A label whose every word must be walked is the worst case for the per-word loop.
func BenchmarkLooksLikeFieldLabelManyWords(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = LooksLikeFieldLabel("member id number field value primary", benchKeywords)
	}
}

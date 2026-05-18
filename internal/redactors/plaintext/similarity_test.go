// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package plaintext

import (
	"math"
	"testing"
)

// TestCalculateTextSimilarity_HandlesMultiByteRunes guards the rune-aware
// fix to calculateTextSimilarity. The previous implementation indexed the
// longer string by byte offset while iterating the shorter string by rune,
// which silently scored multi-byte content wrong.
func TestCalculateTextSimilarity_HandlesMultiByteRunes(t *testing.T) {
	ptr := NewPlainTextRedactor(nil, nil)

	cases := []struct {
		name string
		a, b string
		want float64
	}{
		{"identical ASCII", "hello", "hello", 1.0},
		{"identical multi-byte", "héllo", "héllo", 1.0},
		{"one differs in non-ASCII", "héllo", "hèllo", 4.0 / 5.0},
		{"identical CJK", "日本語", "日本語", 1.0},
		{"empty inputs", "", "anything", 0.0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ptr.calculateTextSimilarity(tc.a, tc.b)
			if math.Abs(got-tc.want) > 1e-9 {
				t.Errorf("similarity(%q, %q) = %.4f, want %.4f", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

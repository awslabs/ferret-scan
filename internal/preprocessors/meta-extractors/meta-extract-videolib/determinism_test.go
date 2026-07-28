// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractvideolib

import (
	"testing"
)

// TestToProcessedContent_DeterministicPropertyOrder is the regression test for
// the video-metadata emit nondeterminism. ToProcessedContent ranged over the
// Properties map directly, so the extracted text — and therefore finding line
// numbers and the byte-for-byte redaction output — varied run to run. Verified
// originally on a real .mov and .mp4.
func TestToProcessedContent_DeterministicPropertyOrder(t *testing.T) {
	vm := &VideoMetadata{
		Filename: "sample.mov",
		Properties: map[string]string{
			"MajorBrand":      "qt",
			"MinorVersion":    "0",
			"CompatibleBrand": "qt",
			"CreationTime":    "2026-01-01",
			"HandlerType":     "vide",
			"Encoder":         "example",
			"MediaLanguage":   "und",
			"ColorPrimaries":  "bt709",
			"FrameRate":       "30",
			"TrackCount":      "2",
		},
	}

	first := vm.ToProcessedContent()
	for i := 0; i < 300; i++ {
		if got := vm.ToProcessedContent(); got != first {
			t.Fatalf("iter %d: video ToProcessedContent order is not stable:\n--- first ---\n%s\n--- iter %d ---\n%s", i, first, i, got)
		}
	}
}

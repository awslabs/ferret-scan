// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package audiolib

import (
	"testing"
)

// TestToProcessedContent_DeterministicPropertyOrder is the regression test for
// the audio-metadata emit nondeterminism. ToProcessedContent ranged over the
// Properties map directly, so the extracted text — and therefore every finding's
// line number and the byte-for-byte redaction output — varied run to run.
// Verified originally on a real .m4a where EncodingTool jumped lines between runs.
func TestToProcessedContent_DeterministicPropertyOrder(t *testing.T) {
	am := &AudioMetadata{
		Filename: "sample.m4a",
		Properties: map[string]string{
			"EncodingTool":    "com.apple.VoiceMemos",
			"FileExtension":   ".m4a",
			"FilePath":        "/tmp/sample.m4a",
			"MajorBrand":      "M4A",
			"MinorVersion":    "0",
			"CompatibleBrand": "isom",
			"CreationTime":    "2026-01-01",
			"Encoder":         "example-encoder",
			"HandlerType":     "soun",
			"MediaLanguage":   "und",
		},
	}

	first := am.ToProcessedContent()
	for i := 0; i < 300; i++ {
		if got := am.ToProcessedContent(); got != first {
			t.Fatalf("iter %d: audio ToProcessedContent order is not stable:\n--- first ---\n%s\n--- iter %d ---\n%s", i, first, i, got)
		}
	}
}

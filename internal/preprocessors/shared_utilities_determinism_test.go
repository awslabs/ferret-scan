// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"strings"
	"testing"
)

// TestFormatPropertiesMap_DeterministicOrder is the regression test for the
// metadata-emit nondeterminism. FormatPropertiesMap ranged over the properties
// map directly, so the formatted metadata text — and therefore every finding's
// line number and the byte-for-byte redaction output — varied run to run.
//
// Go randomizes map iteration WITHIN a single process across range statements,
// so calling the function repeatedly in one test samples different orders; on
// the unfixed code this fails within a handful of iterations.
func TestFormatPropertiesMap_DeterministicOrder(t *testing.T) {
	mf := NewMetadataFormatter()

	props := map[string]string{
		"EncodingTool": "com.example.Tool 1.0",
		"Album":        "Example Album",
		"Artist":       "Example Artist",
		"Comment":      "some comment",
		"Genre":        "Example",
		"Track":        "3",
		"Year":         "2026",
		"Composer":     "Example Composer",
		"Publisher":    "Example Publisher",
		"Copyright":    "example",
	}

	first := mf.FormatPropertiesMap(props, nil)
	for i := 0; i < 300; i++ {
		if got := mf.FormatPropertiesMap(props, nil); got != first {
			t.Fatalf("iter %d: FormatPropertiesMap output order is not stable:\n--- first ---\n%s\n--- iter %d ---\n%s", i, first, i, got)
		}
	}
}

// TestFormatPropertiesMap_ExclusionAndEmptyStillHold guards that making the
// order deterministic did not change WHICH properties are emitted: excluded keys
// and empty values must still be dropped.
func TestFormatPropertiesMap_ExclusionAndEmptyStillHold(t *testing.T) {
	mf := NewMetadataFormatter()

	props := map[string]string{
		"Keep":        "value",
		"DropEmpty":   "",
		"DropExclude": "should not appear",
	}
	out := mf.FormatPropertiesMap(props, []string{"DropExclude"})

	if !strings.Contains(out, "Keep") {
		t.Errorf("kept key missing from output: %q", out)
	}
	if strings.Contains(out, "DropEmpty") {
		t.Errorf("empty-valued key should be dropped: %q", out)
	}
	if strings.Contains(out, "DropExclude") {
		t.Errorf("excluded key should be dropped: %q", out)
	}
}

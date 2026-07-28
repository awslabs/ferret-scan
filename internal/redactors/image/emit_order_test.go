// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"strings"
	"testing"
)

// iterations is high enough that a randomized Go map order over the eight
// supported formats is overwhelmingly unlikely to match the expected order every
// time by chance.
const iterations = 200

// TestGetSupportedTypes_StableOrder locks the reported type list. It was built by
// ranging the supported-format map, so the same redactor described itself
// differently on every call — the list reaches registration logs and
// operator-facing output.
func TestGetSupportedTypes_StableOrder(t *testing.T) {
	// Sorted extensions, each immediately followed by its undotted spelling.
	want := []string{
		".bmp", "bmp",
		".gif", "gif",
		".jpeg", "jpeg",
		".jpg", "jpg",
		".png", "png",
		".tif", "tif",
		".tiff", "tiff",
		".webp", "webp",
	}

	for i := 0; i < iterations; i++ {
		got := NewImageMetadataRedactor(nil, nil).GetSupportedTypes()
		if len(got) != len(want) {
			t.Fatalf("iteration %d: got %d types, want %d: %v", i, len(got), len(want), got)
		}
		for j := range want {
			if got[j] != want[j] {
				t.Fatalf("iteration %d: type %d = %q, want %q\nfull order: %v",
					i, j, got[j], want[j], got)
			}
		}
	}
}

// TestSortedEXIFFieldNames_StableOrder locks the EXIF field iteration order used
// when building redaction mappings. Those mappings become audit-log entries whose
// IDs are assigned from slice position (doc_N_redaction_I), so ranging the EXIF
// map gave the same field a different ID on every run and made two audit logs of
// one image impossible to compare.
func TestSortedEXIFFieldNames_StableOrder(t *testing.T) {
	exifData := map[string]string{
		"GPSLongitude": "-122.4194",
		"Make":         "ExampleCorp",
		"DateTime":     "2026:07:27 10:00:00",
		"GPSLatitude":  "37.7749",
		"Model":        "ExampleCam",
		"Artist":       "A. Example",
	}
	want := []string{"Artist", "DateTime", "GPSLatitude", "GPSLongitude", "Make", "Model"}

	for i := 0; i < iterations; i++ {
		got := sortedEXIFFieldNames(exifData)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("iteration %d: got %v, want %v", i, got, want)
		}
	}
}

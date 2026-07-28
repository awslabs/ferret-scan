// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractvideolib

import (
	"math"
	"strings"
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

// TestSearchForGPSInMetadata_DeterministicCoordinate covers the second video-side
// map-order defect: searchForGPSInMetadata scraped coordinates out of the
// Properties map, and both parse helpers write the SAME scalar GPSLatitude/
// GPSLongitude fields. Ranging the map meant whichever candidate property landed
// last won, so the emitted "GPS_Coordinates" value itself — not just its position
// in the text — changed between runs of the same binary on the same file.
//
// The fixture mirrors a real file: the property names are the udta string boxes
// this scrape actually sees (Information, Warning, URL — populated by parseUdtaBox
// before the scrape runs), two of which parse as coordinates. Built into a real
// .mov with ffmpeg, this shape made the parent emit a SPLICED coordinate — the
// latitude from "Information" with the longitude 11.111100 from "Warning" — in 23
// of 25 runs, and the correct -82.698500 in the other 2. A wrong location, not
// just a reordered one.
//
// So the assertion is on the VALUE, not merely on stability: "Warning" sorts
// after "Information", so sorting the keys without the first-complete-wins guard
// would be deterministic yet deterministically wrong.
func TestSearchForGPSInMetadata_DeterministicCoordinate(t *testing.T) {
	const wantLat, wantLon = 36.3506, -82.6985

	newFixture := func() *VideoMetadata {
		return &VideoMetadata{
			Filename: "clip.mov",
			Properties: map[string]string{
				"Information": `36 deg 21' 2.16" N, 82 deg 41' 54.60" W, 447.403 m Above Sea Level`,
				"Warning":     "Coordinates +11.1111-022.2222+033.333/ embedded",
				"URL":         "https://example.test/clip?t=+1-2+3",
				"Genre":       "example",
				"MajorBrand":  "qt  ",
			},
		}
	}

	// DMS-to-decimal conversion is inexact, so compare within a tolerance far
	// tighter than the gap between the competing candidates (whole degrees apart).
	const eps = 1e-6

	for i := 0; i < 300; i++ {
		vm := newFixture()
		searchForGPSInMetadata(vm)
		if math.Abs(vm.GPSLatitude-wantLat) > eps || math.Abs(vm.GPSLongitude-wantLon) > eps {
			t.Fatalf("iter %d: GPS scrape picked a different property: got (%.6f, %.6f), want (%.6f, %.6f)",
				i, vm.GPSLatitude, vm.GPSLongitude, wantLat, wantLon)
		}
	}

	// And the emitted text carries that one stable coordinate.
	vm := newFixture()
	searchForGPSInMetadata(vm)
	out := vm.ToProcessedContent()
	if !strings.Contains(out, "36.350600, -82.698500") {
		t.Errorf("expected the stable coordinate in emitted text, got:\n%s", out)
	}
}

// TestSearchForGPSInMetadata_DoesNotOverwriteContainerCoordinate asserts the
// precedence half of the fix: when the container's own atom already produced a
// complete coordinate, the property scrape must not replace it with a guess.
func TestSearchForGPSInMetadata_DoesNotOverwriteContainerCoordinate(t *testing.T) {
	vm := &VideoMetadata{
		Filename:     "clip.mov",
		GPSLatitude:  36.3506,
		GPSLongitude: -82.6985,
		Properties: map[string]string{
			"Warning":    "Coordinates +11.1111-022.2222+033.333/ embedded",
			"GPS_SOURCE": "Apple QuickTime Location",
		},
	}
	searchForGPSInMetadata(vm)
	if math.Abs(vm.GPSLatitude-36.3506) > 1e-6 || math.Abs(vm.GPSLongitude-(-82.6985)) > 1e-6 {
		t.Errorf("property scrape overwrote the authoritative container coordinate: got (%.4f, %.4f)",
			vm.GPSLatitude, vm.GPSLongitude)
	}
}

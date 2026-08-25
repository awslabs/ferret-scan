// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tagmeta

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// The pre-write gate must see a value the file spells DIFFERENTLY from the way it was reported.
//
// Measured on a real .m4a given two tags with exiftool:
//
//	card 4532-0151-1283-0366   present RAW twice: the ilst copy and the XMP packet
//	Patrick O'Connor           present RAW once (ilst), and as `Patrick O&#39;Connor` in the packet
//
// Both were reported (VISA 100, PERSON_NAME 91). Before the XMP packet was mapped as a region, the
// card's raw copy inside it made ResidualAnywhere refuse the whole file — which INCIDENTALLY also
// protected the apostrophe value. Mapping the packet removed the card's copy, the refusal went away,
// and the file was written with `Patrick O&#39;Connor` still in it: exit 0, no warning, and exiftool
// read `[XMP-dc] Title : Patrick O'Connor` straight out of the "redacted" file.
//
// So closing one leak re-opened a smaller one standing behind it. Measured before and after:
//
//	main            rc=3  REFUSED  "2 reported value(s) remain anywhere"
//	XMP span only   rc=0  WROTE    escaped value still present   <- the regression
//	with this gate  rc=3  REFUSED  "... as XML-encoded text ... (e.g. an apostrophe written as &#39;)"

// buildXMPRegion returns a buffer holding one masked ilst copy and one XMP packet, plus the region
// describing the packet — the geometry of the real failure.
func buildXMPRegion(t *testing.T, packetBody string) ([]byte, []Region) {
	t.Helper()
	buf := []byte("....ilst.©nam.data.Patrick O********")
	start := len(buf)
	buf = append(buf, []byte(`<x:xmpmeta><dc:title>`+packetBody+`</dc:title></x:xmpmeta>`)...)
	end := len(buf)
	return buf, []Region{{Start: start, End: end, Label: "MP4 XMP", XMLText: true}}
}

// TestResidualEncodedCatchesWhatResidualAnywhereCannot is the reported defect.
func TestResidualEncodedCatchesWhatResidualAnywhereCannot(t *testing.T) {
	buf, regions := buildXMPRegion(t, "Patrick O&#39;Connor")
	matches := []detector.Match{{Text: "Patrick O'Connor", Type: "PERSON_NAME"}}

	// The premise: the raw gate genuinely cannot see this. If it could, the new gate would be
	// redundant and this test would be asserting nothing.
	if got := ResidualAnywhere(buf, matches); got != 0 {
		t.Fatalf("ResidualAnywhere = %d, want 0 — the fixture must be invisible to the raw search, "+
			"or this test does not exercise the gap", got)
	}

	if got := ResidualEncoded(buf, regions, matches); got != 1 {
		t.Errorf("ResidualEncoded = %d, want 1. The value is in the packet as `Patrick O&#39;Connor`; "+
			"missing it means the file is written and reported clean with the name still readable.", got)
	}
}

// TestResidualEncodedDoesNotDoubleCountARawHit keeps the refusal message truthful.
//
// A raw occurrence is ResidualAnywhere's to report. Counting it here as well would say "2 reported
// value(s) remain" for one surviving byte range, and an operator reads that as two distinct
// survivals in two distinct places.
func TestResidualEncodedDoesNotDoubleCountARawHit(t *testing.T) {
	buf, regions := buildXMPRegion(t, "Patrick O'Connor") // raw, not encoded
	matches := []detector.Match{{Text: "Patrick O'Connor", Type: "PERSON_NAME"}}

	if got := ResidualAnywhere(buf, matches); got != 1 {
		t.Fatalf("ResidualAnywhere = %d, want 1: the raw gate owns this case", got)
	}
	if got := ResidualEncoded(buf, regions, matches); got != 0 {
		t.Errorf("ResidualEncoded = %d, want 0 — a raw hit is already reported by ResidualAnywhere", got)
	}
}

// TestResidualEncodedIgnoresBinaryRegions is the other direction, and it is not cosmetic.
//
// Decoding a binary region would invent values out of bytes that merely look like a reference, so a
// region must opt in. A caller that forgets XMLText gets the old behaviour rather than a surprise.
func TestResidualEncodedIgnoresBinaryRegions(t *testing.T) {
	buf, regions := buildXMPRegion(t, "Patrick O&#39;Connor")
	matches := []detector.Match{{Text: "Patrick O'Connor", Type: "PERSON_NAME"}}

	binary := []Region{{Start: regions[0].Start, End: regions[0].End, Label: "MP4 udta"}} // XMLText false
	if got := ResidualEncoded(buf, binary, matches); got != 0 {
		t.Errorf("ResidualEncoded = %d over a region not marked XMLText, want 0", got)
	}
}

// TestResidualEncodedBoundsAndEmptyValues covers the inputs a caller can hand it by accident.
func TestResidualEncodedBoundsAndEmptyValues(t *testing.T) {
	buf, regions := buildXMPRegion(t, "Patrick O&#39;Connor")

	if got := ResidualEncoded(buf, regions, []detector.Match{{Text: "", Type: "EMPTY"}}); got != 0 {
		t.Errorf("an empty value counted as residual (%d); it would match everywhere", got)
	}
	for _, bad := range []Region{
		{Start: -1, End: 10, XMLText: true},
		{Start: 5, End: len(buf) + 100, XMLText: true},
		{Start: 10, End: 10, XMLText: true},
		{Start: 20, End: 5, XMLText: true},
	} {
		matches := []detector.Match{{Text: "Patrick O'Connor", Type: "PERSON_NAME"}}
		if got := ResidualEncoded(buf, []Region{bad}, matches); got != 0 {
			t.Errorf("out-of-bounds region %+v returned %d rather than being skipped", bad, got)
		}
	}
}

// TestResidualEncodedCountsOncePerValue mirrors ResidualAnywhere's contract.
func TestResidualEncodedCountsOncePerValue(t *testing.T) {
	body := "Patrick O&#39;Connor and again Patrick O&#x27;Connor"
	buf, regions := buildXMPRegion(t, body)
	matches := []detector.Match{{Text: "Patrick O'Connor", Type: "PERSON_NAME"}}

	if got := ResidualEncoded(buf, regions, matches); got != 1 {
		t.Errorf("ResidualEncoded = %d for one value in two spellings, want 1: the count is of "+
			"VALUES that survived, not of occurrences", got)
	}
}

// TestResidualEncodedSurvivesABareAmpersandRun is the work bound for the CALLER, asserted by shape.
//
// The decoder's own termination behaviour is pinned in internal/xmlref, where it now lives. What
// matters here is that a packet made of attacker-supplied bare ampersands does not make the gate
// invent a residual value out of bytes that merely look like references.
func TestResidualEncodedSurvivesABareAmpersandRun(t *testing.T) {
	run := strings.Repeat("&", 200000)
	buf, regions := buildXMPRegion(t, run)
	matches := []detector.Match{{Text: "Patrick O'Connor", Type: "PERSON_NAME"}}
	if got := ResidualEncoded(buf, regions, matches); got != 0 {
		t.Errorf("ResidualEncoded = %d on a packet of bare ampersands, want 0", got)
	}
}

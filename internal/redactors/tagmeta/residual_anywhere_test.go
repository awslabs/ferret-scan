// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tagmeta

import (
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// The pre-write gate must see a value that survives OUTSIDE the rewritten spans.
//
// Residual searches only the regions it is handed, and those regions are the spans the overwrite
// pass just rewrote — so it is structurally unable to see the one failure mode that matters. It
// therefore returned 0 for a file that still contained a reported credit card number, and the audio
// redactor wrote that file and reported success (#449).
//
// Measured on a real .m4a: exiftool writes Artist to BOTH moov/udta/meta/ilst/©ART/data (mapped,
// overwritten) AND an XMP packet (unmapped, untouched). Offsets 10973 and 11337; the mapped span
// covered [10892,11268).
//
// This test reproduces that geometry rather than the whole file: one occurrence inside the region,
// one outside, and the inside one already overwritten.
func TestResidualAnywhereSeesWhatResidualCannot(t *testing.T) {
	value := "4532-0151-1283-0366"

	// A buffer shaped like the real failure: the in-region copy is overwritten, an out-of-region
	// copy survives.
	buf := make([]byte, 0, 256)
	buf = append(buf, []byte("....ilst.©ART.data.")...)      // 19 bytes of container noise
	regionStart := len(buf)                                  //
	buf = append(buf, []byte("card ****-****-****-0366")...) // the OVERWRITTEN copy
	regionEnd := len(buf)                                    //
	buf = append(buf, []byte("...<x:xmpmeta><tiff:Artist>card ")...)
	buf = append(buf, []byte(value)...) // the SURVIVING copy, outside the region
	buf = append(buf, []byte("</tiff:Artist></x:xmpmeta>")...)

	regions := []Region{{Start: regionStart, End: regionEnd, Label: "MP4 udta"}}
	matches := []detector.Match{{Text: value, Type: "VISA"}}

	if got := Residual(buf, regions, matches); got != 0 {
		t.Fatalf("test setup: Residual should be blind here, got %d — the region no longer excludes "+
			"the surviving copy, so this test is not reproducing #449", got)
	}
	if got := ResidualAnywhere(buf, matches); got != 1 {
		t.Errorf("ResidualAnywhere = %d, want 1: a value surviving outside the rewritten spans is "+
			"exactly what the pre-write gate exists to catch, and missing it means writing a file "+
			"that looks redacted and is not", got)
	}
}

// A fully cleaned buffer must pass, or the gate refuses every file and media redaction stops working.
//
// This is the other direction, and it is not hypothetical: a whole-buffer search is strictly
// stricter, so the risk of the fix is refusing files that were being redacted correctly. Measured on
// a real .m4a carrying only a Comment tag — one occurrence, inside the mapped span — the redactor
// still writes the file and the value is gone from the bytes.
func TestResidualAnywherePassesACleanedBuffer(t *testing.T) {
	value := "4532-0151-1283-0366"
	buf := []byte("....ilst.©cmt.data.card ****-****-****-0366....moov....")
	matches := []detector.Match{{Text: value, Type: "VISA"}}

	if got := ResidualAnywhere(buf, matches); got != 0 {
		t.Errorf("ResidualAnywhere = %d on a buffer with no surviving value, want 0: a gate that "+
			"refuses a correctly redacted file trades a leak for losing redaction entirely", got)
	}
}

// Wide encodings must be searched, exactly as the overwrite writes them.
//
// A check that looked only for the narrow form would pass on a value stored as UTF-16, which is how
// several container formats store text. Residual already does this; the replacement must not be
// weaker than the thing it replaces.
func TestResidualAnywhereSearchesWideEncodings(t *testing.T) {
	value := "449-87-4100"

	for _, tc := range []struct {
		name string
		buf  []byte
	}{
		{"utf-16 le", append([]byte("prefix"), UTF16LE(value)...)},
		{"utf-16 be", append([]byte("prefix"), UTF16BE(value)...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			matches := []detector.Match{{Text: value, Type: "SSN"}}
			if got := ResidualAnywhere(tc.buf, matches); got != 1 {
				t.Errorf("ResidualAnywhere = %d, want 1: a value stored in %s survived a check that "+
					"only looked for the narrow form", got, tc.name)
			}
		})
	}
}

// Counted per MATCH, not per occurrence, so the number is the count of values still exposed.
//
// Two surviving copies of one value is one exposed value, and reporting 2 would overstate it in a
// message an operator reads. Three different values surviving is three.
func TestResidualAnywhereCountsValuesNotOccurrences(t *testing.T) {
	buf := []byte("aaa 449-87-4100 bbb 449-87-4100 ccc 4532-0151-1283-0366 ddd")
	matches := []detector.Match{
		{Text: "449-87-4100", Type: "SSN"},
		{Text: "4532-0151-1283-0366", Type: "VISA"},
	}
	if got := ResidualAnywhere(buf, matches); got != 2 {
		t.Errorf("ResidualAnywhere = %d, want 2 (two distinct values, one of them twice)", got)
	}
}

// An empty match text must not count, and must not match everything.
//
// bytes.Contains with an empty needle is TRUE for any buffer, so an empty Text would make the gate
// refuse every file — the same class of failure as the guard being blind, in the opposite direction.
func TestResidualAnywhereIgnoresEmptyValues(t *testing.T) {
	buf := []byte("nothing sensitive here")
	matches := []detector.Match{{Text: "", Type: "EMPTY"}}

	if got := ResidualAnywhere(buf, matches); got != 0 {
		t.Errorf("ResidualAnywhere = %d for an empty match text, want 0: an empty needle matches "+
			"every buffer and would refuse every file", got)
	}
	if got := ResidualAnywhere(nil, matches); got != 0 {
		t.Errorf("ResidualAnywhere = %d on a nil buffer, want 0", got)
	}
	if got := ResidualAnywhere(buf, nil); got != 0 {
		t.Errorf("ResidualAnywhere = %d with no matches, want 0", got)
	}
}

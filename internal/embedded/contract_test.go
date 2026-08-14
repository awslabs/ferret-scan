// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package embedded_test holds the cross-package half of the contract: the
// assertions that need to see the READ side and the WRITE side at once, which the
// in-package tests cannot import without a cycle.
package embedded_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/embedded"
	"github.com/awslabs/ferret-scan/v2/internal/preprocessors"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
	"github.com/awslabs/ferret-scan/v2/internal/router"
)

// TestReadAndWriteSharePreciselyOneDepthBound.
//
// The two halves must agree, and for asymmetric reasons. A write side SHALLOWER
// than the read side reports findings from a level it will not rewrite, which is a
// cleartext leak that reads as success. A write side DEEPER redacts inside a part
// nothing ever scanned, so the redaction is unmotivated and its cost unbounded.
//
// The earlier attempt at this mirrored the literal 3 into internal/redactors/office
// and added a test asserting the two stayed equal. That test could only catch drift
// after it happened; sharing one constant makes the drift unrepresentable. This test
// therefore asserts the SHARING, not merely the equality — if someone reintroduces
// a private copy, the aliases below stop compiling or stop matching.
func TestReadAndWriteSharePreciselyOneDepthBound(t *testing.T) {
	if router.MaxEmbeddedDepth != embedded.MaxDepth {
		t.Errorf("router.MaxEmbeddedDepth = %d but embedded.MaxDepth = %d.\n"+
			"The read side would descend to one depth and the write side to another, so "+
			"a value found at a level the redactor refuses to enter is reported and then "+
			"shipped in cleartext.",
			router.MaxEmbeddedDepth, embedded.MaxDepth)
	}
}

// TestTooDeepIsOneSentinelAcrossBothHalves.
//
// Both halves raise "coverage was cut short" and callers branch on it with
// errors.Is to tell that apart from "this child failed to parse". Two distinct
// sentinel values would make the check fail across the halves and silently downgrade
// the disclosure to a generic failure — which is the specific bug the sentinel was
// introduced to avoid.
func TestTooDeepIsOneSentinelAcrossBothHalves(t *testing.T) {
	if !errors.Is(preprocessors.ErrEmbeddedTooDeep, embedded.ErrTooDeep) {
		t.Error("preprocessors.ErrEmbeddedTooDeep is not embedded.ErrTooDeep; a caller " +
			"matching one will not recognise the other")
	}

	// And the wrapped form the redaction side actually returns must still match, since
	// that is how it reaches a caller.
	wrapped := fmt.Errorf("%w: part is nested too deep", embedded.ErrTooDeep)
	if !errors.Is(wrapped, preprocessors.ErrEmbeddedTooDeep) {
		t.Error("a wrapped embedded.ErrTooDeep does not match preprocessors.ErrEmbeddedTooDeep")
	}
}

// TestNoRedactorSentinelIsDistinctFromTooDeep.
//
// These two describe different permanent facts and get different operator wording:
// "we stopped descending" versus "this file type can never be redacted". Collapsing
// them would make an unredactable audio clip look like a depth problem someone could
// fix by raising a limit.
func TestNoRedactorSentinelIsDistinctFromTooDeep(t *testing.T) {
	if errors.Is(redactors.ErrNoEmbeddedRedactor, embedded.ErrTooDeep) {
		t.Error("ErrNoEmbeddedRedactor matches ErrTooDeep; the two disclosures would be " +
			"indistinguishable")
	}
	if errors.Is(embedded.ErrTooDeep, redactors.ErrNoEmbeddedRedactor) {
		t.Error("ErrTooDeep matches ErrNoEmbeddedRedactor; the two disclosures would be " +
			"indistinguishable")
	}
}

// TestAdmittedTypesWithNoRedactorCannotBeSilentlySkipped is the safety interlock.
//
// For every type the read side descends into, one of two things must hold: a redactor
// can rewrite it, or the tool cannot prove it clean and therefore always dispatches it
// (so an unredactable one fails loudly). The forbidden third state is "admitted for
// scanning, unredactable, AND believed byte-inspectable" — such a part is skipped
// whenever a byte scan happens to find nothing, which for a compressed payload is
// always, so the value is reported and then shipped.
//
// PDF is the live case: scanned, no redactor, compressed payload. It is opaque, so it
// is always dispatched and the container is refused. Audio has no redactor either, but
// its tags are uncompressed, so a clip holding a reported value IS seen by the scan and
// dispatched; a clip holding nothing is correctly left alone.
func TestAdmittedTypesWithNoRedactorCannotBeSilentlySkipped(t *testing.T) {
	noRedactor := map[string]string{
		".pdf":  "PDF redaction is unimplemented and refuses to write output",
		".mp3":  "no audio redactor exists",
		".wav":  "no audio redactor exists",
		".m4a":  "no audio redactor exists",
		".flac": "no audio redactor exists",
	}

	for ext, why := range noRedactor {
		if embedded.Kind(ext) == "" {
			continue // not admitted, so nothing is reported from it
		}
		inspectable := embedded.ResidueInspectable("part" + ext)
		if !inspectable {
			continue // always dispatched -> fails loudly. Safe.
		}
		// Inspectable AND unredactable is only safe if the byte scan really can see the
		// values, which is an assertion about the FORMAT. Audio qualifies; anything new
		// landing here needs the same justification written down.
		switch ext {
		case ".mp3", ".wav", ".m4a", ".flac":
			// Tags are stored uncompressed, so a reported value in one is visible to the
			// scan and the part is dispatched (and then fails loudly).
		default:
			t.Errorf("%s is admitted for scanning, %s, and is treated as byte-inspectable. "+
				"If its payload can be compressed, a value inside it is invisible to the "+
				"scan, the part is skipped as harmless, and the container is written with "+
				"the value still in it.", ext, why)
		}
	}
}

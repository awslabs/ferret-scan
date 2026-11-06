// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phone

import (
	"strings"
	"testing"
)

// TestNoDigitOnlyKeyword: the evidence vocabulary is words. A digit keyword can only ever match the
// digits of a value: "800" inside "2972800405" (TestNoCreditFromTheMatchItself).
func TestNoDigitOnlyKeyword(t *testing.T) {
	for _, list := range [][]string{phoneEvidenceTokens, phoneEvidencePhrases, genericPhoneLabelWords} {
		for _, kw := range list {
			if strings.IndexFunc(kw, func(r rune) bool { return r >= '0' && r <= '9' }) >= 0 {
				t.Errorf("evidence keyword %q contains a digit", kw)
			}
			if kw != strings.ToLower(kw) {
				t.Errorf("evidence keyword %q is not lower-case; lines are matched lower-cased", kw)
			}
		}
	}
}

// TestCountryStateInternals pins the two outcomes evidence_test.go cannot reach through a scan: a
// format the check rejects keeps its -10 exactly as before (the emission base agrees with the
// score), and a pattern the check has no rule for reports no result instead of a pass.
func TestCountryStateInternals(t *testing.T) {
	v := NewValidator()
	// A format the check rejects keeps its -10, scored as before: the emission base agrees.
	conf, emissionBase, checks, state := v.calculateConfidence("(297) 201-0001 x12")
	if state != countryInvalid || checks["valid_country"] || conf != emissionBase {
		t.Errorf("12-digit US/CA match: state %v, valid_country %v, confidence %v vs emission base %v; want invalid, false, equal",
			state, checks["valid_country"], conf, emissionBase)
	}
	// A pattern with no rule reports no check rather than a pass.
	if s := v.countryFormat("12345678", phonePattern{country: "Unknown"}); s != countryNotChecked {
		t.Errorf("unknown pattern: state %v, want countryNotChecked", s)
	}
	if s := v.countryFormat("44207946", phonePattern{country: "UK"}); s != countryNotChecked {
		t.Errorf("UK pattern without +44/0: state %v, want countryNotChecked", s)
	}
	_, _, checks, _ = v.calculateConfidenceWithPattern("2972010001", phonePattern{country: "Unknown"})
	if _, reported := checks["valid_country"]; reported {
		t.Errorf("unknown pattern reports valid_country=%v; an unchecked rule must not report a result", checks["valid_country"])
	}
}

// TestNANPPossible pins the rule: area NXX not N11, exchange NXX.
func TestNANPPossible(t *testing.T) {
	for d, want := range map[string]bool{
		"2972010001": true, "2125550173": true, "8002010001": true, "9002020000": true,
		"1972010001": false, "0972010001": false, "2112010001": false, "9111020000": false,
		"2970010001": false, "2971010001": false, "297201000": false,
	} {
		if got := nanpPossible(d); got != want {
			t.Errorf("nanpPossible(%q) = %v, want %v", d, got, want)
		}
	}
}

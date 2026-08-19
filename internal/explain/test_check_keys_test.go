// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package explain

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// verdict() and rationale() used to consult exactly one check key, "not_test",
// which only creditcard sets. Every other validator records its test judgement
// under a different name, so --explain contradicted itself: the rendered check
// list showed `Not Test Number: false` while the verdict on the same finding read
// `likely_real` and the drafted reason said "REVIEW BEFORE SUPPRESSING".
//
// These tests pin the whole family. See testCheckKeys.

func matchWithChecks(conf float64, checks map[string]bool) detector.Match {
	return detector.Match{
		Type:       "PHONE",
		Confidence: conf,
		Filename:   "/srv/app/contacts.txt", // not a test path, so inTestFile is false
		Metadata:   map[string]any{"validation_checks": checks},
	}
}

func TestVerdictHonoursEveryValidatorsTestCheckKey(t *testing.T) {
	s := NewSignalSynthesizer()

	for _, key := range testCheckKeys {
		t.Run(key, func(t *testing.T) {
			// Below MEDIUM with the test check FAILED must read likely_test.
			got := s.Explain(matchWithChecks(15, map[string]bool{key: false}))
			if got.Verdict != VerdictLikelyTest {
				t.Errorf("checks[%q]=false at 15%%: verdict = %q, want %q -- this key is "+
					"not being consulted, so the validator's own test judgement is invisible "+
					"to --explain", key, got.Verdict, VerdictLikelyTest)
			}
			if !strings.Contains(got.Rationale, "known test/placeholder pattern") {
				t.Errorf("checks[%q]=false: rationale omits the test signal: %q", key, got.Rationale)
			}
			if strings.Contains(got.DraftSuppressReason, "REVIEW BEFORE SUPPRESSING") {
				t.Errorf("checks[%q]=false: drafted reason still says REVIEW BEFORE "+
					"SUPPRESSING: %q", key, got.DraftSuppressReason)
			}

			// The same key PASSING must not manufacture a test signal.
			got = s.Explain(matchWithChecks(15, map[string]bool{key: true}))
			if got.Verdict == VerdictLikelyTest {
				t.Errorf("checks[%q]=true at 15%%: verdict = %q, want anything but %q -- a "+
					"passing check must not be read as a test signal",
					key, got.Verdict, VerdictLikelyTest)
			}
		})
	}
}

// The existing guarantees must survive: a HIGH finding is never talked down, and
// a failed test check does not by itself demote a MEDIUM one. The confidence
// ceilings in the validators are what put reserved values below MEDIUM; the
// explainer only glosses the score it is given.
func TestTestCheckKeysDoNotOverrideConfidence(t *testing.T) {
	s := NewSignalSynthesizer()

	if got := s.Explain(matchWithChecks(95, map[string]bool{"not_test_number": false})); got.Verdict != VerdictLikelyReal {
		t.Errorf("HIGH finding with a failed test check: verdict = %q, want %q -- the "+
			"explainer must never talk a reviewer out of a high-confidence finding",
			got.Verdict, VerdictLikelyReal)
	}
	if got := s.Explain(matchWithChecks(70, map[string]bool{"not_test_number": false})); got.Verdict != VerdictLikelyReal {
		t.Errorf("MEDIUM finding with a failed test check: verdict = %q, want %q -- the "+
			"test signal only applies below MEDIUM", got.Verdict, VerdictLikelyReal)
	}
}

func TestHasFailedTestCheck(t *testing.T) {
	if hasFailedTestCheck(nil) {
		t.Error("hasFailedTestCheck(nil) = true, want false")
	}
	if hasFailedTestCheck(map[string]bool{}) {
		t.Error("hasFailedTestCheck(empty) = true, want false")
	}
	if hasFailedTestCheck(map[string]bool{"luhn": false, "valid_format": false}) {
		t.Error("unrelated failing checks must not read as a test signal")
	}
	if !hasFailedTestCheck(map[string]bool{"luhn": true, "not_example": false}) {
		t.Error("a failing test key alongside passing checks must still be a test signal")
	}
}

// testCheckKeys must stay in step with the validators. A validator that adds a
// new test-check key and forgets this list silently loses its --explain signal,
// which is the exact defect these tests were written for -- so the list is
// checked against the source rather than trusted.
//
// Kept as a list assertion rather than a source scan: internal/explain must not
// import the validators (they import detector, not the other way round), and a
// filesystem walk from a unit test is fragile across build environments. The
// comment on each entry names its owner so a grep can verify by hand:
//
//	grep -rhoE 'checks\["not_[a-z_]*"\]' internal/validators/*/validator.go | sort -u
func TestTestCheckKeysAreDistinctAndNonEmpty(t *testing.T) {
	seen := map[string]bool{}
	for _, k := range testCheckKeys {
		if k == "" {
			t.Error("testCheckKeys contains an empty key")
		}
		if !strings.HasPrefix(k, "not_") {
			t.Errorf("testCheckKeys entry %q does not follow the not_* convention, so a "+
				"false value under it does not mean what this list assumes", k)
		}
		if seen[k] {
			t.Errorf("testCheckKeys contains %q twice", k)
		}
		seen[k] = true
	}
	if len(testCheckKeys) < 7 {
		t.Errorf("testCheckKeys has %d entries; the validators define at least 7 distinct "+
			"test-check keys, and a missing one is a silently dropped signal", len(testCheckKeys))
	}
}

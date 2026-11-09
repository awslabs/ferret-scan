// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package help

import (
	"strings"
	"testing"
)

// TestCheckHelpPrintsNoSharedKeywordWeights: the Contextual Analysis section of `--help <check>` is
// rendered here for every check, and it used to print one set of weights for all of them: "up to +25%
// or -50% adjustment", "+5% each" for a positive keyword and "-10% each" for a negative one. No check
// scored that way: VIN adds 25 and takes 15 per keyword within +/-50, PHONE adds 15 and takes 35
// within -80/+40. The section now lists the keywords and leaves the weights to the check's own text.
func TestCheckHelpPrintsNoSharedKeywordWeights(t *testing.T) {
	h := NewSystem(true)
	h.RegisterProvider(fakeProvider{info: CheckInfo{
		Name:                "PHONE",
		ShortDescription:    "desc for PHONE",
		DetailedDescription: "Each phone word adds 15; each negative word costs 35.",
		PositiveKeywords:    []string{"phone", "tel"},
		NegativeKeywords:    []string{"test", "example"},
	}})

	out := captureStdout(t, func() {
		if !h.ShowCheckHelp("PHONE") {
			t.Fatal("ShowCheckHelp did not find the registered check")
		}
	})

	for _, stale := range []string{"+25% or -50%", "+5% each", "-10% each"} {
		if strings.Contains(out, stale) {
			t.Errorf("check help still prints the shared weight %q, which is wrong for most checks:\n%s",
				stale, out)
		}
	}
	for _, want := range []string{
		"Contextual Analysis",
		"Positive keywords (raise confidence): phone, tel",
		"Negative keywords (lower confidence): test, example",
		"Each phone word adds 15; each negative word costs 35.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("check help does not contain %q:\n%s", want, out)
		}
	}
}

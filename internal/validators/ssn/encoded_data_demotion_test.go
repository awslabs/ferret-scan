// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ssn

import (
	"context"
	"strings"
	"testing"
)

// isEncodedData used to be consumed as a hard `continue`, and both of its tests
// count things ANYWHERE on the line. That made a line-global, author-controlled
// heuristic able to delete a value that had already passed structural validation.
//
// Deleting it is the worst outcome this tool has: only reported findings are handed
// to the redactor, so an erased finding is left in cleartext in the "redacted"
// output, and the run still exits 0. Measured before the change, each of these a
// valid SSN behind an explicit label:
//
//	"Employee SSN: 130-07-5728 1 2 ... 12"  -> HIGH 100
//	"Employee SSN: 130-07-5728 1 2 ... 13"  -> NO FINDINGS   (>15 number groups)
//	"Employee SSN: 130-07-5728"             -> HIGH 100
//	"130-07-5728 1 2 3 4"                   -> NO FINDINGS   (>85% numeric)
//
// One extra number is the entire difference, and no attacker is needed: a log line,
// a CSV row of counters, or an ID printed beside a few figures all reach it.
//
// These tests pin the demotion. There was no coverage of this heuristic's EFFECT
// before — the only mention in the suite is a comment — which is how the veto
// shipped and survived.

func findSSN(t *testing.T, content string) (found bool, confidence float64) {
	t.Helper()
	v := NewValidator()
	matches, err := v.ValidateContentCtx(context.Background(), content, "test.txt")
	if err != nil {
		t.Fatalf("ValidateContentCtx: %v", err)
	}
	for _, m := range matches {
		if strings.Contains(m.Text, "5728") || strings.Contains(m.Text, "4100") {
			return true, m.Confidence
		}
	}
	return false, 0
}

// The regression, both triggers. A labelled SSN must survive any amount of
// surrounding numeric noise.
func TestEncodedDataDemotesRatherThanDeletes(t *testing.T) {
	cases := []struct {
		desc    string
		content string
	}{
		{
			desc:    "16 number groups, the >15 trigger",
			content: "Employee SSN: 130-07-5728 1 2 3 4 5 6 7 8 9 10 11 12 13\n",
		},
		{
			desc:    "far past the trigger",
			content: "Employee SSN: 130-07-5728 " + strings.Repeat("7 ", 40) + "\n",
		},
		{
			desc:    "over 85% numeric with 5 number groups",
			content: "130-07-5728 1 2 3 4\n",
		},
		{
			desc:    "over 85% numeric, no label at all",
			content: "130-07-5728 11 22 33 44 55\n",
		},
		{
			desc:    "a real SSN in a row of counters",
			content: "130-07-5728 4 17 92 3 88 12 45 6 231 9 14 77 2 58 31 6\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			found, conf := findSSN(t, tc.content)
			if !found {
				t.Fatalf("the SSN was DELETED (%s).\ninput: %q\n"+
					"A value that passed structural validation must never be erased by a "+
					"line-global heuristic: an unreported finding is never redacted, so it "+
					"stays in cleartext in the output while the run exits 0.",
					tc.desc, tc.content)
			}
			// The canonical hyphenated form must remain visible under the default
			// confidence filter. Anything below MEDIUM is filtered out of the review
			// surface, which for this shape is a deletion in all but name.
			if conf < encodedDataStrongFloor {
				t.Errorf("confidence %.1f is below the %.1f floor.\ninput: %q\n"+
					"The canonical XXX-XX-XXXX form with a valid area number is what an SSN "+
					"looks like; no quantity of surrounding digits should push it out of the "+
					"default view.", conf, encodedDataStrongFloor, tc.content)
			}
		})
	}
}

// The complement, and the reason this is a DEMOTION and not simply removing the
// heuristic: a dense numeric line must still score lower than the same value in
// clean labelled prose. Without this, the fix would be "delete the heuristic",
// which reintroduces the false positives it exists to suppress.
func TestEncodedDataStillCostsConfidence(t *testing.T) {
	// A weak shape — bare 9 digits, no label — is where the penalty must bite. The
	// hyphenated form is protected by the floor and so is excluded here on purpose.
	clean := "449874100\n"
	dense := "449874100 " + strings.Repeat("5 ", 20) + "\n"

	_, cleanConf := findSSN(t, clean)
	denseFound, denseConf := findSSN(t, dense)

	if !denseFound {
		t.Fatal("the bare candidate was deleted on a dense line; the demotion must " +
			"lower confidence, not erase the finding")
	}
	if denseConf >= cleanConf {
		t.Errorf("dense line scored %.1f, clean line %.1f — the encoded-data signal must "+
			"still COST confidence, or this change is just deleting the heuristic and "+
			"restoring the false positives it exists to suppress", denseConf, cleanConf)
	}
	t.Logf("bare candidate: clean %.1f -> dense %.1f (penalty %.1f)",
		cleanConf, denseConf, cleanConf-denseConf)
}

// The two control cases from the measurement above: lines just BELOW each trigger
// must be untouched, so the change cannot be credited for a difference that was
// never there.
func TestEncodedDataControlsUnchanged(t *testing.T) {
	controls := map[string]string{
		"15 number groups, below the >15 trigger": "Employee SSN: 130-07-5728 1 2 3 4 5 6 7 8 9 10 11 12\n",
		"labelled SSN alone":                      "Employee SSN: 130-07-5728\n",
		"labelled SSN in prose":                   "The employee SSN is 130-07-5728 per the HR record.\n",
	}
	for desc, content := range controls {
		t.Run(desc, func(t *testing.T) {
			found, conf := findSSN(t, content)
			if !found {
				t.Fatalf("control case lost its finding: %q", content)
			}
			if conf < 90 {
				t.Errorf("control confidence dropped to %.1f (want HIGH >= 90): %q — "+
					"the demotion must not reach lines the heuristic never flagged",
					conf, content)
			}
		})
	}
}

// A structurally INVALID candidate must still be rejected on a dense line. The
// demotion changes what an encoded-data verdict costs, not what counts as an SSN.
func TestEncodedDataDoesNotAdmitInvalidValues(t *testing.T) {
	for _, invalid := range []string{
		"000-12-3456", // area 000
		"666-12-3456", // area 666
		"900-12-3456", // area 900+
		"123-00-4567", // group 00
		"123-45-0000", // serial 0000
	} {
		content := invalid + " " + strings.Repeat("3 ", 20) + "\n"
		v := NewValidator()
		matches, err := v.ValidateContentCtx(context.Background(), content, "test.txt")
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range matches {
			if m.Text == invalid {
				t.Errorf("structurally invalid %q was reported on a dense line; the "+
					"demotion must not weaken validation", invalid)
			}
		}
	}
}

// The denylisted test SSNs must still be dropped. That drop happens after context
// analysis and is a deliberate exception to demote-never-delete: those values are
// not PII, so removing them costs nothing and reporting them at any confidence is
// a false positive.
func TestEncodedDataDoesNotResurrectTestSSNs(t *testing.T) {
	for _, fake := range []string{"123-45-6789", "111-11-1111", "000-00-0000"} {
		content := "SSN " + fake + " " + strings.Repeat("2 ", 20) + "\n"
		v := NewValidator()
		matches, err := v.ValidateContentCtx(context.Background(), content, "test.txt")
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range matches {
			if m.Text == fake {
				t.Errorf("denylisted test SSN %q was reported; the demotion must not "+
					"resurrect known non-PII values", fake)
			}
		}
	}
}

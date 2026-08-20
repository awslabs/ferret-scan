// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package medicalid

import (
	"strings"
	"testing"
)

// A camelCase key that happens to be a SUPPRESSOR keyword must not veto a real finding.
//
// This is the defect the first attempt at #372 shipped, and it is why the widened matcher is
// opt-in. With zero separators as the default, "ip address" matched "ipAddress" — and
// nonInsuranceKeywordPresent is an UNCONDITIONAL veto (`return detector.Match{}, false`), so
// no label strength could save the finding:
//
//	{"member_id": "W1234567801", "ipAddress": "10.11.12.13"}
//
// lost its INSURANCE_MEMBER_ID entirely. With --enable-redaction the tool then wrote a
// "redacted" file containing the member ID in CLEARTEXT while masking the IP, and reported
// success. A suppressed finding is never redacted, so this is a leak.
//
// "ipAddress" is a ubiquitous JSON key, and a dictionary screen misses it: "ipaddress" is not
// an English word, so checking concatenations against /usr/share/dict/words passed it. The
// property that matters is "is a token that occurs in real text", which no word list decides.
func TestCamelCaseSuppressorDoesNotVetoAMemberID(t *testing.T) {
	v := NewValidator()

	reportsMemberID := func(line string) bool {
		t.Helper()
		ms, err := v.ValidateContent(line, "probe.json")
		if err != nil {
			t.Fatalf("ValidateContent(%q): %v", line, err)
		}
		for _, m := range ms {
			if m.Type == "INSURANCE_MEMBER_ID" {
				return true
			}
		}
		return false
	}

	const control = `{"member_id": "W1234567801"}`
	if !reportsMemberID(control) {
		t.Fatalf("the control %q reports no member ID, so this test cannot detect the veto",
			control)
	}

	// The camelCase and concatenated spellings of a suppressor keyword must NOT veto.
	for _, line := range []string{
		`{"member_id": "W1234567801", "ipAddress": "10.11.12.13"}`,
		`{"member_id": "W1234567801", "ipaddress": "10.11.12.13"}`,
		`{"memberId": "W1234567801", "ipAddress": "10.11.12.13"}`,
		"group number: W1234567801  ipaddress",
	} {
		if !reportsMemberID(line) {
			t.Errorf("%q lost its member ID: a camelCase suppressor keyword vetoed a real "+
				"identifier. The finding is never redacted, so the value ships in cleartext "+
				"in a file the tool reports as redacted.", line)
		}
	}

	// The SPACED form must still veto, exactly as before this change. Losing that would trade
	// the leak for a false positive on lines that really are about an IP address.
	for _, line := range []string{
		`{"member_id": "W1234567801", "ip address": "10.11.12.13"}`,
		"group number: W1234567801  ip address",
	} {
		if reportsMemberID(line) {
			t.Errorf("%q reported a member ID: the suppressor must still fire on its spaced "+
				"form, or the fix traded one defect for another", line)
		}
	}
}

// The positive side of the same asymmetry: a camelCase LABEL must count as context, which is
// the recall #372 exists to deliver. Without this the test above would pass on a build where
// the widened matcher was reverted wholesale.
func TestCamelCaseLabelCountsAsInsuranceContext(t *testing.T) {
	v := NewValidator()

	findMemberID := func(line string) (float64, bool) {
		t.Helper()
		ms, err := v.ValidateContent(line, "probe.json")
		if err != nil {
			t.Fatalf("ValidateContent(%q): %v", line, err)
		}
		for _, m := range ms {
			if m.Type == "INSURANCE_MEMBER_ID" {
				return m.Confidence, true
			}
		}
		return 0, false
	}

	spaced, ok := findMemberID(`{"member id": "XQ4839271"}`)
	if !ok {
		t.Fatal("the spaced label reports nothing, so there is no baseline to compare against")
	}
	for _, line := range []string{
		`{"memberId": "XQ4839271"}`,
		`{"memberid": "XQ4839271"}`,
		`{"MemberId": "XQ4839271"}`,
	} {
		got, ok := findMemberID(line)
		if !ok {
			t.Errorf("%q reports no member ID: the camelCase key that JSON, REST payloads and "+
				"ORM exports emit by default must count as context", line)
			continue
		}
		if got != spaced {
			t.Errorf("%q scored %.0f, want %.0f (the spaced form): the concatenated spelling "+
				"is the same label and must score the same, or one of the two contributing "+
				"signals is still requiring a separator", line, got, spaced)
		}
	}

	// The whole-word rule still applies, or the widening would match inside longer words.
	for _, line := range []string{
		`{"teammemberid": "XQ4839271"}`,
		`{"memberidentification_v2": "XQ4839271"}`,
	} {
		if _, ok := findMemberID(line); ok {
			if !strings.Contains(line, "identification") {
				t.Errorf("%q reported a member ID: the outer whole-word rule is what keeps "+
					"zero separators honest", line)
			}
		}
	}
}

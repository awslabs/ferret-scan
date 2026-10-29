// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package medicalid

import "testing"

// Every value below passes the CMS NPI-Luhn check, so the check digit is not what any
// of these tests exercises: 1751328000 is 2025-07-01T00:00:00Z, 1735689600 is
// 2025-01-01T00:00:00Z, and 1761609639 is 2025-10-28T00:00:39Z (not a round number, so
// the rule cannot be a statement about trailing zeros).

// TestNPI_UnixSecondsNotReported pins #806: a Unix timestamp whose own label or unit
// says it is a time is not an NPI. Every case was reported at 90 or 100 before the
// fix; the issue's own line was 90 HIGH.
func TestNPI_UnixSecondsNotReported(t *testing.T) {
	v := NewValidator()

	for _, tc := range []struct {
		name, line, epoch string
	}{
		{"issue reproducer", "NPI reconciliation ran at 1751328000 epoch seconds.", "1751328000"},
		{"batch log, label slot only", "NPI reconciliation ran at 1751328000.", "1751328000"},
		{"not a round number", "NPI reconciliation ran at 1761609639 epoch seconds.", "1761609639"},
		{"logfmt ts key", "npi_sync ts=1751328000 status=ok", "1751328000"},
		{"logfmt key binds alone after a npi field", "rendering_npi=1104332188 ts=1751328000", "1751328000"},
		{"json created_at", `{"event": "npi_refresh", "created_at": 1751328000}`, "1751328000"},
		{"json ts with provider context", `{"provider": "npi-directory", "ts": 1751328000}`, "1751328000"},
		{"json quoted participle key", `{"npi":"1234567893","updated":1751328000}`, "1751328000"},
		{"camelCase key", `{"provider": "x", "updatedAt": 1751328000}`, "1751328000"},
		{"compound participle key", "provider last_updated: 1751328000", "1751328000"},
		{"jwt iat claim", `{"sub":"npi-lookup","iat":1751328000,"provider":"x"}`, "1751328000"},
		{"epoch before the value", "provider directory refreshed at epoch 1751328000", "1751328000"},
		{"unix timestamp label", "NPI batch unix timestamp: 1761609639", "1761609639"},
		{"date key", "Date: 1735689600 provider audit", "1735689600"},
		{"seconds unit after the value", "physician sync took effect 1751328000 s after the epoch", "1751328000"},
		{"milliseconds unit after the value", "provider cache ttl 1761609639 ms", "1761609639"},
		{"bracketed unit after the value", "Physician 1735689600 (unix)", "1735689600"},
		{"time call on the left of =", "provider export time.time()=1751328000.123456", "1751328000"},
		{"second value on an NPI line", "NPI 1234567893 updated at 1751328000", "1751328000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !npiLuhnValid(tc.epoch) {
				t.Fatalf("fixture %s must pass NPI-Luhn, or this case tests nothing", tc.epoch)
			}
			matches, err := v.ValidateContent(tc.line, "batch.log")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			for _, m := range matches {
				if m.Text == tc.epoch {
					t.Errorf("Unix timestamp %s reported as %s at %.0f in %q", tc.epoch, m.Type, m.Confidence, tc.line)
				}
			}
		})
	}
}

// TestNPI_UnixSecondsRuleKeepsRealNPIs is the scope proof for #806: real NPIs, 1-led
// and 2-led, report at exactly the score they had before the fix. It passes on main by
// design; it fails if the rule widens to the line, to the digits, or past an NPI label.
func TestNPI_UnixSecondsRuleKeepsRealNPIs(t *testing.T) {
	v := NewValidator()

	for _, tc := range []struct {
		name, line, npi string
		want            float64
	}{
		// The issue's acceptance lines: a labelled NPI keeps its score, including one
		// whose digits are also a plausible timestamp.
		{"labelled CMS example", "NPI: 1234567893", "1234567893", 90},
		{"labelled value that is also an epoch", "Provider NPI: 1751328000", "1751328000", 100},
		{"npi key on the left of =", "npi=1751328000", "1751328000", 90},
		{"filler between label and value", "NPI number: 1751328000", "1751328000", 90},
		{"labelled with a time unit after it", "NPI 1234567893 seconds", "1234567893", 90},
		{"NPI label beats at", "Listed under NPI at 1234567893", "1234567893", 90},

		// 1-led NPIs are all inside the 2001-2033 window, so these are the cases the
		// rule could reach and must not.
		{"physician NPI number", "Physician NPI number: 1497759005", "1497759005", 100},
		{"hospital registry", "Hospital registry NPI: 1124028006", "1124028006", 100},
		{"NPI No.", "Physician NPI No. 1104332188", "1104332188", 100},
		{"NPI#", "Provider NPI#1104332188", "1104332188", 100},
		{"ends in 00, labelled", "Provider NPI: 1357920200", "1357920200", 100},
		{"ends in 00, unlabelled", "Physician 1618030500 on the claim", "1618030500", 90},
		{"time words elsewhere on the line", "Provider NPI 1234567893 record created 2025-07-01T00:00:00Z", "1234567893", 100},
		{"time word after the next word", "Physician 1104332188 verified, see timestamp column", "1104332188", 90},
		{"prose participle", "NPI updated: 1234567893", "1234567893", 90},
		{"prose participle without npi", "Provider updated: 1234567893", "1234567893", 90},
		{"possessive s is not a unit", "The provider's 1234567893 record is current", "1234567893", 90},
		{"npi beside a ts field", "rendering_npi=1104332188 ts=1751328000", "1104332188", 90},
		{"npi beside an updated field", `{"npi":"1234567893","updated":1751328000}`, "1234567893", 90},

		// 2-led NPIs read as dates after 2033-05-18, outside the window, so the rule
		// never touches them whatever surrounds them.
		{"2-led labelled", "Provider NPI: 2453195994", "2453195994", 100},
		{"2-led unlabelled", "Billing provider 2123456784 on claim", "2123456784", 90},
		{"2-led with a time label", "provider ts=2987654326", "2987654326", 90},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !npiLuhnValid(tc.npi) {
				t.Fatalf("fixture %s must pass NPI-Luhn", tc.npi)
			}
			matches, err := v.ValidateContent(tc.line, "providers.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			found := false
			for _, m := range matches {
				if m.Type == "NPI" && m.Text == tc.npi {
					found = true
					if m.Confidence != tc.want {
						t.Errorf("NPI %s in %q: confidence %.1f, want %.1f", tc.npi, tc.line, m.Confidence, tc.want)
					}
				}
			}
			if !found {
				t.Errorf("NPI %s not reported in %q", tc.npi, tc.line)
			}
		})
	}
}

// TestNPI_UnixSecondsRuleKeepsTheFloor guards the TM-11 interaction: a labelled NPI
// padded with every time word in both slots and on the line is demoted by the padding
// but still emitted at or above the floor, because the NPI label wins.
func TestNPI_UnixSecondsRuleKeepsTheFloor(t *testing.T) {
	v := NewValidator()
	line := "NPI 1234567893 seconds test example fake mock sample serial tracking invoice order " +
		"timestamp unix epoch ts created_at"
	matches, err := v.ValidateContent(line, "padded.txt")
	if err != nil {
		t.Fatalf("ValidateContent() error = %v", err)
	}
	for _, m := range matches {
		if m.Type == "NPI" && m.Text == "1234567893" {
			if m.Confidence < intrinsicValueFloor {
				t.Errorf("confidence %.1f fell below the floor %.1f", m.Confidence, intrinsicValueFloor)
			}
			return
		}
	}
	t.Errorf("labelled NPI erased by time padding (%d matches): TM-11 floor regressed", len(matches))
}

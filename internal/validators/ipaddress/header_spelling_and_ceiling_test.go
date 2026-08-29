// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ipaddress

import (
	"strings"
	"testing"
)

// Two defects found while verifying the ten PRs merged for v2.4.3 against the built binary.
//
// #548 — the same genuine public address scored 100 HIGH or 75 MEDIUM according to how its column
// header was spelled. Measured on a 3-row CSV of real public AWS addresses, one column, differing
// only in the header:
//
//	header                --confidence high
//	"Source IP address"   3 findings
//	"source_ip_address"   3 findings
//	"sourceIPAddress"     0 findings
//	"SourceIpAddress"     0 findings
//
// Real CloudTrail writes the spaced form; anything derived from the JSON field name writes the
// camel form. The cause was ORDER inside tabular.Analyze — headers are stored lower-cased, and
// lower-casing first collapses "sourceIPAddress" to "sourceipaddress", one token with no
// boundaries left for a whole-word lookup.
//
// #545 — the confidence ceiling was published only when the cap had ALREADY fired
// (`ambiguousShape && confidence >= 90`), so a value whose pre-cap score was below 90 got no
// ceiling at all. The dual-path bridge adds a document-level adjustment after this validator
// returns, so nothing was left to clamp it: the exact failure mode confidenceCeilingKey's own
// comment describes ("validator 55, CLI 75"), reintroduced by withholding the bound in precisely
// the cases that had not yet crossed it.

const publicIP = "52.94.236.248"

func csvWithHeader(header string) string {
	return "eventTime," + header + ",userName\n" +
		"2026-08-01," + publicIP + ",alice\n"
}

// TestEveryHeaderSpellingClearsTheCapIdentically is #548's regression test.
//
// Asserted through the validator, not through the header string, because the property that
// matters is that the KEYWORD is findable — the underscored spelling keeps its underscores and
// always worked, since the matcher treats '_' as a word boundary.
func TestEveryHeaderSpellingClearsTheCapIdentically(t *testing.T) {
	v := NewValidator()
	spellings := []string{
		"Source IP address", "source_ip_address", "sourceIPAddress", "SourceIpAddress",
		"sourceIpAddr", "clientIPAddress", "IPAddress",
	}
	for _, h := range spellings {
		t.Run(h, func(t *testing.T) {
			ms, err := v.ValidateContent(csvWithHeader(h), "t.csv")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(ms) == 0 {
				t.Fatalf("no finding under header %q, so nothing is being measured", h)
			}
			for _, m := range ms {
				if m.Confidence < 90 {
					t.Errorf("confidence %.0f under header %q, want >= 90.\nThe header names the "+
						"column an IP address, so it clears the ambiguous-shape cap — and a "+
						"genuine address must not be demoted because the export spelled its "+
						"header in camelCase (#548). A gate filtering on HIGH stops seeing it.",
						m.Confidence, h)
				}
				if _, capped := m.Metadata[confidenceCeilingKey]; capped {
					t.Errorf("header %q published a confidence ceiling; a header that names an IP "+
						"address must not leave the value cap-eligible at all", h)
				}
			}
		})
	}
}

// TestAHeaderThatNamesSomethingElseStillCaps bounds the blast radius.
//
// Normalising headers can only ever find MORE of the vocabulary, so the risk is that it finds it
// where it should not. A column that is not an address must still be capped.
func TestAHeaderThatNamesSomethingElseStillCaps(t *testing.T) {
	v := NewValidator()
	for _, h := range []string{
		"buildVersion", "productVersion", "recordId", "parcelId", "meterNumber",
		"orderTotal", "userName", "eventTime",
	} {
		t.Run(h, func(t *testing.T) {
			ms, err := v.ValidateContent(csvWithHeader(h), "t.csv")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(ms) == 0 {
				t.Skipf("no finding under %q", h)
			}
			for _, m := range ms {
				if m.Confidence > ambiguousShapeCap {
					t.Errorf("confidence %.0f under header %q, want <= %.0f: this header does not "+
						"name an address, so normalising it must not manufacture a signal",
						m.Confidence, h, ambiguousShapeCap)
				}
			}
		})
	}
}

// TestTheCeilingIsPublishedWheneverTheValueIsCapEligible is #545's regression test.
//
// The ceiling describes the value's CLASS, not its current score. Publishing it only once the
// score already exceeds it leaves the below-threshold cases unprotected against a later
// adjustment — which is the whole reason the key exists.
func TestTheCeilingIsPublishedWheneverTheValueIsCapEligible(t *testing.T) {
	v := NewValidator()
	cases := map[string]string{
		// A context-free quad in a column naming something else: cap-eligible.
		"header names something else": csvWithHeader("buildVersion"),
		// A product version in prose: cap-eligible via the product-token rule.
		"product version": "Generator: LibreOffice/24.8.4.2$MacOSX_AARCH64\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			ms, err := v.ValidateContent(content, "t.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(ms) == 0 {
				t.Fatalf("no finding, so nothing is being measured")
			}
			for _, m := range ms {
				raw, present := m.Metadata[confidenceCeilingKey]
				if !present {
					t.Errorf("confidence %.0f but NO %s published.\nThe bound must be published "+
						"whenever the value is eligible for the cap, not only once it exceeds it: "+
						"the dual-path bridge adds a document-level adjustment after this "+
						"validator returns, and without the key there is nothing to clamp it "+
						"(#545).", m.Confidence, confidenceCeilingKey)
					continue
				}
				got, ok := raw.(float64)
				if !ok {
					t.Errorf("%s is %T, want float64 — clampToCeiling reads it with that exact "+
						"type assertion and silently ignores anything else", confidenceCeilingKey, raw)
					continue
				}
				if got != ambiguousShapeCap {
					t.Errorf("%s = %v, want %v", confidenceCeilingKey, got, ambiguousShapeCap)
				}
				if m.Confidence > got {
					t.Errorf("confidence %.0f exceeds its own published ceiling %v", m.Confidence, got)
				}
			}
		})
	}
}

// TestAClearedValuePublishesNoCeiling is the other direction: a value with a genuine signal is
// not cap-eligible, so it must carry no bound that a later stage would clamp it to.
func TestAClearedValuePublishesNoCeiling(t *testing.T) {
	v := NewValidator()
	for _, content := range []string{
		"Server address: " + publicIP + "\n",
		"see http://" + publicIP + "/health for status\n",
		csvWithHeader("sourceIPAddress"),
	} {
		t.Run(strings.TrimSpace(content)[:24], func(t *testing.T) {
			ms, err := v.ValidateContent(content, "t.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(ms) == 0 {
				t.Fatalf("no finding")
			}
			for _, m := range ms {
				if _, present := m.Metadata[confidenceCeilingKey]; present {
					t.Errorf("a value with a genuine IP signal published %s; it is not "+
						"cap-eligible and must not carry a bound", confidenceCeilingKey)
				}
			}
		})
	}
}

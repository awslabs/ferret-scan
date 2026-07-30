// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package medicalid

import "testing"

// TestLabelledMemberIDSurvivesIdentifierLabels is the leak this file exists for.
//
// nonInsuranceKeywordPresent lumped identifier LABELS (account/order/invoice/
// tracking) in with different NUMBER TYPES (phone/ssn/serial/...), and the whole
// list hard-suppressed. But account, order, invoice and tracking are the
// definitional content of a claim form, an EOB and a remittance advice, so they
// co-occur with a real member ID constantly.
//
// evaluateMRN has carried a hard/soft split for exactly this reason for a while;
// the insurance path simply never adopted it. Only reported findings are handed
// to the redactor, and a file with no findings has no redacted output written at
// all, so the member ID stayed in cleartext.
func TestLabelledMemberIDSurvivesIdentifierLabels(t *testing.T) {
	v := NewValidator()

	lines := []string{
		"Subscriber member id W1234567801, patient account 88213 has a zero balance",
		"Subscriber member id W1234567801, order 55 shipped",
		"member id W1234567801, invoice 22 paid",
		"Insurance member id W1234567801 with tracking 99",
	}

	for _, line := range lines {
		t.Run(line, func(t *testing.T) {
			matches, err := v.ValidateContent(line, "claim.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) == 0 {
				t.Fatalf("an identifier label elsewhere on the line deleted a labelled "+
					"member ID: %s", line)
			}
		})
	}
}

// TestUnlabelledValueWithIdentifierLabelStaysSuppressed is why the words are
// SPLIT rather than deleted. With no insurance keyword on the line, "order" and
// "tracking" are still the best available evidence that a mixed alphanumeric
// token is an order number and not a member ID.
func TestUnlabelledValueWithIdentifierLabelStaysSuppressed(t *testing.T) {
	v := NewValidator()

	lines := []string{
		"order 55 and W1234567801 shipped",
		"tracking 99 for W1234567801",
		"invoice 22 references W1234567801",
		"account W1234567801 was updated",
	}

	for _, line := range lines {
		t.Run(line, func(t *testing.T) {
			matches, err := v.ValidateContent(line, "orders.csv")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) != 0 {
				t.Errorf("an unlabelled value beside an identifier label was reported: %s (got %d)",
					line, len(matches))
			}
		})
	}
}

// TestNumberTypeKeywordsStillHardSuppress pins the tier that did NOT change. A
// word naming a different number type suppresses regardless of the insurance
// label, because a member-ID-shaped token really is likelier to be that other
// thing.
func TestNumberTypeKeywordsStillHardSuppress(t *testing.T) {
	v := NewValidator()

	lines := []string{
		"Subscriber member id W1234567801, phone 555-0100",
		"member id W1234567801 ssn on file",
		"member id W1234567801 serial number",
		"member id W1234567801 model 4",
		"member id W1234567801 version 2",
	}

	for _, line := range lines {
		t.Run(line, func(t *testing.T) {
			matches, err := v.ValidateContent(line, "mixed.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) != 0 {
				t.Errorf("a different-number-type keyword failed to suppress: %s (got %d)",
					line, len(matches))
			}
		})
	}
}

// TestInsuranceTiersMirrorMRN documents the invariant behind the split: the two
// suppressor sets must be disjoint, or a word would be both hard and soft and the
// soft tier would be unreachable.
func TestInsuranceTiersMirrorMRN(t *testing.T) {
	v := NewValidator()

	hard := []string{"phone", "ssn", "serial", "model", "version", "ip address"}
	soft := []string{"account", "order", "invoice", "tracking"}

	for _, kw := range hard {
		if !v.nonInsuranceKeywordPresent("x " + kw + " y") {
			t.Errorf("hard keyword %q not detected by nonInsuranceKeywordPresent", kw)
		}
		if v.nonInsuranceSoftKeywordPresent("x " + kw + " y") {
			t.Errorf("hard keyword %q also matched the SOFT set; the tiers must be disjoint", kw)
		}
	}
	for _, kw := range soft {
		if !v.nonInsuranceSoftKeywordPresent("x " + kw + " y") {
			t.Errorf("soft keyword %q not detected by nonInsuranceSoftKeywordPresent", kw)
		}
		if v.nonInsuranceKeywordPresent("x " + kw + " y") {
			t.Errorf("soft keyword %q also matched the HARD set, so the soft tier is unreachable", kw)
		}
	}
}

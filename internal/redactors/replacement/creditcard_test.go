// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package replacement

import (
	"strings"
	"testing"
)

// These tests lock in that EVERY credit-card finding type the validator can
// emit routes to credit-card redaction across all three strategies. Before
// this was centralised, the Simple/FormatPreserving/Synthetic switches listed
// only VISA/MASTERCARD/AMERICAN_EXPRESS/DISCOVER, so the other brands the
// validator emits (MAESTRO, JCB, DINERS_CLUB, UNIONPAY) were handled
// inconsistently — Simple would leak the brand as "[JCB-REDACTED]" and
// FormatPreserving/Synthetic would fall through to the generic branches.

// allCardTypes is every finding type getCreditCardType (in
// internal/validators/creditcard) can return. Keep in sync with it and with
// the creditCardTypes map.
var allCardTypes = []string{
	"CREDIT_CARD", "VISA", "MASTERCARD", "MAESTRO", "AMERICAN_EXPRESS",
	"JCB", "DINERS_CLUB", "DISCOVER", "UNIONPAY",
}

func TestCreditCard_AllTypesRecognised(t *testing.T) {
	for _, ct := range allCardTypes {
		if !isCreditCardType(ct) {
			t.Errorf("isCreditCardType(%q) = false, want true — this brand would "+
				"fall through to the generic redaction branch", ct)
		}
	}
}

// TestCreditCard_SimpleIsGenericPlaceholder confirms every brand collapses to
// the same brand-free placeholder under the Simple strategy (no "[JCB-REDACTED]").
func TestCreditCard_SimpleIsGenericPlaceholder(t *testing.T) {
	const want = "[CREDIT-CARD-REDACTED]"
	for _, ct := range allCardTypes {
		if got := Simple(ct); got != want {
			t.Errorf("Simple(%q) = %q, want %q", ct, got, want)
		}
	}
}

// TestCreditCard_FormatPreservingConsistentAcrossBrands confirms every brand
// gets the same credit-card format-preserving mask (last-4 visible, everything
// else — including the BIN / first-4 — masked, structure preserved) rather than
// the generic full mask.
func TestCreditCard_FormatPreservingConsistentAcrossBrands(t *testing.T) {
	const card = "4532-0151-1283-0366"
	want := FormatPreserving(card, "CREDIT_CARD")
	// Sanity: the CC mask keeps only the last-4 and masks the BIN / first-4.
	if strings.Contains(want, "4532") || !strings.HasSuffix(want, "0366") || !strings.Contains(want, "*") {
		t.Fatalf("unexpected baseline CC mask %q", want)
	}
	for _, ct := range allCardTypes {
		if got := FormatPreserving(card, ct); got != want {
			t.Errorf("FormatPreserving(card, %q) = %q, want %q (brand should use "+
				"the same CC mask as CREDIT_CARD)", ct, got, want)
		}
	}
}

// TestCreditCard_SyntheticConsistentAcrossBrands confirms every brand routes to
// the synthetic credit-card generator (a Luhn-valid fake), not the generic
// random-string fallback. We can't assert the exact value (it's random), so we
// assert structural properties the generic fallback would not satisfy.
func TestCreditCard_SyntheticConsistentAcrossBrands(t *testing.T) {
	const card = "4532015112830366"
	for _, ct := range allCardTypes {
		got, err := Synthetic(card, ct)
		if err != nil {
			t.Errorf("Synthetic(card, %q) error: %v", ct, err)
			continue
		}
		// syntheticCreditCard preserves length and emits only digits;
		// the generic randomString fallback emits mixed alphanumerics.
		if len(got) != len(card) {
			t.Errorf("Synthetic(card, %q) length = %d, want %d", ct, len(got), len(card))
		}
		for _, r := range got {
			if r < '0' || r > '9' {
				t.Errorf("Synthetic(card, %q) = %q contains non-digit %q — did not route "+
					"to the credit-card generator", ct, got, string(r))
				break
			}
		}
	}
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package bankaccount

import "testing"

// TestPublishedExampleIBANsAreWellFormed: every listed value is compact, upper case and passes the
// same isValidIBAN gate a finding must pass, so no entry is dead.
func TestPublishedExampleIBANsAreWellFormed(t *testing.T) {
	v := NewValidator()
	for iban, source := range publishedExampleIBANs {
		if source == "" {
			t.Errorf("%s has no source", iban)
		}
		for i := 0; i < len(iban); i++ {
			c := iban[i]
			if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
				t.Errorf("%s: byte %q is not compact upper-case form", iban, c)
			}
		}
		if !v.isValidIBAN(iban) {
			t.Errorf("%s does not pass isValidIBAN, so it can never be reported", iban)
		}
	}
}

func TestPublishedExampleCeilingIsLow(t *testing.T) {
	if publishedExampleCeiling != wantPublishedCeiling {
		t.Errorf("publishedExampleCeiling = %v, issue930_test.go asserts %v", publishedExampleCeiling, wantPublishedCeiling)
	}
	if publishedExampleCeiling >= 60 {
		t.Errorf("publishedExampleCeiling = %v is MEDIUM or above", publishedExampleCeiling)
	}
}

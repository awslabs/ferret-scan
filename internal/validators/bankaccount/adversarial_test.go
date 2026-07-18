// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package bankaccount

import (
	"fmt"
	"strings"
	"testing"
)

// =============================================================================
// ADVERSARIAL TEST SUITE: bankaccount validator
//
// Attack vectors:
//   1. FALSE POSITIVES - things that match but SHOULD NOT
//   2. FALSE NEGATIVES - things that should match but DON'T
//   3. CONTEXT WEAKNESS - same value with/without keywords
//   4. CROSS-VALIDATOR CONFUSION - overlap with SSN, phone, ZIP, CC
//   5. EDGE CASES - empty, unicode, split lines, max-length
// =============================================================================

// --- ATTACK VECTOR 1: FALSE POSITIVES ---

func TestAdversarial_FalsePositives_ABA(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		content string
		desc    string
	}{
		{
			name:    "phone_number_looks_like_routing",
			content: "Call us at 021000089 for support",
			desc:    "A 9-digit number that passes ABA checksum in a non-banking context MUST NOT match",
		},
		{
			name:    "zip_code_9_digit",
			content: "Zip code: 071000013",
			desc:    "ZIP code context should suppress even valid ABA checksum",
		},
		{
			name:    "random_9digit_no_context",
			content: "Reference: 071000013",
			desc:    "Bare 9-digit valid ABA without any banking keywords must not match",
		},
		{
			name:    "order_number_valid_aba_checksum",
			content: "Order #026009593 confirmed",
			desc:    "Order context with valid ABA checksum must not match",
		},
		{
			name:    "employee_id_9_digits",
			content: "Employee ID: 011401533",
			desc:    "Employee ID context should not match even with valid ABA",
		},
		{
			name:    "confirmation_code",
			content: "Your confirmation code is 121000248",
			desc:    "Confirmation context is in negative keywords - should suppress",
		},
		{
			name:    "invoice_number_valid_aba",
			content: "Invoice number 071000013 is due",
			desc:    "Invoice context (negative keyword) should suppress",
		},
		{
			name:    "ip_address_like_nine_digits",
			content: "IP address range 071000013 allocated",
			desc:    "IP address context should suppress ABA match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			abaMatches := filterByType(matches, "ABA_ROUTING")
			if len(abaMatches) > 0 {
				t.Errorf("FALSE POSITIVE: %s\n  input: %q\n  got ABA_ROUTING match with confidence %.1f",
					tt.desc, tt.content, abaMatches[0].Confidence)
			}
		})
	}
}

func TestAdversarial_FalsePositives_SWIFT(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		content string
		desc    string
	}{
		{
			name:    "TESTTEST_not_real_swift",
			content: "SWIFT: TESTTEST",
			desc:    "TESTTEST is not a real SWIFT code (TE is not a valid country code)",
		},
		{
			name:    "common_word_BASEBALL_no_context",
			content: "The BASEBALL game was fun",
			desc:    "All-letter 8-char word without banking context must not match",
		},
		{
			name:    "common_word_EVERYONE_no_context",
			content: "EVERYONE should attend the meeting",
			desc:    "All-letter 8-char word must not match",
		},
		{
			name:    "code_identifier_ABCDUS12",
			content: "Module ABCDUS12 loaded successfully",
			desc:    "Random SWIFT-format string without banking context should have very low or no match",
		},
		{
			name:    "env_variable_PRODGB2X",
			content: "Environment variable PRODGB2X is set",
			desc:    "SWIFT-like env variable without banking context should be suppressed or very low confidence",
		},
		{
			name:    "all_alpha_with_bank_keyword_but_not_swift",
			content: "The bank uses STARTING as a code name",
			desc:    "All-alpha word even with 'bank' keyword should be suppressed by isCommonWord",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			swiftMatches := filterByType(matches, "SWIFT_BIC")
			if len(swiftMatches) > 0 {
				// For ABCDUS12 and PRODGB2X without banking context, we expect
				// them to pass through since they have digits. We tolerate
				// confidence <= 50 as "low enough to be borderline acceptable".
				// But anything flagged in clearly non-financial context is a FP.
				if swiftMatches[0].Confidence > 50 {
					t.Errorf("FALSE POSITIVE: %s\n  input: %q\n  got SWIFT_BIC match with confidence %.1f (want <=50 or no match)",
						tt.desc, tt.content, swiftMatches[0].Confidence)
				}
			}
		})
	}
}

func TestAdversarial_FalsePositives_IBAN(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		content string
		desc    string
	}{
		{
			name:    "invalid_mod97_checksum",
			content: "IBAN: DE12370400440532013000",
			desc:    "IBAN with invalid mod-97 checksum MUST NOT match",
		},
		{
			name:    "wrong_length_for_country",
			content: "Transfer to DE893704004405320130001",
			desc:    "German IBAN must be exactly 22 chars, 23 should fail",
		},
		{
			name:    "fake_country_code",
			content: "IBAN: ZZ89370400440532013000",
			desc:    "ZZ is not a valid IBAN country code",
		},
		{
			name:    "check_digits_99",
			content: "Account: GB99NWBK60161331926819",
			desc:    "Check digits 99 are never valid per spec",
		},
		{
			name:    "check_digits_01",
			content: "Account: DE01370400440532013000",
			desc:    "Check digits 01 are never valid per spec",
		},
		{
			name:    "alphanumeric_but_not_iban",
			content: "Product code GB29ABCDEFGHIJKLMNOP12",
			desc:    "Random alphanumeric that looks like IBAN but fails checksum",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			ibanMatches := filterByType(matches, "IBAN")
			if len(ibanMatches) > 0 {
				t.Errorf("FALSE POSITIVE: %s\n  input: %q\n  got IBAN match with confidence %.1f",
					tt.desc, tt.content, ibanMatches[0].Confidence)
			}
		})
	}
}

func TestAdversarial_FalsePositives_USAccount(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		content string
		desc    string
	}{
		{
			name:    "phone_in_banking_context",
			content: "Bank phone number: 5551234567",
			desc:    "Phone number even with 'bank' keyword should be suppressed",
		},
		{
			name:    "credit_card_in_bank_context",
			content: "Bank account ending in 4111111111111111",
			desc:    "16-digit CC number in banking context - cross-validator overlap",
		},
		{
			name:    "date_in_bank_context",
			content: "Bank statement from 2024-01-15 shows balance",
			desc:    "Date patterns near bank keyword should not flag",
		},
		{
			name:    "version_in_bank_context",
			content: "Bank software version 12345678 released",
			desc:    "Version context should suppress despite banking keyword",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			acctMatches := filterByType(matches, "US_BANK_ACCOUNT")
			if len(acctMatches) > 0 {
				t.Errorf("FALSE POSITIVE: %s\n  input: %q\n  got US_BANK_ACCOUNT match with confidence %.1f",
					tt.desc, tt.content, acctMatches[0].Confidence)
			}
		})
	}
}

// --- ATTACK VECTOR 2: FALSE NEGATIVES ---

func TestAdversarial_FalseNegatives_ABA(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name      string
		content   string
		matchType string
		desc      string
	}{
		{
			name:      "wells_fargo_routing_in_banking_context",
			content:   "Wire transfer routing number: 121042882",
			matchType: "ABA_ROUTING",
			desc:      "Wells Fargo routing number with banking keywords must be detected",
		},
		{
			name:      "aba_with_ach_keyword",
			content:   "ACH routing: 021000089",
			matchType: "ABA_ROUTING",
			desc:      "Valid ABA with ACH keyword must be HIGH confidence",
		},
		{
			name:      "aba_multiline_context",
			content:   "Please use the following for wire transfer:\nRouting: 026009593\nAccount: 12345678",
			matchType: "ABA_ROUTING",
			desc:      "ABA on second line with routing keyword on same line must match",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			typed := filterByType(matches, tt.matchType)
			if len(typed) == 0 {
				t.Errorf("FALSE NEGATIVE: %s\n  input: %q\n  expected %s match, got none (all matches: %v)",
					tt.desc, tt.content, tt.matchType, matchTypes(matches))
			}
		})
	}
}

func TestAdversarial_FalseNegatives_IBAN(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		content string
		desc    string
	}{
		{
			name:    "valid_iban_lowercase",
			content: "Transfer to de89370400440532013000",
			desc:    "Lowercase IBAN should be detected (real-world formatting)",
		},
		{
			name:    "valid_iban_mixed_case",
			content: "IBAN: De89370400440532013000",
			desc:    "Mixed-case IBAN should be detected",
		},
		{
			name:    "valid_iban_no_keyword",
			content: "Send funds to GB29NWBK60161331926819 please",
			desc:    "Valid IBAN with correct checksum should match even without explicit IBAN keyword",
		},
		{
			name:    "austrian_iban",
			content: "IBAN: AT611904300234573201",
			desc:    "Valid Austrian IBAN must be detected",
		},
		{
			name:    "belgian_iban",
			content: "Payment to BE68539007547034",
			desc:    "Valid Belgian IBAN must be detected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			ibanMatches := filterByType(matches, "IBAN")
			if len(ibanMatches) == 0 {
				t.Errorf("FALSE NEGATIVE: %s\n  input: %q\n  expected IBAN match, got none (all matches: %v)",
					tt.desc, tt.content, matchTypes(matches))
			}
		})
	}
}

func TestAdversarial_FalseNegatives_SWIFT(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		content string
		desc    string
	}{
		{
			name:    "deutdeff_with_swift_keyword",
			content: "SWIFT code: DEUTDEFF",
			desc:    "Deutsche Bank Frankfurt SWIFT with keyword must match",
		},
		{
			name:    "11char_swift_with_bic",
			content: "BIC: COBADEFFXXX",
			desc:    "11-char Commerzbank SWIFT with BIC keyword must match",
		},
		{
			name:    "swift_with_digits_no_keyword",
			content: "Transfer via CHASUS33 immediately",
			desc:    "SWIFT with digits (not all-alpha) should match even without keyword at low confidence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			swiftMatches := filterByType(matches, "SWIFT_BIC")
			if len(swiftMatches) == 0 {
				t.Errorf("FALSE NEGATIVE: %s\n  input: %q\n  expected SWIFT_BIC match, got none (all matches: %v)",
					tt.desc, tt.content, matchTypes(matches))
			}
		})
	}
}

func TestAdversarial_FalseNegatives_USAccount(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name    string
		content string
		desc    string
	}{
		{
			name:    "17_digit_account_with_bank_keyword",
			content: "Bank account: 12345678901234567",
			desc:    "17-digit (max length) account number with keyword must match",
		},
		{
			name:    "8_digit_account_with_checking",
			content: "Checking account no: 98765432",
			desc:    "8-digit (min length) account with checking keyword must match",
		},
		{
			name:    "account_with_acct_abbreviation",
			content: "Acct #1234567890",
			desc:    "Account with 'acct' abbreviation must trigger",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := validator.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			acctMatches := filterByType(matches, "US_BANK_ACCOUNT")
			if len(acctMatches) == 0 {
				t.Errorf("FALSE NEGATIVE: %s\n  input: %q\n  expected US_BANK_ACCOUNT match, got none (all matches: %v)",
					tt.desc, tt.content, matchTypes(matches))
			}
		})
	}
}

// --- ATTACK VECTOR 3: CONTEXT WEAKNESS ---

func TestAdversarial_ContextWeakness(t *testing.T) {
	validator := NewValidator()

	// Same ABA routing number with different contexts - confidence must differ dramatically.
	t.Run("aba_high_vs_no_context", func(t *testing.T) {
		highCtx := "Wire transfer routing number: 021000089"
		noCtx := "The value is 021000089 for reference"

		highMatches, _ := validator.ValidateContent(highCtx, "test.txt")
		noMatches, _ := validator.ValidateContent(noCtx, "test.txt")

		highABA := filterByType(highMatches, "ABA_ROUTING")
		noABA := filterByType(noMatches, "ABA_ROUTING")

		if len(highABA) == 0 {
			t.Fatal("Expected ABA_ROUTING match in banking context")
		}
		// Without banking keywords, the validator should not match at all or be very low.
		// The code says: "if !hasBankingContext && confidence < 50 { continue }"
		// Base is 40 without context, + context impact (which is 0 for neutral text) = 40 < 50 → skip.
		if len(noABA) > 0 {
			t.Errorf("CONTEXT WEAKNESS: same number without banking context should NOT match\n"+
				"  with context: confidence=%.1f\n  without context: confidence=%.1f (should be suppressed)",
				highABA[0].Confidence, noABA[0].Confidence)
		}

		if len(highABA) > 0 && highABA[0].Confidence < 70 {
			t.Errorf("CONTEXT WEAKNESS: banking context should give HIGH confidence, got %.1f",
				highABA[0].Confidence)
		}
	})

	t.Run("aba_banking_vs_phone_context", func(t *testing.T) {
		bankCtx := "Routing number for ACH direct deposit: 021000089"
		phoneCtx := "Phone number: 021000089"

		bankMatches, _ := validator.ValidateContent(bankCtx, "test.txt")
		phoneMatches, _ := validator.ValidateContent(phoneCtx, "test.txt")

		bankABA := filterByType(bankMatches, "ABA_ROUTING")
		phoneABA := filterByType(phoneMatches, "ABA_ROUTING")

		if len(bankABA) == 0 {
			t.Fatal("Expected ABA_ROUTING match in strong banking context")
		}
		// With "phone" negative keyword but no positive keywords, base=40, impact=-20, total=20 < 50 → skip.
		if len(phoneABA) > 0 {
			t.Errorf("CONTEXT WEAKNESS: phone context should suppress ABA match\n"+
				"  banking context: confidence=%.1f\n  phone context: confidence=%.1f (should be suppressed)",
				bankABA[0].Confidence, phoneABA[0].Confidence)
		}
	})

	t.Run("aba_banking_vs_mixed_phone_routing", func(t *testing.T) {
		// This is the tricky case: "Phone routing: 021000089" has both phone (negative)
		// and routing (positive). The validator should NOT give high confidence here.
		mixedCtx := "Phone routing: 021000089"

		matches, _ := validator.ValidateContent(mixedCtx, "test.txt")
		abaMatches := filterByType(matches, "ABA_ROUTING")

		if len(abaMatches) > 0 && abaMatches[0].Confidence >= 70 {
			t.Errorf("CONTEXT WEAKNESS: mixed phone+routing context should NOT give high confidence\n"+
				"  got confidence=%.1f (want <70 or no match)",
				abaMatches[0].Confidence)
		}
	})

	t.Run("swift_with_vs_without_banking_keyword", func(t *testing.T) {
		withKW := "SWIFT code: CHASUS33"
		withoutKW := "Transfer via CHASUS33 immediately"

		withMatches, _ := validator.ValidateContent(withKW, "test.txt")
		withoutMatches, _ := validator.ValidateContent(withoutKW, "test.txt")

		withSWIFT := filterByType(withMatches, "SWIFT_BIC")
		withoutSWIFT := filterByType(withoutMatches, "SWIFT_BIC")

		if len(withSWIFT) == 0 {
			t.Fatal("Expected SWIFT_BIC match with SWIFT keyword")
		}

		// Without explicit keyword but with digits in code, it should still match
		// but at lower confidence.
		if len(withoutSWIFT) > 0 && len(withSWIFT) > 0 {
			diff := withSWIFT[0].Confidence - withoutSWIFT[0].Confidence
			if diff < 10 {
				t.Errorf("CONTEXT WEAKNESS: SWIFT keyword should provide significant confidence boost\n"+
					"  with keyword: %.1f, without: %.1f, diff: %.1f (want >=10)",
					withSWIFT[0].Confidence, withoutSWIFT[0].Confidence, diff)
			}
		}
	})

	t.Run("iban_with_vs_without_keyword", func(t *testing.T) {
		withKW := "IBAN: DE89370400440532013000"
		withoutKW := "Transfer to DE89370400440532013000"

		withMatches, _ := validator.ValidateContent(withKW, "test.txt")
		withoutMatches, _ := validator.ValidateContent(withoutKW, "test.txt")

		withIBAN := filterByType(withMatches, "IBAN")
		withoutIBAN := filterByType(withoutMatches, "IBAN")

		if len(withIBAN) == 0 {
			t.Fatal("Expected IBAN match with IBAN keyword")
		}
		if len(withoutIBAN) == 0 {
			t.Fatal("Expected IBAN match without keyword too (valid checksum gives high base)")
		}

		// IBAN base is 85, so both should be high. But with keyword should be higher.
		if len(withIBAN) > 0 && len(withoutIBAN) > 0 {
			if withIBAN[0].Confidence <= withoutIBAN[0].Confidence {
				t.Errorf("CONTEXT WEAKNESS: IBAN keyword should boost confidence above bare IBAN\n"+
					"  with keyword: %.1f, without keyword: %.1f",
					withIBAN[0].Confidence, withoutIBAN[0].Confidence)
			}
		}
	})
}

// --- ATTACK VECTOR 4: CROSS-VALIDATOR CONFUSION ---

func TestAdversarial_CrossValidatorConfusion(t *testing.T) {
	validator := NewValidator()

	t.Run("ssn_must_not_match_as_aba", func(t *testing.T) {
		// SSNs like 071-00-0013 when stripped to 071000013 pass ABA checksum!
		// But with "ssn" or "social security" keyword they should be suppressed.
		tests := []struct {
			name    string
			content string
		}{
			{"ssn_keyword", "SSN: 071000013"},
			{"social_security_keyword", "Social Security Number: 071000013"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				matches, _ := validator.ValidateContent(tt.content, "test.txt")
				abaMatches := filterByType(matches, "ABA_ROUTING")
				if len(abaMatches) > 0 {
					t.Errorf("CROSS-VALIDATOR: SSN context must suppress ABA match\n"+
						"  input: %q\n  got ABA_ROUTING with confidence %.1f",
						tt.content, abaMatches[0].Confidence)
				}
			})
		}
	})

	t.Run("routing_in_longer_number_must_not_match", func(t *testing.T) {
		// A credit card or other long number might contain a 9-digit subsequence
		// that passes ABA checksum. The word-boundary regex should prevent this.
		tests := []struct {
			name    string
			content string
		}{
			{"embedded_in_cc", "Card: 4111021000089123"},
			{"embedded_in_long_number", "ID: 12345021000089678"},
			{"preceded_by_digit", "Code 1021000089"},
			{"followed_by_digit", "Code 0210000890"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				matches, _ := validator.ValidateContent(tt.content, "test.txt")
				abaMatches := filterByType(matches, "ABA_ROUTING")
				if len(abaMatches) > 0 {
					t.Errorf("CROSS-VALIDATOR: ABA embedded in longer number must not match\n"+
						"  input: %q\n  matched: %q",
						tt.content, abaMatches[0].Text)
				}
			})
		}
	})

	t.Run("cc_number_must_not_match_as_us_account", func(t *testing.T) {
		// 16-digit credit card numbers overlap with US account (8-17 digits).
		// When banking context is present, the CC might get flagged as US_BANK_ACCOUNT.
		// This is debatable -- noting it as potential cross-validator issue.
		content := "Bank card 4111111111111111 used for payment"
		matches, _ := validator.ValidateContent(content, "test.txt")
		acctMatches := filterByType(matches, "US_BANK_ACCOUNT")
		if len(acctMatches) > 0 {
			// A credit card number should ideally NOT be flagged as a bank account.
			// This is a design limitation - noting but not failing hard.
			t.Logf("NOTE: Credit card number matched as US_BANK_ACCOUNT (confidence %.1f) - "+
				"potential cross-validator overlap. Consider adding CC pattern exclusion.",
				acctMatches[0].Confidence)
		}
	})

	t.Run("zip_code_with_routing_keyword_nearby", func(t *testing.T) {
		// A ZIP code that happens to pass ABA checksum, with "routing" on same line
		// for a totally different reason.
		content := "Routing mail to zip 071000013 area"
		matches, _ := validator.ValidateContent(content, "test.txt")
		abaMatches := filterByType(matches, "ABA_ROUTING")
		// "routing" is a positive keyword but "zip" is negative.
		// posCount=1 (routing), negCount=1 (zip). hasStrongNegativeContext requires
		// negCount >= 2 with posCount == 0, or negCount >= 3 with posCount <= 1.
		// So it passes through. hasBankingContext is true (routing keyword matches).
		// This IS a potential false positive.
		if len(abaMatches) > 0 && abaMatches[0].Confidence > 60 {
			t.Errorf("CROSS-VALIDATOR: ZIP context with 'routing' as postal routing should not give high confidence\n"+
				"  input: %q\n  got confidence %.1f (want <=60)",
				content, abaMatches[0].Confidence)
		}
	})
}

// --- ATTACK VECTOR 5: EDGE CASES ---

func TestAdversarial_EdgeCases(t *testing.T) {
	validator := NewValidator()

	t.Run("empty_content", func(t *testing.T) {
		matches, err := validator.ValidateContent("", "test.txt")
		if err != nil {
			t.Fatalf("error on empty content: %v", err)
		}
		if len(matches) > 0 {
			t.Error("Empty content should produce no matches")
		}
	})

	t.Run("only_digits_max_length", func(t *testing.T) {
		// 17 digits (max US account length) with banking keyword
		content := "Bank account: 12345678901234567"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		acctMatches := filterByType(matches, "US_BANK_ACCOUNT")
		if len(acctMatches) == 0 {
			t.Error("17-digit number with banking keyword should match")
		}
	})

	t.Run("18_digits_too_long_for_us_account", func(t *testing.T) {
		// 18 digits exceeds max US account length (17)
		content := "Bank account: 123456789012345678"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		acctMatches := filterByType(matches, "US_BANK_ACCOUNT")
		if len(acctMatches) > 0 {
			t.Error("18-digit number should NOT match as US_BANK_ACCOUNT (max is 17)")
		}
	})

	t.Run("unicode_around_iban", func(t *testing.T) {
		// Unicode characters around IBAN (German umlauts)
		content := "Uberweisung an DE89370400440532013000 bitte"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		ibanMatches := filterByType(matches, "IBAN")
		if len(ibanMatches) == 0 {
			t.Error("IBAN surrounded by unicode should still be detected")
		}
	})

	t.Run("split_across_lines", func(t *testing.T) {
		// IBAN split across lines should NOT match (each line scanned independently)
		content := "IBAN: DE8937040044\n0532013000"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		ibanMatches := filterByType(matches, "IBAN")
		if len(ibanMatches) > 0 {
			t.Error("IBAN split across lines should NOT match")
		}
	})

	t.Run("very_long_line", func(t *testing.T) {
		// Performance edge case: very long line
		padding := strings.Repeat("X", 5000)
		content := padding + " Routing number: 021000089 " + padding
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("error on long line: %v", err)
		}
		abaMatches := filterByType(matches, "ABA_ROUTING")
		if len(abaMatches) == 0 {
			t.Error("Match in very long line should still be found")
		}
	})

	t.Run("multiple_matches_same_line", func(t *testing.T) {
		content := "IBAN: DE89370400440532013000 SWIFT: DEUTDEFF routing: 021000089"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		ibanMatches := filterByType(matches, "IBAN")
		swiftMatches := filterByType(matches, "SWIFT_BIC")
		abaMatches := filterByType(matches, "ABA_ROUTING")

		if len(ibanMatches) == 0 {
			t.Error("Expected IBAN match on multi-match line")
		}
		if len(swiftMatches) == 0 {
			t.Error("Expected SWIFT match on multi-match line")
		}
		if len(abaMatches) == 0 {
			t.Error("Expected ABA match on multi-match line")
		}
	})

	t.Run("iban_at_line_start", func(t *testing.T) {
		content := "DE89370400440532013000"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		ibanMatches := filterByType(matches, "IBAN")
		if len(ibanMatches) == 0 {
			t.Error("Valid IBAN at start of line (no prefix) should still match")
		}
	})

	t.Run("iban_at_line_end", func(t *testing.T) {
		content := "Pay to DE89370400440532013000"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		ibanMatches := filterByType(matches, "IBAN")
		if len(ibanMatches) == 0 {
			t.Error("Valid IBAN at end of line should still match")
		}
	})

	t.Run("partially_redacted_routing", func(t *testing.T) {
		// A partially redacted routing number should NOT match
		content := "Routing: 02100****"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		abaMatches := filterByType(matches, "ABA_ROUTING")
		if len(abaMatches) > 0 {
			t.Error("Partially redacted routing number should NOT match")
		}
	})

	t.Run("routing_with_dashes", func(t *testing.T) {
		// Some systems format routing numbers with dashes
		content := "Routing: 021-000-089"
		matches, err := validator.ValidateContent(content, "test.txt")
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		// The regex requires contiguous digits, so this should NOT match.
		// This is a known limitation but not a bug.
		abaMatches := filterByType(matches, "ABA_ROUTING")
		if len(abaMatches) > 0 {
			t.Logf("NOTE: Dashed routing number matched - unexpected but possibly a design choice")
		}
	})
}

// --- CONFIDENCE BOUNDS VERIFICATION ---

func TestAdversarial_ConfidenceBounds(t *testing.T) {
	validator := NewValidator()

	// All confidence values must be in [0, 100]
	inputs := []string{
		"Wire transfer routing number for direct deposit ACH bank checking savings: 021000089",
		"IBAN: DE89370400440532013000 for wire transfer to bank account",
		"SWIFT code BIC bank wire: DEUTDEFF",
		"Bank account checking savings ACH deposit wire: 1234567890",
		// Stress test: many negative keywords
		"test example sample fake mock demo placeholder: 021000089",
		// Stress test: many positive keywords
		strings.Repeat("routing bank wire ach deposit ", 10) + "021000089",
	}

	for i, input := range inputs {
		t.Run(fmt.Sprintf("bounds_check_%d", i), func(t *testing.T) {
			matches, err := validator.ValidateContent(input, "test.txt")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			for _, m := range matches {
				if m.Confidence < 0 || m.Confidence > 100 {
					t.Errorf("Confidence out of bounds: %.1f for match %q (type %s)",
						m.Confidence, m.Text, m.Type)
				}
			}
		})
	}
}

// --- IBAN MOD-97 ADVERSARIAL ---

func TestAdversarial_IBAN_Mod97_Attacks(t *testing.T) {
	validator := NewValidator()

	t.Run("off_by_one_checksum", func(t *testing.T) {
		// DE89 is valid. DE88, DE90 should fail mod-97.
		invalid := []string{
			"DE88370400440532013000",
			"DE90370400440532013000",
			"DE87370400440532013000",
		}
		for _, iban := range invalid {
			if validator.isValidIBAN(iban) {
				t.Errorf("IBAN %q should fail mod-97 validation but passed", iban)
			}
		}
	})

	t.Run("valid_ibans_from_multiple_countries", func(t *testing.T) {
		valid := []string{
			"DE89370400440532013000",      // Germany
			"GB29NWBK60161331926819",      // UK
			"FR7630006000011234567890189", // France
			"NL91ABNA0417164300",          // Netherlands
			"ES9121000418450200051332",    // Spain
			"CH9300762011623852957",       // Switzerland
			"AT611904300234573201",        // Austria
			"BE68539007547034",            // Belgium
			"SE4550000000058398257466",    // Sweden
		}
		for _, iban := range valid {
			if !validator.isValidIBAN(iban) {
				t.Errorf("IBAN %q should be valid but failed", iban)
			}
		}
	})
}

// --- SWIFT ADVERSARIAL ---

func TestAdversarial_SWIFT_Structure(t *testing.T) {
	validator := NewValidator()

	t.Run("real_swift_codes_validate", func(t *testing.T) {
		real := []string{
			"DEUTDEFF",    // Deutsche Bank Frankfurt
			"COBADEFFXXX", // Commerzbank Frankfurt
			"BNPAFRPP",    // BNP Paribas
			"CHASUS33",    // JPMorgan Chase
			"CITIUS33",    // Citibank
			"BOFAUS3N",    // Bank of America
			"WFBIUS6S",    // Wells Fargo
		}
		for _, code := range real {
			if !validator.isValidSWIFT(code) {
				t.Errorf("Real SWIFT code %q should validate but failed", code)
			}
		}
	})

	t.Run("invalid_swift_rejected", func(t *testing.T) {
		invalid := []string{
			"TESTTEST",   // TE is not valid country
			"1234DEFF",   // digits in bank code
			"DEUTXXFF",   // XX not valid country
			"DEUT",       // too short
			"DEUTDEFFXX", // wrong length (10)
			"DEUTDE",     // too short (6)
		}
		for _, code := range invalid {
			if validator.isValidSWIFT(code) {
				t.Errorf("Invalid SWIFT code %q should not validate but passed", code)
			}
		}
	})
}

// --- ABA CHECKSUM ADVERSARIAL ---

func TestAdversarial_ABA_Checksum(t *testing.T) {
	validator := NewValidator()

	t.Run("boundary_prefixes", func(t *testing.T) {
		// Prefix 00 should be invalid (too low)
		if validator.isValidABA("001000013") {
			t.Error("Prefix 00 should be invalid")
		}
		// Prefix 33 should be invalid (gap between 32 and 61)
		if validator.isValidABA("330000007") {
			t.Error("Prefix 33 should be invalid")
		}
		// Prefix 60 should be invalid (gap between 32 and 61)
		if validator.isValidABA("600000003") {
			t.Error("Prefix 60 should be invalid")
		}
		// Prefix 73 should be invalid (gap between 72 and 80)
		if validator.isValidABA("730000009") {
			t.Error("Prefix 73 should be invalid")
		}
		// Prefix 81 should be invalid (above 80)
		if validator.isValidABA("810000005") {
			t.Error("Prefix 81 should be invalid")
		}
	})

	t.Run("valid_prefix_boundaries", func(t *testing.T) {
		// Prefix 01 should be valid (bottom of range)
		// Need to find a number that passes checksum with prefix 01.
		// 3*(0+d3+d6) + 7*(1+d4+d7) + (d2+d5+d8) mod 10 == 0
		// Try 011401533
		if !validator.isValidABA("011401533") {
			t.Error("011401533 should be valid (prefix 01)")
		}
		// Prefix 32 should be valid (top of first range)
		if !validator.isValidABA("322271627") {
			t.Error("322271627 should be valid (prefix 32)")
		}
	})
}

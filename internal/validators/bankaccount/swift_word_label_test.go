// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package bankaccount

import "testing"

// swiftShapedWords are English words that pass isValidSWIFT: 8 or 11 letters whose
// 5th and 6th letters spell a country code. The first three are the words from the
// #801 corpus review; the rest show the rule is about the shape, not those words.
var swiftShapedWords = []string{
	"CUSTOMER",    // CUST + OM (Oman) + ER
	"BUSINESS",    // BUSI + NE (Niger) + SS
	"MITIGATIONS", // MITI + GA (Gabon) + TI + ONS
	"PLATFORM",    // PLAT + FO + RM
	"DOCUMENT",    // DOCU + ME + NT
	"MORTGAGE",    // MORT + GA + GE
	"BRANCHES",    // BRAN + CH + ES
	"TRAINING",    // TRAI + NI + NG
	"MEETINGS",    // MEET + IN + GS
	"ACCEPTED",    // ACCE + PT + ED
	"INSTITUTION", // INST + IT + UT + ION
	"INVESTMENTS", // INVE + ST + ME + NTS
}

// genericBankingWords are positive keywords that say a line is about banking without
// naming a SWIFT/BIC code. Each one alone used to admit an all-letter candidate.
var genericBankingWords = []string{
	"bank", "bank account", "wire", "deposit", "savings", "routing", "ach", "acct",
}

// An all-letter word on a line whose only banking evidence is a generic banking word is
// not a SWIFT/BIC. On main each of these was SWIFT_BIC at 90-100 HIGH (#801).
func TestAllLetterWordOnBankingLineIsNotSWIFT(t *testing.T) {
	v := NewValidator()

	issueLines := []string{
		"The bank account team reviews CUSTOMER and BUSINESS onboarding before any wire is released.",
		"Documented MITIGATIONS apply to every bank deposit workflow.",
	}
	for _, line := range issueLines {
		matches, err := v.ValidateContent(line, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent(%q): %v", line, err)
		}
		for _, m := range filterByType(matches, "SWIFT_BIC") {
			t.Errorf("%q: %q reported as SWIFT_BIC at %.0f; want no SWIFT_BIC", line, m.Text, m.Confidence)
		}
	}

	for _, word := range swiftShapedWords {
		// The decoy must reach the word gate. "STARTING" in the older adversarial case
		// never did (TI is not a country code), which is why that case missed #801.
		if !v.isValidSWIFT(word) {
			t.Fatalf("%s does not pass isValidSWIFT, so it cannot exercise the word gate", word)
		}
		for _, kw := range genericBankingWords {
			line := "The " + kw + " team reviewed " + word + " today."
			matches, err := v.ValidateContent(line, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent(%q): %v", line, err)
			}
			if !v.hasBankingKeywords(line) {
				t.Fatalf("%q carries no banking keyword, so it does not test the waiver", line)
			}
			for _, m := range filterByType(matches, "SWIFT_BIC") {
				t.Errorf("%q: %q reported as SWIFT_BIC at %.0f; want no SWIFT_BIC", line, m.Text, m.Confidence)
			}
		}
	}
}

// The issue's controls: a SWIFT/BIC whose line names the code reports at the confidence it
// had before #801, all-letter or not, and a candidate with a digit keeps the generic-word
// rule. Passes on main too; it is the scope proof for the change above.
func TestSWIFTLabelledAndDigitCandidatesKeepTheirConfidence(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		line string
		text string
		want float64
	}{
		{"BIC: DEUTDEFF", "DEUTDEFF", 90},
		{"swift code CHASUS33", "CHASUS33", 90},
		{"SWIFT code: DEUTDEFF", "DEUTDEFF", 90},
		{"BIC: COBADEFFXXX", "COBADEFFXXX", 90},
		{"Wire transfer SWIFT: BNPAFRPP", "BNPAFRPP", 100},
		{"Bank SWIFT/BIC: CHASUS33", "CHASUS33", 100},
		{"IBAN DE89370400440532013000 DEUTDEFF", "DEUTDEFF", 90},
		{"IBAN: DE89370400440532013000 SWIFT: DEUTDEFF routing: 021000089", "DEUTDEFF", 100},
		// A digit makes the candidate no word, so a generic banking word still admits it.
		{"bank CHASUS33", "CHASUS33", 90},
		{"Wire to NWBKGB2L", "NWBKGB2L", 90},
		{"Transfer via CHASUS33 immediately", "CHASUS33", 50},
	}
	for _, tt := range tests {
		matches, err := v.ValidateContent(tt.line, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent(%q): %v", tt.line, err)
		}
		swift := filterByType(matches, "SWIFT_BIC")
		if len(swift) != 1 || swift[0].Text != tt.text {
			t.Errorf("%q: want one SWIFT_BIC %q, got %v", tt.line, tt.text, swift)
			continue
		}
		if swift[0].Confidence != tt.want {
			t.Errorf("%q: SWIFT_BIC %q at %.0f, want %.0f", tt.line, tt.text, swift[0].Confidence, tt.want)
		}
	}
}

// The trade-off of #801, pinned so that changing it is a decision: an all-letter BIC whose
// line names only the bank is not reported. Its shape is the shape of a word (DEUTDEFF has
// three vowels and no consonant run longer than two, like CUSTOMER and BUSINESS), so the only
// thing that tells it from CUSTOMER is a label naming the code. Each line is also checked
// with that label added, and must then be reported.
func TestAllLetterBICBesideOnlyAGenericBankingWordIsNotReported(t *testing.T) {
	v := NewValidator()

	for _, line := range []string{
		"bank DEUTDEFF",
		"Pay to Deutsche Bank DEUTDEFF today.",
		"Wire transfer to BNPAFRPP",
		"Deposit at COBADEFFXXX",
	} {
		matches, err := v.ValidateContent(line, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent(%q): %v", line, err)
		}
		for _, m := range filterByType(matches, "SWIFT_BIC") {
			t.Errorf("%q: %q reported as SWIFT_BIC at %.0f; an all-letter candidate needs swift, bic or iban on the line",
				line, m.Text, m.Confidence)
		}
		// The same line with the label is reported, so the drop above is the rule, not the value.
		labelled := line + " (SWIFT)"
		lm, err := v.ValidateContent(labelled, "test.txt")
		if err != nil {
			t.Fatalf("ValidateContent(%q): %v", labelled, err)
		}
		if len(filterByType(lm, "SWIFT_BIC")) != 1 {
			t.Errorf("%q: want one SWIFT_BIC with the label, got %v", labelled, matchTypes(lm))
		}
	}
}

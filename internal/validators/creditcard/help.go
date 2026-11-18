// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package creditcard

import "github.com/awslabs/ferret-scan/v2/internal/help"

// GetCheckInfo returns standardized information about the credit card check
func (v *Validator) GetCheckInfo() help.CheckInfo {
	return help.CheckInfo{
		Name:             "CREDIT_CARD",
		ShortDescription: "Detects credit card numbers from major card providers",
		DetailedDescription: `The Credit Card check detects credit card numbers from major providers and automatically identifies specific credit card types for better categorization.

It uses pattern matching to identify potential credit card numbers and then performs validation checks to determine the confidence level. The validator also analyzes surrounding context to improve accuracy and reduce false positives.

The check looks for 16-digit numbers (15 for American Express) that may be formatted with spaces or dashes between groups of 4 digits. It validates the numbers using the Luhn algorithm and identifies the specific card type based on the number pattern.

A bare run of digits (no spaces or dashes between groups) reaches HIGH only when something names it as a card: a card word on its line, inside an identifier on the line (cardNumber, card_number), or in the header of its CSV column. Without one it scores at most 75 (MEDIUM), so a counter or row number that happens to pass the Luhn check is not presented as a confirmed card. It is still reported and redacted.

**Supported Credit Card Types:**
- **VISA** - Cards starting with 4
- **MASTERCARD** - Cards starting with 5 (51-55) or 2221-2720 range
- **AMERICAN_EXPRESS** - Cards starting with 34 or 37
- **DISCOVER** - Cards starting with 6011, 65, or 644-649 range
- **DINERS_CLUB** - Cards starting with 30, 36, or 38
- **JCB** - Cards starting with 35
- **UNIONPAY** - Cards starting with 62
- **MAESTRO** - Cards starting with 50 or 56-58 range
- **CREDIT_CARD** - Generic type for unrecognized patterns, including cards starting with 8 (private label or regional cards)

**Card track data and security codes (CARD_TRACK_DATA, CARD_SECURITY_CODE):**
- **CARD_TRACK_DATA** - A whole magnetic-stripe track (ISO/IEC 7813 Track 1 %B...^NAME^... or Track 2 ;PAN=...?, including a URL-encoded %3B...%3D...%3F) or a chip card's Track 2 Equivalent Data (EMV tag 57, PAN D YYMM ..., bare or inside a TLV). The finding's text is the whole frame, from its first byte to its last, so redaction removes the expiry, service code, discretionary data and Track 1's cardholder name with the PAN. metadata.card_frame names the frame (track1, track2, emv57) and metadata.card_type the PAN's brand. The PAN inside the frame is also reported under its brand type. A frame whose expiry month, service code or length is invalid reports the PAN only.
- **CARD_SECURITY_CODE** - A labelled CVV2/CVC2/CID: the value must follow its label on the same line (cvv: 123, cvv=123, "cvv": "123", CID 1234). The finding's text runs from the label to the last digit, with metadata.card_frame security_code. With a card on the same line or within 3 lines it takes the card's confidence; an unambiguous label (cvv, cvv2, cvc, cvc2, ccv, cav2, card security code, card verification value/code/number) with no card in reach is reported at 40 (LOW); a context-only label (cid, csc, cvn, cvn2, security code) is reported only with a card in reach. Three or four digits with no label (a CSV column, PAN|12/28|123) are not reported.

Both types belong to this check: --checks CREDIT_CARD reports them, and a suppression rule names the type itself (a rule written in v2.6.0, when these were reported under the brand type and CREDIT_CARD, no longer matches: regenerate it). Redaction: simple writes [CARD_TRACK_DATA-REDACTED] and [CARD_SECURITY_CODE-REDACTED]; format_preserving masks every byte of the frame, or of the label and code, with *; synthetic writes a fake frame of the same shape whose PAN fails the Luhn check, and a random string for a code.`,

		Patterns: []string{
			"4 groups of 4 digits (e.g., 1234 5678 9012 3456)",
			"16 consecutive digits (e.g., 1234567890123456)",
			"4 groups of 4 digits with dashes (e.g., 1234-5678-9012-3456)",
			"Track 1 (e.g., %B<PAN>^SURNAME/GIVEN^YYMM<service code>...?) as CARD_TRACK_DATA",
			"Track 2 (e.g., ;<PAN>=YYMM<service code>...?) or EMV tag 57 (<PAN>DYYMM...) as CARD_TRACK_DATA",
			"A labelled security code (e.g., CVV: 123, cvc=123) as CARD_SECURITY_CODE",
		},

		SupportedFormats: []string{
			"Visa (starts with 4)",
			"MasterCard (starts with 51-55, 2221-2720)",
			"American Express (starts with 34 or 37)",
			"Discover (starts with 6011 or 65)",
			"JCB (starts with 35)",
			"Diners Club (starts with 30, 36, or 38)",
		},

		ConfidenceFactors: []help.ConfidenceFactor{
			{Name: "Length", Description: "Must be 16 digits (15 for AmEx)", Weight: 15},
			{Name: "Digits", Description: "Must contain only digits", Weight: 20},
			{Name: "Vendor", Description: "Must match a known card vendor pattern", Weight: 25},
			{Name: "Luhn", Description: "Must pass the Luhn checksum algorithm", Weight: 20},
			{Name: "Test Number", Description: "Must not be a known test number", Weight: 10},
			{Name: "Sequential", Description: "Must not be sequential digits", Weight: 10},
		},

		PositiveKeywords: v.positiveKeywords,
		NegativeKeywords: v.negativeKeywords,

		Examples: []string{
			"ferret-scan --file financial-data.txt --confidence high",
			"ferret-scan --file logs.txt --verbose | grep CREDIT_CARD",
		},
	}
}

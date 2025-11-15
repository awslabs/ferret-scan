// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package email

import "ferret-scan/internal/help"

// GetCheckInfo returns standardized information about the email check
func (v *Validator) GetCheckInfo() help.CheckInfo {
	return help.CheckInfo{
		Name:             "EMAIL",
		ShortDescription: "Detects email addresses and identifies specific email providers",
		DetailedDescription: `The Email check detects email addresses using pattern matching and contextual analysis, with automatic identification of specific email providers.

It validates email addresses against RFC standards and performs additional checks to reduce false positives from test data and placeholder emails. The validator analyzes the username, domain, and TLD components separately for comprehensive validation.

The validator automatically identifies specific email providers and displays them in the TYPE column for better categorization:

SUPPORTED EMAIL PROVIDER TYPES:
• GMAIL - Gmail and Google Mail addresses
• GOOGLE_WORKSPACE - Google Workspace/G Suite business emails
• OUTLOOK - Outlook, Hotmail, Live, MSN addresses
• MICROSOFT_365 - Microsoft 365 business emails
• YAHOO - Yahoo Mail addresses (all international variants)
• ICLOUD - iCloud, me.com, mac.com addresses
• APPLE_CORPORATE - Apple corporate emails
• PROTONMAIL - ProtonMail secure email addresses
• TUTANOTA - Tutanota secure email addresses
• FASTMAIL - FastMail addresses
• ZOHO - Zoho Mail addresses
• YANDEX - Yandex Mail addresses
• MAIL_RU - Mail.ru and related Russian email services
• AOL - AOL Mail addresses
• EDUCATIONAL - Educational institution emails (.edu, .ac.uk, etc.)
• GOVERNMENT - Government emails (.gov, .mil, etc.)
• BUSINESS - Corporate/business domain emails
• DISPOSABLE - Temporary/disposable email services
• EMAIL - Generic email addresses (fallback)

The validator automatically categorizes emails based on their domain for better handling and analysis.`,

		Patterns: []string{
			"Standard format (e.g., user@domain.com)",
			"Business emails (e.g., firstname.lastname@company.com)",
			"Service emails (e.g., support@company.org)",
			"Complex usernames (e.g., user.name+tag@subdomain.domain.co.uk)",
		},

		SupportedFormats: []string{
			"Major email providers (Gmail, Outlook, Yahoo, etc.)",
			"Business and corporate domains",
			"Educational institutions (.edu, .ac.uk, etc.)",
			"Government domains (.gov, .mil, etc.)",
			"International domains and country code TLDs",
			"Secure email providers (ProtonMail, Tutanota, etc.)",
			"Disposable/temporary email services",
			"Complex usernames with dots, plus signs, and underscores",
		},

		ConfidenceFactors: []help.ConfidenceFactor{
			{Name: "Valid Format", Description: "Must match email format standards", Weight: 30},
			{Name: "Valid Domain", Description: "Domain must be properly formatted", Weight: 20},
			{Name: "Valid TLD", Description: "Top-level domain must be recognized", Weight: 15},
			{Name: "Not Test Email", Description: "Must not match known test patterns", Weight: 20},
			{Name: "Reasonable Length", Description: "Must be within standard email length limits", Weight: 10},
			{Name: "No Consecutive Dots", Description: "Must not contain consecutive dots", Weight: 5},
		},

		PositiveKeywords: v.positiveKeywords,
		NegativeKeywords: v.negativeKeywords,

		Examples: []string{
			"ferret-scan --file customer-data.csv --checks EMAIL",
			"ferret-scan --file logs.txt --confidence high | grep GMAIL",
			"ferret-scan --file contacts.json --verbose --checks EMAIL",
			"ferret-scan --file emails.txt | grep BUSINESS  # Find business emails",
			"ferret-scan --file data.csv | grep DISPOSABLE  # Find temporary emails",
		},
	}
}

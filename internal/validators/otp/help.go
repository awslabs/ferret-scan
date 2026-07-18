// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package otp

import "github.com/awslabs/ferret-scan/v2/internal/help"

// GetCheckInfo returns standardized information about the OTP check.
func (v *Validator) GetCheckInfo() help.CheckInfo {
	return help.CheckInfo{
		Name:             "OTP",
		ShortDescription: "Detects two-factor authentication secrets, provisioning URIs, and recovery codes",
		DetailedDescription: `The OTP check detects two-factor authentication (2FA/MFA) secrets that could allow an attacker to generate valid one-time passwords or bypass two-factor authentication entirely.

It looks for three categories of OTP-related sensitive data:

1. otpauth:// URIs - Provisioning URLs used to set up authenticator apps (typically encoded in QR codes). These contain the shared secret and are sufficient to clone an authenticator.

2. TOTP/HOTP Secret Keys - Base32-encoded shared secrets (16-64 characters) that are used by authenticator apps to generate time-based or counter-based one-time passwords. These are detected only when accompanied by relevant context keywords to minimize false positives.

3. Recovery/Backup Codes - Groups of alphanumeric blocks (typically 8-10 codes) provided during 2FA setup as emergency access codes. Each code can be used once to bypass the second factor.

The validator requires contextual keywords for base32 secrets and recovery codes to avoid false positives on random alphanumeric strings.`,

		Patterns: []string{
			"otpauth://totp/... or otpauth://hotp/... (provisioning URIs)",
			"Base32-encoded secrets: 16-64 chars [A-Z2-7] with OTP context",
			"Recovery code blocks: XXXX-XXXX-XXXX patterns with backup/recovery context",
		},

		SupportedFormats: []string{
			"TOTP (Time-based One-Time Password) provisioning URIs",
			"HOTP (HMAC-based One-Time Password) provisioning URIs",
			"Base32 secret keys (RFC 4648 alphabet: A-Z, 2-7)",
			"Dash-separated recovery/backup code blocks",
		},

		ConfidenceFactors: []help.ConfidenceFactor{
			{Name: "Format", Description: "Must match OTP URI, base32 secret, or recovery code pattern", Weight: 30},
			{Name: "Context Keywords", Description: "Requires OTP/2FA/MFA keywords for non-URI matches", Weight: 30},
			{Name: "Length", Description: "Longer base32 secrets score higher (32+ chars preferred)", Weight: 15},
			{Name: "Structure", Description: "URI completeness, block uniformity in recovery codes", Weight: 15},
			{Name: "Not Excluded", Description: "Must not match UUID, hex hash, or license patterns", Weight: 10},
		},

		PositiveKeywords: v.positiveKeywords,
		NegativeKeywords: v.negativeKeywords,

		Examples: []string{
			"ferret-scan --file config.yaml --checks OTP",
			"ferret-scan --file env-backup.txt --checks OTP --confidence high",
			"ferret-scan --file . --recursive --checks OTP,SECRETS",
		},
	}
}

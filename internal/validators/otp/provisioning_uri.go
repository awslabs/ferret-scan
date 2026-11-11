// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package otp

import "strings"

// carriesSecret reports whether an otpauth:// URI carries a shared secret: a secret= parameter
// (the key matched case-insensitively) whose value is not empty and not only an ellipsis.
//
// OTPAUTH_URI reports a provisioning URI because the URI holds the shared secret; the Key Uri
// Format makes that parameter REQUIRED, and docs/validators-new.md states the same contract ("must
// contain `secret=` parameter"). A URI without one, or with a placeholder for it, is the format
// written down rather than a provisioning URI (#940). Measured on main @ 2fb4719, each line alone
// in a file (--config /dev/null --confidence all):
//
//	"otpauth://totp/... or otpauth://hotp/... (provisioning URIs)",      OTPAUTH_URI 100 HIGH, twice
//	| `OTPAUTH_URI` | `otpauth://totp/...` or `otpauth://hotp/...` | ...  OTPAUTH_URI 100 HIGH, twice
//	otpauth://totp/ACME:alice@example.com?issuer=ACME                     OTPAUTH_URI 100 HIGH
//
// while the same URI with its published example secret reads 15 LOW, so the URI with nothing in
// it outranked the one that carries a secret.
//
// Such a URI is not reported as OTPAUTH_URI at all: nothing in it is the secret this type exists
// to protect. An account name in its label is still reported by the email validator, and a base32
// run inside the URI is still kept out of the OTP_SECRET pass by the URI's span, which the caller
// leaves in place.
//
// It walks the query once without allocating, so its cost is linear in the URI.
func carriesSecret(uri string) bool {
	q := strings.IndexByte(uri, '?')
	if q < 0 {
		return false
	}
	for rest := uri[q+1:]; rest != ""; {
		param := rest
		if amp := strings.IndexByte(rest, '&'); amp >= 0 {
			param, rest = rest[:amp], rest[amp+1:]
		} else {
			rest = ""
		}
		key, value, ok := strings.Cut(param, "=")
		if !ok || !strings.EqualFold(key, "secret") {
			continue
		}
		if strings.Trim(value, ".\u2026") != "" {
			return true
		}
	}
	return false
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"strings"
	"testing"
)

// An unquoted assignment is the dominant real-world form, and none could be detected.
//
// compileKeywordPatterns emits two patterns per keyword and both require ["'] on either side of
// the value, so nothing an unquoted assignment produces could match — while
// containsSecretIndicators admits exactly those lines and its comment promises them ("This
// catches cases like: api_key=abc123 or password:secret123"). The line was admitted and then no
// pattern could claim it, which is why the symptom looked like a scoring problem.
//
// Measured before this, with --checks SECRETS --confidence high,medium,low:
//
//	FOUND  password="Sup3rS3cretDbPass!"     MISS  password=Sup3rS3cretDbPass!
//	FOUND  password='Sup3rS3cretDbPass!'     MISS  api_key=abc12345678
//	FOUND  "password": "Sup3rS3cretDbPass!"  MISS  password: Sup3rS3cretDbPass!
//
// See #360.

// findsValue reports whether the validator produces a candidate covering want.
func findsValue(t *testing.T, line, want string) bool {
	t.Helper()
	v := NewValidator()
	for _, c := range v.findKeywordSecrets(line) {
		if strings.Contains(c.text, want) {
			return true
		}
	}
	return false
}

// The forms credentials actually take in .env, shell, CI, Dockerfile, ini and unquoted YAML.
func TestUnquotedAssignmentsAreDetected(t *testing.T) {
	cases := []struct {
		line, want string
	}{
		{"password=Sup3rS3cretDbPass!", "Sup3rS3cretDbPass!"},
		{"PASSWORD=hunter2XYZ", "hunter2XYZ"},
		{"db_password: Tr0ub4dor&3", "Tr0ub4dor"},
		{"DATABASE_PASSWORD=pgAdmin!2024x", "pgAdmin!2024x"},
		{"secret=Sup3rS3cretDbPass!", "Sup3rS3cretDbPass!"},
		{"api_key=abc12345678", "abc12345678"},
		{"export API_TOKEN=ghp_aBcD1234efGH5678ijKL", "ghp_aBcD1234efGH5678ijKL"},
		{"ENV DB_PASSWORD=hunter2XYZ", "hunter2XYZ"},
		// A real AWS secret access key contains '/', which is why '/' is not excluded from the
		// value: excluding it would remove file-path false positives at the cost of a real
		// credential class.
		//
		// Written as `secret=` rather than `AWS_SECRET_ACCESS_KEY=`, because in that name the
		// text between the keyword and the delimiter is "_ACCESS_KEY", so no keyword stem sits
		// adjacent to the '=' and this path is not what matches it — a provider-specific
		// pattern does. This case exercises the '/' allowance, which is the point.
		{"secret=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI/K7MDENG"},
	}

	for _, tc := range cases {
		t.Run(tc.line, func(t *testing.T) {
			if !findsValue(t, tc.line, tc.want) {
				t.Errorf("no candidate covering %q.\nThe quoted patterns require [\"'] on both "+
					"sides of the value, so an unquoted assignment matches nothing — and this is "+
					"the form .env, shell exports, CI variables and Dockerfile ENV all use.", tc.want)
			}
		})
	}
}

// Quoted assignments must keep working. The unquoted patterns are a separate set precisely so
// they cannot change the behaviour of the existing ones.
func TestQuotedAssignmentsStillDetected(t *testing.T) {
	for _, line := range []string{
		`password="Sup3rS3cretDbPass!"`,
		`password='Sup3rS3cretDbPass!'`,
		`"password": "Sup3rS3cretDbPass!"`,
		`api_key = "abc12345678"`,
	} {
		if !findsValue(t, line, "") {
			t.Errorf("quoted form stopped matching: %s", line)
		}
	}
}

// The false-positive class the value filter exists for.
//
// An unquoted capture takes whatever follows the delimiter, so without a filter a keyword in a
// log line or a doc turns prose into a HIGH-confidence credential. Measured on the naive
// pattern: "token: creating" and "password: something" both scored HIGH, and "secret:
// available" MEDIUM. A secrets validator that calls "something" a credential trains people to
// ignore it, which costs more than the detections gain.
func TestImplausibleUnquotedValuesAreRejected(t *testing.T) {
	cases := []struct {
		line, unwanted, why string
	}{
		{"token: creating", "creating", "an English word in a log line"},
		{"password: something", "something", "an English word"},
		{"secret: available", "available", "an English word"},
		{"password: required", "required", "an English word"},
		{"session_token: 550e8400-e29b-41d4-a716-446655440000", "550e8400", "a UUID identifies, it does not authenticate"},
		{"password: 4152671234", "4152671234", "all digits: a phone number or id"},
		{"api_key: 2024-01-15", "2024-01-15", "digits and hyphens: a date"},
		{"password: {{ .Values.dbPassword }}", "{{", "a template placeholder"},
		{"password: $DB_PASSWORD", "$DB", "a variable reference"},
		{"secret: <redacted>", "<redacted", "a sentinel"},
		{"api_key: [REDACTED]", "[REDACTED", "a redaction marker"},
	}

	for _, tc := range cases {
		t.Run(tc.line, func(t *testing.T) {
			if findsValue(t, tc.line, tc.unwanted) {
				t.Errorf("reported %q as a secret — %s", tc.unwanted, tc.why)
			}
		})
	}
}

// The stated cost of the lowercase rule, pinned so it is a decision rather than an accident.
//
// All-lowercase values shorter than 16 characters are rejected as prose. A genuine
// all-lowercase passphrase is longer than that, so it survives; a short all-lowercase secret
// does not, and that is deliberate.
func TestAllLowercaseValuesAreJudgedByLength(t *testing.T) {
	if findsValue(t, "password: something", "something") {
		t.Error("a 9-character all-lowercase word was accepted")
	}
	if !findsValue(t, "password: correcthorsebatterystaple", "correcthorsebatterystaple") {
		t.Error("a 25-character all-lowercase passphrase was rejected; the length floor exists " +
			"so that dictionary words are filtered without discarding real passphrases")
	}
}

// plausibleUnquotedSecret is the filter the whole separation exists for, so its contract is
// pinned directly rather than only through the validator.
func TestPlausibleUnquotedSecret(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{"Sup3rS3cretDbPass!", true},
		{"hunter2XYZ", true},
		{"abc12345678", true},
		{"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", true},
		{"correcthorsebatterystaple", true}, // long enough to be a passphrase
		{"MixedCaseNoDigits", true},         // uppercase present
		{"creating", false},                 // short all-lowercase prose
		{"something", false},
		{"4152671234", false},                           // all digits
		{"2024-01-15", false},                           // digits and hyphens
		{"550e8400-e29b-41d4-a716-446655440000", false}, // UUID
		{"550E8400-E29B-41D4-A716-446655440000", false}, // UUID, uppercase
		{"short", false},                                // under the 8-char floor
	}

	for _, tc := range cases {
		if got := plausibleUnquotedSecret(tc.value); got != tc.want {
			t.Errorf("plausibleUnquotedSecret(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

// The two keyword lists must stay in step: an unquoted assignment should be detectable for
// every keyword a quoted one is. Drift would mean a keyword silently loses unquoted coverage.
func TestUnquotedPatternsCoverEveryKeyword(t *testing.T) {
	v := NewValidator()
	if len(v.unquotedPatterns) != len(secretAssignmentKeywords) {
		t.Fatalf("compiled %d unquoted patterns for %d keywords",
			len(v.unquotedPatterns), len(secretAssignmentKeywords))
	}
	if len(v.unquotedPatterns) == 0 {
		t.Fatal("no unquoted patterns compiled")
	}
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import "testing"

// The placeholder list is spelled with underscores (your_api_key_here, replace_with_actual), so
// the same placeholder written with dashes or as a bare token was scored as a credential:
// `api_key=your-api-key` reported HIGH and `api_key=REPLACE_ME` MEDIUM. The check now compares
// the value with '-' read as '_' and case folded, still by whole-value equality, so a real secret
// that merely contains one of these words is unaffected.
func TestDashedAndBarePlaceholdersSuppressed(t *testing.T) {
	for _, line := range []string{
		"api_key=your-api-key",
		"api_key=REPLACE_ME",
		"api_key=replace-me",
		"api_key=your_api_key",
		"api_key=YOUR-API-KEY-HERE",
		"secret=your-secret",
		"password=your-password",
		"token=your-token",
		"api_key=insert-key-here",
		"api_key=replace-with-actual",
		`api_key = "your-api-key"`,
	} {
		t.Run(line, func(t *testing.T) {
			ms, err := NewValidator().ValidateContent(line+"\n", "settings.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			for _, m := range ms {
				t.Errorf("%q: reported %q as %s at %.0f, want no finding", line, m.Text, m.Type, m.Confidence)
			}
		})
	}
}

// Whole-value equality is what keeps the extension precision-only: a credential that contains a
// placeholder word, or ends in one, is still a credential.
func TestPlaceholderWordInsideRealSecretStillReported(t *testing.T) {
	for _, line := range []string{
		"api_key=Xk9mQ2vL8nR4pT6wZ3yB",
		"password=Changeme-Kp7Rq2Lx9Vw4",
		"api_key=your-api-key-Kp7Rq2Lx9Vw4Zt3",
		"secret=Replace_Me9Kp7Rq2Lx9Vw4Zt",
	} {
		t.Run(line, func(t *testing.T) {
			ms, err := NewValidator().ValidateContent(line+"\n", "settings.txt")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}
			if len(ms) == 0 {
				t.Errorf("%q: no finding, want the credential reported", line)
			}
		})
	}
}

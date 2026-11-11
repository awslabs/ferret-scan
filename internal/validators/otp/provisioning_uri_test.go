// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package otp

import (
	"strings"
	"testing"
)

func TestCarriesSecret(t *testing.T) {
	cases := map[string]bool{
		"otpauth://totp/A:b?secret=K5CU":          true,
		"otpauth://totp/A:b?issuer=A&secret=K5CU": true,
		"otpauth://totp/A:b?Secret=K5CU":          true,
		"otpauth://totp/A:b?secret=K5CU#frag":     true,
		"otpauth://totp/A:b?secret=.K5CU.":        true,
		"otpauth://totp/A:b":                      false,
		"otpauth://totp/...":                      false,
		"otpauth://totp/A:b?":                     false,
		"otpauth://totp/A:b?secret":               false,
		"otpauth://totp/A:b?secret=":              false,
		"otpauth://totp/A:b?secret=...":           false,
		"otpauth://totp/A:b?secret=\u2026":        false,
		"otpauth://totp/A:b?secrets=K5CU":         false,
		"otpauth://totp/A:b?xsecret=K5CU":         false,
		"otpauth://totp/A:b?&&&":                  false,
	}
	for uri, want := range cases {
		if got := carriesSecret(uri); got != want {
			t.Errorf("carriesSecret(%q) = %v, want %v", uri, got, want)
		}
	}
	// Linear in the URI: a query of many empty parameters is one pass.
	long := "otpauth://totp/A:b?" + strings.Repeat("&", 1<<20) + "secret=K5CU"
	if !carriesSecret(long) {
		t.Error("carriesSecret missed a secret after a long run of empty parameters")
	}
}

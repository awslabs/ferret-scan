// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"testing"
)

// The #753 lexical gate reads the file type from the NAME the caller supplies, on every channel. A
// ScanText Label is that name, so a library caller scanning TypeScript held in memory gets the
// same behaviour as the CLI scanning x.ts -- and a label with no extension (the default "<text>",
// "clipboard") keeps today's behaviour, because nothing says what grammar the bytes are in.
//
// The bytes are the #753 contrast: in TypeScript `token: AuthToken` is a type annotation, in YAML
// an unquoted scalar is a value.
func TestScanTextLabelDecidesTheSourceGate(t *testing.T) {
	const body = "token: AuthToken\npassword: MixedCaseNoDigits\n"
	cases := []struct {
		label string
		want  int
	}{
		{"x.ts", 0},
		{"src/models.py", 0},
		{"", 2}, // defaults to "<text>"
		{"clipboard", 2},
		{"settings.yaml", 2},
		{"x.tsx", 2},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			res, err := ScanText(context.Background(), body, TextOptions{
				Checks: []string{"SECRETS"}, Label: tc.label, DisableConfigDiscovery: true,
			})
			if err != nil {
				t.Fatalf("ScanText: %v", err)
			}
			if len(res.Findings) != tc.want {
				t.Errorf("label %q: %d findings, want %d: %+v", tc.label, len(res.Findings), tc.want, res.Findings)
			}
		})
	}
}

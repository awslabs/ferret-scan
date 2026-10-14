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

// A ScanText caller hands the bytes over as they are, so a Windows-1252 smart quote arrives as the
// raw byte 0x93 rather than the U+0093 a file decodes to. In code position it is not valid source
// in any gated grammar, so the gate fails open and both lines report exactly as on an ungated
// label; the same text with ASCII quotes is valid Python, and the type annotation drops.
func TestScanTextFailsOpenOnARawWindows1252Quote(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       int
	}{
		{"raw cp1252 quotes", "token: AuthToken\npassword = \x93MixedCaseNoDigits\x94\n", 2},
		{"ASCII quotes", "token: AuthToken\npassword = \"MixedCaseNoDigits\"\n", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ScanText(context.Background(), tc.body, TextOptions{
				Checks: []string{"SECRETS"}, Label: "settings.py", DisableConfigDiscovery: true,
			})
			if err != nil {
				t.Fatalf("ScanText: %v", err)
			}
			if len(res.Findings) != tc.want {
				t.Errorf("%d findings, want %d: %+v", len(res.Findings), tc.want, res.Findings)
			}
		})
	}
}

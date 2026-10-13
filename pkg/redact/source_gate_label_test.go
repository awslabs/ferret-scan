// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"context"
	"strings"
	"testing"
)

// A Redact Label names the grammar the #753 lexical gate reads, exactly as a ScanText label and a
// CLI path do. Under a .ts label a type annotation is not a credential, so it is not rewritten --
// which is the corruption the gate removes: redacting `token: AuthToken` in a typed codebase
// replaced the TYPE. With no extension the bytes keep today's treatment.
func TestRedactLabelDecidesTheSourceGate(t *testing.T) {
	const body = "token: AuthToken\n"
	for _, tc := range []struct {
		label   string
		changed bool
	}{
		{"models.ts", false},
		{"", true}, // defaults to "<request>"
		{"settings.yaml", true},
	} {
		t.Run(tc.label, func(t *testing.T) {
			eng, err := NewEngine(EngineOptions{Checks: []string{"SECRETS"}, Strategy: Simple})
			if err != nil {
				t.Fatalf("NewEngine: %v", err)
			}
			defer func() { _ = eng.Close() }()
			res, err := eng.Redact(context.Background(), Request{Text: body, Label: tc.label})
			if err != nil {
				t.Fatalf("Redact: %v", err)
			}
			if got := res.Redacted != body; got != tc.changed {
				t.Errorf("label %q: redacted=%v, want %v; output %q", tc.label, got, tc.changed, res.Redacted)
			}
		})
	}
}

// The sink for a raw Windows-1252 smart quote (Redact, like ScanText, receives the bytes as they
// are): the gate fails open, so the value between the quotes is reported and rewritten, as it is
// under an ungated label. With the gate active on that line the value would be dropped as code and
// left in cleartext in the redacted text.
func TestRedactFailsOpenOnARawWindows1252Quote(t *testing.T) {
	const value = "MixedCaseNoDigits"
	body := "password = \x93" + value + "\x94\n"
	eng, err := NewEngine(EngineOptions{Checks: []string{"SECRETS"}, Strategy: Simple})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer func() { _ = eng.Close() }()
	for _, label := range []string{"settings.py", "notes"} {
		res, err := eng.Redact(context.Background(), Request{Text: body, Label: label})
		if err != nil {
			t.Fatalf("Redact: %v", err)
		}
		if strings.Contains(res.Redacted, value) {
			t.Errorf("label %q: the value survived redaction: %q", label, res.Redacted)
		}
	}
}

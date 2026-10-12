// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"context"
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

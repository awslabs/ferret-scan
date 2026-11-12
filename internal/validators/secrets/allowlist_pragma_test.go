// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// pragmaFind returns the finding whose Text is text, or nil.
func pragmaFind(ms []detector.Match, text string) *detector.Match {
	for i := range ms {
		if ms[i].Text == text {
			return &ms[i]
		}
	}
	return nil
}

// Tests for the allowlist pragma (allowlist_pragma.go, #933): its words do not label the value
// beside them, and it does not exempt its line. Values come from synth/hexBody, built at run time.

func TestAllowlistPragmaIsNotALabel(t *testing.T) {
	v := NewValidator()
	digest := hexBody(933, 64)
	pragma := "pragma: " + "allowlist secret"
	cases := []struct{ path, plain, withPragma string }{
		{"rules.yaml", `hash: "` + digest + `"`, `hash: "` + digest + `" # ` + pragma},
		{"edge_test.go", `	"` + digest + `",`, `	"` + digest + `", // ` + pragma},
		{"guide.md", `    hash: "` + digest + `"`, `    hash: "` + digest + `" # ` + pragma},
	}
	for _, c := range cases {
		a, _ := v.ValidateContent(c.plain+"\n", c.path)
		b, _ := v.ValidateContent(c.withPragma+"\n", c.path)
		if len(a) != len(b) {
			t.Errorf("%s: %d findings without the pragma, %d with it", c.path, len(a), len(b))
			continue
		}
		for i := range a {
			if a[i].Text != b[i].Text || a[i].Confidence != b[i].Confidence || a[i].LineNumber != b[i].LineNumber {
				t.Errorf("%s: pragma moved a finding: %q %.0f -> %q %.0f", c.path, a[i].Text, a[i].Confidence, b[i].Text, b[i].Confidence)
			}
			if b[i].Confidence >= 60 {
				t.Errorf("%s: digest beside the pragma reported at %.0f, want < 60", c.path, b[i].Confidence)
			}
		}
	}
}

// TestAllowlistPragmaDoesNotExempt: a credential on a line carrying the pragma is reported exactly
// as it is without it. A typed comment is not a suppression mechanism.
func TestAllowlistPragmaDoesNotExempt(t *testing.T) {
	v := NewValidator()
	val := synth(933)
	plain := `api_key = "` + val + `"`
	a, _ := v.ValidateContent(plain+"\n", "settings.py")
	b, _ := v.ValidateContent(plain+"  # pragma: "+"allowlist secret\n", "settings.py")
	if m := pragmaFind(b, val); m == nil || m.Confidence < 60 {
		t.Fatalf("credential beside the pragma not reported at >= 60: %+v", b)
	}
	if ma, mb := pragmaFind(a, val), pragmaFind(b, val); ma == nil || ma.Confidence != mb.Confidence {
		t.Errorf("pragma changed the credential's score: %+v vs %+v", ma, mb)
	}
	if got, want := blankAllowlistPragma("x # Pragma: AllowList nextline secret"), "x # "+strings.Repeat(" ", 33); got != want {
		t.Errorf("blankAllowlistPragma: %q", got)
	}
}

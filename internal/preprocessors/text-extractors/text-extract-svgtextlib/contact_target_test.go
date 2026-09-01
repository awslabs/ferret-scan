// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package textextractsvgtextlib

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Excluding EVERY href traded a coordinate flood for a real miss, and this is the narrowest rule that
// keeps the first without paying the second.
//
// Measured on a diagram whose only contact is the target of an <a> wrapping a "Contact the owner"
// label — the commonest way a real drawing carries one:
//
//	pre-rule   0 findings   (the address is in the attribute, and no attribute was read)
//	post-rule  4 findings   (3 BUSINESS + 1 PHONE)
//
// And the flood stays out, because the rule admits two SCHEMES rather than an attribute:
//
//	400 real SVGs from /Applications, /Library, /System/Library   394 -> 1 finding (125 HIGH -> 0)
//	300 <a> elements with numeric https CDN asset URLs            265 -> 0 findings
//
// The 265 is the number that justifies the scheme restriction rather than admitting href outright.

func TestContactTargetAdmitsOnlyContactSchemes(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want string // "" means not admitted
	}{
		// Admitted.
		{"mailto", "mailto:margaret.halloway@corp.example.com", "margaret.halloway@corp.example.com"},
		{"tel", "tel:+14159263481", "+14159263481"},
		{"uppercase scheme", "MAILTO:ops@corp.example.com", "ops@corp.example.com"},
		{"mixed-case tel", "TeL:+14159263481", "+14159263481"},
		{"percent-encoded at sign", "mailto:dana%40corp.example.com", "dana@corp.example.com"},
		{"mailto with a subject query", "mailto:ops@corp.example.com?subject=Help%20me", "ops@corp.example.com"},
		{"leading and trailing space", "  mailto:a@b.example  ", "a@b.example"},
		{"tel with separators", "tel:+1-415-926-3481", "+1-415-926-3481"},

		// NOT admitted — this is the half that keeps the flood out.
		{"https asset url", "https://cdn.example.com/asset/1234567890/v2", ""},
		{"http", "http://example.com/1234567890", ""},
		{"data uri", "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg==", ""},
		{"fragment reference", "#gradient-1234567890", ""},
		{"relative path", "../assets/1234567890.png", ""},
		{"bare scheme, no value", "mailto:", ""},
		{"scheme with only a query", "mailto:?subject=hi", ""},
		{"scheme-like prose", "email me at mailto:a@b.example", ""},
		{"empty", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := contactTarget(tc.raw)
			if tc.want == "" {
				if ok {
					t.Errorf("contactTarget(%q) admitted %q; it must not.\n"+
						"Admitting a non-contact target is what re-opens the flood: 300 numeric CDN "+
						"asset URLs produced 256 PHONE and 9 NPI findings, every one false.", tc.raw, got)
				}
				return
			}
			if !ok {
				t.Fatalf("contactTarget(%q) declined it; a contact in a link target is the commonest "+
					"place a real diagram carries one, and excluding it costs a HIGH finding.", tc.raw)
			}
			if got != tc.want {
				t.Errorf("contactTarget(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

// TestTelPlusSurvives pins the specific bug PathUnescape fixes. QueryUnescape decodes "+" to a SPACE,
// so "tel:+14159263481" became "14159263481" and PHONE then declined it — the recall this rule exists
// to restore, lost inside the rule itself.
func TestTelPlusSurvives(t *testing.T) {
	got, ok := contactTarget("tel:+14159263481")
	if !ok {
		t.Fatal("tel: target not admitted")
	}
	if !strings.HasPrefix(got, "+") {
		t.Errorf("contactTarget stripped the international prefix: got %q, want a leading '+'.\n"+
			"url.QueryUnescape decodes '+' to a space; a tel: URI is a path, so PathUnescape is the "+
			"correct decoder.", got)
	}
}

// TestSchemeFilteredExtractionEndToEnd drives the extractor rather than the helper, so a future edit
// that stops CALLING contactTarget is caught. Testing the helper alone leaves that mutation surviving.
func TestSchemeFilteredExtractionEndToEnd(t *testing.T) {
	const doc = `<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <path d="M 452111 9384123 L 4155512 9263451 Z"/>
  <text>Network Diagram</text>
  <a xlink:href="mailto:margaret.halloway@corp.example.com"><text>Contact the owner</text></a>
  <a href="TEL:+14159263481"><text>On-call</text></a>
  <a href="https://cdn.example.com/asset/1234567890/v2"><text>asset</text></a>
</svg>`

	dir := t.TempDir()
	path := filepath.Join(dir, "diagram.svg")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	tc, err := ExtractText(path)
	if err != nil {
		t.Fatalf("ExtractText: %v", err)
	}
	got := tc.Text

	for _, want := range []string{"margaret.halloway@corp.example.com", "+14159263481", "Network Diagram"} {
		if !strings.Contains(got, want) {
			t.Errorf("extraction is missing %q:\n%s", want, got)
		}
	}
	// The geometry and the https target must NOT be extracted.
	for _, bad := range []string{"452111", "9384123", "cdn.example.com", "1234567890"} {
		if strings.Contains(got, bad) {
			t.Errorf("extraction admitted %q, which is geometry or a non-contact target:\n%s", bad, got)
		}
	}
}

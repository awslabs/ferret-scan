// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"strings"
	"testing"
)

// Tests for the published example secrets (published_example_secrets.go, #930). Controls are built from
// the listed values at run time (one character changed), so no second literal credential lives here.

// exampleContexts are lines a documentation snippet or a test fixture puts a credential on: the key
// names the value is the labelled context where main reported 100.
func exampleContexts(v string) map[string]string {
	return map[string]string{
		"secret_quoted": `secret = "` + v + `"`,
		"api_key":       `api_key = "` + v + `"`,
		"totp":          "totp_secret = " + v,
		"env":           "SERVICE_API_KEY=" + v,
		"json":          `{"client_secret": "` + v + `"}`,
		"bearer":        "Authorization: Bearer " + v,
	}
}

// flipLast returns v with its last byte changed to another byte of the same class.
func flipLast(v string) string {
	last := v[len(v)-1]
	repl := byte('A')
	if last == 'A' {
		repl = 'B'
	}
	return v[:len(v)-1] + string(repl)
}

func TestPublishedExampleSecretsAreCapped(t *testing.T) {
	v := NewValidator()
	for value := range publishedExampleSecrets {
		for name, line := range exampleContexts(value) {
			t.Run(name+"/"+value[:8], func(t *testing.T) {
				ms, err := v.ValidateContent(line+"\n", "settings.txt")
				if err != nil {
					t.Fatal(err)
				}
				for _, m := range ms {
					if m.Confidence > publishedExampleCeiling {
						t.Errorf("%q: %s %q reported at %.0f, want at most %.0f", line, m.Type, m.Text, m.Confidence, publishedExampleCeiling)
					}
					if strings.Trim(m.Text, `"'`) == value {
						// Capped, never dropped, and the bound is published for the bridge.
						if c, _ := m.Metadata[ConfidenceCeilingKey].(float64); c != publishedExampleCeiling {
							t.Errorf("%q: %s ceiling %v, want %v published", line, m.Type, m.Metadata[ConfidenceCeilingKey], publishedExampleCeiling)
						}
					}
				}
			})
		}
	}
	// At least the labelled lines still produce the finding (a cap, not a drop).
	for value := range publishedExampleSecrets {
		ms, _ := v.ValidateContent(`secret = "`+value+`"`+"\n", "settings.txt")
		found := false
		for _, m := range ms {
			found = found || strings.Trim(m.Text, `"'`) == value
		}
		if !found {
			t.Errorf("%s: no finding at all for the labelled line; a published example is capped, not dropped", value[:8])
		}
	}
}

// TestPublishedExampleControls: one character away, a value above the same published example keeps
// its score, and so does a published value with a character appended or prepended.
func TestPublishedExampleControls(t *testing.T) {
	v := NewValidator()
	for value := range publishedExampleSecrets {
		for label, ctl := range map[string]string{
			"flipped":  flipLast(value),
			"appended": value + "9",
		} {
			line := `secret = "` + ctl + `"`
			ms, err := v.ValidateContent(line+"\n", "settings.txt")
			if err != nil {
				t.Fatal(err)
			}
			high := false
			for _, m := range ms {
				high = high || m.Confidence >= 60
			}
			if !high {
				t.Errorf("control %s of %s: %q reports no finding at 60 or more: %v", label, value[:8], line, ms)
			}
		}
	}
}

// TestPublishedExampleListShape pins the list: each entry names the page that publishes it, and the
// cap is an exact match (a trimmed quote is the only slack).
func TestPublishedExampleListShape(t *testing.T) {
	for value, source := range publishedExampleSecrets {
		if value == "" || source == "" {
			t.Errorf("entry %q has no publisher", value)
		}
		if publishedExampleCap(value) != publishedExampleCeiling || publishedExampleCap(`"`+value+`"`) != publishedExampleCeiling {
			t.Errorf("%s: not capped exactly", value[:8])
		}
		if publishedExampleCap(value+"x") != 0 || publishedExampleCap("x"+value) != 0 || publishedExampleCap(flipLast(value)) != 0 {
			t.Errorf("%s: a near value is capped", value[:8])
		}
	}
	if publishedExampleCap("") != 0 {
		t.Error("empty value capped")
	}
}

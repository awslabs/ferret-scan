// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"strings"
	"testing"
)

// The #931 residuals: prose that says where a token goes, an angle-bracket redaction marker and an
// index expression. Credential-shaped controls are synthetic (synth, source_gate_test.go).

func TestResidualNonLiteralShapes(t *testing.T) {
	for _, v := range []string{
		"your-bot-token-goes-here-replace-me",
		"replace-with-your-token",
		"paste-your-token-here",
		"<REDACTED>",
		"<redacted>",
		"<API-KEY-REMOVED>",
		"<token_masked>",
		"os.environ[",
		`os.environ["SECRET_KEY"]`,
		"process.env['JWT_SECRET']",
		"config.secrets[0]",
	} {
		if !nonLiteralValue(v, true) {
			t.Errorf("nonLiteralValue(%q) = false, want true", v)
		}
	}
	controls := []string{
		"correct-horse-battery-staple",    // a passphrase: no marker word
		"my-example-passphrase-horse",     // one marker word, not two
		"your-token",                      // two words
		"Your-Bot-Token-Goes-Here",        // upper case: not the lower-case sentence
		"your-b0t-token-goes-here",        // a digit: not a word
		"<Sup3rS3cret>",                   // brackets around a password
		"<redacted-by-" + synth(31) + ">", // the last word is not a redaction word
		"Pa55word[",                       // no dotted chain
		"k7Fq.9xLm2P[",                    // dotted, but not identifier words
		"os.environ[" + synth(32),         // an index that opens on a credential
		"<" + synth(33) + ">",             // brackets around a generated value
	}
	for _, v := range controls {
		if nonLiteralValue(v, true) {
			t.Errorf("control nonLiteralValue(%q) = true, want false", v)
		}
	}
	// The index expression is an expression shape: off with the flag. The other two are not.
	if nonLiteralValue("os.environ[", false) {
		t.Error("index expression rejected with expressions=false")
	}
	if !nonLiteralValue("<REDACTED>", false) || !nonLiteralValue("replace-with-your-token", false) {
		t.Error("marker or prose rejected only with expressions=true")
	}
}

// TestResidualNonLiteralValuesNotReported is the end to end reading: on main each decoy reported
// API_KEY_OR_SECRET at 75 or 100, and the same keys with a credential-shaped value still report.
func TestResidualNonLiteralValuesNotReported(t *testing.T) {
	v := NewValidator()
	decoys := []struct{ path, line string }{
		{"settings.txt", "token = your-bot-token-goes-here-replace-me"},
		{"settings.txt", "token = replace-with-your-token"},
		{"settings.yaml", `secret: "<REDACTED>"`},
		{"settings.txt", `secret = os.environ["SECRET_KEY"]`},
		{"settings.txt", `api_key = "paste-your-api-key-here"`},
		{"README.md", "password = <redacted>"},
	}
	for _, d := range decoys {
		ms, err := v.ValidateContent(d.line+"\n", d.path)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range ms {
			t.Errorf("%s: %q reported %s %.0f", d.path, m.Text, m.Type, m.Confidence)
		}
	}
	for i, c := range []struct{ path, key string }{
		{"settings.txt", "token = "}, {"settings.txt", "secret = "}, {"settings.yaml", "secret: "},
		{"settings.txt", `api_key = "`}, {"settings.txt", "password = "},
	} {
		val := synth(40 + i)
		line := c.key + val
		if strings.HasSuffix(c.key, `"`) {
			line += `"`
		}
		ms, _ := v.ValidateContent(line+"\n", c.path)
		found := false
		for _, m := range ms {
			found = found || strings.Contains(m.Text, val) && m.Confidence >= 60
		}
		if !found {
			t.Errorf("control %q not reported at >= 60: %+v", line, ms)
		}
	}
}

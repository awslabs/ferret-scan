// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"strings"
	"testing"
)

// Tests for non-literal assignment values (non_literal_values.go, #931 and #981's marker half).
// Credential-shaped controls are synthetic: synth(n) (source_gate_test.go) builds them at run time.

// TestNonLiteralValueShapes pins the predicate: each non-literal shape is rejected, and each
// credential-shaped control next to it is not.
func TestNonLiteralValueShapes(t *testing.T) {
	for _, v := range []string{
		`\\b(Confidential|Trade\\s+Secret|Proprietary)\\b`,
		`\b(Trade\s+Secret)\b` + "`",
		`^\d{3}-\d{2}-\d{4}$`,
		"/etc/ssl/private/server.key",
		"~/keys/id_ed25519.pub",
		"./conf/app.pem",
		`C:\app\conf\abc.pem`,
		"config.secret_key`",
		"this.form.value.password`",
		"process.env.JWT_SECRET",
		"os.getenv(DB_PASSWORD_ENV",
		"os.getenv(DB_PASSWORD_ENV)",
		"+joinedValues[2]+",
		"[API_KEY_OR_SECRET-REDACTED]",
		"[CREDIT-CARD-REDACTED]",
		`[SSH_PRIVATE_KEY-REDACTED]\n`,
		"****-****-****-****",
		"**** **** **** ****",
		"glpat-xxxxxxxxxxxxxxxxxxxx",
		"xoxb-not-a-real-token-this-will-not-work",
	} {
		if !nonLiteralValue(v, true) {
			t.Errorf("nonLiteralValue(%q) = false, want true", v)
		}
	}
	controls := []string{
		synth(1),                        // generated alphanumerics
		"/9j/4AAQSkZJRgABAQ" + synth(2), // base64 that starts with '/'
		"/Zq7.Kp9xW2" + synth(3),        // rooted, but a segment mixes cases and digits
		"Pa55(word" + synth(4),          // a password with a parenthesis: no dotted callee
		`Xk9\d` + synth(5),              // a backslash class escape with no regex operator
		"k7Fq.9xLm2P" + synth(6),        // dotted, but not identifier words
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0." + synth(7), // JWT-shaped
		"glpat-" + synth(8), // a provider prefix with a real-shaped body
		"xoxb-" + synth(9) + "-" + synth(10),
		"[" + synth(11) + "]", // brackets, but not the marker
		"****" + synth(12),    // a mask with real characters left
	}
	for _, v := range controls {
		if nonLiteralValue(v, true) {
			t.Errorf("control nonLiteralValue(%q) = true, want false", v)
		}
	}
	// The expression shapes are switched off by the flag; the others are not.
	if nonLiteralValue("config.secret_key", false) {
		t.Error("member chain rejected with expressions=false")
	}
	if !nonLiteralValue("[API_KEY_OR_SECRET-REDACTED]", false) {
		t.Error("marker kept with expressions=false")
	}
}

// TestNonLiteralValuesNotReported: lines main reported at 75-100 report nothing; the same keys with
// a credential-shaped value still report.
func TestNonLiteralValuesNotReported(t *testing.T) {
	v := NewValidator()
	decoys := []struct{ path, line string }{
		{"config.yaml", `trade_secret: "\\b(Confidential|Trade\\s+Secret|Proprietary)\\b"`},
		{"renewal.conf", "private_key=/etc/ssl/private/server.key"},
		{"README.md", "Use `secret = config.secret_key` in application code."},
		{"overlap.txt", `password = "[API_KEY_OR_SECRET-REDACTED]"`},
		{"key.json", `{"private_key": "[SSH_PRIVATE_KEY-REDACTED]\n"}`},
		{"card.txt", `card_token = "****-****-****-****"`},
		{"README.md", "GITLAB_TOKEN=glpat-xxxxxxxxxxxxxxxxxxxx"},
		{"slack.env", "SLACK_BOT_TOKEN=xoxb-not-a-real-token-this-will-not-work"},
		{"app.env", "jwt_secret = process.env.JWT_SECRET"},
		{"settings.txt", "password = os.getenv(DB_PASSWORD_ENV)"},
		{"probe.txt", `apikey = "+joinedValues[2]+"`},
		// Quoted in an expression-language file: a string literal's text is judged here.
		{"fixture_test.go", `const line = "jwt_secret = process.env.JWT_SECRET"`},
	}
	for _, d := range decoys {
		ms, err := v.ValidateContent(d.line+"\n", d.path)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range ms {
			t.Errorf("%s: %q reported %s %.0f (%v)", d.path, m.Text, m.Type, m.Confidence, m.Metadata["detection_method"])
		}
	}
	for _, c := range []struct{ path, line, value string }{
		{"config.yaml", `trade_secret: "` + synth(21) + `"`, synth(21)},
		{"renewal.conf", "private_key=" + synth(22), synth(22)},
		{"overlap.txt", `password = "` + synth(23) + `"`, synth(23)},
		{"app.env", "jwt_secret = " + synth(24), synth(24)},
	} {
		ms, _ := v.ValidateContent(c.line+"\n", c.path)
		found := false
		for _, m := range ms {
			found = found || strings.Contains(m.Text, c.value) && m.Confidence >= 60
		}
		if !found {
			t.Errorf("control %s: %q not reported at >= 60: %+v", c.path, c.line, ms)
		}
	}
}

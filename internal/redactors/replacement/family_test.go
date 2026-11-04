// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package replacement

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// What each family renders, by Type (#864). The email validator reports 24 Type values and the
// renderers listed three of them, so 21 took the generic arm in every strategy.

// emailProviderTypes is internal/validators/email's getEmailProviderType range, in its order.
// family_guard_test.go checks the list against the validator's source.
var emailProviderTypes = []string{
	"EMAIL", "GMAIL", "GOOGLE_WORKSPACE", "OUTLOOK", "MICROSOFT_365", "YAHOO", "ICLOUD",
	"APPLE_CORPORATE", "AOL", "PROTONMAIL", "TUTANOTA", "FASTMAIL", "ZOHO", "YANDEX", "MAIL_RU",
	"SALESFORCE", "SLACK", "ATLASSIAN", "GITHUB", "GITLAB", "EDUCATIONAL", "GOVERNMENT",
	"DISPOSABLE", "BUSINESS",
}

func TestEveryEmailTypeRendersAsAnEmail(t *testing.T) {
	const addr = "zz.synthetic.0004@outlook.com"
	for _, typ := range emailProviderTypes {
		if got := gen(t, addr, typ, redactors.RedactionSimple); got != "[EMAIL-REDACTED]" {
			t.Errorf("simple %s = %q, want [EMAIL-REDACTED]: the placeholder must not name the provider", typ, got)
		}
		if got := gen(t, addr, typ, redactors.RedactionFormatPreserving); got != "z****************@outlook.com" {
			t.Errorf("format_preserving %s = %q, want the first character and the domain kept", typ, got)
		}
		got := gen(t, addr, typ, redactors.RedactionSynthetic)
		if !strings.HasSuffix(got, "@example.com") || strings.Contains(got, "zz.synthetic") {
			t.Errorf("synthetic %s = %q, want a random local part at example.com", typ, got)
		}
		// Kept counts letters and digits: the first character and the domain's ten ("outlookcom").
		if r := rend(t, addr, typ, redactors.RedactionFormatPreserving); r.Kept() != 1+len("outlookcom") {
			t.Errorf("format_preserving %s keeps %d value bytes, want %d (first character and domain)",
				typ, r.Kept(), 1+len("outlookcom"))
		}
	}
}

// An address and a profile are both reported as GITHUB, by different validators. The value decides.
func TestGitHubRendersByWhatTheValueIs(t *testing.T) {
	const addr = "zz.synthetic.0019@github.com"
	const profile = "https://github.com/zz-synthetic-0002"

	if got := gen(t, addr, "GITHUB", redactors.RedactionSimple); got != "[EMAIL-REDACTED]" {
		t.Errorf("simple, address = %q", got)
	}
	if got := gen(t, addr, "GITHUB", redactors.RedactionFormatPreserving); got != "z****************@github.com" {
		t.Errorf("format_preserving, address = %q", got)
	}
	if got := gen(t, addr, "GITHUB", redactors.RedactionSynthetic); !strings.HasSuffix(got, "@example.com") {
		t.Errorf("synthetic, address = %q: an address at github.com must stay an address, not become a profile URL", got)
	}

	if got := gen(t, profile, "GITHUB", redactors.RedactionSimple); got != "[SOCIAL-MEDIA-REDACTED]" {
		t.Errorf("simple, profile = %q", got)
	}
	if got := gen(t, profile, "GITHUB", redactors.RedactionFormatPreserving); got != strings.Repeat("*", len(profile)) {
		t.Errorf("format_preserving, profile = %q: a profile is masked whole, as before", got)
	}
	got := gen(t, profile, "GITHUB", redactors.RedactionSynthetic)
	if !strings.HasPrefix(got, "https://github.com/") || strings.Contains(got, "@") || strings.Contains(got, "zz-synthetic") {
		t.Errorf("synthetic, profile = %q, want a fake profile URL on github.com", got)
	}
	// Simple has no value; the documented choice for the shared type.
	if got := Simple("GITHUB"); got != "[SOCIAL-MEDIA-REDACTED]" {
		t.Errorf("Simple(GITHUB) = %q", got)
	}
}

func TestEverySocialMediaTypeRendersAsAProfile(t *testing.T) {
	for _, c := range []struct{ typ, url, host string }{
		{"LINKEDIN", "https://www.linkedin.com/in/zz-synthetic-0001", "https://www.linkedin.com/in/"},
		{"GITHUB", "https://github.com/zz-synthetic-0002", "https://github.com/"},
		{"TWITTER", "https://twitter.com/zz_synthetic", "https://x.com/"},
		{"REDDIT", "https://www.reddit.com/user/zz-synthetic", "https://www.reddit.com/user/"},
		{"SOCIAL_MEDIA", "https://www.linkedin.com/in/zz-synthetic-0003", "https://www.linkedin.com/in/"},
	} {
		if got := gen(t, c.url, c.typ, redactors.RedactionSimple); got != "[SOCIAL-MEDIA-REDACTED]" {
			t.Errorf("simple %s = %q, want [SOCIAL-MEDIA-REDACTED]: the placeholder must not name the platform", c.typ, got)
		}
		if got := gen(t, c.url, c.typ, redactors.RedactionSynthetic); !strings.HasPrefix(got, c.host) || strings.Contains(got, "zz") {
			t.Errorf("synthetic %s = %q, want a fake profile under %s", c.typ, got, c.host)
		}
		if got := gen(t, c.url, c.typ, redactors.RedactionFormatPreserving); got != strings.Repeat("*", len(c.url)) {
			t.Errorf("format_preserving %s = %q, want the mask it always was", c.typ, got)
		}
	}
	// The rest of the platform range takes the same arm; a handle has no host to keep.
	for typ := range socialMediaTypes {
		if typ == "GITHUB" {
			continue
		}
		if got := gen(t, "@zz_synthetic_handle", typ, redactors.RedactionSynthetic); !strings.HasPrefix(got, "@") || strings.Contains(got, "zz_synthetic") {
			t.Errorf("synthetic %s handle = %q, want a fake handle", typ, got)
		}
	}
}

// Decoys: what must NOT change.
func TestFamiliesLeaveEverythingElseAlone(t *testing.T) {
	// The metadata validator reports an address in document properties as EMAIL; it renders as before.
	if got := gen(t, "zz.synthetic.0004@outlook.com", "EMAIL", redactors.RedactionFormatPreserving); got != "z****************@outlook.com" {
		t.Errorf("metadata EMAIL = %q", got)
	}
	// Secrets keep their typed simple markers; only the dead SECRETS arm is gone.
	for typ, want := range map[string]string{
		"GITHUB_TOKEN":          "[GITHUB_TOKEN-REDACTED]",
		"AWS_ACCESS_KEY":        "[AWS_ACCESS_KEY-REDACTED]",
		"AWS_SECRET_ACCESS_KEY": "[AWS_SECRET_ACCESS_KEY-REDACTED]",
		"API_KEY_OR_SECRET":     "[API_KEY_OR_SECRET-REDACTED]",
		"SLACK_TOKEN":           "[SLACK_TOKEN-REDACTED]",
	} {
		if got := Simple(typ); got != want {
			t.Errorf("Simple(%s) = %q, want %q", typ, got, want)
		}
	}
	// The single-type families are untouched.
	for typ, want := range map[string]string{
		"SSN": "[SSN-REDACTED]", "PHONE": "[PHONE-REDACTED]", "VISA": "[CREDIT-CARD-REDACTED]",
		"PERSON_NAME": "[PERSON-NAME-REDACTED]", "IBAN": "[IBAN-REDACTED]",
	} {
		if got := Simple(typ); got != want {
			t.Errorf("Simple(%s) = %q, want %q", typ, got, want)
		}
	}
	// A provider-named type that is not an address (a SLACK_TOKEN is not SLACK) stays a secret.
	if got := gen(t, "xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx", "SLACK_TOKEN", redactors.RedactionSynthetic); !strings.HasPrefix(got, "xoxb-") {
		t.Errorf("synthetic SLACK_TOKEN = %q", got)
	}
}

// AWS_SECRET_ACCESS_KEY was the one secret type synthetic's secrets arm did not list.
func TestEverySecretTypeReachesTheSecretGenerator(t *testing.T) {
	const v = "zZ9yY8xX7wW6vV5uU4tT3sS2rR1qQ0pPoOnNmMlL"
	got, err := Synthetic(v, "AWS_SECRET_ACCESS_KEY")
	if err != nil || len(got) != len(v) || got == v {
		t.Fatalf("synthetic AWS_SECRET_ACCESS_KEY = %q, %v", got, err)
	}
	for typ := range secretTypes {
		if !secretTypes[typ] || isEmailType(typ, v) || isSocialMediaType(typ, v) {
			t.Errorf("%s does not route to the secret generator alone", typ)
		}
	}
}

// An overlap group's placeholder is its representative's, decided by the representative's value.
func TestGroupPlaceholderFollowsTheFamily(t *testing.T) {
	line := "owner zz.synthetic.0004@outlook.com"
	ms := []detector.Match{
		{Text: "zz.synthetic.0004@outlook.com", Type: "OUTLOOK", Validator: "email", Confidence: 100, LineNumber: 1, Context: detector.ContextInfo{FullLine: line}},
		{Text: "zz.synthetic.0004@outlook.com", Type: "EMAIL", Validator: "metadata", Confidence: 50, LineNumber: 1, Context: detector.ContextInfo{FullLine: line}},
	}
	groups := redactors.ResolveOverlaps(ms)
	if len(groups) != 1 || !groups[0].IsGroup() {
		t.Fatalf("fixture did not form one group: %+v", groups)
	}
	if got := rendGroup(t, groups[0], ms, redactors.RedactionSimple).Text; got != "[EMAIL-REDACTED]" {
		t.Errorf("simple group = %q", got)
	}
	// Both members now keep the first character and the domain, so the group may too.
	if got := rendGroup(t, groups[0], ms, redactors.RedactionFormatPreserving).Text; got != "z****************@outlook.com" {
		t.Errorf("format_preserving group = %q", got)
	}
}

func TestLooksLikeEmailAddress(t *testing.T) {
	for v, want := range map[string]bool{
		"zz.synthetic.0019@github.com":         true,
		"a@b.co":                               true,
		"https://github.com/zz-synthetic-0002": false,
		"github.com/zz-synthetic-0002":         false,
		"@zz_synthetic":                        false,
		"user@github":                          false,
		"a@b@c.com":                            false,
		"mailto:a@b.co":                        false,
		"":                                     false,
	} {
		if got := looksLikeEmailAddress(v); got != want {
			t.Errorf("looksLikeEmailAddress(%q) = %v, want %v", v, got, want)
		}
	}
}

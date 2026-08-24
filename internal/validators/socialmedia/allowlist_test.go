// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package socialmedia

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
)

// An allowlist entry is an operator INSTRUCTION, not a heuristic, so it has to be a veto.
//
// validateNotFalsePositive says "if match is allowlisted, exclude it", but its return value is
// only advisory: the caller turns it into a 30-point penalty. Confidence is capped at 100 while
// the raw total for a well-formed profile URL exceeds 130, so the penalty is absorbed entirely.
// Measured on a two-line fixture where one URL was allowlisted and the other was not, both were
// reported at HIGH 100 — indistinguishable, so the configuration had no visible effect at all.
//
// This is the same failure the reserved-path veto in reserved_paths.go was added for, and the
// same reasoning: a penalty that the cap eats is not a control.

const (
	allowlistedURL = "https://twitter.com/companybrand"
	realProfileURL = "https://twitter.com/realperson_x"
)

// configuredWithAllowlist builds a validator with two twitter patterns and one allowlist entry
// covering only allowlistedURL.
func configuredWithAllowlist(t *testing.T, key string) *Validator {
	t.Helper()
	v := NewValidator()
	v.Configure(&config.Config{Validators: map[string]map[string]any{
		"social_media": {
			"platform_patterns": map[string]any{
				"twitter": []any{`(?i)https?://(?:www\.)?twitter\.com/[a-zA-Z0-9_]{1,15}`},
			},
			key: []any{`twitter\.com/companybrand`},
		},
	}})
	if len(v.allowlistPatterns) == 0 {
		t.Fatalf("config key %q did not load any allowlist pattern, so the test would pass "+
			"for the wrong reason", key)
	}
	return v
}

func reportedTexts(t *testing.T, v *Validator, content string) []string {
	t.Helper()
	matches, err := v.ValidateContent(content, "profiles.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, m.Text)
	}
	return out
}

// TestAllowlistedMatchIsNotReported is the whole point: absent, not merely scored lower.
func TestAllowlistedMatchIsNotReported(t *testing.T) {
	v := configuredWithAllowlist(t, "allowlist_patterns")
	content := "Profile: " + allowlistedURL + "\nProfile: " + realProfileURL + "\n"

	got := reportedTexts(t, v, content)
	for _, text := range got {
		if strings.Contains(text, "companybrand") {
			t.Errorf("allowlisted value still reported as %q", text)
		}
	}
	found := false
	for _, text := range got {
		if strings.Contains(text, "realperson_x") {
			found = true
		}
	}
	if !found {
		t.Errorf("the NON-allowlisted profile disappeared too: %v — an allowlist must not "+
			"silence anything it does not name", got)
	}
}

// TestAllowlistIsAVetoNotAPenalty states the defect directly. Before the fix both URLs came out
// at HIGH 100, so a confidence comparison could not tell them apart; the assertion has to be
// about presence.
func TestAllowlistIsAVetoNotAPenalty(t *testing.T) {
	v := configuredWithAllowlist(t, "allowlist_patterns")

	allowlisted, err := v.ValidateContent("Profile: "+allowlistedURL, "profiles.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	real, err := v.ValidateContent("Profile: "+realProfileURL, "profiles.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}

	if len(real) == 0 {
		t.Fatalf("the comparison profile produced no finding, so this test cannot detect a " +
			"veto that never fired")
	}
	if len(allowlisted) != 0 {
		t.Errorf("allowlisted URL produced %d finding(s) at %.0f confidence; the "+
			"non-allowlisted one scores %.0f, so a penalty cannot separate them",
			len(allowlisted), allowlisted[0].Confidence, real[0].Confidence)
	}
}

// TestAllowlistAcceptsBothConfigKeys covers the inclusive rename. "allowlist_patterns" is the
// documented spelling; "whitelist_patterns" has to keep working or existing configs break
// silently, which for a suppression control means findings reappearing.
func TestAllowlistAcceptsBothConfigKeys(t *testing.T) {
	for _, key := range []string{"allowlist_patterns", "whitelist_patterns"} {
		t.Run(key, func(t *testing.T) {
			v := configuredWithAllowlist(t, key)
			got := reportedTexts(t, v, "Profile: "+allowlistedURL)
			if len(got) != 0 {
				t.Errorf("key %q did not take effect: reported %v", key, got)
			}
		})
	}
}

// TestInclusiveKeyWinsWhenBothArePresent pins the precedence. Merging the two lists would make
// the effective configuration depend on which key a reader happened to notice.
func TestInclusiveKeyWinsWhenBothArePresent(t *testing.T) {
	v := NewValidator()
	v.Configure(&config.Config{Validators: map[string]map[string]any{
		"social_media": {
			"platform_patterns": map[string]any{
				"twitter": []any{`(?i)https?://(?:www\.)?twitter\.com/[a-zA-Z0-9_]{1,15}`},
			},
			"allowlist_patterns": []any{`twitter\.com/companybrand`},
			"whitelist_patterns": []any{`twitter\.com/realperson_x`},
		},
	}})

	// The inclusive key names companybrand, so that one is vetoed and realperson_x is not.
	got := reportedTexts(t, v, "A: "+allowlistedURL+"\nB: "+realProfileURL+"\n")
	joined := strings.Join(got, " ")
	if strings.Contains(joined, "companybrand") {
		t.Errorf("allowlist_patterns was ignored: %v", got)
	}
	if !strings.Contains(joined, "realperson_x") {
		t.Errorf("whitelist_patterns was applied as well: the two lists must not be merged, "+
			"got %v", got)
	}
}

// overlappingAllowlistValidator configures two platforms whose patterns both claim part of a
// YouTube @-handle URL: youtube's URL pattern spans the whole thing, twitter's bare-handle
// pattern spans "@brandchannel" inside it.
func overlappingAllowlistValidator(t *testing.T) *Validator {
	t.Helper()
	v := NewValidator()
	v.Configure(&config.Config{Validators: map[string]map[string]any{
		"social_media": {
			"platform_patterns": map[string]any{
				"twitter": []any{
					`(?i)@[a-zA-Z0-9_]{1,15}\b`,
					`(?i)https?://(?:www\.)?twitter\.com/[a-zA-Z0-9_]+`,
				},
				"youtube": []any{`(?i)https?://(?:www\.)?youtube\.com/@[a-zA-Z0-9_-]+`},
			},
			"allowlist_patterns": []any{`youtube\.com/@brandchannel`},
		},
	}})
	return v
}

// TestAllowlistVetoesAFragmentOfTheAllowlistedValue is why the veto works on SPANS.
//
// A second platform's pattern can claim a fragment of the allowlisted value under a different
// name: twitter's bare-handle pattern reports "@brandchannel" out of an allowlisted YouTube
// channel URL. Comparing the allowlist against each match's TEXT leaves that fragment reported
// — measured at HIGH 100 — so the operator allowlists a channel and still gets a finding for it.
func TestAllowlistVetoesAFragmentOfTheAllowlistedValue(t *testing.T) {
	v := overlappingAllowlistValidator(t)

	got := reportedTexts(t, v, "Follow: https://www.youtube.com/@brandchannel")
	for _, text := range got {
		if strings.Contains(text, "brandchannel") {
			t.Errorf("reported %q despite the allowlist: a fragment of the allowlisted value "+
				"is still the allowlisted value", text)
		}
	}
}

// TestAllowlistDoesNotSuppressAnotherProfileOnTheSameLine is the collateral gate, and the
// reason the veto is span-based rather than line-based. A line-level "does the allowlist match
// anywhere on this line" test would silence the real profile next to the allowlisted one.
func TestAllowlistDoesNotSuppressAnotherProfileOnTheSameLine(t *testing.T) {
	v := overlappingAllowlistValidator(t)

	got := reportedTexts(t, v,
		"Brand: https://www.youtube.com/@brandchannel and person: "+realProfileURL)

	joined := strings.Join(got, " ")
	if strings.Contains(joined, "brandchannel") {
		t.Errorf("allowlisted value still reported: %v", got)
	}
	if !strings.Contains(joined, "realperson_x") {
		t.Errorf("the real profile on the same line was suppressed too: %v — an allowlist "+
			"must veto the spans it names and nothing else", got)
	}
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"math/rand"
	"testing"
)

// Tests for #808: a hexadecimal password in URI user info, the shape `openssl rand -hex 16` prints
// and REDIS_URL/DATABASE_URL values carry, was held at 55 LOW by unlabelledHexIdentifierCap, a
// ceiling that reads the LINE for a secret word. A URI password is labelled by its position in the
// URI grammar instead (#766), and `REDIS_URL` names none of secretLabelWords, so on main the hex
// password was capped while the same URI with a mixed-case password reported 100 HIGH, and
// --pre-commit-mode exited 0 on the hex line. Values are built at run time; none is a credential.

// randomHex returns n lower-case hex bytes from rng.
func randomHex(rng *rand.Rand, n int) string {
	const digits = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = digits[rng.Intn(len(digits))]
	}
	return string(b)
}

// uriHexLines places a URI user-info value in the shapes #808 is about: the issue's REDIS_URL, a
// bare URI, a DATABASE_URL and, for a token with no password, the user name of a clone URL.
func uriHexLines(value string) map[string]string {
	return map[string]string{
		"REDIS_URL":    "REDIS_URL=redis://default:" + value + "@cache.orders.invalid:6379/0",
		"bare":         "redis://default:" + value + "@cache.orders.invalid:6379/0",
		"DATABASE_URL": "DATABASE_URL=postgres://app_user:" + value + "@db1.orders.invalid:5432/appdb",
		"user only":    "git clone https://" + value + "@git.orders.invalid/orders/app.git",
	}
}

// TestURIUserinfoHexValueIsNotAnUnlabelledIdentifier: at every identifier length the ceiling
// claims (32, 40, 64), a hex value in user info reports once, uncapped, at the confidence a
// mixed-case value of the same length gets in the same place. The hex charset alone no longer
// moves it.
func TestURIUserinfoHexValueIsNotAnUnlabelledIdentifier(t *testing.T) {
	v := NewValidator()
	rng := rand.New(rand.NewSource(808))
	for _, n := range []int{32, 40, 64} {
		hex := randomHex(rng, n)
		mixed := uriPW(n, n)
		hexLines, mixedLines := uriHexLines(hex), uriHexLines(mixed)
		for name, line := range hexLines {
			ms := secretsOn(t, v, line, ".env")
			if len(ms) != 1 || ms[0].Text != hex || ms[0].Metadata["detection_method"] != uriUserinfoMethod {
				t.Errorf("%d hex/%s: got %v, want one uri_userinfo finding of the value", n, name, ms)
				continue
			}
			if c, capped := ms[0].Metadata[ConfidenceCeilingKey]; capped {
				t.Errorf("%d hex/%s: the value carries confidence_ceiling %v; a URI user-info value is "+
					"labelled by its grammar position, not by a word on the line", n, name, c)
			}
			control := secretsOn(t, v, mixedLines[name], ".env")
			if len(control) != 1 {
				t.Fatalf("%d mixed/%s: control got %v, want one finding", n, name, control)
			}
			if ms[0].Confidence != control[0].Confidence {
				t.Errorf("%d hex/%s reported at %.0f, the mixed-case control at %.0f: want the same score, "+
					"the charset is not evidence either way here", n, name, ms[0].Confidence, control[0].Confidence)
			}
			// The HIGH band is the issue's acceptance for a password. A token in the user name scores
			// 85 here for the mixed-case control as well, so for it the equality above is the claim.
			if name != "user only" && ms[0].Confidence < 90 {
				t.Errorf("%d hex/%s reported at %.0f, want the HIGH band (>= 90) that --pre-commit-mode blocks on",
					n, name, ms[0].Confidence)
			}
		}
	}
}

// TestUnlabelledHexCeilingStillHoldsOffTheURIGrammar is the scope proof. The ceiling's own cases
// keep it, and so do the URI dispositions that cap a value for what its bytes are: a hex password
// that repeats the user name is still LOW, with the 55 published. Only the hex rule stopped
// reading the line for a structural candidate.
func TestUnlabelledHexCeilingStillHoldsOffTheURIGrammar(t *testing.T) {
	v := NewValidator()
	rng := rand.New(rand.NewSource(8080))
	hex := randomHex(rng, 32)

	for name, line := range map[string]string{
		"ImageUniqueID": `ImageUniqueID: "` + hex + `"`, // the case the ceiling was built for
		"ETag":          `ETag: "` + hex + `"`,
	} {
		ms := secretsOn(t, v, line, "settings.txt")
		if len(ms) != 1 || ms[0].Confidence != unlabelledHexIdentifierCeiling {
			t.Errorf("%s: got %v, want one finding at the %.0f ceiling", name, ms, unlabelledHexIdentifierCeiling)
			continue
		}
		if c, _ := ms[0].Metadata[ConfidenceCeilingKey].(float64); c != unlabelledHexIdentifierCeiling {
			t.Errorf("%s: published ceiling %v, want %.0f", name, ms[0].Metadata[ConfidenceCeilingKey], unlabelledHexIdentifierCeiling)
		}
	}

	line := "REDIS_URL=redis://" + hex + ":" + hex + "@cache.orders.invalid:6379/0"
	ms := secretsOn(t, v, line, ".env")
	if len(ms) != 1 || ms[0].Text != hex || ms[0].Confidence > uriUserinfoLowCeiling {
		t.Fatalf("user name repeated as a hex password: got %v, want one finding at LOW (<= %.0f)", ms, uriUserinfoLowCeiling)
	}
	if c, _ := ms[0].Metadata[ConfidenceCeilingKey].(float64); c != uriUserinfoLowCeiling {
		t.Errorf("user name repeated: published ceiling %v, want %.0f", ms[0].Metadata[ConfidenceCeilingKey], uriUserinfoLowCeiling)
	}
}

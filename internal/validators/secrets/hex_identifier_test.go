// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import "testing"

// A bare hex value on a line that names nothing secret is an identifier shape, not a
// credential, and gets a confidence ceiling below the MEDIUM band.
//
// The case that prompted it: an EXIF ImageUniqueID — an image GUID — was reported as
// API_KEY_OR_SECRET at 80 inside a real 10 MB .docx. It reaches the entropy path at all
// only because containsSecretIndicators admits any quoted value of 20+ bytes; no secret
// keyword is involved. Digests, ETags, commit ids and content hashes share the shape.
//
// The discriminator is the LINE'S LABEL read as a POSITIVE signal — the ceiling applies
// when nothing says "secret" — and the direction is the point. A negative list of
// identifier field names would let a document author suppress a REAL secret by writing
// `ImageUniqueID: "AKIA..."`. That is attacker-controlled suppression, the same class of
// defect the surrounding work has been removing. Here relabelling can only REMOVE the
// ceiling, never trigger it.

func TestUnlabelledHexIdentifierCap(t *testing.T) {
	const guid = "14f6364997257b9170c016a13d1f1127" // 32 hex, the measured EXIF value

	cases := []struct {
		name    string
		value   string
		line    string
		capped  bool
		comment string
	}{
		// Capped: identifier shapes with no credential label.
		{"exif image guid", guid, `ImageUniqueID: "` + guid + `"`, true, "the reported false positive"},
		{"md5 digest", "d41d8cd98f00b204e9800998ecf8427e", `checksum: "d41d8cd98f00b204e9800998ecf8427e"`, true, ""},
		{"sha1 commit", "9f8e7d6c5b4a39281706f5e4d3c2b1a0f9e8d7c6", `commit "9f8e7d6c5b4a39281706f5e4d3c2b1a0f9e8d7c6"`, true, ""},
		{"sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", `digest "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"`, true, ""},
		{"uppercase hex", "14F6364997257B9170C016A13D1F1127", `SerialNumber: "14F6364997257B9170C016A13D1F1127"`, true, "case must not matter"},

		// NOT capped: the line labels the value as a credential. This is the direction
		// that makes the rule safe — an author cannot demote a real secret by renaming
		// its field, because any secret-ish word removes the ceiling.
		{"api_key label", guid, `api_key = "` + guid + `"`, false, "SAME VALUE as the FP, must keep full score"},
		{"secret label", guid, `client_secret: "` + guid + `"`, false, ""},
		{"token label", guid, `token "` + guid + `"`, false, ""},
		{"password label", guid, `password: "` + guid + `"`, false, ""},
		{"auth label", guid, `authorization: "` + guid + `"`, false, ""},
		{"private label", guid, `private_value: "` + guid + `"`, false, ""},
		{"hmac label", guid, `hmac: "` + guid + `"`, false, ""},
		{"session label", guid, `session: "` + guid + `"`, false, ""},

		// NOT capped: wrong shape. Anything that is not pure hex at an identifier
		// length keeps its score, so the rule cannot quietly demote real secrets that
		// merely contain hex.
		{"base64ish", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", `value = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`, false, ""},
		{"hex with dashes", "14f63649-9725-7b91-70c0-16a13d1f1127", `id: "14f63649-9725-7b91-70c0-16a13d1f1127"`, false, "a dashed GUID is not bare hex"},
		{"too short", "14f6364997257b91", `id: "14f6364997257b91"`, false, "16 hex is not an identifier length we claim"},
		{"48 hex is not a known length", "14f6364997257b9170c016a13d1f112714f6364997257b91", `id: "x"`, false, ""},
		{"hex plus suffix", guid + "z", `id: "` + guid + `z"`, false, ""},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := unlabelledHexIdentifierCap(genericSecretType, tc.value, tc.line)
			capped := got > 0

			if capped != tc.capped {
				verb := "was not capped but should be"
				if !tc.capped {
					verb = "was capped but should not be"
				}
				extra := ""
				if tc.comment != "" {
					extra = " (" + tc.comment + ")"
				}
				t.Errorf("%s%s\n  value: %q\n  line:  %q\n  ceiling returned: %v",
					verb, extra, tc.value, tc.line, got)
			}
			if capped && got != unlabelledHexIdentifierCeiling {
				t.Errorf("ceiling = %v, want %v (below the MEDIUM band so the finding "+
					"reports as LOW)", got, unlabelledHexIdentifierCeiling)
			}
		})
	}
}

// TestUnlabelledHexIdentifierCapOnlyAppliesToGenericFindings keeps the rule away from
// provider-identified secrets. A value that matched a provider signature has been
// identified by its own shape, and no line-label heuristic should second-guess it.
func TestUnlabelledHexIdentifierCapOnlyAppliesToGenericFindings(t *testing.T) {
	const guid = "14f6364997257b9170c016a13d1f1127"
	line := `ImageUniqueID: "` + guid + `"`

	if got := unlabelledHexIdentifierCap("AWS_SECRET_ACCESS_KEY", guid, line); got != 0 {
		t.Errorf("ceiling = %v for a provider-identified type, want 0: a value that "+
			"matched a provider signature must not be demoted by a label heuristic", got)
	}
	if got := unlabelledHexIdentifierCap(genericSecretType, guid, line); got == 0 {
		t.Error("the generic type should be capped on this line; the test above would " +
			"otherwise pass for the wrong reason")
	}
}

// TestSecretLabelWordsCoverTheIndicatorKeywords is the consistency floor between the
// two lists. containsSecretIndicators decides whether a line is scanned at all; the
// ceiling must never fire on a line that check would have called secret-labelled, or
// the two would disagree about the same line.
func TestSecretLabelWordsCoverTheIndicatorKeywords(t *testing.T) {
	indicatorKeywords := []string{
		"key", "secret", "token", "password", "pass", "pwd", "auth",
		"credential", "private", "bearer", "jwt", "api",
	}

	have := make(map[string]bool, len(secretLabelWords))
	for _, w := range secretLabelWords {
		have[w] = true
	}
	for _, kw := range indicatorKeywords {
		if !have[kw] {
			t.Errorf("secretLabelWords is missing %q, which containsSecretIndicators "+
				"treats as a secret label. The ceiling could then demote a line the "+
				"indicator check considers credential-labelled.", kw)
		}
	}
}

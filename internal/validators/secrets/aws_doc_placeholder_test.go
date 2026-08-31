// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"strings"
	"testing"
)

// The two credential values AWS publishes in its own documentation. Measured at HEAD
// before this change, through the CLI with --config /dev/null:
//
//	AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE                        -> 84.00% MEDIUM
//	AKIAIOSFODNN7EXAMPLE (bare)                                   -> 69.00% MEDIUM
//	AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY -> 75.00% MEDIUM
//
// The secret half already carried a local cap of 65 in findAWSSecretKeys and still
// reported 75: mergeBySpanKeepStrongest takes the max across detection paths and the
// bridge then adds document context, both after the cap ran. That is the reason the
// bound is now PUBLISHED as well as applied. See #364.
const (
	docAccessKeyID = "AKIAIOSFODNN7EXAMPLE"
	docSecretKey   = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)

// realAccessKeyID and realSecretKey are the SAFETY CONTROLS for every assertion in
// this file: synthetic values with the same shape as the placeholders but without the
// marker. Built at runtime so the literal never appears in the repository as a
// scannable AWS key.
//
// A fix that demoted these alongside the placeholders would be worse than the bug it
// fixes — a demoted real credential is a leak that looks like a pass.
func realAccessKeyID() string { return buildTestToken("AKIA", "MM6S3F290FXU6O0Q") }

const realSecretKey = "tIWgqmCdzQo6ZmMWR4A92POE5IkrJSPkdQYtpCx5"

func TestAWSDocPlaceholderCap(t *testing.T) {
	cases := []struct {
		name       string
		secretType string
		value      string
		want       float64
		why        string
	}{
		{
			name:       "documented access key id",
			secretType: "AWS_ACCESS_KEY",
			value:      docAccessKeyID,
			want:       awsDocPlaceholderCeiling,
			why:        "AWS publishes this exact key in its documentation",
		},
		{
			name:       "documented secret access key",
			secretType: "AWS_SECRET_ACCESS_KEY",
			value:      docSecretKey,
			want:       awsDocPlaceholderCeiling,
			why:        "the matching documented secret half",
		},
		{
			name:       "quoted value still capped",
			secretType: "AWS_ACCESS_KEY",
			value:      `"` + docAccessKeyID + `"`,
			want:       awsDocPlaceholderCeiling,
			why:        "quotes are stripped before the marker test, as in unlabelledHexIdentifierCap",
		},
		{
			name:       "mixed case marker still capped",
			secretType: "AWS_SECRET_ACCESS_KEY",
			value:      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYExampleKEY",
			want:       awsDocPlaceholderCeiling,
			why:        "the comparison is upper-cased, matching the check this replaced",
		},
		{
			name:       "real access key id untouched",
			secretType: "AWS_ACCESS_KEY",
			value:      realAccessKeyID(),
			want:       0,
			why:        "SAFETY: a real key carries no ceiling and keeps its full score",
		},
		{
			name:       "real secret access key untouched",
			secretType: "AWS_SECRET_ACCESS_KEY",
			value:      realSecretKey,
			want:       0,
			why:        "SAFETY: same, for the secret half",
		},
		{
			name:       "generic secret with the marker is NOT capped",
			secretType: genericSecretType,
			value:      realSecretKey + "EXAMPLE",
			want:       0,
			why: "the generic type has no length gate, so honouring the marker there would " +
				"let an author suppress a real credential by appending seven characters — " +
				"attacker-controlled suppression",
		},
		{
			name:       "unrelated typed secret with the marker is NOT capped",
			secretType: "GITHUB_TOKEN",
			value:      "ghp_" + strings.Repeat("a", 29) + "EXAMPLE",
			want:       0,
			why:        "the rule is about AWS's documentation convention, not the word EXAMPLE",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := awsDocPlaceholderCap(tc.secretType, tc.value); got != tc.want {
				t.Errorf("awsDocPlaceholderCap(%q, %q) = %v, want %v\n%s",
					tc.secretType, tc.value, got, tc.want, tc.why)
			}
		})
	}
}

// TestAWSDocPlaceholdersReportAtLOWAndPublishTheirCeiling drives the validator for
// real rather than testing the predicate in isolation, so it fails if the cap is
// computed but never wired into an emit site.
//
// Two assertions, and both matter:
//
//   - Confidence is at or below the ceiling. That is the defect: #364 measured the
//     documented access key at 84% MEDIUM and the documented secret at 75% MEDIUM,
//     both presented to a reviewer as real credentials.
//   - The finding still EXISTS. Only reported findings reach the redactor, so a drop
//     would leave AKIAIOSFODNN7EXAMPLE in the cleartext of a redacted document. This
//     is why the treatment is a demotion and not a suppression.
func TestAWSDocPlaceholdersReportAtLOWAndPublishTheirCeiling(t *testing.T) {
	cases := []struct {
		name     string
		content  string
		wantType string
		wantText string
	}{
		{
			name:     "labelled access key id",
			content:  "AWS_ACCESS_KEY_ID=" + docAccessKeyID + "\n",
			wantType: "AWS_ACCESS_KEY",
			wantText: docAccessKeyID,
		},
		{
			name:     "bare access key id",
			content:  docAccessKeyID + "\n",
			wantType: "AWS_ACCESS_KEY",
			wantText: docAccessKeyID,
		},
		{
			name:     "labelled secret access key",
			content:  "AWS_SECRET_ACCESS_KEY=" + docSecretKey + "\n",
			wantType: "AWS_SECRET_ACCESS_KEY",
			wantText: docSecretKey,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matches, err := NewValidator().ValidateContent(tc.content, "creds.env")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}

			var found int
			for _, m := range matches {
				if m.Type != tc.wantType || !strings.Contains(m.Text, tc.wantText) {
					continue
				}
				found++

				if m.Confidence > awsDocPlaceholderCeiling {
					t.Errorf("%s reported at %.2f, want <= %v (top of LOW).\n"+
						"A value AWS prints in its own documentation must not present as a "+
						"real credential (#364).", tc.wantType, m.Confidence, awsDocPlaceholderCeiling)
				}
				// Absolute, NOT relative to awsDocPlaceholderCeiling. The check above
				// moves with the constant, so raising the ceiling to 85 — the
				// alternative #364's thread debated — would satisfy it while leaving the
				// value in MEDIUM, which is the band the complaint is about.
				// pkg/scan/confidence.go puts the LOW/MEDIUM boundary at 60.
				if m.Confidence >= 60 {
					t.Errorf("%s reported at %.2f, which is MEDIUM or HIGH. The whole point "+
						"is that --confidence medium,high (this repo's own pre-commit filter) "+
						"must not show a documentation placeholder as a finding to act on.",
						tc.wantType, m.Confidence)
				}

				ceiling, ok := m.Metadata[ConfidenceCeilingKey]
				if !ok {
					t.Fatalf("%s carries no %q, so the bridge has nothing to clamp.\n"+
						"Applying the cap locally is not enough: the span merge takes the max "+
						"across detection paths and the bridge then adds document context, both "+
						"after the validator returns. Measured: a local cap of 65 on the secret "+
						"half still reported 75.", tc.wantType, ConfidenceCeilingKey)
				}
				if ceiling != awsDocPlaceholderCeiling {
					t.Errorf("published ceiling = %v (%T), want %v as a float64.\n"+
						"clampToCeiling ignores any other type, which turns the ceiling into a "+
						"silent no-op.", ceiling, ceiling, awsDocPlaceholderCeiling)
				}
			}

			// Vacuity guard: everything above is inside a loop that a zero-match run
			// would skip entirely, reporting a pass for a value that was never scanned.
			if found != 1 {
				t.Fatalf("got %d %s findings for %q, want exactly 1.\n"+
					"The placeholder must still be REPORTED — only reported findings are "+
					"redacted, so dropping it would leave the value in the cleartext of a "+
					"redacted document.", found, tc.wantType, strings.TrimSpace(tc.content))
			}
		})
	}
}

// TestRealAWSCredentialsAreNotDemotedByThePlaceholderCeiling is the non-negotiable
// safety half. The confidences asserted here were measured on the code BEFORE the
// placeholder ceiling existed and must not move.
func TestRealAWSCredentialsAreNotDemotedByThePlaceholderCeiling(t *testing.T) {
	cases := []struct {
		name     string
		content  string
		wantType string
		wantText string
		wantConf float64
	}{
		{
			name:     "labelled real access key id",
			content:  "AWS_ACCESS_KEY_ID=" + realAccessKeyID() + "\n",
			wantType: "AWS_ACCESS_KEY",
			wantText: realAccessKeyID(),
			wantConf: 100,
		},
		{
			name:     "bare real access key id",
			content:  realAccessKeyID() + "\n",
			wantType: "AWS_ACCESS_KEY",
			wantText: realAccessKeyID(),
			wantConf: 94,
		},
		{
			name:     "labelled real secret access key",
			content:  "AWS_SECRET_ACCESS_KEY=" + realSecretKey + "\n",
			wantType: "AWS_SECRET_ACCESS_KEY",
			wantText: realSecretKey,
			wantConf: 100,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matches, err := NewValidator().ValidateContent(tc.content, "creds.env")
			if err != nil {
				t.Fatalf("ValidateContent() error = %v", err)
			}

			var found int
			for _, m := range matches {
				if m.Type != tc.wantType || !strings.Contains(m.Text, tc.wantText) {
					continue
				}
				found++
				if m.Confidence != tc.wantConf {
					t.Errorf("real %s reported at %.2f, want %.2f (the pre-change value).\n"+
						"Demoting a real credential alongside the placeholders would be worse "+
						"than the bug: the finding still appears, so the scan looks like it "+
						"worked, while the credential drops out of the band that blocks a commit.",
						tc.wantType, m.Confidence, tc.wantConf)
				}
				if ceiling, ok := m.Metadata[ConfidenceCeilingKey]; ok {
					t.Errorf("real %s published a ceiling of %v; a real credential must carry none",
						tc.wantType, ceiling)
				}
			}
			if found != 1 {
				t.Fatalf("got %d %s findings, want exactly 1 — the control value must be "+
					"detected or this test asserts nothing", found, tc.wantType)
			}
		})
	}
}

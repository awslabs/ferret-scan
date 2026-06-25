// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package gitlabsast

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/internal/detector"
	"github.com/awslabs/ferret-scan/internal/formatters"
)

// TestGitLabSAST_NoLeakWhenHidden is a regression test for the gitlab-sast PII
// leak: the vulnerability description embedded the surrounding line via a
// pattern-based scrub that masked card-shaped substrings but left names and
// SSN-shaped values intact. With ShowMatch=false the raw line must be withheld
// entirely.
func TestGitLabSAST_NoLeakWhenHidden(t *testing.T) {
	const secret = "4929-3813-3266-4295"
	const name = "Robert Aragon"
	const ssn = "489-36-8350"
	matches := []detector.Match{{
		Text:       secret,
		LineNumber: 5,
		Type:       "CREDIT_CARD",
		Confidence: 100,
		Filename:   "cards.tsv",
		Validator:  "creditcard",
		Context: detector.ContextInfo{
			FullLine: name + "\t" + ssn + "\t" + secret,
		},
		Metadata: map[string]interface{}{"card_type": "VISA"},
	}}

	allLevels := map[string]bool{"high": true, "medium": true, "low": true}

	f := NewFormatter()
	hidden, err := f.Format(matches, nil, formatters.FormatterOptions{ShowMatch: false, Verbose: true, ConfidenceLevel: allLevels})
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}
	for _, leak := range []string{secret, name, ssn} {
		if strings.Contains(hidden, leak) {
			t.Errorf("gitlab-sast leaked %q with ShowMatch=false", leak)
		}
	}

	// With ShowMatch the surrounding line (and value) may appear.
	shown, err := f.Format(matches, nil, formatters.FormatterOptions{ShowMatch: true, Verbose: true, ConfidenceLevel: allLevels})
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}
	if !strings.Contains(shown, secret) {
		t.Errorf("gitlab-sast should include the value when ShowMatch=true")
	}
}

// TestGitLabSAST_RevealsValueWithoutFullLine is a regression test for the
// reveal gap: gitlab-sast hardcodes "[HIDDEN]" in the message, so the only
// surface that can reveal the matched value was the Context block sourced from
// Context.FullLine. Validators that never populate FullLine (e.g. secrets/AWS
// keys) therefore revealed nothing even with --show-match. The description must
// fall back to the matched value itself when FullLine is empty and ShowMatch is
// set — and still reveal nothing when it is not.
func TestGitLabSAST_RevealsValueWithoutFullLine(t *testing.T) {
	const awsKey = "AKIAIOSFODNN7EXAMPLE"
	// Secrets-style finding: no Context.FullLine populated.
	match := detector.Match{
		Text:       awsKey,
		LineNumber: 1,
		Type:       "AWS_ACCESS_KEY",
		Confidence: 90,
		Filename:   "config.env",
		Validator:  "secrets",
	}
	s := NewDataSanitizer()

	hidden := s.SanitizeDescription(match, false)
	if strings.Contains(hidden, awsKey) {
		t.Errorf("gitlab-sast revealed the value without --show-match:\n%s", hidden)
	}

	shown := s.SanitizeDescription(match, true)
	if !strings.Contains(shown, awsKey) {
		t.Errorf("gitlab-sast should reveal the matched value with --show-match even when "+
			"Context.FullLine is empty (secrets-style finding):\n%s", shown)
	}
}

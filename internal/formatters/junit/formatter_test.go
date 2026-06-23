// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package junit

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/internal/detector"
	"github.com/awslabs/ferret-scan/internal/formatters"
)

// TestJUnitFormatter_VerboseDoesNotLeakWhenHidden is a regression test for the
// PII-leak class: when ShowMatch is false the raw secret must never reach the
// output, and --verbose must not re-leak it via the FullLine context field.
func TestJUnitFormatter_VerboseDoesNotLeakWhenHidden(t *testing.T) {
	const secret = "sk_live_51H7qYKJ2eZvKYlo2C8nKqp6"
	matches := []detector.Match{{
		Text:       secret,
		LineNumber: 1,
		Type:       "SECRETS",
		Confidence: 95,
		Filename:   "config.go",
		Validator:  "secrets",
		Context:    detector.ContextInfo{FullLine: `apiKey := "` + secret + `"`},
	}}

	out, err := NewFormatter().Format(matches, nil, formatters.FormatterOptions{
		ShowMatch:       false,
		Verbose:         true, // verbose must not re-leak the value
		ConfidenceLevel: map[string]bool{"high": true, "medium": true, "low": true},
	})
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}
	if strings.Contains(out, secret) {
		t.Errorf("JUnit output leaked the secret value with ShowMatch=false, Verbose=true:\n%s", out)
	}

	// Sanity: with ShowMatch=true the value is allowed to appear (confirms the
	// match isn't simply being filtered out, so the negative case above is real).
	out2, err := NewFormatter().Format(matches, nil, formatters.FormatterOptions{
		ShowMatch:       true,
		Verbose:         true,
		ConfidenceLevel: map[string]bool{"high": true, "medium": true, "low": true},
	})
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}
	if !strings.Contains(out2, secret) {
		t.Errorf("JUnit output should include the value when ShowMatch=true")
	}
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package text

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/internal/detector"
	"github.com/awslabs/ferret-scan/internal/formatters"
)

// TestTextFormatter_VerboseDoesNotLeakWhenHidden is a regression test for the
// PII-leak class: the verbose "Context snippet" prints the raw before/[match]/
// after text, so it must be gated on ShowMatch. With ShowMatch=false the secret
// must not appear, even under --verbose.
func TestTextFormatter_VerboseDoesNotLeakWhenHidden(t *testing.T) {
	const secret = "sk_live_51H7qYKJ2eZvKYlo2C8nKqp6"
	matches := []detector.Match{{
		Text:       secret,
		LineNumber: 1,
		Type:       "SECRETS",
		Confidence: 95,
		Filename:   "config.go",
		Validator:  "secrets",
		Context: detector.ContextInfo{
			FullLine:   `apiKey := "` + secret + `"`,
			BeforeText: `apiKey := "`,
			AfterText:  `"`,
		},
	}}

	out, err := NewFormatter().Format(matches, nil, formatters.FormatterOptions{
		ShowMatch: false,
		Verbose:   true, // verbose must not re-leak the value via the context snippet
		NoColor:   true,
	})
	if err != nil {
		t.Fatalf("Format error: %v", err)
	}
	if strings.Contains(out, secret) {
		t.Errorf("text output leaked the secret value with ShowMatch=false, Verbose=true")
	}
}

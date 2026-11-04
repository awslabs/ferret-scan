// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package legacyole

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// What each strategy writes into a legacy Office file (#863), asserted on the bytes of the output.
//
// These replace a test that only read GetSupportedStrategies. That list left synthetic out, the test
// passed, and nothing read the list in production: synthetic was written as a mask and simple as
// format_preserving, byte-identical to it, on .doc, .xls and .ppt alike.
//
// synthetic is refused for an embedded legacy part (see the redactors package's registry tests); a
// top-level file still takes the mask, as GetSupportedStrategies explains.

// Synthetic values: a reserved-domain address, an unassignable NANP number (exchange 010) and a
// sequential card serial with its Luhn digit.
const (
	strategyEmail = "jane.doe@example.com"
	strategyPhone = "(555) 010-0199"
	strategyCard  = "4123456789012349"
)

func strategyBody() string {
	return "Email " + strategyEmail + "\rPhone " + strategyPhone + "\rCard " + strategyCard + "\r"
}

func strategyMatches() []detector.Match {
	return []detector.Match{
		{Text: strategyEmail, Type: "EMAIL", Validator: "email", Confidence: 90, LineNumber: 1},
		{Text: strategyPhone, Type: "PHONE", Validator: "phone", Confidence: 90, LineNumber: 2},
		{Text: strategyCard, Type: "VISA", Validator: "creditcard", Confidence: 90, LineNumber: 3},
	}
}

// TestSimpleWritesAFullMaskOfEveryValue is the headline: simple keeps nothing of the value. It used
// to keep a card's last four digits, the email's first character and domain, and the phone's last
// four, because simple was rendered as format_preserving.
func TestSimpleWritesAFullMaskOfEveryValue(t *testing.T) {
	want := "Email " + strings.Repeat("*", len(strategyEmail)) +
		"\rPhone " + strings.Repeat("*", len(strategyPhone)) +
		"\rCard " + strings.Repeat("*", len(strategyCard)) + "\r"
	for ext, data := range legacyContainers(strategyBody()) {
		got, res, err := redactLegacy(t, ext, data, strategyMatches(), redactors.RedactionSimple)
		if err != nil {
			t.Fatalf("%s: %v", ext, err)
		}
		if got != want {
			t.Errorf("%s simple: main stream = %q, want %q", ext, got, want)
		}
		for _, kept := range []string{"2349", "@example.com", "0199"} {
			if strings.Contains(got, kept) {
				t.Errorf("%s simple: %q survives; simple promises nothing of the value is kept", ext, kept)
			}
		}
		for _, m := range res.RedactionMap {
			if strings.Trim(m.RedactedText, "*") != "" {
				t.Errorf("%s simple: mapping for %s records %q, which is not the mask that was written",
					ext, m.DataType, m.RedactedText)
			}
		}
	}
}

// TestFormatPreservingIsUnchanged pins the default's bytes: the fix moves simple and synthetic only.
func TestFormatPreservingIsUnchanged(t *testing.T) {
	want := "Email j*******@example.com\rPhone (***) ***-0199\rCard ************2349\r"
	for ext, data := range legacyContainers(strategyBody()) {
		got, _, err := redactLegacy(t, ext, data, strategyMatches(), redactors.RedactionFormatPreserving)
		if err != nil {
			t.Fatalf("%s: %v", ext, err)
		}
		if got != want {
			t.Errorf("%s format_preserving: main stream = %q, want %q", ext, got, want)
		}
	}
}


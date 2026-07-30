// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package plaintext

import (
	"bytes"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// TestNoPayloadInRedactionLog is the BSC4 gate for the plaintext redactor: no
// byte of the content being redacted may reach the observability log.
//
// This leak had a different shape from the validator ones — the value was not
// interpolated into a debug string but placed in STRUCTURED event metadata
// ("match_text"), so a keyword sweep for format specifiers missed it entirely.
// It was also the worst-placed instance: the redactor sees every confirmed
// finding, so scanning with --enable-redaction --debug wrote each SSN, card and
// email in cleartext to stderr, one line per redaction, at the exact moment the
// tool was masking them in the output file.
//
// The assertion is on the INPUT bytes rather than on a field name, so it also
// fails for a leak introduced at a site that does not exist yet.
func TestNoPayloadInRedactionLog(t *testing.T) {
	content := strings.Join([]string{
		"Patient ssn 219-09-9993 seen on Monday.",
		"Card 5500-0000-0000-0004 charged.",
		"Mail nobody@acmehealthcorp.example for records.",
	}, "\n")

	matches := []detector.Match{
		{Text: "219-09-9993", Type: "SSN", LineNumber: 1, Confidence: 90, Validator: "ssn"},
		{Text: "5500-0000-0000-0004", Type: "MASTERCARD", LineNumber: 2, Confidence: 95, Validator: "creditcard"},
		{Text: "nobody@acmehealthcorp.example", Type: "BUSINESS", LineNumber: 3, Confidence: 45, Validator: "email"},
	}

	sentinels := []string{
		"219-09-9993",
		"5500-0000-0000-0004",
		"nobody@acmehealthcorp.example",
		"acmehealthcorp",
		"Patient",
	}

	for _, strategy := range []redactors.RedactionStrategy{
		redactors.RedactionSimple,
		redactors.RedactionFormatPreserving,
		redactors.RedactionSynthetic,
	} {
		t.Run(strategy.String(), func(t *testing.T) {
			var log bytes.Buffer
			debugObs := observability.NewDebugObserver(&log)
			observer := debugObs.StandardObserver
			observer.DebugObserver = debugObs

			ptr := NewPlainTextRedactor(nil, observer)

			redacted, mappings, err := ptr.RedactString(content, matches, strategy)
			if err != nil {
				t.Fatalf("RedactString error: %v", err)
			}

			// Non-vacuity, part 1: redaction must actually have happened, or the
			// log would be empty and the sentinel loop would prove nothing.
			if len(mappings) != len(matches) {
				t.Fatalf("redacted %d of %d matches; the log would not cover every path", len(mappings), len(matches))
			}
			for _, s := range []string{"219-09-9993", "5500-0000-0000-0004", "nobody@acmehealthcorp.example"} {
				if strings.Contains(redacted, s) {
					t.Errorf("value %q survived redaction in the output", s)
				}
			}

			got := log.String()

			// Non-vacuity, part 2: the events under test must be present.
			if log.Len() == 0 {
				t.Fatal("no observability output captured, so this test cannot detect a leak")
			}
			for _, want := range []string{"position_correlation", "redaction_applied"} {
				if !strings.Contains(got, want) {
					t.Errorf("event %q was not emitted, so this test does not cover it.\n--- log ---\n%s", want, got)
				}
			}

			for _, s := range sentinels {
				if strings.Contains(got, s) {
					t.Errorf("document content %q leaked into the observability log (BSC4).\n--- log ---\n%s", s, got)
				}
			}
		})
	}
}

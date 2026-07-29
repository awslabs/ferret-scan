// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package socialmedia

import (
	"bytes"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/observability"
)

// TestNoPayloadInDebugLog is the BSC4 gate for this validator: no byte of the
// scanned document may reach the observability log.
//
// PR #123 masked the raw matched value at six sites but left a second, worse
// shape untouched — the @handle false-positive filters logged the match AND the
// whole source LINE. Because the line is arbitrary document content, an
// unrelated SSN and card number sitting beside a filtered handle went straight
// to the log, from a validator that reported no finding at all.
//
// This test asserts on the INPUT bytes rather than on a list of known-bad format
// strings, so it also fails for a leak introduced at a site that does not exist
// yet. It runs a configured validator (a bare NewValidator has no patterns and
// would reach none of these paths) and drives every @handle filter branch.
func TestNoPayloadInDebugLog(t *testing.T) {
	// Each line trips a different filter — email domain, doc annotation, code
	// comment, invalid handle format, partial domain — while carrying a bystander
	// value that must not be logged.
	lines := []string{
		"Patient @acmehealthcorp SSN 219-09-9999 mail a@acmehealthcorp.com",
		"// @param see card 5500-0000-0000-0004 for details",
		"@1nvalid handle beside SSN 219-09-9998",
		"contact @mycompany.com about card 4111-1111-1111-1111",
		"Follow https://twitter.com/zyxwvutqwerty and https://linkedin.com/in/zyxwvut-qwerty",
	}
	content := strings.Join(lines, "\n")

	// Every distinctive substring of the input. Includes the handles and profile
	// URLs themselves: a filtered handle is still document content, and a
	// detected one belongs in the finding, not the log (--show-match is a
	// formatter-layer decision).
	sentinels := []string{
		"219-09-9999",
		"219-09-9998",
		"5500-0000-0000-0004",
		"4111-1111-1111-1111",
		"acmehealthcorp",
		"mycompany",
		"1nvalid",
		"zyxwvutqwerty",
		"zyxwvut-qwerty",
	}

	var log bytes.Buffer
	debugObs := observability.NewDebugObserver(&log)
	observer := debugObs.StandardObserver
	observer.DebugObserver = debugObs

	v := newConfiguredValidator()
	v.SetObserver(observer)

	if _, err := v.ValidateContent(content, "nopayload.txt"); err != nil {
		t.Fatalf("ValidateContent error: %v", err)
	}

	got := log.String()

	// Non-vacuity: the filters must actually have run and logged, or an empty log
	// would pass this test while proving nothing. Assert both that there is
	// output and that the specific filter paths under test were exercised.
	if log.Len() == 0 {
		t.Fatal("no debug output captured, so this test cannot detect a leak")
	}
	for _, want := range []string{
		"is part of an email address",
		"Filtered documentation annotation",
		"Filtered invalid handle format",
		"Filtered partial domain match",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("filter path %q was not exercised, so this test does not cover it.\n--- log ---\n%s", want, got)
		}
	}

	for _, s := range sentinels {
		if strings.Contains(got, s) {
			t.Errorf("document content %q leaked into the observability log (BSC4).\n--- log ---\n%s", s, got)
		}
	}
}

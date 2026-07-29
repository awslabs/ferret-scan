// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package intellectualproperty

import (
	"bytes"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/observability"
)

// TestNoPayloadInDebugLog is the BSC4 gate for this validator: no byte of the
// scanned document may reach the observability log.
//
// PR #123 masked the one stderr site but left three untouched: the legal-notice
// and reconstruction analyses logged every match's raw text, and the
// reconstructed text is a concatenation spanning the surrounding content.
//
// The assertion is on the INPUT bytes rather than on a list of known-bad format
// strings, so it also fails for a leak introduced at a site that does not exist
// yet.
func TestNoPayloadInDebugLog(t *testing.T) {
	// A legal notice dense enough to trigger reconstruction, carrying bystander
	// values that must not be logged even though this validator never reports
	// them.
	content := strings.Join([]string{
		"CONFIDENTIAL AND PROPRIETARY - Copyright (c) 2026 Zyxwvut Holdings Ltd.",
		"All Rights Reserved. Contact ssn 219-09-9997 for licensing.",
		"Trade Secret: the Qwertyuiop process must not be disclosed.",
	}, "\n")

	sentinels := []string{
		"219-09-9997",
		"Zyxwvut",
		"Qwertyuiop",
		"CONFIDENTIAL AND PROPRIETARY",
		"All Rights Reserved",
		"Trade Secret",
	}

	var log bytes.Buffer
	debugObs := observability.NewDebugObserver(&log)
	observer := debugObs.StandardObserver
	observer.DebugObserver = debugObs

	v := NewValidator()
	v.SetObserver(observer)

	if _, err := v.ValidateContent(content, "nopayload.txt"); err != nil {
		t.Fatalf("ValidateContent error: %v", err)
	}

	got := log.String()

	// Non-vacuity: an empty log, or one that never reached the analysis paths,
	// would pass the sentinel loop below while proving nothing.
	if log.Len() == 0 {
		t.Fatal("no debug output captured, so this test cannot detect a leak")
	}
	for _, want := range []string{
		"Legal notice analysis for",
		"Match 1: [HIDDEN]",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("log path %q was not exercised, so this test does not cover it.\n--- log ---\n%s", want, got)
		}
	}

	for _, s := range sentinels {
		if strings.Contains(got, s) {
			t.Errorf("document content %q leaked into the observability log (BSC4).\n--- log ---\n%s", s, got)
		}
	}
}

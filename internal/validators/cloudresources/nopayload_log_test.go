// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cloudresources

import (
	"bytes"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/observability"
)

// TestNoPayloadInDebugLog is the BSC4 gate for this validator: no byte of the
// scanned document may reach the observability log.
//
// This validator's own README documents [HIDDEN] as the convention, yet both
// filter paths logged the raw matched identifier — which for an ARN embeds the
// bucket or role name, and for a subscription ID the GUID itself, i.e. the exact
// values the finding exists to protect.
//
// The assertion is on the INPUT bytes rather than on a list of known-bad format
// strings, so it also fails for a leak introduced at a site that does not exist
// yet.
func TestNoPayloadInDebugLog(t *testing.T) {
	// Line 1 trips the public-by-design filter (a published GCP dataset project);
	// line 2 scores under the accept floor via the same-line test keyword.
	content := strings.Join([]string{
		"net: projects/bigquery-public-data/global/networks/qwertyuiop",
		"# example: arn:aws:s3:::zyxwvutqwerty-private-bucket/keypath",
	}, "\n")

	// Every distinctive substring of the input. A filtered match is still
	// document content, so the bucket and project names must not appear.
	sentinels := []string{
		"bigquery-public-data",
		"qwertyuiop",
		"zyxwvutqwerty-private-bucket",
		"keypath",
		"arn:aws:s3:::",
		"projects/",
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

	// Non-vacuity: an empty log, or one that never reached a filter path, would
	// pass the sentinel loop below while proving nothing. Both filter sites are
	// asserted individually because they were fixed independently.
	if log.Len() == 0 {
		t.Fatal("no debug output captured, so this test cannot detect a leak")
	}
	for _, want := range []string{
		"Match filtered (public-by-design resource)",
		"Match filtered (confidence",
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

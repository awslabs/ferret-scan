// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build examples_lambda
// +build examples_lambda

package main

import (
	"context"
	"strings"
	"testing"
)

// Run with: go test -tags examples_lambda ./examples/lambda-redact/
//
// TestIncompleteRedactionIsAnErrorNotARedactedResponse pins #770 for the gateway: when Redact cannot
// examine the whole request the handler answers with a payload-free error and no "redacted" text.
// It used to return res.Redacted whenever err == nil, and a cut-short scan returned err == nil, so
// a fired deadline sent the request's own text back as the redacted response.
func TestIncompleteRedactionIsAnErrorNotARedactedResponse(t *testing.T) {
	const secret = "reach j7.example@example.org about 517-17-1007"
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the invocation's deadline has already passed

	resp, err := handle(ctx, Request{Text: secret, Label: "req-770"})
	if err == nil {
		t.Fatalf("no error; response %+v", resp)
	}
	if err.Error() != "request_id=req-770: redaction incomplete" {
		t.Errorf("error = %q, want the payload-free \"request_id=req-770: redaction incomplete\"", err)
	}
	if resp.Redacted != "" || resp.RequestID != "" || resp.FindingsByType != nil || resp.DurationMS != 0 {
		t.Errorf("response %+v, want the empty Response: no redacted field on an incomplete scan", resp)
	}
	for _, part := range []string{"j7.example@example.org", "517-17-1007"} {
		if strings.Contains(err.Error(), part) {
			t.Errorf("the error carries input bytes (%q)", part)
		}
	}
}

// TestCompleteRedactionStillAnswers: a request the engine examines fully is redacted as before.
func TestCompleteRedactionStillAnswers(t *testing.T) {
	resp, err := handle(context.Background(), Request{Text: "reach j7.example@example.org", Label: "req-ok"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(resp.Redacted, "j7.example@example.org") || resp.RequestID != "req-ok" {
		t.Errorf("response %+v", resp)
	}
}

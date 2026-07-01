// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/internal/parallel"
)

// TestSummarizeIncompleteFiles covers the v2 Phase 4 degraded-coverage summary
// the /scan response carries: empty when complete, names the single offender,
// counts several.
func TestSummarizeIncompleteFiles(t *testing.T) {
	if got := summarizeIncompleteFiles(nil, 3); got != "" {
		t.Errorf("complete scan must summarize to empty string, got %q", got)
	}

	one := []parallel.FileDiagnostic{{FilePath: "big.json", Reason: "context deadline exceeded"}}
	got := summarizeIncompleteFiles(one, 1)
	for _, want := range []string{"big.json", "context deadline exceeded", "findings may be missing"} {
		if !strings.Contains(got, want) {
			t.Errorf("single-file summary missing %q; got %q", want, got)
		}
	}

	many := []parallel.FileDiagnostic{
		{FilePath: "a.txt", Reason: "match budget exceeded"},
		{FilePath: "b.txt", Reason: "context deadline exceeded"},
	}
	got = summarizeIncompleteFiles(many, 10)
	if !strings.Contains(got, "2 of 10 files") {
		t.Errorf("multi-file summary should count '2 of 10 files', got %q", got)
	}
}

// TestScanResponse_CompleteScanOmitsIncompleteFields is the behavior-preserving
// guarantee: a complete scan's JSON must NOT contain the new incomplete fields
// (omitempty), so existing clients see byte-identical output to before Phase 4.
func TestScanResponse_CompleteScanOmitsIncompleteFields(t *testing.T) {
	out, err := json.Marshal(ScanResponse{Success: true})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(out)
	if strings.Contains(s, "incomplete") {
		t.Errorf("complete scan response must omit incomplete fields, got %s", s)
	}
}

// TestScanResponse_IncompleteScanSurfacesFields confirms the fields are present
// and populated when coverage was cut short.
func TestScanResponse_IncompleteScanSurfacesFields(t *testing.T) {
	out, err := json.Marshal(ScanResponse{
		Success:          true,
		Incomplete:       true,
		IncompleteReason: "coverage incomplete for big.json: context deadline exceeded — findings may be missing",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(out)
	if !strings.Contains(s, `"incomplete":true`) {
		t.Errorf("incomplete scan must set incomplete=true, got %s", s)
	}
	if !strings.Contains(s, `"incomplete_reason"`) {
		t.Errorf("incomplete scan must carry incomplete_reason, got %s", s)
	}
}

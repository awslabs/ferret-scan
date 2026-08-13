// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestSuppressedByIsAlwaysEmpty pins the claim the deprecation notice makes.
//
// This package never sets core.ScanConfig.SuppressionManager, so the suppression
// stage does not run: nothing is filtered and nothing can populate SuppressedBy.
// The field is retained only for compilation compatibility.
//
// If suppression is ever wired into this package, this test fails and that is the
// right outcome — it is the prompt to undeprecate the field, populate it from
// detector.SuppressedMatch, and rewrite the note on Result. Deleting the test to
// make a change pass would put the docs back into the state this replaced, where
// a public field described behaviour the package did not have.
func TestSuppressedByIsAlwaysEmpty(t *testing.T) {
	const body = "Employee SSN 796-58-4123 on file\n" +
		"Corporate card 4111-1111-1111-1111 expires soon\n" +
		"AWS key AKIAIOSFODNN7EXAMPLE rotate quarterly\n"

	path := filepath.Join(t.TempDir(), "findings.txt")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	textResult, err := ScanText(context.Background(), body, TextOptions{Explain: true})
	if err != nil {
		t.Fatalf("ScanText: %v", err)
	}
	fileResult, err := ScanFile(context.Background(), path, FileOptions{Explain: true})
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}

	for _, tc := range []struct {
		entry    string
		findings []Finding
	}{
		{"ScanText", textResult.Findings},
		{"ScanFile", fileResult.Findings},
	} {
		if len(tc.findings) == 0 {
			t.Fatalf("%s: fixture produced no findings, so the assertion is vacuous", tc.entry)
		}
		for _, f := range tc.findings {
			if f.SuppressedBy != "" {
				t.Errorf("%s: %s finding on line %d has SuppressedBy = %q; this package applies "+
					"no suppression, so the field cannot be set. If suppression was just wired in, "+
					"update the Finding and Result doc comments instead of relaxing this test.",
					tc.entry, f.Type, f.LineNumber, f.SuppressedBy)
			}
		}
	}
}

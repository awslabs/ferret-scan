// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"strings"
	"testing"
)

// TestValidate_StableDocumentTypeError locks which document-type entry a config
// validation failure names. The loop ranged the map, so a config with several
// bad entries reported a different one on every run: the user fixed whichever
// error surfaced, re-ran, and got a fresh complaint about a different key.
func TestValidate_StableDocumentTypeError(t *testing.T) {
	seen := make(map[string]int)
	for i := 0; i < auditIterations; i++ {
		cfg := NewDefaultRedactionConfig()
		// Three invalid entries: an unrecognized strategy fails validation.
		for _, docType := range []string{"zeta", "alpha", "mid"} {
			cfg.DocumentTypes[docType] = DocumentTypeConfig{Strategy: "not-a-strategy"}
		}

		err := cfg.Validate()
		if err == nil {
			t.Fatalf("iteration %d: want a validation error, got nil", i)
		}
		seen[err.Error()]++
	}

	if len(seen) != 1 {
		t.Fatalf("the same invalid config produced %d distinct error messages, want 1: %v", len(seen), seen)
	}
	for msg := range seen {
		if !strings.Contains(msg, "document_types.alpha") {
			t.Fatalf("want the lowest-sorting document type reported, got %q", msg)
		}
	}
}

// TestValidate_StableDataTypeError is the same guard for data-type entries.
func TestValidate_StableDataTypeError(t *testing.T) {
	seen := make(map[string]int)
	for i := 0; i < auditIterations; i++ {
		cfg := NewDefaultRedactionConfig()
		for _, dataType := range []string{"ZETA", "BRAVO", "MIKE"} {
			cfg.DataTypes[dataType] = DataTypeConfig{Strategy: "not-a-strategy"}
		}

		err := cfg.Validate()
		if err == nil {
			t.Fatalf("iteration %d: want a validation error, got nil", i)
		}
		seen[err.Error()]++
	}

	if len(seen) != 1 {
		t.Fatalf("the same invalid config produced %d distinct error messages, want 1: %v", len(seen), seen)
	}
	for msg := range seen {
		if !strings.Contains(msg, "data_types.BRAVO") {
			t.Fatalf("want the lowest-sorting data type reported, got %q", msg)
		}
	}
}

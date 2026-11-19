// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The "every preprocessor failed" refusal is a typed error (#1022): the CLI and the unscanned
// report match it with errors.Is instead of looking for its words, and its text is the wording
// users and the unscanned report's prefix strip have always seen.
func TestAllPreprocessorsFailedIsTypedAndKeepsItsText(t *testing.T) {
	p := filepath.Join(t.TempDir(), "corrupt.docx")
	if err := os.WriteFile(p, []byte("PK\x03\x04 not really a zip"), 0o600); err != nil {
		t.Fatal(err)
	}
	fr := NewFileRouter(false)
	RegisterDefaultPreprocessors(fr)
	fr.InitializePreprocessors(nil)
	_, err := fr.ProcessFile(p, nil)
	if err == nil {
		t.Fatal("a corrupt .docx returned no error")
	}
	if !errors.Is(err, ErrAllPreprocessorsFailed) {
		t.Fatalf("error %q does not wrap ErrAllPreprocessorsFailed", err)
	}
	if want := "all preprocessors failed for file: " + p; err.Error() != want {
		t.Fatalf("error text changed:\n got %q\nwant %q", err.Error(), want)
	}
}

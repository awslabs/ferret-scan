// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
)

func writeTemp(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRedactFile_WritesRedactedCopyWithoutRawValues(t *testing.T) {
	in := t.TempDir()
	out := t.TempDir()
	// Reserved documentation values.
	src := writeTemp(t, in, "leak.txt", "card 5500-0000-0000-0004 email jordan@example.com\n")

	res, err := RedactFile(RedactConfig{
		FilePath:  src,
		OutputDir: out,
		Strategy:  "format_preserving",
		Checks:    []string{"all"},
		Config:    config.LoadConfigOrDefault(""),
		LogWriter: io.Discard,
	})
	if err != nil {
		t.Fatalf("RedactFile error: %v", err)
	}
	if res.RedactedFilePath == "" {
		t.Fatal("expected a redacted file path")
	}
	if res.RedactionCount == 0 {
		t.Error("expected at least one redaction")
	}

	data, err := os.ReadFile(res.RedactedFilePath)
	if err != nil {
		t.Fatalf("redacted file not readable: %v", err)
	}
	content := string(data)
	if strings.Contains(content, "5500-0000-0000-0004") {
		t.Errorf("redacted output still contains raw card number:\n%s", content)
	}
	if strings.Contains(content, "jordan@example.com") {
		t.Errorf("redacted output still contains raw email:\n%s", content)
	}
	// Output preserves the source file type.
	if filepath.Ext(res.RedactedFilePath) != ".txt" {
		t.Errorf("expected .txt output, got %s", res.RedactedFilePath)
	}
}

func TestRedactFile_CleanFileIsCopiedThrough(t *testing.T) {
	in := t.TempDir()
	out := t.TempDir()
	src := writeTemp(t, in, "clean.txt", "nothing sensitive here\n")

	res, err := RedactFile(RedactConfig{
		FilePath:  src,
		OutputDir: out,
		Config:    config.LoadConfigOrDefault(""),
		LogWriter: io.Discard,
	})
	if err != nil {
		t.Fatalf("RedactFile error: %v", err)
	}
	if _, err := os.Stat(res.RedactedFilePath); err != nil {
		t.Errorf("expected a passed-through copy for a clean file: %v", err)
	}
}

// TestRedactFile_UnredactableFileTypeIsAnError pins the hard-error guard. A
// source file has no registered redactor, so its findings cannot be masked. The
// only safe outcome is an error: returning success would hand the caller a path
// that RedactFile's own doc comment calls "safe to share", and RedactionCount
// would read 0 — indistinguishable from a genuinely clean file. The clean-file
// passthrough made that worse by copying the original there verbatim.
func TestRedactFile_UnredactableFileTypeIsAnError(t *testing.T) {
	in := t.TempDir()
	out := t.TempDir()
	// Reserved documentation values, in a file type with no redactor.
	src := writeTemp(t, in, "creds.go",
		"package main\n\nconst key = \"AKIAIOSFODNN7EXAMPLE\" // jordan@example.com\n")

	res, err := RedactFile(RedactConfig{
		FilePath:  src,
		OutputDir: out,
		Checks:    []string{"all"},
		Config:    config.LoadConfigOrDefault(""),
		LogWriter: io.Discard,
	})
	if err == nil {
		t.Fatalf("expected an error for an unredactable file type; got result %+v", res)
	}
	if !strings.Contains(err.Error(), "could not redact") {
		t.Errorf("error should say redaction failed, got: %v", err)
	}
	if res != nil {
		t.Errorf("no result may be returned alongside the error, got %+v", res)
	}

	// And nothing may have been written under the output dir — the leak was a
	// cleartext copy at a path the caller treats as sanitized.
	err = filepath.Walk(out, func(path string, info os.FileInfo, werr error) error {
		if werr != nil || info.IsDir() {
			return werr
		}
		data, rerr := os.ReadFile(path) // #nosec G304 - test-controlled temp path
		if rerr != nil {
			return rerr
		}
		if strings.Contains(string(data), "AKIAIOSFODNN7EXAMPLE") {
			t.Errorf("cleartext value was copied to the output path %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking output dir: %v", err)
	}
}

func TestRedactFile_DefaultsToFormatPreserving(t *testing.T) {
	in := t.TempDir()
	out := t.TempDir()
	src := writeTemp(t, in, "e.txt", "email jordan@example.com\n")

	res, err := RedactFile(RedactConfig{
		FilePath:  src,
		OutputDir: out,
		Config:    config.LoadConfigOrDefault(""),
		LogWriter: io.Discard,
	})
	if err != nil {
		t.Fatalf("RedactFile error: %v", err)
	}
	if res.Strategy != "format_preserving" {
		t.Errorf("expected default strategy format_preserving, got %q", res.Strategy)
	}
}

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

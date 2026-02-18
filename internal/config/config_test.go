// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigOrDefault_NoFile(t *testing.T) {
	// With no config file, should return defaults without error
	cfg := LoadConfigOrDefault("")
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.Defaults.Format == "" {
		t.Error("expected default format to be set")
	}
}

func TestLoadConfigOrDefault_NonexistentFile(t *testing.T) {
	// A path that doesn't exist should fall back to defaults
	cfg := LoadConfigOrDefault("/nonexistent/path/config.yaml")
	if cfg == nil {
		t.Fatal("expected non-nil config (fallback to defaults)")
	}
}

func TestLoadConfigOrDefault_ValidFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	content := `
defaults:
  format: json
  confidence_levels: high
  checks: EMAIL,SSN
`
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	cfg := LoadConfigOrDefault(configPath)
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.Defaults.Format != "json" {
		t.Errorf("expected format=json, got %q", cfg.Defaults.Format)
	}
	if cfg.Defaults.ConfidenceLevels != "high" {
		t.Errorf("expected confidence_levels=high, got %q", cfg.Defaults.ConfidenceLevels)
	}
}

func TestLoadConfigOrDefault_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "bad.yaml")

	if err := os.WriteFile(configPath, []byte(":::invalid yaml:::"), 0600); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	// Should fall back to defaults, not panic
	cfg := LoadConfigOrDefault(configPath)
	if cfg == nil {
		t.Fatal("expected non-nil config (fallback to defaults on parse error)")
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Defaults.Format != "text" {
		t.Errorf("expected default format=text, got %q", cfg.Defaults.Format)
	}
	if cfg.Defaults.ConfidenceLevels != "all" {
		t.Errorf("expected default confidence_levels=all, got %q", cfg.Defaults.ConfidenceLevels)
	}
	if !cfg.Defaults.EnablePreprocessors {
		t.Error("expected enable_preprocessors=true by default")
	}
}

func TestLoadConfig_ProfilesInitialized(t *testing.T) {
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Profiles == nil {
		t.Error("expected profiles map to be initialized")
	}
	// Default precommit profile should exist
	if _, ok := cfg.Profiles["precommit"]; !ok {
		t.Error("expected 'precommit' profile to exist in defaults")
	}
}

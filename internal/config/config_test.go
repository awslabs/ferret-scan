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

func TestLoadConfig_NewDefaultsFields(t *testing.T) {
	// Verify that the newly-added defaults fields are parsed from YAML.
	// These were previously documented but silently ignored.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	content := `
defaults:
  format: text
  respect_gitignore: true
  show_match: true
  quiet: true
  show_suppressed: true
  generate_suppressions: true
  exclude_patterns:
    - ".git"
    - "node_modules"
    - "*.log"
`
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg := LoadConfigOrDefault(configPath)
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if !cfg.Defaults.RespectGitignore {
		t.Error("expected respect_gitignore=true")
	}
	if !cfg.Defaults.ShowMatch {
		t.Error("expected show_match=true")
	}
	if !cfg.Defaults.Quiet {
		t.Error("expected quiet=true")
	}
	if !cfg.Defaults.ShowSuppressed {
		t.Error("expected show_suppressed=true")
	}
	if !cfg.Defaults.GenerateSuppressions {
		t.Error("expected generate_suppressions=true")
	}
	if len(cfg.Defaults.ExcludePatterns) != 3 {
		t.Errorf("expected 3 exclude_patterns, got %d: %v", len(cfg.Defaults.ExcludePatterns), cfg.Defaults.ExcludePatterns)
	}
}

func TestLoadConfig_NewProfileFields(t *testing.T) {
	// Same fields should be parsed at profile level too.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	content := `
defaults:
  format: text

profiles:
  strict:
    format: json
    respect_gitignore: true
    show_match: true
    quiet: true
    show_suppressed: true
    generate_suppressions: true
    exclude_patterns:
      - "vendor/"
`
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg := LoadConfigOrDefault(configPath)
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	p, ok := cfg.Profiles["strict"]
	if !ok {
		t.Fatal("expected 'strict' profile")
	}
	if !p.RespectGitignore {
		t.Error("profile: expected respect_gitignore=true")
	}
	if !p.ShowMatch {
		t.Error("profile: expected show_match=true")
	}
	if !p.Quiet {
		t.Error("profile: expected quiet=true")
	}
	if !p.ShowSuppressed {
		t.Error("profile: expected show_suppressed=true")
	}
	if !p.GenerateSuppressions {
		t.Error("profile: expected generate_suppressions=true")
	}
	if len(p.ExcludePatterns) != 1 || p.ExcludePatterns[0] != "vendor/" {
		t.Errorf("profile: expected exclude_patterns=[vendor/], got %v", p.ExcludePatterns)
	}
}

func TestLoadConfig_ProfileCanDisableDefault(t *testing.T) {
	// Regression: a profile setting a bool to false must be preserved in the
	// parsed Profile struct so the resolver can override an inherited default
	// of true. (Previously the resolver had "if activeProfile.Quiet" guards
	// that silently ignored false profile values.)
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	content := `
defaults:
  quiet: true
  show_match: true
  respect_gitignore: true
  show_suppressed: true
  generate_suppressions: true

profiles:
  loud:
    quiet: false
    show_match: false
    respect_gitignore: false
    show_suppressed: false
    generate_suppressions: false
`
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg := LoadConfigOrDefault(configPath)
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}

	// Defaults preserved
	if !cfg.Defaults.Quiet || !cfg.Defaults.ShowMatch || !cfg.Defaults.RespectGitignore ||
		!cfg.Defaults.ShowSuppressed || !cfg.Defaults.GenerateSuppressions {
		t.Errorf("defaults not parsed: %+v", cfg.Defaults)
	}

	// Profile values are false — parse must NOT collapse them into zero-value
	// ambiguity. (Go's YAML unmarshaling reads explicit false as false, so
	// this verifies the struct tag layout is correct.)
	p, ok := cfg.Profiles["loud"]
	if !ok {
		t.Fatal("expected 'loud' profile")
	}
	if p.Quiet || p.ShowMatch || p.RespectGitignore || p.ShowSuppressed || p.GenerateSuppressions {
		t.Errorf("profile 'loud' should have all five fields false, got %+v", p)
	}
}

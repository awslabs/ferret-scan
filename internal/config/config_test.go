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

// --- New defaults/profile field parsing tests --------------------------------

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

// --- Profile bool inheritance tests ------------------------------------------

// TestProfile_InheritsDefaultBoolsWhenOmitted: the core fix. A profile that
// doesn't mention a bool field must NOT zero it out — it inherits the value
// from defaults instead. Previously, profile.Verbose parsed as false even
// when defaults.verbose was true, because Go unmarshals missing bools as false.
func TestProfile_InheritsDefaultBoolsWhenOmitted(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	content := `
defaults:
  verbose: true
  debug: true
  no_color: true
  recursive: true
  enable_preprocessors: false
  respect_gitignore: true
  show_match: true
  quiet: true
  show_suppressed: true
  generate_suppressions: true

redaction:
  enabled: true

profiles:
  bare:
    # Intentionally omits every bool field.
    description: "should inherit all bool settings from defaults"
`
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg := LoadConfigOrDefault(configPath)
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	p, ok := cfg.Profiles["bare"]
	if !ok {
		t.Fatal("expected 'bare' profile")
	}

	// Every bool on the profile must equal the corresponding defaults value.
	if !p.Verbose {
		t.Error("expected profile.verbose to inherit defaults.verbose=true")
	}
	if !p.Debug {
		t.Error("expected profile.debug to inherit defaults.debug=true")
	}
	if !p.NoColor {
		t.Error("expected profile.no_color to inherit defaults.no_color=true")
	}
	if !p.Recursive {
		t.Error("expected profile.recursive to inherit defaults.recursive=true")
	}
	if p.EnablePreprocessors {
		t.Error("expected profile.enable_preprocessors to inherit defaults.enable_preprocessors=false")
	}
	if !p.Redaction.Enabled {
		t.Error("expected profile.redaction.enabled to inherit redaction.enabled=true")
	}
	if !p.RespectGitignore {
		t.Error("expected profile.respect_gitignore to inherit defaults.respect_gitignore=true")
	}
	if !p.ShowMatch {
		t.Error("expected profile.show_match to inherit defaults.show_match=true")
	}
	if !p.Quiet {
		t.Error("expected profile.quiet to inherit defaults.quiet=true")
	}
	if !p.ShowSuppressed {
		t.Error("expected profile.show_suppressed to inherit defaults.show_suppressed=true")
	}
	if !p.GenerateSuppressions {
		t.Error("expected profile.generate_suppressions to inherit defaults.generate_suppressions=true")
	}
}

// TestProfile_ExplicitFalseWins: a profile that explicitly writes `false`
// for a bool must keep that false, even when defaults say true. This was the
// case silently broken before the fix.
func TestProfile_ExplicitFalseWins(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	content := `
defaults:
  verbose: true
  debug: true
  no_color: true
  recursive: true
  enable_preprocessors: true
  respect_gitignore: true
  show_match: true
  quiet: true
  show_suppressed: true
  generate_suppressions: true

redaction:
  enabled: true

profiles:
  loud:
    verbose: false
    debug: false
    no_color: false
    recursive: false
    enable_preprocessors: false
    respect_gitignore: false
    show_match: false
    quiet: false
    show_suppressed: false
    generate_suppressions: false
    redaction:
      enabled: false
`
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg := LoadConfigOrDefault(configPath)
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	p, ok := cfg.Profiles["loud"]
	if !ok {
		t.Fatal("expected 'loud' profile")
	}

	if p.Verbose || p.Debug || p.NoColor || p.Recursive || p.EnablePreprocessors ||
		p.Redaction.Enabled || p.RespectGitignore || p.ShowMatch || p.Quiet ||
		p.ShowSuppressed || p.GenerateSuppressions {
		t.Errorf("explicit profile false must win over default true; got %+v (redaction.enabled=%v)",
			p, p.Redaction.Enabled)
	}
}

// TestProfile_ExplicitTrueWins: symmetric check — explicit profile true
// survives even when defaults are false (this already worked, but worth
// locking in so the backfill doesn't regress it).
func TestProfile_ExplicitTrueWins(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	content := `
defaults:
  verbose: false
  debug: false

profiles:
  noisy:
    verbose: true
    debug: true
`
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg := LoadConfigOrDefault(configPath)
	p, ok := cfg.Profiles["noisy"]
	if !ok {
		t.Fatal("expected 'noisy' profile")
	}
	if !p.Verbose || !p.Debug {
		t.Errorf("explicit profile true must win over default false; got verbose=%v debug=%v",
			p.Verbose, p.Debug)
	}
}

// TestProfile_PartialOverride: a profile sets some bools and omits others.
// Set ones keep their explicit value; omitted ones inherit defaults.
func TestProfile_PartialOverride(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	content := `
defaults:
  verbose: true
  debug: false
  no_color: true
  recursive: false
  enable_preprocessors: true

profiles:
  mixed:
    verbose: false          # explicit override (false beats default true)
    recursive: true         # explicit override (true beats default false)
    # debug, no_color, enable_preprocessors omitted — inherit from defaults
`
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg := LoadConfigOrDefault(configPath)
	p, ok := cfg.Profiles["mixed"]
	if !ok {
		t.Fatal("expected 'mixed' profile")
	}

	// Explicit overrides
	if p.Verbose {
		t.Error("expected profile.verbose=false (explicit override of default true)")
	}
	if !p.Recursive {
		t.Error("expected profile.recursive=true (explicit override of default false)")
	}
	// Inherited from defaults
	if p.Debug {
		t.Error("expected profile.debug=false (inherited from defaults)")
	}
	if !p.NoColor {
		t.Error("expected profile.no_color=true (inherited from defaults)")
	}
	if !p.EnablePreprocessors {
		t.Error("expected profile.enable_preprocessors=true (inherited from defaults)")
	}
}

// TestProfile_NoDefaultsBlock: profile inheritance must not crash when the
// YAML has no defaults block at all. All profile bools should resolve to
// their zero values.
func TestProfile_NoDefaultsBlock(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	// Intentionally no defaults: block at top level.
	content := `
profiles:
  only:
    description: "profile with no defaults block to inherit from"
`
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg := LoadConfigOrDefault(configPath)
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	p, ok := cfg.Profiles["only"]
	if !ok {
		t.Fatal("expected 'only' profile")
	}
	// Built-in Config defaults for EnablePreprocessors is true; others are
	// zero-valued. Backfill should honor the built-in defaults.
	if !p.EnablePreprocessors {
		t.Error("expected enable_preprocessors=true from built-in default")
	}
	if p.Verbose || p.Debug || p.NoColor || p.Recursive {
		t.Error("expected other bools to be false (zero value for missing defaults)")
	}
}

// TestProfile_MultipleProfilesIndependent: profile A's settings must not
// leak into profile B. Each profile's inheritance is evaluated independently.
func TestProfile_MultipleProfilesIndependent(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	content := `
defaults:
  verbose: true

profiles:
  a:
    verbose: false          # explicit false
  b:
    description: "inherits verbose=true from defaults"
  c:
    verbose: true           # explicit true (same as default)
`
	if err := os.WriteFile(configPath, []byte(content), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg := LoadConfigOrDefault(configPath)
	if cfg.Profiles["a"].Verbose {
		t.Error("profile a: expected verbose=false (explicit)")
	}
	if !cfg.Profiles["b"].Verbose {
		t.Error("profile b: expected verbose=true (inherited)")
	}
	if !cfg.Profiles["c"].Verbose {
		t.Error("profile c: expected verbose=true (explicit)")
	}
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestValidateSchema_EnumFields covers the accept/reject matrix for every
// enum-like field in both the Defaults block and a profile.
func TestValidateSchema_EnumFields(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string // substring expected in the error; "" means expect success
	}{
		{"empty defaults valid", func(c *Config) {}, ""},
		{"valid format", func(c *Config) { c.Defaults.Format = "json" }, ""},
		{"invalid format", func(c *Config) { c.Defaults.Format = "jsonn" }, "defaults.format"},
		{"empty format accepted", func(c *Config) { c.Defaults.Format = "" }, ""},
		{"valid strategy", func(c *Config) { c.Redaction.Strategy = "synthetic" }, ""},
		{"invalid strategy", func(c *Config) { c.Redaction.Strategy = "fromat_preserving" }, "redaction.strategy"},
		{"confidence all wildcard", func(c *Config) { c.Defaults.ConfidenceLevels = "all" }, ""},
		{"confidence combo", func(c *Config) { c.Defaults.ConfidenceLevels = "high,medium" }, ""},
		{"confidence bad token", func(c *Config) { c.Defaults.ConfidenceLevels = "high,extreme" }, "defaults.confidence_levels"},
		{"checks all wildcard", func(c *Config) { c.Defaults.Checks = "all" }, ""},
		{"checks combo", func(c *Config) { c.Defaults.Checks = "SSN,CREDIT_CARD" }, ""},
		{"checks bad token", func(c *Config) { c.Defaults.Checks = "SSN,CREDIT_KARD" }, "defaults.checks"},
		{"checks METADATA allowed", func(c *Config) { c.Defaults.Checks = "METADATA" }, ""},
		{"profile invalid format", func(c *Config) {
			c.Profiles = map[string]Profile{"p": {Format: "xml"}}
		}, `profile "p".format`},
		{"profile invalid checks", func(c *Config) {
			c.Profiles = map[string]Profile{"p": {Checks: "BOGUS"}}
		}, `profile "p".checks`},
		{"profile valid", func(c *Config) {
			c.Profiles = map[string]Profile{"p": {Format: "csv", Checks: "SSN"}}
		}, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{}
			tc.mutate(cfg)
			err := ValidateSchema(cfg)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected success, got error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// TestValidateSchema_ErrorNamesValueAndDomain confirms the message is
// actionable: it quotes the offending value and lists the valid set.
func TestValidateSchema_ErrorNamesValueAndDomain(t *testing.T) {
	cfg := &Config{}
	cfg.Defaults.Format = "jsonn"
	err := ValidateSchema(cfg)
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	for _, want := range []string{`"jsonn"`, "defaults.format", "json", "text", "sarif"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q missing %q", msg, want)
		}
	}
}

// TestValidateSchema_NilConfig guards the nil path.
func TestValidateSchema_NilConfig(t *testing.T) {
	if err := ValidateSchema(nil); err == nil {
		t.Error("expected error for nil config")
	}
}

// TestLoadConfigStrict_RejectsInvalidEnum proves the schema is enforced on the
// strict (operator-supplied) path.
func TestLoadConfigStrict_RejectsInvalidEnum(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("defaults:\n  format: jsonn\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfigStrict(path)
	if err == nil {
		t.Fatal("LoadConfigStrict must reject an invalid enum value")
	}
	if cfg != nil {
		t.Error("cfg should be nil on validation failure")
	}
	if !strings.Contains(err.Error(), "defaults.format") {
		t.Errorf("error should name the offending field; got: %v", err)
	}
}

// TestLoadConfig_LenientPathIgnoresInvalidEnum proves the default (best-effort)
// path is UNCHANGED: a bad enum value still loads, preserving prior behavior.
// This is the behavior-preservation guarantee for the schema addition.
func TestLoadConfig_LenientPathIgnoresInvalidEnum(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("defaults:\n  format: jsonn\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// LoadConfig does not run schema validation.
	if _, err := LoadConfig(path); err != nil {
		t.Errorf("LoadConfig (lenient) should not run schema validation; got: %v", err)
	}
	// LoadConfigOrDefault likewise loads without erroring.
	if cfg := LoadConfigOrDefault(path); cfg == nil {
		t.Error("LoadConfigOrDefault should return a config, not nil")
	}
}

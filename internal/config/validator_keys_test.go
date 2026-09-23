// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The behavioural half of #726: every position inside the validators subtree that used to be
// SILENT must now surface through UnknownKeys, the honored control must stay silent, and the
// shipped example configs must produce no validator warnings (they use only declared keys — if
// this fails, either an example promises a knob the code ignores, or the declaration lost one).
func TestValidatorsSubtreeUnknownKeysWarn(t *testing.T) {
	load := func(t *testing.T, yaml string) *Config {
		t.Helper()
		p := filepath.Join(t.TempDir(), "c.yaml")
		if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := LoadConfig(p)
		if err != nil {
			t.Fatalf("LoadConfig: %v", err)
		}
		return cfg
	}
	validatorWarnings := func(cfg *Config) []string {
		var out []string
		for _, k := range cfg.UnknownKeys {
			if strings.Contains(k, "validators") {
				out = append(out, k)
			}
		}
		return out
	}

	t.Run("disabled_types under secrets names the honoring section", func(t *testing.T) {
		cfg := load(t, "validators:\n  secrets:\n    disabled_types:\n      - api_key\n")
		w := validatorWarnings(cfg)
		if len(w) != 1 || !strings.Contains(w[0], "only intellectual_property honors disabled_types") {
			t.Fatalf("want one warning naming the honoring section, got %v", w)
		}
	})

	t.Run("unknown section warns once, not per key", func(t *testing.T) {
		cfg := load(t, "validators:\n  no_such:\n    a: 1\n    b: 2\n    c: 3\n")
		if w := validatorWarnings(cfg); len(w) != 1 {
			t.Fatalf("want exactly one section-level warning, got %v", w)
		}
	})

	t.Run("bogus key under a known section lists the honored keys", func(t *testing.T) {
		cfg := load(t, "validators:\n  intellectual_property:\n    bogus: true\n")
		w := validatorWarnings(cfg)
		if len(w) != 1 || !strings.Contains(w[0], "internal_urls") {
			t.Fatalf("want the honored-keys list in the warning, got %v", w)
		}
	})

	t.Run("profile-level validators are covered", func(t *testing.T) {
		cfg := load(t, "profiles:\n  p1:\n    validators:\n      secrets:\n        x: 1\n")
		w := validatorWarnings(cfg)
		if len(w) != 1 || !strings.HasPrefix(w[0], "profiles.p1.validators.secrets") {
			t.Fatalf("want a profiles.p1-prefixed warning, got %v", w)
		}
	})

	t.Run("honored keys stay silent", func(t *testing.T) {
		cfg := load(t, "validators:\n  intellectual_property:\n    disabled_types:\n      - copyright\n    internal_urls:\n      - 'x'\n")
		if w := validatorWarnings(cfg); len(w) != 0 {
			t.Fatalf("honored keys warned: %v", w)
		}
	})

	t.Run("shipped examples produce no validator warnings", func(t *testing.T) {
		root := repoRootFromGoModConfig(t)
		for _, f := range []string{"examples/ferret.yaml", "examples/ferret-windows.yaml"} {
			cfg, err := LoadConfig(filepath.Join(root, f))
			if err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			if w := validatorWarnings(cfg); len(w) != 0 {
				t.Errorf("%s warns: %v", f, w)
			}
		}
	})
}

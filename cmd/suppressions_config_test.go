// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
)

// The `suppressions:` block was documented in the shipped config.yaml but had no
// struct field, so all three of its keys were discarded by the YAML decoder. Now
// that they parse, they also have to reach the resolved configuration — parsing
// into a field nothing reads is the same defect one layer up.
//
// No CLI flag is set in-test, so isFlagSet is false throughout and these cover
// the config-file half of the precedence chain.

func TestResolveConfiguration_SuppressionsBlock(t *testing.T) {
	t.Run("suppressions.file reaches the resolved config", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Suppressions.File = "/tmp/probe-suppressions.yaml"

		final := resolveConfiguration(cfg, nil, &configFlags{})
		if final.suppressionFile != "/tmp/probe-suppressions.yaml" {
			t.Errorf("suppressionFile = %q, want the configured path — the suppression "+
				"manager is constructed from this value, so an unread key means the "+
				"user's rules are never loaded", final.suppressionFile)
		}
	})

	t.Run("suppressions.generate_on_scan enables generation", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Suppressions.GenerateOnScan = true

		final := resolveConfiguration(cfg, nil, &configFlags{})
		if !final.generateSuppressions {
			t.Error("suppressions.generate_on_scan=true did not enable suppression generation")
		}
	})

	t.Run("suppressions.show_suppressed enables display", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Suppressions.ShowSuppressed = true

		final := resolveConfiguration(cfg, nil, &configFlags{})
		if !final.showSuppressed {
			t.Error("suppressions.show_suppressed=true did not enable suppressed display")
		}
	})

	t.Run("defaults.* still works on its own", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Defaults.ShowSuppressed = true
		cfg.Defaults.GenerateSuppressions = true

		final := resolveConfiguration(cfg, nil, &configFlags{})
		if !final.showSuppressed || !final.generateSuppressions {
			t.Error("the pre-existing defaults.show_suppressed / defaults.generate_suppressions " +
				"keys must keep working; the suppressions: block is an addition, not a " +
				"replacement")
		}
	})

	t.Run("a profile still overrides both", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Suppressions.ShowSuppressed = true
		cfg.Suppressions.GenerateOnScan = true
		prof := &config.Profile{ShowSuppressed: false, GenerateSuppressions: false}

		final := resolveConfiguration(cfg, prof, &configFlags{})
		if final.showSuppressed {
			t.Error("an active profile must override suppressions.show_suppressed")
		}
		if final.generateSuppressions {
			t.Error("an active profile must override suppressions.generate_on_scan")
		}
	})

	t.Run("empty file leaves the platform default", func(t *testing.T) {
		final := resolveConfiguration(&config.Config{}, nil, &configFlags{})
		if final.suppressionFile != "" {
			t.Errorf("suppressionFile = %q, want empty so the suppression manager picks "+
				"its own platform-specific default", final.suppressionFile)
		}
	})
}

// TestWarnUnknownConfigKeys covers the helper's output and its nil-safety. The
// config loader's failure path can hand back a nil config, and the writer is
// io.Discard whenever stderr is a data channel rather than a human one.
func TestWarnUnknownConfigKeys(t *testing.T) {
	t.Run("nil inputs do not panic", func(t *testing.T) {
		var buf bytes.Buffer
		warnUnknownConfigKeys(&buf, nil)
		warnUnknownConfigKeys(nil, &config.Config{UnknownKeys: []string{"x"}})
		if buf.Len() != 0 {
			t.Errorf("expected no output for a nil config, got %q", buf.String())
		}
	})

	t.Run("one line per unknown key", func(t *testing.T) {
		var buf bytes.Buffer
		warnUnknownConfigKeys(&buf, &config.Config{
			UnknownKeys: []string{"shwo_match", "nonsense_block"},
		})
		out := buf.String()
		for _, want := range []string{"shwo_match", "nonsense_block"} {
			if !strings.Contains(out, want) {
				t.Errorf("output %q does not mention %q", out, want)
			}
		}
		if got := strings.Count(out, "\n"); got != 2 {
			t.Errorf("expected 2 warning lines, got %d: %q", got, out)
		}
	})

	t.Run("a clean config writes nothing", func(t *testing.T) {
		var buf bytes.Buffer
		warnUnknownConfigKeys(&buf, &config.Config{})
		if buf.Len() != 0 {
			t.Errorf("expected silence for a config with no unknown keys, got %q", buf.String())
		}
	})
}

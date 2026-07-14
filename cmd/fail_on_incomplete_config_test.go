// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
)

// TestResolveConfiguration_FailOnIncomplete covers the config/profile precedence
// for fail_on_incomplete (no CLI flag set in-test, so isFlagSet is false — the
// flag-override branch is exercised end-to-end by the binary smoke test and by
// TestResolveIncompleteExitCode). Order: config default -> profile overrides.
func TestResolveConfiguration_FailOnIncomplete(t *testing.T) {
	t.Run("defaults false when unset", func(t *testing.T) {
		final := resolveConfiguration(&config.Config{}, nil, &configFlags{})
		if final.failOnIncomplete {
			t.Error("expected failOnIncomplete=false by default")
		}
	})

	t.Run("config default true", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Defaults.FailOnIncomplete = true
		final := resolveConfiguration(cfg, nil, &configFlags{})
		if !final.failOnIncomplete {
			t.Error("expected config Defaults.FailOnIncomplete=true to be honored")
		}
	})

	t.Run("profile overrides config", func(t *testing.T) {
		cfg := &config.Config{}
		cfg.Defaults.FailOnIncomplete = true
		prof := &config.Profile{FailOnIncomplete: false}
		final := resolveConfiguration(cfg, prof, &configFlags{})
		if final.failOnIncomplete {
			t.Error("expected active profile FailOnIncomplete=false to override config default true")
		}
	})

	t.Run("profile enables when config default false", func(t *testing.T) {
		cfg := &config.Config{}
		prof := &config.Profile{FailOnIncomplete: true}
		final := resolveConfiguration(cfg, prof, &configFlags{})
		if !final.failOnIncomplete {
			t.Error("expected active profile FailOnIncomplete=true to enable")
		}
	})
}

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

// TestResolveIncompleteExitCode_CountsUnreadableFiles pins that a file which could
// not be OPENED escalates the exit code the same way a cut-short scan does.
//
// The two are the same class of problem from the caller's point of view — findings
// may be missing — and the unreadable case is the more severe of the pair: a
// cut-short scan examined part of the file, an unreadable one was never examined at
// all. Before this, an unreadable file left the exit code at 0 and printed "No
// matches found", so CI treated a file the scanner never opened as clean.
func TestResolveIncompleteExitCode_CountsUnreadableFiles(t *testing.T) {
	// The production call site passes len(incompleteFiles)+len(unreadableFiles);
	// this asserts the policy those counts feed.
	if got := resolveIncompleteExitCode(0, true, 1); got != exitCodeIncompleteCoverage {
		t.Errorf("one coverage gap with --fail-on-incomplete = %d, want %d",
			got, exitCodeIncompleteCoverage)
	}
	if got := resolveIncompleteExitCode(0, false, 1); got != 0 {
		t.Errorf("without --fail-on-incomplete the warning must stay advisory, got %d", got)
	}
	// A findings/error verdict is never downgraded to the coverage code.
	if got := resolveIncompleteExitCode(1, true, 1); got != 1 {
		t.Errorf("a non-zero base must not be replaced, got %d", got)
	}
}

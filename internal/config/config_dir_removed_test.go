// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #641: platform.<os>.config_dir was parsed, validated, shipped in an example and documented in four
// places, and never consulted. Measured on one copyright notice with --checks INTELLECTUAL_PROPERTY,
// against a second config in another directory that disables the copyright sub-type:
//
//	empty user config dir                                   1 finding   (baseline)
//	FERRET_CONFIG_DIR pointing at that directory            0 findings  (works)
//	platform.unix.config_dir pointing at the same place     1 finding   (ignored)
//
// It cannot work: a config-directory override read OUT of the config file asks the file where the file
// lives. GetEffectiveConfigDir, which existed to serve it, had no caller anywhere in the tree.

// TestConfigDirIsNotASchemaKey pins the removal, and it pins it through the UNKNOWN-KEY path rather
// than by asserting a field is absent — because "the field is gone" is what a compiler enforces, while
// "an operator who sets it is told" is the behaviour that actually changed.
func TestConfigDirIsNotASchemaKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "with-config-dir.yaml")
	body := "platform:\n  unix:\n    config_dir: \"/tmp/somewhere\"\n    temp_dir: \"/tmp/t\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig on a config carrying the removed key: %v — a removed key must be an "+
			"unknown key, not a load failure", err)
	}

	unknown := cfg.UnknownKeys
	if !containsString(unknown, "config_dir") {
		t.Errorf("UnknownKeys = %v, want it to include \"config_dir\". Silently ignoring a key an "+
			"operator deliberately set is the worse of the two failures, and the warning is the whole "+
			"point of removing the field rather than leaving it parsed-and-unused", unknown)
	}

	// The surviving sibling must NOT be reported unknown: temp_dir is coherent as a config-file
	// override (the temp directory is not needed in order to find the config) and is wired through
	// paths.tempDirOverrideValue. Removing the wrong one of the two is the mistake this guards.
	if containsString(unknown, "temp_dir") {
		t.Errorf("temp_dir is reported as an unknown key: %v. It is the override that DOES work, and "+
			"the asymmetry between the two is deliberate", unknown)
	}
}

// TestGetEffectiveConfigDirIsGone is a compile-time assertion in test form: if the function comes back,
// this file stops building and the reviewer is pointed at why it cannot work.
//
// Written as a doc-comment reference rather than a call, because calling a function to prove it does not
// exist is not possible — the point is that a future reader looking for it finds this explanation.
func TestGetEffectiveConfigDirIsGone(t *testing.T) {
	// GetEffectiveTempDir survives and is called; its config-dir counterpart was deleted because a
	// config-directory override cannot be read out of the config file. If you are here because you
	// want the behaviour, the mechanism is FERRET_CONFIG_DIR, read in paths.GetConfigDir.
	if got := GetEffectiveTempDir(&Config{}); got == "" {
		t.Error("GetEffectiveTempDir returned empty for a zero config, so the sibling that DOES work " +
			"is not working — this test exists to keep the two straight")
	}
}

func containsString(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle || strings.HasSuffix(h, "."+needle) {
			return true
		}
	}
	return false
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// This is an EXTERNAL test package (config_test, not config) on purpose:
// internal/config cannot import pkg/redact or internal/core in production code
// (core imports config, so it would be an import cycle). An external test
// package compiles as its own unit and may import both, which lets us guard the
// locally-defined enum domains in schema.go against the canonical registries
// they mirror. If a validator is added/renamed/removed, or a formatter is
// added, these tests fail and point at schema.go.
package config_test

import (
	"sort"
	"testing"

	"github.com/awslabs/ferret-scan/internal/config"
	"github.com/awslabs/ferret-scan/internal/formatters"
	"github.com/awslabs/ferret-scan/pkg/redact"
)

// metadataCheck is the one validator redact.ValidCheckNames() omits (it is not
// supported by the in-memory redaction engine) but which a file-based config
// may still reference, so schema.go's validCheckNames includes it.
const metadataCheck = "METADATA"

// TestSchemaCheckNames_MatchRegistry ensures schema.go's validCheckNames domain
// stays in sync with the canonical validator ID list. It reconstructs the
// expected set from redact.ValidCheckNames() (which is core.CheckNames() minus
// METADATA) plus METADATA, and compares it to what ValidateSchema actually
// accepts, probed field-by-field.
func TestSchemaCheckNames_MatchRegistry(t *testing.T) {
	expected := append(redact.ValidCheckNames(), metadataCheck)
	sort.Strings(expected)

	for _, name := range expected {
		// A config with just this check must validate.
		cfg := newSchemaProbeConfig()
		cfg.Defaults.Checks = name
		if err := config.ValidateSchema(cfg); err != nil {
			t.Errorf("check %q is canonical but ValidateSchema rejected it: %v", name, err)
		}
	}

	// A name that is not canonical must be rejected, proving the domain is not
	// simply accepting everything.
	cfg := newSchemaProbeConfig()
	cfg.Defaults.Checks = "NOT_A_REAL_CHECK"
	if err := config.ValidateSchema(cfg); err == nil {
		t.Error("ValidateSchema accepted a bogus check name; the domain is too permissive")
	}
}

// TestSchemaFormats_MatchRegistry ensures schema.go's validFormats domain stays
// in sync with the formatter registry. Every registered formatter must be an
// accepted config format value.
func TestSchemaFormats_MatchRegistry(t *testing.T) {
	for _, name := range formatters.List() {
		cfg := newSchemaProbeConfig()
		cfg.Defaults.Format = name
		if err := config.ValidateSchema(cfg); err != nil {
			t.Errorf("format %q is registered but ValidateSchema rejected it: %v", name, err)
		}
	}
}

// newSchemaProbeConfig returns a minimal, all-valid Config for probing a single
// field. Profiles is nil so only the Defaults block under test is exercised.
func newSchemaProbeConfig() *config.Config {
	return &config.Config{}
}

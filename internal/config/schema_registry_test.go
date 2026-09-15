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

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
	"github.com/awslabs/ferret-scan/v2/pkg/redact"
)

// checksNotInRedactAPI are the validators redact.ValidCheckNames() omits
// because the in-memory redaction engine cannot make them produce a finding —
// METADATA needs filesystem access, and SOCIAL_MEDIA has no built-in patterns
// (its only pattern source is project config, which pkg/redact does not
// accept). A FILE-BASED config may legitimately reference both, so schema.go's
// validCheckNames must keep them; that asymmetry is deliberate and is exactly
// what this constant records.
var checksNotInRedactAPI = []string{"METADATA", "SOCIAL_MEDIA"}

// TestSchemaCheckNames_MatchRegistry ensures schema.go's validCheckNames domain
// stays in sync with the canonical validator ID list. It reconstructs the
// expected set from redact.ValidCheckNames() (which is core.CheckNames() minus
// checksNotInRedactAPI) plus those names back, and compares it to what
// ValidateSchema actually accepts, probed field-by-field.
func TestSchemaCheckNames_MatchRegistry(t *testing.T) {
	expected := append(redact.ValidCheckNames(), checksNotInRedactAPI...)
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

// confidenceSpellings is one table fed to BOTH the config schema and the scanner's parser.
//
// The divergence it exists to prevent: validateEnumField compared the "all" wildcard with == against
// the RAW field value, while core.ParseConfidenceLevels lowercases and trims every token. So
// `confidence_levels: ALL` in a config file was REJECTED while `--confidence ALL` on the command line
// was accepted — and `All`, ` all `, `all,high` and `HIGH` behaved the same way. One of those is the
// documented default, so a user moving a working command line into a config file got a validation
// error for a value the tool itself accepts.
//
// Asserted as AGREEMENT rather than by sharing code, because internal/config cannot import
// internal/core — core imports config. An external test package can import both, which is the same
// reason the check-name and formatter guards in this file are here.
var confidenceSpellings = []string{
	"all", "ALL", "All", "aLL", " all ", "all,high", "high,all",
	"high", "HIGH", "Medium", "high,medium", " high , low ",
	"", "   ", ",", "high,,low",
	"nonsense", "hi", "high,med", "medum", "HIGHEST", "none",
}

func TestConfidenceSpellingsAgreeWithTheScanner(t *testing.T) {
	for _, spelling := range confidenceSpellings {
		cfg := &config.Config{}
		cfg.Defaults.ConfidenceLevels = spelling
		schemaRejected := config.ValidateSchema(cfg) != nil

		_, parseErr := core.ParseConfidenceLevels(spelling)
		parserRejected := parseErr != nil

		if schemaRejected != parserRejected {
			verdict := func(rejected bool) string {
				if rejected {
					return "REJECTED"
				}
				return "accepted"
			}
			t.Errorf("confidence_levels %q: the config schema %s it and the scanner's parser %s it.\n"+
				"  A value the tool accepts on the command line must be valid in a config file, and a "+
				"value it refuses must be refused in both places. Update validateConfidenceLevels in "+
				"schema.go and core.ParseConfidenceLevels together.",
				spelling, verdict(schemaRejected), verdict(parserRejected))
		}
	}
}

// TestConfidenceSpellingsTableIsNotVacuous: the table must contain both accepted and rejected values,
// or the agreement above holds trivially.
func TestConfidenceSpellingsTableIsNotVacuous(t *testing.T) {
	var accepted, rejected int
	for _, spelling := range confidenceSpellings {
		if _, err := core.ParseConfidenceLevels(spelling); err != nil {
			rejected++
		} else {
			accepted++
		}
	}
	if accepted < 5 || rejected < 5 {
		t.Errorf("the spelling table has %d accepted and %d rejected values; it needs both in numbers "+
			"for the agreement test to mean anything", accepted, rejected)
	}
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"sort"
	"strings"
)

// This file adds typed-schema validation for the enum-like string fields in a
// configuration file (v2 gap 6.4). YAML unmarshaling accepts any string for
// these fields, so a typo like `format: jsonn` or `strategy: fromat_preserving`
// used to be silently ignored (the field kept an unusable value and the tool
// fell back to a default downstream). ValidateSchema rejects such values with a
// message that names the field, the bad value, and the valid set.
//
// It is intentionally wired ONLY into LoadConfigStrict (the operator-supplied
// `--config <path>` / web `--config` path, whose documented contract is to
// surface errors immediately). LoadConfig / LoadConfigOrDefault — the
// best-effort auto-discovery path — remain lenient so their behavior is
// unchanged. See LoadConfigStrict for the rationale.

// validFormats is the set of output formats the CLI/web recognize. It mirrors
// the formatter registry (internal/formatters) and the `--format` flag help.
// Kept as a local literal rather than importing the formatters package to avoid
// coupling config loading to formatter registration order; schema_registry_test
// guards it against drift from the real registry.
var validFormats = map[string]bool{
	"text":        true,
	"json":        true,
	"csv":         true,
	"yaml":        true,
	"junit":       true,
	"gitlab-sast": true,
	"sarif":       true,
}

// validRedactionStrategies mirrors redactors.ParseRedactionStrategy.
var validRedactionStrategies = map[string]bool{
	"simple":            true,
	"format_preserving": true,
	"synthetic":         true,
}

// validConfidenceLevels is the domain for a single confidence token. The field
// accepts "all" or a comma-separated combination of these.
var validConfidenceLevels = map[string]bool{
	"high":   true,
	"medium": true,
	"low":    true,
}

// validCheckNames is the domain for a single check token in a `checks` field.
// The field accepts "all" or a comma-separated combination of these. This is a
// local copy of the canonical validator IDs (internal/core.CheckNames, exported
// as redact.ValidCheckNames): config cannot import core/redact without an import
// cycle (core imports config). schema_registry_test.go, an external test
// package, compares this map against redact.ValidCheckNames() so it fails the
// moment the canonical list changes.
var validCheckNames = map[string]bool{
	"CLOUD_RESOURCES":       true,
	"CREDIT_CARD":           true,
	"EMAIL":                 true,
	"PHONE":                 true,
	"IP_ADDRESS":            true,
	"PASSPORT":              true,
	"PERSON_NAME":           true,
	"METADATA":              true,
	"INTELLECTUAL_PROPERTY": true,
	"SOCIAL_MEDIA":          true,
	"SSN":                   true,
	"SECRETS":               true,
	"VIN":                   true,
}

// ValidateSchema checks the enum-like string fields of config (in Defaults and
// every profile) against their known domains and returns the first violation
// found, or nil when every field is valid or empty. Empty strings are accepted:
// an omitted field falls back to its built-in default, which is not a config
// error.
func ValidateSchema(config *Config) error {
	if config == nil {
		return fmt.Errorf("configuration cannot be nil")
	}

	// Defaults block.
	if err := validateEnumField("defaults.format", config.Defaults.Format, validFormats); err != nil {
		return err
	}
	if err := validateEnumField("defaults.confidence_levels", config.Defaults.ConfidenceLevels, validConfidenceLevels, "all"); err != nil {
		return err
	}
	if err := validateEnumField("defaults.checks", config.Defaults.Checks, validCheckNames, "all"); err != nil {
		return err
	}
	if err := validateEnumField("redaction.strategy", config.Redaction.Strategy, validRedactionStrategies); err != nil {
		return err
	}

	// Each profile. Sort names so the error reported for a multi-profile file is
	// deterministic (map iteration order is not).
	names := make([]string, 0, len(config.Profiles))
	for name := range config.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		p := config.Profiles[name]
		prefix := fmt.Sprintf("profile %q", name)
		if err := validateEnumField(prefix+".format", p.Format, validFormats); err != nil {
			return err
		}
		if err := validateEnumField(prefix+".confidence_levels", p.ConfidenceLevels, validConfidenceLevels, "all"); err != nil {
			return err
		}
		if err := validateEnumField(prefix+".checks", p.Checks, validCheckNames, "all"); err != nil {
			return err
		}
		if err := validateEnumField(prefix+".redaction.strategy", p.Redaction.Strategy, validRedactionStrategies); err != nil {
			return err
		}
	}
	return nil
}

// validateEnumField validates a single config field. An empty value is accepted
// (falls back to a default). When wildcards are supplied (e.g. "all"), the whole
// value matching a wildcard is accepted verbatim. Otherwise the value is split
// on commas and every token must be in domain — this handles both scalar fields
// (format, strategy) and list-like fields (checks, confidence_levels), since a
// scalar is just a single-token list.
func validateEnumField(fieldName, value string, domain map[string]bool, wildcards ...string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	for _, w := range wildcards {
		if value == w {
			return nil
		}
	}
	for _, token := range strings.Split(value, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if !domain[token] {
			return fmt.Errorf("invalid value %q for %s: valid values are %s%s",
				token, fieldName, sortedKeys(domain), wildcardSuffix(wildcards))
		}
	}
	return nil
}

// sortedKeys renders a domain as a sorted, comma-separated list for error text.
func sortedKeys(domain map[string]bool) string {
	keys := make([]string, 0, len(domain))
	for k := range domain {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

// wildcardSuffix appends the accepted wildcard(s) to an error message, e.g.
// ` (or "all")`, so operators see the full accepted set.
func wildcardSuffix(wildcards []string) string {
	if len(wildcards) == 0 {
		return ""
	}
	quoted := make([]string, len(wildcards))
	for i, w := range wildcards {
		quoted[i] = fmt.Sprintf("%q", w)
	}
	return fmt.Sprintf(" (or %s)", strings.Join(quoted, ", "))
}

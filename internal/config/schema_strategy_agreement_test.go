// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package config_test

import (
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// strategySpellings mixes the three names, their case and whitespace variants, list spellings, the
// empty and blank values, and typos. Both accepted and refused values are needed, or the agreement
// below holds trivially; TestStrategySpellingsTableIsNotVacuous enforces that.
var strategySpellings = []string{
	"simple", "format_preserving", "synthetic",
	"SIMPLE", "Simple", " simple", "simple ", " simple ", "FORMAT_PRESERVING", "Synthetic",
	"simple,", "simple,synthetic", "simple, simple", ",simple",
	"", "  ", "\t",
	"simpel", "synthetc", "format-preserving", "formatpreserving", "none", "bogus", "default",
}

// TestRedactionStrategySpellingsAgreeWithTheRedactor pins the #772 rule that the config schema and
// the redactor's parser accept and refuse the SAME spellings of redaction.strategy, in both the
// defaults and a profile. Before the fix the schema trimmed and comma-split, so " simple ",
// "simple," and "simple,synthetic" passed it and then reached a parser that matched none of them
// and fell back to format_preserving -- the one enum where the schema's leniency reached the output.
//
// The one deliberate difference: the schema treats the literal empty string as "unset" and the
// parser refuses it, because "unset" is a precedence decision the CLI makes before parsing. So ""
// is excluded from the comparison and pinned on its own below.
func TestRedactionStrategySpellingsAgreeWithTheRedactor(t *testing.T) {
	for _, spelling := range strategySpellings {
		if spelling == "" {
			continue
		}
		cfg := &config.Config{}
		cfg.Redaction.Strategy = spelling
		schemaRejected := config.ValidateSchema(cfg) != nil

		prof := &config.Config{Profiles: map[string]config.Profile{"share": {}}}
		p := prof.Profiles["share"]
		p.Redaction.Strategy = spelling
		prof.Profiles["share"] = p
		profileRejected := config.ValidateSchema(prof) != nil

		_, parseErr := redactors.ParseRedactionStrategy(spelling)
		parserRejected := parseErr != nil

		verdict := func(rejected bool) string {
			if rejected {
				return "REJECTED"
			}
			return "accepted"
		}
		if schemaRejected != parserRejected {
			t.Errorf("redaction.strategy %q: the config schema %s it and the redactor's parser %s it.\n"+
				"  A value the tool applies must be valid in a config file, and a value it refuses must be "+
				"refused in both places. Update validRedactionStrategies/validateExactEnumField in schema.go "+
				"and redactors.ParseRedactionStrategy together.",
				spelling, verdict(schemaRejected), verdict(parserRejected))
		}
		if profileRejected != schemaRejected {
			t.Errorf("redaction.strategy %q: defaults %s, profile %s; the two schema sites must agree",
				spelling, verdict(schemaRejected), verdict(profileRejected))
		}
	}

	// The empty string: unset for the schema, an error for the parser (its callers decide defaults).
	empty := &config.Config{}
	if err := config.ValidateSchema(empty); err != nil {
		t.Errorf("an unset redaction.strategy must pass the schema: %v", err)
	}
	if _, err := redactors.ParseRedactionStrategy(""); err == nil {
		t.Error("the parser must refuse the empty string; a caller that reaches it with \"\" skipped its precedence step")
	}
}

func TestStrategySpellingsTableIsNotVacuous(t *testing.T) {
	var accepted, rejected int
	for _, s := range strategySpellings {
		if _, err := redactors.ParseRedactionStrategy(s); err != nil {
			rejected++
		} else {
			accepted++
		}
	}
	if accepted != 3 || rejected < 10 {
		t.Errorf("the spelling table has %d accepted and %d rejected values; it needs the three names and many refusals", accepted, rejected)
	}
	// The names the schema knows are exactly the names the redactor exports.
	cfg := &config.Config{}
	for _, name := range redactors.RedactionStrategyNames {
		cfg.Redaction.Strategy = name
		if err := config.ValidateSchema(cfg); err != nil {
			t.Errorf("schema rejects %q, which the redactor exports as a valid name: %v", name, err)
		}
	}
}

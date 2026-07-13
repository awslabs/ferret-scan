// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/core"
)

// These tests lock the check-name strings that the CLI derives from
// core.CheckNames() to their exact historical literals. The golden corpus does
// NOT cover --help / --checks stderr text, so without these a drift between
// core.CheckNames() (the single source of truth) and the user-visible strings
// would go unnoticed. They are byte-equality guards for the v2 gap-3.3
// check-name unification.

// checkNameLiteral is the exact, historically-shipped sorted name list with the
// ", " separator used by the --checks flag help and the "Available checks:"
// error message in cmd/main.go.
const checkNameLiteral = "CLOUD_RESOURCES, CREDIT_CARD, EMAIL, INTELLECTUAL_PROPERTY, IP_ADDRESS, METADATA, PASSPORT, PERSON_NAME, PHONE, SECRETS, SOCIAL_MEDIA, SSN, VIN"

func TestCheckNamesJoinMatchesHistoricalLiteral(t *testing.T) {
	got := strings.Join(core.CheckNames(), ", ")
	if got != checkNameLiteral {
		t.Errorf("core.CheckNames() join drifted from the shipped --checks help string:\n  got:  %q\n  want: %q\n(if a validator was intentionally added/removed, update checkNameLiteral)", got, checkNameLiteral)
	}
}

func TestChecksFlagHelpStringByteEqual(t *testing.T) {
	// Reproduces the exact expression used at the --checks flag definition.
	got := "Specific checks to run: " + strings.Join(core.CheckNames(), ", ") + ", all (default: all)"
	want := "Specific checks to run: " + checkNameLiteral + ", all (default: all)"
	if got != want {
		t.Errorf("--checks flag help drifted:\n  got:  %q\n  want: %q", got, want)
	}
}

func TestParseChecksToRun_AcceptsEveryCanonicalName(t *testing.T) {
	for _, name := range core.CheckNames() {
		result := parseChecksToRun(name, false)
		if !result[name] {
			t.Errorf("parseChecksToRun(%q) did not enable %q; result=%v", name, name, result)
		}
	}
}

func TestParseChecksToRun_AllEnablesEverything(t *testing.T) {
	result := parseChecksToRun("all", false)
	for _, name := range core.CheckNames() {
		if !result[name] {
			t.Errorf("parseChecksToRun(\"all\") did not enable %q", name)
		}
	}
}

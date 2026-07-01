// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/internal/core"
)

func TestParseValidatorBudgets_Empty(t *testing.T) {
	for _, in := range []string{"", "   ", "\t"} {
		got, err := parseValidatorBudgets(in)
		if err != nil {
			t.Errorf("empty spec %q must not error, got %v", in, err)
		}
		if got != nil {
			t.Errorf("empty spec %q must yield nil map, got %v", in, got)
		}
	}
}

func TestParseValidatorBudgets_SingleAndMultiple(t *testing.T) {
	got, err := parseValidatorBudgets("SSN=30s, IP_ADDRESS=10s")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 budgets, got %d", len(got))
	}
	if got["SSN"].TimeLimit != 30*time.Second {
		t.Errorf("SSN = %v, want 30s", got["SSN"].TimeLimit)
	}
	if got["IP_ADDRESS"].TimeLimit != 10*time.Second {
		t.Errorf("IP_ADDRESS = %v, want 10s", got["IP_ADDRESS"].TimeLimit)
	}
}

func TestParseValidatorBudgets_CaseInsensitiveName(t *testing.T) {
	got, err := parseValidatorBudgets("ssn=1s")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["SSN"].TimeLimit != time.Second {
		t.Errorf("lower-case name must normalize to SSN, got %v", got)
	}
}

func TestParseValidatorBudgets_AllWildcard(t *testing.T) {
	got, err := parseValidatorBudgets("all=30s")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != len(core.CheckNames()) {
		t.Fatalf("all=30s must budget every check (%d), got %d", len(core.CheckNames()), len(got))
	}
	for _, name := range core.CheckNames() {
		if got[name].TimeLimit != 30*time.Second {
			t.Errorf("%s = %v, want 30s from wildcard", name, got[name].TimeLimit)
		}
	}
}

func TestParseValidatorBudgets_AllWithOverride(t *testing.T) {
	// Specific name overrides the wildcard, regardless of order.
	for _, spec := range []string{"all=30s,SSN=5s", "SSN=5s,all=30s"} {
		got, err := parseValidatorBudgets(spec)
		if err != nil {
			t.Fatalf("%q: unexpected error: %v", spec, err)
		}
		if got["SSN"].TimeLimit != 5*time.Second {
			t.Errorf("%q: SSN = %v, want override 5s", spec, got["SSN"].TimeLimit)
		}
		if got["IP_ADDRESS"].TimeLimit != 30*time.Second {
			t.Errorf("%q: IP_ADDRESS = %v, want wildcard 30s", spec, got["IP_ADDRESS"].TimeLimit)
		}
	}
}

func TestParseValidatorBudgets_ToleratesStrayCommas(t *testing.T) {
	got, err := parseValidatorBudgets("SSN=1s,,")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("stray commas should be tolerated, got %d entries", len(got))
	}
}

func TestParseValidatorBudgets_Errors(t *testing.T) {
	cases := []struct {
		name string
		spec string
	}{
		{"no equals", "SSN"},
		{"missing name", "=30s"},
		{"unknown check", "BOGUS=30s"},
		{"bad duration", "SSN=notaduration"},
		{"zero duration", "SSN=0s"},
		{"negative duration", "SSN=-5s"},
		{"duplicate name", "SSN=1s,SSN=2s"},
		{"duplicate all", "all=1s,all=2s"},
		{"empty duration", "SSN="},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseValidatorBudgets(tc.spec); err == nil {
				t.Errorf("spec %q must be rejected, but parsed cleanly", tc.spec)
			}
		})
	}
}

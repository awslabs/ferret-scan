// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func manyProfiles() map[string]Profile {
	return map[string]Profile{
		"zebra":      {},
		"production": {},
		"ci":         {},
		"precommit":  {},
		"audit":      {},
		"dev":        {},
		"minimal":    {},
		"strict":     {},
	}
}

// TestListProfilesIsSorted pins the `--list-profiles` output order. Ranging the
// Profiles map printed the same config file's profiles in a different sequence
// on every invocation, so the listing could not be diffed and looked like the
// config had changed when it had not.
func TestListProfilesIsSorted(t *testing.T) {
	c := &Config{Profiles: manyProfiles()}
	want := []string{"audit", "ci", "dev", "minimal", "precommit", "production", "strict", "zebra"}
	for i := 0; i < 100; i++ {
		got := c.ListProfiles()
		if len(got) != len(want) {
			t.Fatalf("ListProfiles returned %d names, want %d: %v", len(got), len(want), got)
		}
		for j := range want {
			if got[j] != want[j] {
				t.Fatalf("run %d: ListProfiles = %v, want %v", i, got, want)
			}
		}
	}
}

// TestSortedProfileNamesIsTotal guards the helper against dropping or inventing
// a profile. A dropped profile in ValidateConfig's loop would mean an invalid
// path silently passing validation.
func TestSortedProfileNamesIsTotal(t *testing.T) {
	in := manyProfiles()
	got := sortedProfileNames(in)
	if len(got) != len(in) {
		t.Fatalf("sortedProfileNames returned %d names for %d profiles: %v", len(got), len(in), got)
	}
	seen := make(map[string]bool, len(got))
	for _, name := range got {
		if seen[name] {
			t.Fatalf("sortedProfileNames returned %q twice: %v", name, got)
		}
		seen[name] = true
		if _, ok := in[name]; !ok {
			t.Fatalf("sortedProfileNames returned %q, which is not a profile", name)
		}
	}
}

// TestValidateConfigReportsFirstProfileInNameOrder pins which of several bad
// profiles is reported. ValidateConfig returns on the FIRST invalid path, so
// with the map ranged directly a config with two bad profiles reported whichever
// one Go happened to visit first — an operator fixed it, re-ran, and got a fresh
// complaint about a different profile with no sign the first fix had worked.
func TestValidateConfigReportsFirstProfileInNameOrder(t *testing.T) {
	// A NUL byte is the one thing validateUnixPath rejects, and Windows path
	// validation rejects it via its own rules, so this is invalid on both.
	bad := "/tmp/out\x00dir"
	seen := make(map[string]int)
	for i := 0; i < 100; i++ {
		cfg := &Config{Profiles: map[string]Profile{}}
		for _, name := range []string{"zebra", "alpha", "middle", "production"} {
			p := Profile{}
			p.Redaction.OutputDir = bad
			cfg.Profiles[name] = p
		}
		err := ValidateConfig(cfg)
		if err == nil {
			t.Fatal("ValidateConfig accepted a profile path containing a NUL byte")
		}
		switch {
		case strings.Contains(err.Error(), "'alpha'"):
			seen["alpha"]++
		case strings.Contains(err.Error(), "'middle'"):
			seen["middle"]++
		case strings.Contains(err.Error(), "'production'"):
			seen["production"]++
		case strings.Contains(err.Error(), "'zebra'"):
			seen["zebra"]++
		default:
			t.Fatalf("unexpected error, no profile named: %v", err)
		}
	}
	if len(seen) != 1 {
		t.Fatalf("reported profile varied across 100 runs: %v", seen)
	}
	if seen["alpha"] == 0 {
		t.Fatalf("expected the alphabetically first bad profile to be reported, got %v", seen)
	}
}

// TestValidateConfigAcceptsValidProfiles is the no-false-rejection guard: the
// sorted loop must still visit every profile and pass clean ones.
func TestValidateConfigAcceptsValidProfiles(t *testing.T) {
	a := Profile{}
	a.Redaction.OutputDir = "/tmp/a"
	a.Redaction.IndexFile = "/tmp/a/index.json"
	b := Profile{}
	b.Redaction.OutputDir = "/tmp/b"
	cfg := &Config{Profiles: map[string]Profile{"a": a, "b": b, "c": {}}}
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("ValidateConfig rejected valid profiles: %v", err)
	}
}

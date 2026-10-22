// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"reflect"
	"strings"
	"testing"
)

// The helpers #768 added, pinned directly. profile_precedence_test.go holds the behavioural guards.

// TestProfileBoolRegistryAccessorsAgree: each profileBoolFields entry's setter and getter reach the
// field its yamlPath names. A setter wired to the wrong field backfills one key from another's value.
func TestProfileBoolRegistryAccessorsAgree(t *testing.T) {
	leaves := map[string]profileLeaf{}
	for _, l := range profileLeaves(t) {
		leaves[l.path] = l
	}
	for _, f := range profileBoolFields {
		path := strings.Join(f.yamlPath, ".")
		leaf, ok := leaves[path]
		if !ok || leaf.kind != reflect.Bool {
			t.Errorf("profileBoolFields entry %q names no bool field of Profile", path)
			continue
		}
		for _, v := range []bool{true, false} {
			var p Profile
			if !v {
				leafValue(&p, leaf).SetBool(true)
			}
			f.setProfile(&p, v)
			if got := leafValue(&p, leaf).Bool(); got != v {
				t.Errorf("%s: setProfile(%v) left the field %v", path, v, got)
			}
			if got := f.getProfile(&p); got != v {
				t.Errorf("%s: getProfile = %v after setting %v", path, got, v)
			}
		}
	}
}

func TestBuiltinPrecommitChecksConstant(t *testing.T) {
	if BuiltinPrecommitChecks != strings.Join(builtinPrecommitSix, ",") {
		t.Errorf("BuiltinPrecommitChecks = %q, want %q", BuiltinPrecommitChecks, strings.Join(builtinPrecommitSix, ","))
	}
}

// TestBuiltinProfileReport pins what the CLI is told: which profile is built-in, what it supplied,
// and whether the config's defaults.checks was "all", the one override left.
func TestBuiltinProfileReport(t *testing.T) {
	none, err := LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		cfg      *Config
		supplied []string
		all      bool
	}{
		{"no config", none, []string{"format=text", "confidence_levels=high,medium", "checks=" + BuiltinPrecommitChecks, "no_color=true"}, false},
		{"checks all", loadConfigText(t, "defaults:\n  checks: all\n"), []string{"format=text", "confidence_levels=high,medium", "checks=" + BuiltinPrecommitChecks}, true},
		{"checks named", loadConfigText(t, "defaults:\n  checks: PASSPORT\n  confidence_levels: all\n"), []string{"format=text", "checks=" + BuiltinPrecommitChecks + ",PASSPORT"}, false},
		{"checks absent", loadConfigText(t, "defaults:\n  verbose: true\n"), []string{"format=text", "confidence_levels=high,medium", "checks=" + BuiltinPrecommitChecks}, false},
	}
	for _, c := range cases {
		info := c.cfg.BuiltinProfile("precommit")
		if info == nil {
			t.Errorf("%s: BuiltinProfile(precommit) = nil", c.name)
			continue
		}
		if !reflect.DeepEqual(info.Supplied, c.supplied) || info.ConfigChecksAll != c.all {
			t.Errorf("%s: got supplied %v all %v, want %v all %v", c.name, info.Supplied, info.ConfigChecksAll, c.supplied, c.all)
		}
	}
	own := loadConfigText(t, "profiles:\n  precommit:\n    checks: SSN\n")
	if own.BuiltinProfile("precommit") != nil {
		t.Error("a config's own profiles.precommit is reported as built-in")
	}
	if none.BuiltinProfile("ci") != nil {
		t.Error("BuiltinProfile(ci) is non-nil; only precommit is built in")
	}
}

func TestProfileKeys(t *testing.T) {
	cfg := loadConfigText(t, "profiles:\n  share:\n    checks: SSN\n    redaction:\n      strategy: simple\n      enabled: true\n    quiet: false\n")
	want := []string{"checks", "quiet", "redaction.enabled", "redaction.strategy"}
	if got := cfg.ProfileKeys("share"); !reflect.DeepEqual(got, want) {
		t.Errorf("ProfileKeys(share) = %v, want %v", got, want)
	}
	if got := cfg.ProfileKeys("precommit"); got != nil {
		t.Errorf("ProfileKeys(precommit) = %v for the built-in profile, want nil", got)
	}
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// A profile value nobody wrote must not outrank what the config wrote (#768).
//
// Two members of that class, both measured on v2.5.3:
//
//   - The built-in precommit profile, which pre-commit mode selects on its own, carried checks,
//     confidence_levels, redaction.strategy and redaction.output_dir. Each replaced the config's
//     value: a config naming PASSPORT got six other types, so a HIGH passport passed the hook at
//     exit 0, and `strategy: simple` came back as format_preserving with the passport in cleartext.
//   - Any profile that omitted fail_on_incomplete turned a config's `true` off, because the bool
//     was missing from profileBoolFields, so an unreadable file exited 0 instead of 3. The two
//     suppression bools were backfilled from defaults.* only, so a profile also switched off the
//     `suppressions:` block's show_suppressed and generate_on_scan.
//
// The guards below walk Profile by reflection, so a field added later has to be classified here
// before the suite passes again. That is the point: both members were a field nobody classified.

// builtinPrecommitSix is the built-in profile's check list, spelled out so this file needs nothing
// the fix added. TestBuiltinPrecommitChecksConstant pins the exported constant to it.
var builtinPrecommitSix = []string{"CREDIT_CARD", "SECRETS", "SSN", "EMAIL", "PHONE", "IP_ADDRESS"}

// profileLeaf is one settable leaf of Profile, by its YAML path relative to a profile block.
type profileLeaf struct {
	path  string
	index []int
	kind  reflect.Kind
}

// profileLeaves walks Profile's YAML-visible fields. Struct and pointer-to-struct fields are
// descended into only when they are a plain nested block (redaction); maps, slices and the platform
// block are leaves, because the guards classify them as a whole.
func profileLeaves(t *testing.T) []profileLeaf {
	t.Helper()
	var out []profileLeaf
	var walk func(rt reflect.Type, prefix string, index []int)
	walk = func(rt reflect.Type, prefix string, index []int) {
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			name := strings.Split(f.Tag.Get("yaml"), ",")[0]
			if name == "-" || !f.IsExported() {
				continue
			}
			if name == "" {
				t.Fatalf("Profile field %s%s has no yaml tag; the guards cannot name it", prefix, f.Name)
			}
			idx := append(append([]int{}, index...), i)
			if f.Type.Kind() == reflect.Struct {
				walk(f.Type, prefix+name+".", idx)
				continue
			}
			out = append(out, profileLeaf{path: prefix + name, index: idx, kind: f.Type.Kind()})
		}
	}
	walk(reflect.TypeOf(Profile{}), "", nil)
	return out
}

func leafValue(p *Profile, l profileLeaf) reflect.Value {
	return reflect.ValueOf(p).Elem().FieldByIndex(l.index)
}

// loadConfigText writes body to a temp file and loads it the lenient way, which is the path an
// auto-discovered config takes. LoadConfigStrict adds only schema validation on top.
func loadConfigText(t *testing.T, body string) *Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cfg.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig(%q): %v", body, err)
	}
	return cfg
}

// profileBoolSources maps each Profile bool, by YAML path, to the config keys a profile that omits
// it must inherit from. A profile bool absent from this table and from profileBoolExempt fails
// TestEveryProfileBoolInheritsFromTheConfig, which is what makes "each bool registered" checkable.
var profileBoolSources = map[string][]string{
	"verbose":               {"defaults.verbose"},
	"debug":                 {"defaults.debug"},
	"no_color":              {"defaults.no_color"},
	"recursive":             {"defaults.recursive"},
	"enable_preprocessors":  {"defaults.enable_preprocessors"},
	"respect_gitignore":     {"defaults.respect_gitignore"},
	"show_match":            {"defaults.show_match"},
	"quiet":                 {"defaults.quiet"},
	"show_suppressed":       {"defaults.show_suppressed", "suppressions.show_suppressed"},
	"generate_suppressions": {"defaults.generate_suppressions", "suppressions.generate_on_scan"},
	"fail_on_incomplete":    {"defaults.fail_on_incomplete"},
	"redaction.enabled":     {"redaction.enabled"},
}

// profileBoolExempt names a Profile bool that deliberately does NOT inherit, with the reason. Empty
// today; an entry needs a reason a reviewer can check.
var profileBoolExempt = map[string]string{}

// yamlFor renders "a.b: v" as nested YAML.
func yamlFor(dotted string, value bool) string {
	parts := strings.Split(dotted, ".")
	var b strings.Builder
	for i, p := range parts {
		b.WriteString(strings.Repeat("  ", i) + p + ":")
		if i == len(parts)-1 {
			fmt.Fprintf(&b, " %t", value)
		}
		b.WriteString("\n")
	}
	return b.String()
}

// TestEveryProfileBoolInheritsFromTheConfig is the bool guard: every Profile bool is registered in
// profileBoolFields and inherits each of its config sources when a profile omits it, for a profile
// the file defines and for the built-in precommit profile alike.
//
// The value written is the opposite of the built-in default, so a profile that does not inherit is
// visible as the default coming back.
func TestEveryProfileBoolInheritsFromTheConfig(t *testing.T) {
	registered := map[string]bool{}
	for _, f := range profileBoolFields {
		registered[strings.Join(f.yamlPath, ".")] = true
	}

	for _, leaf := range profileLeaves(t) {
		if leaf.kind != reflect.Bool {
			continue
		}
		if reason, ok := profileBoolExempt[leaf.path]; ok {
			t.Logf("%s exempt: %s", leaf.path, reason)
			continue
		}
		sources, classified := profileBoolSources[leaf.path]
		if !classified {
			t.Errorf("Profile bool %q is unclassified: register it in profileBoolFields so a profile that "+
				"omits it inherits the config, add its config keys to profileBoolSources, or exempt it by "+
				"name in profileBoolExempt with the reason", leaf.path)
			continue
		}
		if !registered[leaf.path] {
			t.Errorf("Profile bool %q is not in profileBoolFields, so every profile that omits it -- the "+
				"built-in precommit one included -- sets it to false over whatever the config wrote", leaf.path)
		}
		for _, source := range sources {
			want := true
			if source == "defaults.enable_preprocessors" {
				want = false // its built-in default is true
			}
			cfg := loadConfigText(t, yamlFor(source, want)+"profiles:\n  other:\n    description: other\n")
			for _, name := range []string{"other", "precommit"} {
				p := cfg.Profiles[name]
				if got := leafValue(&p, leaf).Bool(); got != want {
					t.Errorf("config %s: %v, profile %q omits %s and has %v: the profile overrides a value "+
						"nobody wrote for it", source, want, name, leaf.path, got)
				}
			}
		}
	}
}

// builtinFieldRule says how the built-in precommit profile treats each Profile field when a config
// file is loaded and does not define profiles.precommit:
//
//	yield      the profile leaves it unset, so the config's value (or the global default) applies
//	inherit    a bool, copied from the config by backfillProfileBools
//	ifUnset    the profile's own value applies only when the config lacks the key
//	union      the profile's value is merged with the config's, and never narrows the profile's own
//	exempt     the profile keeps its own value, for the reason given
var builtinFieldRule = map[string]string{
	"format":                   "exempt: a hook prints for a person; --format overrides it",
	"description":              "exempt: not a setting",
	"confidence_levels":        "ifUnset",
	"checks":                   "union",
	"exclude_patterns":         "yield",
	"suppression_expires_in":   "yield",
	"validators":               "yield",
	"platform":                 "yield",
	"redaction.output_dir":     "yield",
	"redaction.strategy":       "yield",
	"redaction.index_file":     "yield",
	"redaction.audit_log_file": "yield",
	"verbose":                  "inherit",
	"debug":                    "inherit",
	"no_color":                 "inherit",
	"recursive":                "inherit",
	"enable_preprocessors":     "inherit",
	"respect_gitignore":        "inherit",
	"show_match":               "inherit",
	"quiet":                    "inherit",
	"show_suppressed":          "inherit",
	"generate_suppressions":    "inherit",
	"fail_on_incomplete":       "inherit",
	"redaction.enabled":        "inherit",
}

// TestBuiltinPrecommitProfileYieldsToTheConfig is the field guard: every Profile field is classified
// for the built-in profile, and each classification holds against a config that writes a distinctive
// value for every key a profile can shadow.
func TestBuiltinPrecommitProfileYieldsToTheConfig(t *testing.T) {
	dir := t.TempDir()
	full := "defaults:\n  format: json\n  confidence_levels: all\n  checks: PASSPORT,SSN\n" +
		"  exclude_patterns: [vendor]\n  verbose: true\n  no_color: false\n  fail_on_incomplete: true\n" +
		"redaction:\n  enabled: true\n  strategy: simple\n" +
		"  output_dir: " + filepath.ToSlash(filepath.Join(dir, "cfgout")) + "\n" +
		"  index_file: " + filepath.ToSlash(filepath.Join(dir, "audit.json")) + "\n" +
		"suppressions:\n  expires_in: 30d\n"
	cfg := loadConfigText(t, full)
	p, ok := cfg.Profiles["precommit"]
	if !ok {
		t.Fatal("no built-in precommit profile after loading a config that defines no profiles")
	}

	for _, leaf := range profileLeaves(t) {
		rule, classified := builtinFieldRule[leaf.path]
		if !classified {
			t.Errorf("Profile field %q is unclassified for the built-in precommit profile: decide whether "+
				"it yields to the config, and record that in builtinFieldRule", leaf.path)
			continue
		}
		v := leafValue(&p, leaf)
		switch {
		case rule == "yield":
			if !isUnset(v) {
				t.Errorf("built-in precommit profile sets %s = %v; resolveConfiguration lets a non-empty "+
					"profile value outrank the config, so this replaces what the config wrote", leaf.path, v)
			}
		case rule == "ifUnset":
			if v.String() != "" {
				t.Errorf("config sets defaults.%s, yet the built-in profile carries %q, which outranks it",
					leaf.path, v.String())
			}
			if bare := loadConfigText(t, "defaults:\n  verbose: false\n").Profiles["precommit"]; leafValue(&bare, leaf).String() != "high,medium" {
				t.Errorf("config without defaults.%s: built-in profile has %q, want high,medium",
					leaf.path, leafValue(&bare, leaf).String())
			}
		case rule == "union":
			assertChecksUnion(t, cfg, []string{"PASSPORT"})
		case rule == "inherit":
			if v.Kind() != reflect.Bool {
				t.Errorf("%s is classified inherit but is a %s", leaf.path, v.Kind())
			}
			// TestEveryProfileBoolInheritsFromTheConfig checks the value for every source.
		case strings.HasPrefix(rule, "exempt"):
		default:
			t.Errorf("%s: unknown rule %q", leaf.path, rule)
		}
	}
	if p.Format != "text" {
		t.Errorf("built-in profile format = %q, want text (exempt: a hook prints for a person)", p.Format)
	}
	if !p.FailOnIncomplete || !p.Verbose || !p.Redaction.Enabled {
		t.Errorf("built-in profile bools did not come from the config: fail_on_incomplete=%v verbose=%v "+
			"redaction.enabled=%v, want all true", p.FailOnIncomplete, p.Verbose, p.Redaction.Enabled)
	}
}

func isUnset(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Map, reflect.Slice:
		return v.Len() == 0
	default:
		return v.IsZero()
	}
}

// assertChecksUnion asserts the built-in profile's checks are exactly the six plus extra.
func assertChecksUnion(t *testing.T, cfg *Config, extra []string) {
	t.Helper()
	want := append(append([]string{}, builtinPrecommitSix...), extra...)
	sort.Strings(want)
	var got []string
	for _, c := range strings.Split(cfg.Profiles["precommit"].Checks, ",") {
		if c = strings.TrimSpace(c); c != "" {
			got = append(got, c)
		}
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("built-in precommit checks = %v, want %v: the config's types are added to the six, "+
			"and a config can neither narrow the six nor get its own types dropped", got, want)
	}
}

// TestBuiltinPrecommitChecksNeverNarrow pins the union in both directions. A config naming a type
// outside the six adds it; a config naming fewer, which is what a planted project config would do
// (#293), or "all", leaves the six.
func TestBuiltinPrecommitChecksNeverNarrow(t *testing.T) {
	cases := []struct {
		checks string
		extra  []string
	}{
		{"PASSPORT,SSN", []string{"PASSPORT"}},
		{"passport, ssn ,PERSON_NAME", []string{"PASSPORT", "PERSON_NAME"}},
		{"EMAIL", nil},
		{"all", nil},
		{"ALL", nil},
	}
	for _, c := range cases {
		cfg := loadConfigText(t, "defaults:\n  checks: \""+c.checks+"\"\n")
		assertChecksUnion(t, cfg, c.extra)
	}
}

// TestNullAndEmptyProfilesAgree: `profiles:` null, `profiles: {}` and no key all define no profile,
// so all three get the same built-in precommit profile. The profile used to be added before decoding,
// and a null `profiles:` wiped it while `{}` kept it, so the two spellings gave opposite hooks.
func TestNullAndEmptyProfilesAgree(t *testing.T) {
	head := "defaults:\n  checks: PASSPORT,SSN\n"
	var profiles []Profile
	for _, tail := range []string{"", "profiles: {}\n", "profiles:\n"} {
		cfg := loadConfigText(t, head+tail)
		p, ok := cfg.Profiles["precommit"]
		if !ok {
			t.Errorf("config %q: no precommit profile, so pre-commit mode runs without one", tail)
			continue
		}
		profiles = append(profiles, p)
	}
	for i := 1; i < len(profiles); i++ {
		if !reflect.DeepEqual(profiles[0], profiles[i]) {
			t.Errorf("profile differs by spelling of 'no profiles':\n%+v\n%+v", profiles[0], profiles[i])
		}
	}
}

// TestAConfigsOwnPrecommitProfileIsKeptAsWritten is a decoy: a file that defines profiles.precommit
// gets exactly what it wrote, as before #768, with no built-in values mixed in.
func TestAConfigsOwnPrecommitProfileIsKeptAsWritten(t *testing.T) {
	cfg := loadConfigText(t, "defaults:\n  checks: PASSPORT,SSN\nprofiles:\n  precommit:\n    description: own\n")
	p := cfg.Profiles["precommit"]
	if p.Checks != "" || p.ConfidenceLevels != "" || p.Format != "" || p.Redaction.Strategy != "" || p.Description != "own" {
		t.Errorf("own precommit profile was altered: %+v", p)
	}
}

// TestBuiltinPrecommitProfileWithoutConfigIsUnchanged is a decoy: with no config file there is
// nothing to yield to, and the profile a no-config hook runs is the one it always ran.
func TestBuiltinPrecommitProfileWithoutConfigIsUnchanged(t *testing.T) {
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	p := cfg.Profiles["precommit"]
	if p.Format != "text" || p.ConfidenceLevels != "high,medium" || p.Checks != strings.Join(builtinPrecommitSix, ",") ||
		!p.NoColor || !p.EnablePreprocessors || p.Redaction.Enabled || p.FailOnIncomplete {
		t.Errorf("no-config built-in precommit profile changed: %+v", p)
	}
	// Strategy and output_dir are no longer set on the profile; the global defaults they equalled
	// are what a no-config run now resolves them from.
	if cfg.Redaction.Strategy != "format_preserving" || filepath.Clean(cfg.Redaction.OutputDir) != "redacted" {
		t.Errorf("global redaction defaults changed: strategy %q output_dir %q", cfg.Redaction.Strategy, cfg.Redaction.OutputDir)
	}
}

// TestGetPrecommitProfileIsGone: the method was an uncalled second copy of the built-in profile, and
// a second copy is how this profile's values drift apart.
func TestGetPrecommitProfileIsGone(t *testing.T) {
	if _, ok := reflect.TypeOf(&Config{}).MethodByName("GetPrecommitProfile"); ok {
		t.Error("Config.GetPrecommitProfile still exists: a second definition of the built-in profile")
	}
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"sort"
)

// validatorConfigKeys declares, per `validators:` section, every key its validator actually reads.
//
// WHY A DECLARATION EXISTS AT ALL. Config.Validators is a map type, so the strict YAML pass that
// produces the unknown-key warnings cannot see inside it: any key under `validators:` was accepted
// silently. Measured before this file existed (#726): `disabled_types` under `secrets` — a user
// deliberately disabling a detection — produced no error, no warning, and no effect, and 4 of 14
// probed unknown-key positions were silent, all inside this subtree. ASH hit the same wall and
// documented the workaround on its side.
//
// WHY A HAND-WRITTEN MAP IS SAFE HERE, when this repository's own rule is that hand-maintained
// lists cannot stay complete: TestValidatorConfigKeysMatchTheSource harvests every
// `cfg.Validators["name"]` consumer and every `xConfig["key"]` read from the validator sources by
// AST, and fails if this map and the code disagree IN EITHER DIRECTION — a key read but not
// declared re-opens the blind spot; a key declared but never read is documentation fiction.
var validatorConfigKeys = map[string]map[string]bool{
	"intellectual_property": {
		"disabled_types":                 true,
		"intellectual_property_patterns": true,
		"internal_urls":                  true,
	},
	"social_media": {
		"allowlist_patterns": true,
		"negative_keywords":  true,
		"platform_keywords":  true,
		"platform_patterns":  true,
		"positive_keywords":  true,
		"whitelist_patterns": true,
	},
	"cloud_resources": {
		"custom_patterns":   true,
		"enabled_providers": true,
	},
}

// collectUnknownValidatorKeys walks the decoded validators sections — top-level and inside every
// profile — and reports paths the declaration does not recognize, in the same "dotted path" form
// collectUnknownKeys uses so they surface through the same warning channel.
//
// An unknown SECTION yields one warning for the section (naming the known ones), not one per key
// under it. `disabled_types` in the wrong section names the one section that honors it, because
// that exact misplacement is the measured way users hit this (#726).
func collectUnknownValidatorKeys(cfg *Config) []string {
	var out []string
	out = append(out, unknownValidatorPaths("validators", cfg.Validators)...)

	profileNames := make([]string, 0, len(cfg.Profiles))
	for name := range cfg.Profiles {
		profileNames = append(profileNames, name)
	}
	sort.Strings(profileNames)
	for _, name := range profileNames {
		out = append(out, unknownValidatorPaths(
			fmt.Sprintf("profiles.%s.validators", name), cfg.Profiles[name].Validators)...)
	}
	return out
}

func unknownValidatorPaths(prefix string, sections map[string]map[string]interface{}) []string {
	var out []string
	names := make([]string, 0, len(sections))
	for name := range sections {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		known, ok := validatorConfigKeys[name]
		if !ok {
			msg := fmt.Sprintf("%s.%s — no validator reads this section; sections with config: %s",
				prefix, name, knownSectionNames())
			// The measured way users hit this subtree is disabling a type under the wrong
			// validator (#726), so that misplacement names its one honoring section even when
			// the whole section is unknown.
			if _, hasDT := sections[name]["disabled_types"]; hasDT {
				msg += "; note: only intellectual_property honors disabled_types"
			}
			out = append(out, msg)
			continue
		}
		keys := make([]string, 0, len(sections[name]))
		for k := range sections[name] {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if known[k] {
				continue
			}
			if k == "disabled_types" {
				out = append(out, fmt.Sprintf("%s.%s.disabled_types — only intellectual_property honors disabled_types", prefix, name))
				continue
			}
			out = append(out, fmt.Sprintf("%s.%s.%s — %s honors: %s", prefix, name, k, name, sortedKeyList(known)))
		}
	}
	return out
}

func knownSectionNames() string {
	names := make([]string, 0, len(validatorConfigKeys))
	for n := range validatorConfigKeys {
		names = append(names, n)
	}
	sort.Strings(names)
	return fmt.Sprintf("%v", names)
}

func sortedKeyList(m map[string]bool) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return fmt.Sprintf("%v", keys)
}

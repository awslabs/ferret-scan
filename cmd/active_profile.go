// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/config"
)

// What a run says about the profile that governed it (#768).
//
// Pre-commit mode selects the precommit profile on its own (--pre-commit-mode,
// four hook environment variables, or the published hook's --profile precommit),
// and when a config does not define one the tool supplies a built-in one. That
// profile used to override what the config wrote -- checks, confidence levels,
// redaction strategy and output directory -- and no output named it: --verbose
// was byte-identical to a run with no config, and --debug never mentioned a
// profile. internal/config now makes the built-in profile yield to the config
// (injectBuiltinPrecommitProfile); this file names what is left.

// reportBuiltinProfileChecks writes the one line that discloses the built-in
// profile's remaining override: a config that sets defaults.checks to every check
// still gets the profile's six types in a hook. Widening every such hook to every
// type was rejected in #768 on cost, so the line names the profile, its checks,
// the config, and the key that changes it.
//
// Ungated for the reason reportDisabledDetectionTypes and reportConfigProvenance
// are: it states what governed the scan, and pre-commit mode, where --quiet is
// implied, is the only place it can occur. The --stdin path withholds it only
// when stderr carries the findings document. Silent without a config file, when
// the file does not set defaults.checks, under a profile the file defines, and
// when --checks chose the checks instead.
func reportBuiltinProfileChecks(w io.Writer, cfg *config.Config, activeProfileName string) {
	if w == nil || cfg == nil || cfg.SourcePath == "" || isFlagSet("checks") {
		return
	}
	info := cfg.BuiltinProfile(activeProfileName)
	if info == nil || !info.ConfigChecksAll {
		return
	}
	checks := strings.Split(config.BuiltinPrecommitChecks, ",")
	fmt.Fprintf(w,
		"Note: the built-in %s profile runs %d checks (%s), not the \"all\" that defaults.checks sets in %s; "+
			"set profiles.%s.checks in that file to choose what pre-commit runs.\n",
		activeProfileName, len(checks), strings.Join(checks, ", "), configSourceLabel(cfg), activeProfileName)
}

// profileDebugRecord is the --debug record of the active profile: its name, where
// it came from, why it was selected, and each setting it supplied. Both input
// paths log it, so a hook run under --debug says which profile shaped it.
func profileDebugRecord(cfg *config.Config, activeProfileName, explicitProfile string, precommitFlag bool) []string {
	if cfg == nil {
		return nil
	}
	if activeProfileName == "" {
		return []string{"no profile active; settings come from " + configSourceLabel(cfg) + " and the flags"}
	}
	if cfg.GetProfile(activeProfileName) == nil {
		return []string{fmt.Sprintf("profile %q is not defined in %s; no profile active", activeProfileName, configSourceLabel(cfg))}
	}
	why := "selected because a pre-commit hook environment was detected"
	switch {
	case explicitProfile != "":
		why = "selected by --profile"
	case precommitFlag:
		why = "selected because --pre-commit-mode was passed"
	}
	if info := cfg.BuiltinProfile(activeProfileName); info != nil {
		return []string{
			fmt.Sprintf("active profile %q (built-in), %s", activeProfileName, why),
			fmt.Sprintf("profile %q supplied %s. Every other setting comes from %s and the flags",
				activeProfileName, strings.Join(info.Supplied, "; "), configSourceLabel(cfg)),
		}
	}
	keys := "no settings"
	if k := cfg.ProfileKeys(activeProfileName); len(k) > 0 {
		keys = strings.Join(k, ", ")
	}
	return []string{
		fmt.Sprintf("active profile %q defined in %s, %s", activeProfileName, configSourceLabel(cfg), why),
		fmt.Sprintf("profile %q sets %s. The flags outrank it, and it inherits everything else from that file", activeProfileName, keys),
	}
}

// writeProfileList prints --list-profiles from the configuration actually
// loaded, so an auto-discovered config's profiles are listed (they used to be
// reported as "No configuration file found" because only --config was
// consulted), and marks a built-in profile as such.
func writeProfileList(w io.Writer, cfg *config.Config) {
	if cfg == nil {
		fmt.Fprintln(w, "No configuration loaded. No profiles available.")
		return
	}
	profiles := cfg.ListProfiles()
	switch {
	case cfg.SourcePath == "":
		fmt.Fprintln(w, "No configuration file found. Built-in profiles:")
	case len(profiles) == 0:
		fmt.Fprintf(w, "No profiles defined in %s.\n", configSourceLabel(cfg))
		return
	default:
		fmt.Fprintf(w, "Available profiles in %s:\n", configSourceLabel(cfg))
	}
	for _, name := range profiles {
		label := name
		if cfg.BuiltinProfile(name) != nil {
			label += " (built-in)"
		}
		if profile := cfg.GetProfile(name); profile != nil && profile.Description != "" {
			fmt.Fprintf(w, "  - %s: %s\n", label, profile.Description)
		} else {
			fmt.Fprintf(w, "  - %s\n", label)
		}
	}
}

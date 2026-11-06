// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
)

// everyFlagSet is an extractedFlags with every field non-zero, so a field configFlagsFrom forgets to copy
// shows up as a zero below. TestConfigFlagsFromCarriesEveryFlag checks the literal itself first: a field
// added to extractedFlags and not here fails there, rather than passing vacuously.
func everyFlagSet() extractedFlags {
	return extractedFlags{
		webMode: true, webPort: "8081", webBind: "127.0.0.1", inputFile: "in.txt", configFile: "c.yaml",
		profileName: "ci", listProfiles: true, outputFormat: "json", outputFile: "out.json",
		confidenceLevels: "high", checksToRun: "SSN", verbose: true, debug: true, quiet: true, noColor: true,
		recursive: true, enablePreprocessors: true, preprocessOnly: true, precommitMode: true, showMatch: true,
		showSuppressed: true, generateSuppressions: true, failOnIncomplete: true, enableRedaction: true,
		redactionOutputDir: "red", redactionStrategy: "simple", redactionAuditLog: "audit.json",
		suppressionFile: "s.yaml", suppressionExpiresIn: "30d", excludePatterns: []string{"*.log"},
		respectGitignore: true, disableIPTypes: "patent",
	}
}

// stdinDepartures are the configFlags fields --stdin deliberately does not take from the flags, each
// documented in configFlagsFrom. Anything not listed must arrive on both paths.
var stdinDepartures = map[string]bool{
	"recursive": true, "excludePatterns": true, "respectGitignore": true,
	"redactionOutputDir": true, "redactionAuditLog": true,
}

// TestConfigFlagsFromCarriesEveryFlag is the guard on the second mechanism of #887. The two keyed
// literals main() and runStdinScan used to build drifted: #699 added suppressionExpiresIn to main()'s
// only, and nothing reported it, because a field missing from a keyed literal is simply zero.
func TestConfigFlagsFromCarriesEveryFlag(t *testing.T) {
	in := everyFlagSet()
	iv := reflect.ValueOf(in)
	for i := 0; i < iv.NumField(); i++ {
		if iv.Field(i).IsZero() {
			t.Fatalf("everyFlagSet leaves extractedFlags.%s zero; set it, or this test cannot see a "+
				"configFlags field that fails to copy it", iv.Type().Field(i).Name)
		}
	}

	for _, mode := range []runMode{fileRun, stdinRun} {
		cf := reflect.ValueOf(*configFlagsFrom(in, mode, "ci"))
		for i := 0; i < cf.NumField(); i++ {
			name := cf.Type().Field(i).Name
			got := cf.Field(i)
			wantZero := mode == stdinRun && stdinDepartures[name]
			if got.IsZero() != wantZero {
				t.Errorf("mode %d: configFlags.%s zero=%v, want zero=%v. A field --stdin does not take "+
					"from the flags must be listed in configFlagsFrom with its reason and in stdinDepartures",
					mode, name, got.IsZero(), wantZero)
				continue
			}
			if name == "activeProfileName" || wantZero {
				continue
			}
			src := iv.FieldByName(name)
			if !src.IsValid() {
				t.Errorf("configFlags.%s has no extractedFlags field of the same name to come from", name)
				continue
			}
			if fmt.Sprint(src) != fmt.Sprint(got) {
				t.Errorf("mode %d: configFlags.%s = %v, want the flag's %v", mode, name, got, src)
			}
		}
	}
}

func TestSelectProfile(t *testing.T) {
	cfg := &config.Config{Profiles: map[string]config.Profile{"ci": {Description: "ci"}}}
	if p, err := selectProfile(cfg, ""); p != nil || err != nil {
		t.Errorf("no name: got (%v, %v), want no profile and no error", p, err)
	}
	if p, err := selectProfile(cfg, "ci"); err != nil || p == nil || p.Description != "ci" {
		t.Errorf("a defined profile: got (%v, %v)", p, err)
	}
	for _, tc := range []struct {
		cfg  *config.Config
		want string
	}{
		{cfg, "Profile 'nosuch' not found in config file"},
		{nil, "Cannot use profile 'nosuch' - no configuration loaded"},
	} {
		p, err := selectProfile(tc.cfg, "nosuch")
		var pe *profileError
		if p != nil || !errors.As(err, &pe) || pe.msg != tc.want || pe.guidance == "" {
			t.Errorf("an unusable profile must be refused with %q and guidance; got (%v, %v)", tc.want, p, err)
		}
	}
}

func TestIPTypeOverrides(t *testing.T) {
	if o := ipTypeOverrides(&finalConfiguration{}); o != nil {
		t.Errorf("no flag: got %+v, want nil so the configured set stands", o)
	}
	o := ipTypeOverrides(&finalConfiguration{disableIPTypes: " copyright, ,Patent ,"})
	if o == nil || strings.Join(o.DisabledIPTypes, "|") != "copyright|Patent" {
		t.Errorf("got %+v, want the trimmed non-empty names [copyright Patent] (the validator lower-cases them)", o)
	}
	// Only separators: the flag was given and names nothing, so it replaces the set with nothing, as the
	// global-config injection it replaces did.
	if o := ipTypeOverrides(&finalConfiguration{disableIPTypes: ","}); o == nil || o.DisabledIPTypes == nil || len(o.DisabledIPTypes) != 0 {
		t.Errorf("--disable-ip-types ',': got %+v, want a non-nil empty override", o)
	}
}

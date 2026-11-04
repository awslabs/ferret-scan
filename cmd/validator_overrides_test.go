// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/validators/intellectualproperty"
)

// The --disable-ip-types override pass in core.BuildValidatorSetWithOverrides (#887). It is exercised
// from cmd because cmd is its only caller with a flag; the tests drive core directly.

func ipSection(kv map[string]interface{}) map[string]map[string]interface{} {
	return map[string]map[string]interface{}{"intellectual_property": kv}
}

func disabledIPTypesOf(t *testing.T, cfg *config.Config, profile *config.Profile, o *core.ValidatorOverrides) []string {
	t.Helper()
	set := core.BuildValidatorSetWithOverrides(map[string]bool{"INTELLECTUAL_PROPERTY": true}, cfg, profile, o)
	ip, ok := set["INTELLECTUAL_PROPERTY"].(*intellectualproperty.Validator)
	if !ok {
		t.Fatal("INTELLECTUAL_PROPERTY was not built")
	}
	return ip.DisabledSubTypes()
}

// TestDisableIPTypesOutranksConfigAndProfile is the precedence docs/configuration.md states: config,
// then profile, then the flag, each REPLACING the set before it. Before the third pass the flag was
// written into the global config, so a profile's disabled_types beat it on --file (row 10 of #887).
func TestDisableIPTypesOutranksConfigAndProfile(t *testing.T) {
	cfg := &config.Config{Validators: ipSection(map[string]interface{}{"disabled_types": []any{"copyright"}})}
	profile := &config.Profile{Validators: ipSection(map[string]interface{}{"disabled_types": []any{"patent"}})}
	flag := func(types ...string) *core.ValidatorOverrides {
		if types == nil {
			types = []string{}
		}
		return &core.ValidatorOverrides{DisabledIPTypes: types}
	}
	for _, tc := range []struct {
		name    string
		profile *config.Profile
		o       *core.ValidatorOverrides
		want    []string
	}{
		{"config alone", nil, nil, []string{"copyright"}},
		{"the profile replaces the config's set", profile, nil, []string{"patent"}},
		{"the flag replaces the config's set", nil, flag("trademark"), []string{"trademark"}},
		{"the flag replaces the profile's set", profile, flag("copyright"), []string{"copyright"}},
		{"the flag replaces both, with a list", profile, flag("trademark", "trade_secret"), []string{"trade_secret", "trademark"}},
		{"a non-nil empty override re-enables everything", profile, flag(), nil},
		{"no override leaves the profile's set", profile, &core.ValidatorOverrides{}, []string{"patent"}},
	} {
		got := disabledIPTypesOf(t, cfg, tc.profile, tc.o)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: disabled sub-types %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestTheOverridePassKeepsWhatItDoesNotName: only disabled_types is handed to the validator, so an
// internal_urls pattern from config still finds its URL, and the old BuildValidatorSet is unchanged.
func TestTheOverridePassKeepsWhatItDoesNotName(t *testing.T) {
	cfg := &config.Config{Validators: ipSection(map[string]interface{}{
		"internal_urls": []any{`https?://[a-z0-9.-]+\.example\.test`},
	})}
	content := parityFixtures["iu.txt"]
	for _, o := range []*core.ValidatorOverrides{nil, {DisabledIPTypes: []string{"copyright"}}} {
		res, err := core.ScanContent(content, core.ContentScanConfig{
			VirtualPath: "iu.txt", Checks: []string{"INTELLECTUAL_PROPERTY"}, Config: cfg, ValidatorOverrides: o,
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Matches) != 1 || res.Matches[0].Metadata["ip_type"] != "internal_url" {
			t.Errorf("override %+v: %d matches, want the configured internal URL", o, len(res.Matches))
		}
	}
	plain := core.BuildValidatorSet(map[string]bool{"INTELLECTUAL_PROPERTY": true}, cfg, nil)
	viaNil := core.BuildValidatorSetWithOverrides(map[string]bool{"INTELLECTUAL_PROPERTY": true}, cfg, nil, nil)
	if len(plain) != 1 || len(viaNil) != 1 {
		t.Fatalf("BuildValidatorSet built %d, the overrides form with nil built %d", len(plain), len(viaNil))
	}
}

// TestScanContentReportsWhatItsValidatorsDisabled: the --stdin path's Note is printed from
// ScanResult.DisabledDetectionTypes, which must equal what the file path reads off its own validator
// set for the same inputs, override included.
func TestScanContentReportsWhatItsValidatorsDisabled(t *testing.T) {
	cfg := &config.Config{Validators: ipSection(map[string]interface{}{"disabled_types": []any{"copyright", "copyrite"}})}
	profile := &config.Profile{Validators: ipSection(map[string]interface{}{"disabled_types": []any{"patent"}})}
	for _, o := range []*core.ValidatorOverrides{nil, {DisabledIPTypes: []string{"trademark", "patnet"}}} {
		for _, p := range []*config.Profile{nil, profile} {
			res, err := core.ScanContent(parityFixtures["ip.txt"], core.ContentScanConfig{
				VirtualPath: "ip.txt", Config: cfg, Profile: p, ValidatorOverrides: o,
			})
			if err != nil {
				t.Fatal(err)
			}
			set := core.BuildValidatorSetWithOverrides(core.ParseChecksToRun(nil), cfg, p, o)
			wantOff, wantBad := collectDisabledDetectionTypes(set)
			if !reflect.DeepEqual(res.DisabledDetectionTypes, wantOff) || !reflect.DeepEqual(res.UnrecognisedDisabledTypes, wantBad) {
				t.Errorf("profile=%v override=%+v: ScanContent reports %v / %v, the file path's set says %v / %v",
					p != nil, o, res.DisabledDetectionTypes, res.UnrecognisedDisabledTypes, wantOff, wantBad)
			}
			if len(wantOff) == 0 {
				t.Errorf("profile=%v override=%+v: nothing disabled, so the comparison above is vacuous", p != nil, o)
			}
		}
	}
	res, err := core.ScanContent(parityFixtures["ip.txt"], core.ContentScanConfig{VirtualPath: "ip.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if res.DisabledDetectionTypes != nil || res.UnrecognisedDisabledTypes != nil {
		t.Errorf("an unnarrowed scan reports %v / %v, want nil", res.DisabledDetectionTypes, res.UnrecognisedDisabledTypes)
	}
}

// TestRowTenOnTheBinary is row 10 of #887 end to end, on both paths: a profile disables patent and the
// flag disables copyright, so copyright is hidden, patent is REPORTED, and the Note names copyright.
// Measured before the fix on --file: patent hidden, copyright reported, the Note naming patent.
func TestRowTenOnTheBinary(t *testing.T) {
	bin := buildScanner(t)
	work, _, env := profileWorkdir(t)
	for name, body := range parityFixtures {
		writeFixture(t, filepath.Join(work, name), body)
	}
	args := []string{"--format", "json", "--confidence", "all", "--limit", "0", "--checks", "INTELLECTUAL_PROPERTY",
		"--config", "nopat.yaml", "--profile", "nopatent", "--disable-ip-types", "copyright"}
	for _, stdin := range []bool{false, true} {
		var r cliRun
		if stdin {
			r = runCLI(t, bin, work, env, parityFixtures["ip.txt"], append([]string{"--stdin", "--stdin-name", "ip.txt"}, args...)...)
		} else {
			r = runCLI(t, bin, work, env, "", append([]string{"--file", "ip.txt"}, args...)...)
		}
		var doc struct {
			Results []struct {
				Metadata map[string]any `json:"metadata"`
			} `json:"results"`
		}
		if err := json.Unmarshal([]byte(r.stdout), &doc); err != nil {
			t.Fatalf("stdin=%v: not JSON: %v\n%s", stdin, err, r.stdout)
		}
		var kinds []string
		for _, res := range doc.Results {
			if k, ok := res.Metadata["ip_type"].(string); ok {
				kinds = append(kinds, k)
			}
		}
		joined := strings.Join(kinds, ",")
		if strings.Contains(joined, "copyright") || !strings.Contains(joined, "patent") {
			t.Errorf("stdin=%v: ip_types %q, want patent reported and copyright hidden", stdin, joined)
		}
		if !strings.Contains(r.stderr, "detection sub-type(s) for this scan: copyright.") {
			t.Errorf("stdin=%v: the Note does not name copyright alone:\n%s", stdin, r.stderr)
		}
	}
}

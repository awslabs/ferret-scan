// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
)

// Three validators read the `validators:` config block: CLOUD_RESOURCES,
// INTELLECTUAL_PROPERTY and SOCIAL_MEDIA. BuildValidatorSet applied the global
// block to all three but the profile-level block to INTELLECTUAL_PROPERTY only,
// so the identical YAML worked at the top level and did nothing inside a profile.
//
// These tests drive the validators through BuildValidatorSet, because the bug was
// in the wiring rather than in any validator.

// profileWith returns a profile carrying just the given validators block.
func profileWith(validators map[string]map[string]interface{}) *config.Profile {
	return &config.Profile{
		Description: "test",
		Validators:  validators,
	}
}

// TestProfileValidatorConfigReachesCloudResources is the regression: a custom
// pattern set in a profile was dropped, so a resource the user asked to detect
// was not reported — and an unreported finding is never handed to the redactor.
func TestProfileValidatorConfigReachesCloudResources(t *testing.T) {
	const marker = "ZZQQ-9911-CUSTOM"
	validators := map[string]map[string]interface{}{
		"cloud_resources": {
			// custom_patterns is a list of plain regex strings.
			"custom_patterns": []interface{}{`ZZQQ-[0-9]{4}-CUSTOM`},
		},
	}

	set := BuildValidatorSet(
		map[string]bool{"CLOUD_RESOURCES": true},
		&config.Config{},
		profileWith(validators),
	)

	v, ok := set["CLOUD_RESOURCES"]
	if !ok {
		t.Fatal("CLOUD_RESOURCES validator was not built")
	}

	matches, err := v.ValidateContent("resource marker "+marker+" here", "probe.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	if len(matches) == 0 {
		t.Error("a custom_patterns entry set in a PROFILE produced no findings; the " +
			"identical block at the top level works, so the profile's validator " +
			"config was dropped")
	}
}

// TestProfileValidatorConfigReachesSocialMedia covers the second dropped
// validator. SOCIAL_MEDIA is config-gated — with no platform_patterns it returns
// immediately — so a profile-only block being ignored leaves it entirely inert.
func TestProfileValidatorConfigReachesSocialMedia(t *testing.T) {
	validators := map[string]map[string]interface{}{
		"social_media": {
			// Each platform takes a LIST of patterns, not a scalar.
			"platform_patterns": map[string]any{
				"twitter": []any{`https://twitter\.com/[A-Za-z0-9_]+`},
			},
		},
	}

	set := BuildValidatorSet(
		map[string]bool{"SOCIAL_MEDIA": true},
		&config.Config{},
		profileWith(validators),
	)

	v, ok := set["SOCIAL_MEDIA"]
	if !ok {
		t.Fatal("SOCIAL_MEDIA validator was not built")
	}

	matches, err := v.ValidateContent("profile https://twitter.com/probeuser1 here", "probe.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	if len(matches) == 0 {
		t.Error("platform_patterns set in a PROFILE produced no findings; this validator " +
			"is config-gated, so dropping the profile block leaves it permanently inert")
	}
}

// TestProfileValidatorConfigReachesIntellectualProperty pins the one validator
// that already worked, so the refactor that generalized the profile pass cannot
// regress it.
func TestProfileValidatorConfigReachesIntellectualProperty(t *testing.T) {
	validators := map[string]map[string]interface{}{
		"intellectual_property": {
			"internal_urls": []interface{}{`internal\.example\.invalid`},
		},
	}

	set := BuildValidatorSet(
		map[string]bool{"INTELLECTUAL_PROPERTY": true},
		&config.Config{},
		profileWith(validators),
	)

	v, ok := set["INTELLECTUAL_PROPERTY"]
	if !ok {
		t.Fatal("INTELLECTUAL_PROPERTY validator was not built")
	}

	matches, err := v.ValidateContent("see https://wiki.internal.example.invalid/page", "probe.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	if len(matches) == 0 {
		t.Error("internal_urls set in a profile produced no findings — this path already " +
			"worked before the profile pass was generalized")
	}
}

// TestGlobalValidatorConfigStillApplies guards the other direction: the profile
// pass must not clobber global settings for sections the profile does not mention.
// Each Configure returns early on a missing section, which is what makes the
// second pass safe.
func TestGlobalValidatorConfigStillApplies(t *testing.T) {
	global := &config.Config{
		Validators: map[string]map[string]interface{}{
			"cloud_resources": {
				"custom_patterns": []interface{}{`ZZQQ-[0-9]{4}-CUSTOM`},
			},
		},
	}
	// The profile configures a DIFFERENT validator, so cloud_resources must keep
	// the global pattern.
	profile := profileWith(map[string]map[string]interface{}{
		"intellectual_property": {
			"internal_urls": []interface{}{`internal\.example\.invalid`},
		},
	})

	set := BuildValidatorSet(
		map[string]bool{"CLOUD_RESOURCES": true, "INTELLECTUAL_PROPERTY": true},
		global,
		profile,
	)

	matches, err := set["CLOUD_RESOURCES"].ValidateContent("marker ZZQQ-9911-CUSTOM here", "probe.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	if len(matches) == 0 {
		t.Error("a global cloud_resources pattern was lost once a profile configured " +
			"some other validator; the profile pass must override only the sections " +
			"the profile actually sets")
	}
}

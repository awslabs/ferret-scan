// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"sort"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/validators/address"
	"github.com/awslabs/ferret-scan/v2/internal/validators/bankaccount"
	"github.com/awslabs/ferret-scan/v2/internal/validators/cloudresources"
	"github.com/awslabs/ferret-scan/v2/internal/validators/creditcard"
	"github.com/awslabs/ferret-scan/v2/internal/validators/dob"
	"github.com/awslabs/ferret-scan/v2/internal/validators/driverslicense"
	"github.com/awslabs/ferret-scan/v2/internal/validators/email"
	"github.com/awslabs/ferret-scan/v2/internal/validators/intellectualproperty"
	"github.com/awslabs/ferret-scan/v2/internal/validators/ipaddress"
	"github.com/awslabs/ferret-scan/v2/internal/validators/medicalid"
	"github.com/awslabs/ferret-scan/v2/internal/validators/metadata"
	"github.com/awslabs/ferret-scan/v2/internal/validators/otp"
	"github.com/awslabs/ferret-scan/v2/internal/validators/passport"
	"github.com/awslabs/ferret-scan/v2/internal/validators/personname"
	"github.com/awslabs/ferret-scan/v2/internal/validators/phone"
	"github.com/awslabs/ferret-scan/v2/internal/validators/secrets"
	"github.com/awslabs/ferret-scan/v2/internal/validators/socialmedia"
	"github.com/awslabs/ferret-scan/v2/internal/validators/ssn"
	"github.com/awslabs/ferret-scan/v2/internal/validators/vin"
)

// validatorConstructors is the single source of truth for which validator
// IDs ferret-scan recognizes. ParseChecksToRun, BuildValidatorSet, and the
// public redact.ValidCheckNames accessor all derive from this map, so adding
// or renaming a validator is a one-line change here rather than several
// parallel lists that can silently drift apart.
var validatorConstructors = map[string]func() detector.Validator{
	"BANK_ACCOUNT":          func() detector.Validator { return bankaccount.NewValidator() },
	"CLOUD_RESOURCES":       func() detector.Validator { return cloudresources.NewValidator() },
	"CREDIT_CARD":           func() detector.Validator { return creditcard.NewValidator() },
	"DATE_OF_BIRTH":         func() detector.Validator { return dob.NewValidator() },
	"DRIVERS_LICENSE":       func() detector.Validator { return driverslicense.NewValidator() },
	"EMAIL":                 func() detector.Validator { return email.NewValidator() },
	"PHONE":                 func() detector.Validator { return phone.NewValidator() },
	"IP_ADDRESS":            func() detector.Validator { return ipaddress.NewValidator() },
	"MEDICAL_ID":            func() detector.Validator { return medicalid.NewValidator() },
	"OTP":                   func() detector.Validator { return otp.NewValidator() },
	"PASSPORT":              func() detector.Validator { return passport.NewValidator() },
	"PHYSICAL_ADDRESS":      func() detector.Validator { return address.NewValidator() },
	"PERSON_NAME":           func() detector.Validator { return personname.NewValidator() },
	"METADATA":              func() detector.Validator { return metadata.NewValidator() },
	"INTELLECTUAL_PROPERTY": func() detector.Validator { return intellectualproperty.NewValidator() },
	"SOCIAL_MEDIA":          func() detector.Validator { return socialmedia.NewValidator() },
	"SSN":                   func() detector.Validator { return ssn.NewValidator() },
	"SECRETS":               func() detector.Validator { return secrets.NewValidator() },
	"VIN":                   func() detector.Validator { return vin.NewValidator() },
}

// CheckNames returns the sorted set of canonical validator IDs recognized by
// ParseChecksToRun and BuildValidatorSet. It backs the public
// redact.ValidCheckNames so consumers can validate Checks input against the
// real list instead of hardcoding (and drifting from) a private copy. The
// "all" sentinel and the empty default are handled by the callers and are not
// included here.
//
// redact.ValidCheckNames is a strict SUBSET of this list, not a re-export: it
// omits the validators that cannot produce a finding on that package's
// in-memory, no-config path (see checksUnsupportedInMemory there). This list
// is the right one for the CLI's --checks flag and for config-file validation,
// both of which do support those validators.
func CheckNames() []string {
	names := make([]string, 0, len(validatorConstructors))
	for name := range validatorConstructors {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ValidatorOverrides are per-run validator settings that outrank both the config file and the active
// profile: the command line. The zero value, and a nil pointer, override nothing.
//
// They are a third pass rather than an edit to the config handed to the first one, which is what the CLI
// used to do with --disable-ip-types. Written into the global config, the flag lost to any profile that
// set the same key, because the profile pass runs after the global one and Configure replaces the whole
// set; and the --stdin path, which never made the edit, ignored the flag outright (#887). As a pass of its
// own it runs last on every path that builds validators, so the documented precedence (config, then
// profile, then flag) holds by construction.
type ValidatorOverrides struct {
	// DisabledIPTypes, when non-nil, REPLACES the INTELLECTUAL_PROPERTY validator's disabled sub-types
	// after the config and profile passes, as --disable-ip-types always has without a profile. A non-nil
	// empty slice therefore re-enables every sub-type; nil leaves the configured set alone. Only that
	// key is handed to the validator, so whatever else config or profile set (internal_urls, the
	// pattern overrides) is kept.
	DisabledIPTypes []string
}

// BuildValidatorSet constructs the standard set of validators filtered by the
// enabled checks map. Pass nil for cfg to skip validator-specific configuration.
// Pass nil for profile to skip profile-specific overrides. It is
// BuildValidatorSetWithOverrides with no overrides.
func BuildValidatorSet(enabledChecks map[string]bool, cfg *config.Config, profile *config.Profile) map[string]detector.Validator {
	return BuildValidatorSetWithOverrides(enabledChecks, cfg, profile, nil)
}

// BuildValidatorSetWithOverrides is BuildValidatorSet with a third configuration pass, applied after the
// config and profile passes: overrides, which come from the command line. Pass nil for none.
func BuildValidatorSetWithOverrides(enabledChecks map[string]bool, cfg *config.Config, profile *config.Profile, overrides *ValidatorOverrides) map[string]detector.Validator {
	result := make(map[string]detector.Validator)

	for name, newValidator := range validatorConstructors {
		if enabledChecks[name] {
			result[name] = newValidator()
		}
	}

	// Apply global config-level validator settings
	if cfg != nil {
		configureConfigurableValidators(result, cfg)
	}

	// Apply profile-level overrides. This must cover the SAME validators as the
	// global pass: it previously reached only INTELLECTUAL_PROPERTY, so a profile
	// that configured cloud_resources or social_media was silently ignored while
	// the identical block at the top level worked.
	//
	// Each Configure returns early when its own section is absent, so passing a
	// profile-only config overrides just the sections the profile actually sets
	// and leaves the global settings for the others in place.
	if profile != nil && profile.Validators != nil {
		configureConfigurableValidators(result, &config.Config{Validators: profile.Validators})
	}

	// Command-line overrides, last, so they outrank both passes above. Only the validator an override
	// names is reconfigured, and only with the overriding key, so nothing else either pass set is lost.
	if overrides != nil && overrides.DisabledIPTypes != nil {
		if v, ok := result["INTELLECTUAL_PROPERTY"].(*intellectualproperty.Validator); ok {
			types := make([]any, 0, len(overrides.DisabledIPTypes))
			for _, t := range overrides.DisabledIPTypes {
				types = append(types, t)
			}
			v.Configure(&config.Config{Validators: map[string]map[string]interface{}{
				"intellectual_property": {"disabled_types": types},
			}})
		}
	}

	return result
}

// DisabledDetectionTypes asks each configured validator which detection sub-types configuration switched
// off, and which `disabled_types` entries matched nothing.
//
// It asks the VALIDATORS rather than re-reading config, and that is the whole design. Only the
// intellectual-property validator honours `disabled_types`; the key is inert under any other validator's
// section. A config-derived disclosure would therefore announce reduced coverage that did not happen, and a
// disclosure naming a cause that did not occur sends the operator to fix the wrong thing.
//
// Only validators actually in the run are present in the map, so a `disabled_types` block for a validator
// excluded by --checks is correctly silent: nothing was disabled because nothing ran.
//
// Both maps are keyed by the check name the operator would type in --checks, not by the config section
// name, because the disclosure is read alongside the flags rather than alongside the YAML. It lives here,
// beside the passes that decide the answer, so that ScanContent can report it for the validators IT built
// (ScanResult.DisabledDetectionTypes): the CLI's --stdin path has no validator set of its own to ask.
func DisabledDetectionTypes(validators map[string]detector.Validator) (disabled, unrecognised map[string][]string) {
	for name, v := range validators {
		ip, ok := v.(*intellectualproperty.Validator)
		if !ok {
			continue
		}
		if off := ip.DisabledSubTypes(); len(off) > 0 {
			if disabled == nil {
				disabled = make(map[string][]string)
			}
			disabled[name] = off
		}
		if bad := ip.UnrecognisedDisabledSubTypes(); len(bad) > 0 {
			if unrecognised == nil {
				unrecognised = make(map[string][]string)
			}
			unrecognised[name] = bad
		}
	}
	return disabled, unrecognised
}

// configureConfigurableValidators hands cfg to every validator that reads the
// `validators:` config block. Keeping this in one place is what stops the
// global and profile passes from drifting apart again.
func configureConfigurableValidators(result map[string]detector.Validator, cfg *config.Config) {
	if v, ok := result["CLOUD_RESOURCES"].(*cloudresources.Validator); ok {
		v.Configure(cfg)
	}
	if v, ok := result["INTELLECTUAL_PROPERTY"].(*intellectualproperty.Validator); ok {
		v.Configure(cfg)
	}
	if v, ok := result["SOCIAL_MEDIA"].(*socialmedia.Validator); ok {
		v.Configure(cfg)
	}
}

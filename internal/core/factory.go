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
// ParseChecksToRun and BuildValidatorSet. It is re-exported publicly as
// redact.ValidCheckNames so consumers can validate Checks input against the
// real list instead of hardcoding (and drifting from) a private copy. The
// "all" sentinel and the empty default are handled by the callers and are not
// included here.
func CheckNames() []string {
	names := make([]string, 0, len(validatorConstructors))
	for name := range validatorConstructors {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// BuildValidatorSet constructs the standard set of validators filtered by the
// enabled checks map. Pass nil for cfg to skip validator-specific configuration.
// Pass nil for profile to skip profile-specific overrides.
func BuildValidatorSet(enabledChecks map[string]bool, cfg *config.Config, profile *config.Profile) map[string]detector.Validator {
	result := make(map[string]detector.Validator)

	for name, newValidator := range validatorConstructors {
		if enabledChecks[name] {
			result[name] = newValidator()
		}
	}

	// Apply global config-level validator settings
	if cfg != nil {
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

	// Apply profile-level overrides
	if profile != nil && profile.Validators != nil {
		profileCfg := &config.Config{Validators: profile.Validators}
		if v, ok := result["INTELLECTUAL_PROPERTY"].(*intellectualproperty.Validator); ok {
			v.Configure(profileCfg)
		}
	}

	return result
}

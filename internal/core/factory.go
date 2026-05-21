// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"github.com/awslabs/ferret-scan/internal/config"
	"github.com/awslabs/ferret-scan/internal/detector"
	"github.com/awslabs/ferret-scan/internal/validators/creditcard"
	"github.com/awslabs/ferret-scan/internal/validators/email"
	"github.com/awslabs/ferret-scan/internal/validators/intellectualproperty"
	"github.com/awslabs/ferret-scan/internal/validators/ipaddress"
	"github.com/awslabs/ferret-scan/internal/validators/metadata"
	"github.com/awslabs/ferret-scan/internal/validators/passport"
	"github.com/awslabs/ferret-scan/internal/validators/personname"
	"github.com/awslabs/ferret-scan/internal/validators/phone"
	"github.com/awslabs/ferret-scan/internal/validators/secrets"
	"github.com/awslabs/ferret-scan/internal/validators/socialmedia"
	"github.com/awslabs/ferret-scan/internal/validators/ssn"
	"github.com/awslabs/ferret-scan/internal/validators/vin"
)

// BuildValidatorSet constructs the standard set of validators filtered by the
// enabled checks map. Pass nil for cfg to skip validator-specific configuration.
// Pass nil for profile to skip profile-specific overrides.
func BuildValidatorSet(enabledChecks map[string]bool, cfg *config.Config, profile *config.Profile) map[string]detector.Validator {
	result := make(map[string]detector.Validator)

	if enabledChecks["CREDIT_CARD"] {
		result["CREDIT_CARD"] = creditcard.NewValidator()
	}
	if enabledChecks["EMAIL"] {
		result["EMAIL"] = email.NewValidator()
	}
	if enabledChecks["PHONE"] {
		result["PHONE"] = phone.NewValidator()
	}
	if enabledChecks["IP_ADDRESS"] {
		result["IP_ADDRESS"] = ipaddress.NewValidator()
	}
	if enabledChecks["PASSPORT"] {
		result["PASSPORT"] = passport.NewValidator()
	}
	if enabledChecks["PERSON_NAME"] {
		result["PERSON_NAME"] = personname.NewValidator()
	}
	if enabledChecks["METADATA"] {
		result["METADATA"] = metadata.NewValidator()
	}
	if enabledChecks["INTELLECTUAL_PROPERTY"] {
		result["INTELLECTUAL_PROPERTY"] = intellectualproperty.NewValidator()
	}
	if enabledChecks["SOCIAL_MEDIA"] {
		result["SOCIAL_MEDIA"] = socialmedia.NewValidator()
	}
	if enabledChecks["SSN"] {
		result["SSN"] = ssn.NewValidator()
	}
	if enabledChecks["SECRETS"] {
		result["SECRETS"] = secrets.NewValidator()
	}
	if enabledChecks["VIN"] {
		result["VIN"] = vin.NewValidator()
	}

	// Apply global config-level validator settings
	if cfg != nil {
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

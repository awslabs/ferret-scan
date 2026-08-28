// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package validators

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/explain"
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
	"github.com/awslabs/ferret-scan/v2/internal/validators/otp"
	"github.com/awslabs/ferret-scan/v2/internal/validators/passport"
	"github.com/awslabs/ferret-scan/v2/internal/validators/personname"
	"github.com/awslabs/ferret-scan/v2/internal/validators/phone"
	"github.com/awslabs/ferret-scan/v2/internal/validators/secrets"
	"github.com/awslabs/ferret-scan/v2/internal/validators/ssn"
	"github.com/awslabs/ferret-scan/v2/internal/validators/vin"
)

// #363 item 2: four validators produced a verdict with NO rationale. They set no
// validation_checks, and the synthesizer can only narrate the checks it is given — so
// --explain restated the type and the confidence the reviewer had already been shown:
//
//	PHYSICAL_ADDRESS  "Flagged as an us street address. (confidence 100%, high)"
//	BANK_ACCOUNT      "Flagged as an iban; nearby context raised confidence by 15%. ..."
//	SECRETS           "Flagged as an aws secret access key. (confidence 75%, medium)"
//	CLOUD_RESOURCES   "Flagged as an aws arn. (confidence 55%, low)"
//
// SECRETS and CLOUD_RESOURCES are the ones that matter: a 75% MEDIUM secret and a 55% LOW ARN
// are exactly the findings a reviewer needs help judging.
//
// This is deliberately a guard over EVERY validator rather than four separate tests. The defect
// was not four independent mistakes; it was that nothing required a validator to record what it
// checked, so each new one could omit it silently — which is how a dedicated AWS-secret path
// inside a validator that DOES record checks elsewhere ended up with none.

// rationaleCase is one validator, a fixture that makes it produce a finding, and the check
// name that must reach the explanation.
type rationaleCase struct {
	name     string
	validate func(content, path string) ([]detector.Match, error)
	content  string
	// wantCheck is a validation_checks key this validator must report. Naming one specific key
	// rather than asserting "any" means a validator cannot satisfy this test by recording a
	// single throwaway boolean.
	//
	// Every name here was READ OUT of the validator rather than guessed. Three of the first
	// attempt's guesses were wrong — phone reports "valid_format" not "format",
	// driverslicense "format_match", personname "valid_pattern" — and a wrong name here fails
	// the test for the wrong reason, which is indistinguishable from the defect it guards.
	wantCheck string
}

func rationaleCases() []rationaleCase {
	return []rationaleCase{
		// The four from the issue.
		{"physical_address", address.NewValidator().ValidateContent,
			"Mailing address: 1600 Pennsylvania Ave NW, Washington, DC 20500\n", "street_type_suffix"},
		{"bank_account", bankaccount.NewValidator().ValidateContent,
			"IBAN: DE89370400440532013000\n", "mod97_checksum"},
		{"secrets", secrets.NewValidator().ValidateContent,
			"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYzR8h1nQ2vT\n", "entropy"},
		{"cloud_resources", cloudresources.NewValidator().ValidateContent,
			"arn:aws:s3:::my-production-bucket-name\n", "valid_format"},

		// The others, so this is a floor for the whole set rather than a patch for four. Each
		// already recorded checks before this change; listing them is what stops a future
		// refactor from quietly dropping one.
		{"ssn", ssn.NewValidator().ValidateContent, "SSN: 452-11-9384\n", "format"},
		{"credit_card", creditcard.NewValidator().ValidateContent, "card 4111111111111111\n", "luhn"},
		{"ip_address", ipaddress.NewValidator().ValidateContent,
			"Server address: 52.94.236.248\n", "valid_format"},
		{"phone", phone.NewValidator().ValidateContent, "Call me at 415-926-3481 tomorrow\n", "valid_format"},
		{"vin", vin.NewValidator().ValidateContent, "VIN: 1HGCM82633A004352\n", "format"},
		{"passport", passport.NewValidator().ValidateContent, "Passport number: 543216789\n", "format"},
		{"dob", dob.NewValidator().ValidateContent, "Date of birth: 03/15/1985\n", "valid_date"},
		{"drivers_license", driverslicense.NewValidator().ValidateContent,
			"Driver license number: D1234567 issued in CA\n", "format_match"},
		{"email", email.NewValidator().ValidateContent,
			"Contact: alice.brown@corp.example.com\n", "valid_format"},
		{"person_name", personname.NewValidator().ValidateContent,
			"Employee: Jonathan Michael Reed signed the form\n", "valid_pattern"},
		{"otp", otp.NewValidator().ValidateContent,
			"otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example\n", "format"},
		{"intellectual_property", intellectualproperty.NewValidator().ValidateContent,
			"Copyright (c) 2024 Acme Corporation. All rights reserved.\n", "format"},
	}
}

// TestEveryValidatorRecordsWhatItChecked is the guard.
//
// It asserts the METADATA contract rather than the rendered prose, because that is the contract
// the synthesizer depends on and the one a validator author has to satisfy. The rendered half is
// asserted in the companion test below.
func TestEveryValidatorRecordsWhatItChecked(t *testing.T) {
	for _, tc := range rationaleCases() {
		t.Run(tc.name, func(t *testing.T) {
			matches, err := tc.validate(tc.content, "fixture.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			// Non-vacuity: no finding means the fixture stopped working and every assertion
			// below would pass on an empty slice.
			if len(matches) == 0 {
				t.Fatalf("the fixture produced no finding, so this case tests nothing.\n"+
					"content: %q", tc.content)
			}

			var withChecks int
			var sawWanted bool
			for _, m := range matches {
				raw, present := m.Metadata["validation_checks"]
				if !present {
					continue
				}
				checks, ok := raw.(map[string]bool)
				if !ok {
					t.Errorf("validation_checks is %T, want map[string]bool — the explain layer "+
						"reads it with that exact type assertion and silently sees nothing "+
						"otherwise", raw)
					continue
				}
				if len(checks) == 0 {
					continue
				}
				withChecks++
				if _, found := checks[tc.wantCheck]; found {
					sawWanted = true
				}
			}

			if withChecks == 0 {
				t.Errorf("not one of %d finding(s) carried a non-empty validation_checks map.\n"+
					"--explain can only narrate the checks it is given, so its rationale collapses "+
					"to the type and a confidence the reviewer was already shown (#363).", len(matches))
				return
			}
			if !sawWanted {
				t.Errorf("no finding reported the %q check. A validator must record the "+
					"substantive judgement it made, not merely some boolean.", tc.wantCheck)
			}
		})
	}
}

// TestEveryValidatorProducesARationaleSentence is the user-visible half.
//
// The metadata contract above is the mechanism; this is the outcome. A rationale that names no
// check reads as "Flagged as an X. (confidence N%, tier)" — which tells a reviewer nothing they
// did not already have, and is exactly what the issue reported.
func TestEveryValidatorProducesARationaleSentence(t *testing.T) {
	s := explain.NewSignalSynthesizer()
	for _, tc := range rationaleCases() {
		t.Run(tc.name, func(t *testing.T) {
			matches, err := tc.validate(tc.content, "fixture.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) == 0 {
				t.Fatalf("the fixture produced no finding, so this case tests nothing")
			}

			var best string
			for _, m := range matches {
				why := s.Explain(m).Rationale
				if strings.Contains(why, "it passed") || strings.Contains(why, "but it") {
					best = why
					break
				}
				if best == "" {
					best = why
				}
			}
			if !strings.Contains(best, "it passed") && !strings.Contains(best, "but it") {
				t.Errorf("no finding produced a rationale naming a check:\n  %s\n"+
					"A reviewer reading this learns only the type and a confidence they were "+
					"already shown.", best)
			}
		})
	}
}

// TestMedicalIDIsAKnownRemainingGap records a fifth case found while fixing the four, and why it
// is NOT fixed here.
//
// medicalid records no validation_checks on any of its five subtypes, so an NPI — which carries a
// real CMS-Luhn-80840 check digit, exactly the kind of proof a reviewer wants — explains as
// "Flagged as an NPI; nearby context raised confidence by 20%". The issue did not name it,
// probably because that context clause makes the sentence look non-empty.
//
// It is left alone deliberately: internal/validators/medicalid/validator.go is modified by an
// open pull request (#532), and editing the same file here would conflict. Filed separately.
//
// This test asserts the CURRENT state so the exclusion is visible rather than looking like an
// oversight, and so whoever fixes it is told to move the case into rationaleCases above. It fails
// loudly when medicalid starts recording checks, which is the intended trigger.
func TestMedicalIDIsAKnownRemainingGap(t *testing.T) {
	const content = "NPI: 1234567893 for the provider\n"
	matches, err := medicalid.NewValidator().ValidateContent(content, "fixture.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	if len(matches) == 0 {
		t.Skip("the NPI fixture no longer produces a finding; nothing to record")
	}
	for _, m := range matches {
		if raw, present := m.Metadata["validation_checks"]; present {
			if checks, ok := raw.(map[string]bool); ok && len(checks) > 0 {
				t.Fatalf("medicalid now records validation_checks (%v) — the deliberate exclusion "+
					"below is obsolete.\nMove a medical_id case into rationaleCases() and delete "+
					"this test.", checks)
			}
		}
	}
}

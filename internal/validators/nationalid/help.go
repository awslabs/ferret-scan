// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package nationalid

import "github.com/awslabs/ferret-scan/v2/internal/help"

// GetCheckInfo returns standardized information about the NATIONAL_ID check.
func (v *Validator) GetCheckInfo() help.CheckInfo {
	var positive []string
	for _, t := range Types {
		for _, l := range labelsByType[t] {
			positive = append(positive, l.text)
		}
	}
	return help.CheckInfo{
		Name:             "NATIONAL_ID",
		ShortDescription: "Detects labelled Americas national ID numbers (BR CPF, CL RUT, AR CUIL, CA SIN, MX CURP)",
		DetailedDescription: `The NATIONAL_ID check detects national identification numbers that the SSN
check does not cover: Brazil's CPF (BR_CPF), Chile's RUT/RUN (CL_RUT), Argentina's
CUIL and personal CUIT (AR_CUIL), Canada's Social Insurance Number (CA_SIN) and
Mexico's CURP (MX_CURP). A value is reported only when its own label sits right
before it on the same line ("CPF nº", "RUT:", "Employee SIN:", "CURP:" or the
long form), and only when its check digit and structural rules pass. A check
digit passes about one random value in ten, so a valid value with no label is not
reported. An acronym that is also a word (sin, run, NAS) counts only when it is
written in capitals or followed by a colon or an ordinal sign.`,

		Patterns: []string{
			"BR_CPF: XXX.XXX.XXX-XX, XXXXXXXXX-XX or 11 digits; two mod-11 check digits",
			"CL_RUT: XX.XXX.XXX-D or XXXXXXXX-D; mod-11 verifier 0-9 or K",
			"AR_CUIL: 20/23/24/27-XXXXXXXX-X or 11 digits; mod-11 check digit",
			"CA_SIN: XXX-XXX-XXX, XXX XXX XXX or 9 digits; Luhn; leading 0 and 8 (business) excluded",
			"MX_CURP: 18 characters; birth date, sex, state code, consonants and check digit verified",
		},

		SupportedFormats: []string{
			"Same-line label before the value, with ':', '#', '=', 'nº', 'n°' or spaces between",
			"Portuguese, Spanish and French long-form labels, with or without accents",
		},

		ConfidenceFactors: []help.ConfidenceFactor{
			{Name: "Check digit", Description: "The value passes its type's check digit and structure (required)", Weight: 0},
			{Name: "Label", Description: "Its own label right before it (required): 95 for a long form or a label with ':'/'nº', 90 for a bare capitalised acronym", Weight: 95},
		},

		PositiveKeywords: positive,

		Examples: []string{
			"ferret-scan --file onboarding.csv --checks NATIONAL_ID",
			"ferret-scan --file hr-export.txt --checks NATIONAL_ID,SSN --enable-redaction",
		},
	}
}

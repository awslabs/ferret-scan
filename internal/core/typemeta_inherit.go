// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package core

import "sort"

// Sub-type description inheritance.
//
// # The measurement
//
// KnownTypes() lists 64 detection types. typeDescriptors has 37 keys, of which only 27 are types
// KnownTypes lists — and per FIELD the coverage is worse: **15 of 64** types have a SARIFShort, so
// **49** fall back to
//
//	"<TYPE> Detected" / "Sensitive data of type <TYPE> was detected in the scanned content."
//
// which is the ENTIRE explanation a reviewer gets in a code-scanning UI. 45 of 64 have no
// GitLabCheckDesc, 49 no GitLabRemediation, 56 no GitLabName, and **37 have nothing in any field**
// (#662).
//
// # Why the gap is systematic rather than 49 separate omissions
//
// The registry is keyed by Match.Type — the SUB-TYPE a validator emits — but it was POPULATED at
// validator level. The proof is in the registry itself: **10 of its 37 keys are not types at all**.
// `SECRETS`, `METADATA`, `SOCIAL_MEDIA`, `SOCIAL_MEDIA_CLUSTER`, `API_KEY`, `CLOUD_RESOURCE_ID`,
// `GPS`, `PII_PERSON`, `PII_LOCATION` and `PII_ORGANIZATION` are validator/family names that no
// finding ever carries. So carefully written copy sits on keys nothing looks up, while the sub-types
// that DO reach a report — SLACK_TOKEN, AUTHOR_INFO, VISA — look up nothing.
//
// That is also why the parent for a card brand already exists: CREDIT_CARD has copy and a weight of
// 10, and VISA has neither.
//
// # Why inheritance and not 49 bespoke strings
//
// Writing prose for 49 types is the per-instance fix, and it cannot stay complete: sub-types are
// minted by validators, so the next one added arrives with no copy and nothing notices — which is
// exactly how this reached 49. Inheritance makes a new sub-type inherit its family's copy the moment
// it is mapped, and TestEveryKnownTypeHasCopy below makes an UNMAPPED one fail the build.
//
// The pattern is already established here: sarifCloudDesc is one shared descriptor reused across
// every cloud-provider sub-type. This generalises it.
//
// # Why a separate accessor rather than filling in typeDescriptors
//
// TypeDescriptor's contract says "Do NOT collapse the empty fields into shared values", and
// typemeta_mirror_test.go asserts the map is a byte-for-byte mirror of the legacy formatter maps.
// Those are worth keeping: the mirror is what proves the migration lost nothing. So typeDescriptors
// and TypeMeta are untouched, and resolution happens in DescribeType, which every consumer that
// wants a human-facing string now calls instead.

// typeParent maps a sub-type to the family whose descriptor it inherits from.
//
// A type appears here ONLY if it has no copy of its own. The mapping is structural — a fact about
// what the value IS, not a judgement about wording — which is why it is safe to maintain by hand in a
// way 49 prose strings are not: VISA is a credit card whatever anyone writes about it.
var typeParent = map[string]string{
	"AOL":                   "EMAIL",
	"ATLASSIAN":             "EMAIL",
	"FASTMAIL":              "EMAIL",
	"GITLAB":                "EMAIL",
	"GOOGLE_WORKSPACE":      "EMAIL",
	"ICLOUD":                "EMAIL",
	"MAIL_RU":               "EMAIL",
	"MICROSOFT_365":         "EMAIL",
	"OUTLOOK":               "EMAIL",
	"PROTONMAIL":            "EMAIL",
	"SALESFORCE":            "EMAIL",
	"SLACK":                 "EMAIL",
	"TUTANOTA":              "EMAIL",
	"YAHOO":                 "EMAIL",
	"YANDEX":                "EMAIL",
	"ZOHO":                  "EMAIL",
	"MAESTRO":               "CREDIT_CARD",
	"UNIONPAY":              "CREDIT_CARD",
	"CERTIFICATE":           "SECRETS",
	"PGP_PRIVATE_KEY":       "SECRETS",
	"AUDIO_ARTIST_IDENTITY": "METADATA",
	"AUDIO_CONTACT_INFO":    "METADATA",
	"AUDIO_LOCATION_INFO":   "METADATA",
	"AUDIO_METADATA":        "METADATA",
	"CUSTOM_PROPERTY":       "METADATA",
	"DEVICE_INFO":           "METADATA",
	"DOCUMENT_DESCRIPTION":  "METADATA",
	"DOCUMENT_KEYWORDS":     "METADATA",
	"DOCUMENT_METADATA":     "METADATA",
	"GPS":                   "METADATA",
	"MANAGER_INFO":          "METADATA",
	"SOFTWARE_USER_PATH":    "METADATA",
	"VIDEO_CREATOR_INFO":    "METADATA",
	"VIDEO_DEVICE_INFO":     "METADATA",
	"VIDEO_METADATA":        "METADATA",
	"SOCIAL_MEDIA_CLUSTER":  "SOCIAL_MEDIA",
	// Card brands. CREDIT_CARD already carries the copy, the weight of 10 and the remediation.
	"AMERICAN_EXPRESS": "CREDIT_CARD",
	"DINERS_CLUB":      "CREDIT_CARD",
	"DISCOVER":         "CREDIT_CARD",
	"JCB":              "CREDIT_CARD",
	"MASTERCARD":       "CREDIT_CARD",
	"VISA":             "CREDIT_CARD",

	// Email classifications. The email validator emits the CLASS of address it found, and every one
	// of them is still an email address.
	"APPLE_CORPORATE": "EMAIL",
	"BUSINESS":        "EMAIL",
	"DISPOSABLE":      "EMAIL",
	"EDUCATIONAL":     "EMAIL",
	"GMAIL":           "EMAIL",
	"GOVERNMENT":      "EMAIL",

	// Credentials. SECRETS carries "Secret or API Key Detected" and a weight of 9 — the highest in
	// the registry after CREDIT_CARD — and not one of these eleven inherited it before.
	"API_KEY_OR_SECRET":     "SECRETS",
	"AWS_ACCESS_KEY":        "SECRETS",
	"AWS_SECRET_ACCESS_KEY": "SECRETS",
	"DOCKER_TOKEN":          "SECRETS",
	"GITHUB_TOKEN":          "SECRETS",
	"GITLAB_TOKEN":          "SECRETS",
	"GOOGLE_CLOUD_API_KEY":  "SECRETS",
	"JWT_TOKEN":             "SECRETS",
	"SLACK_TOKEN":           "SECRETS",
	"SSH_PRIVATE_KEY":       "SECRETS",
	"STRIPE_API_KEY":        "SECRETS",

	// Document and image metadata. METADATA carries the copy, the weight of 3 and the remediation.
	"APPLICATION_INFO":  "METADATA",
	"AUTHOR_INFO":       "METADATA",
	"COMPANY_INFO":      "METADATA",
	"DOCUMENT_COMMENTS": "METADATA",
	"IMAGE_METADATA":    "METADATA",
	"LAST_MODIFIED_BY":  "METADATA",
	"TEMPLATE_INFO":     "METADATA",

	// A GitHub handle is a social-media handle.
	"GITHUB": "SOCIAL_MEDIA",

	// Cloud provider sub-types. These already share sarifCloudDesc in the registry, so they have SARIF
	// copy — but the gitlab side of the registry had no entry for any of them, and the family key
	// CLOUD_RESOURCE_ID is one of the ten keys no finding ever carries. Mapping them closes the gitlab
	// gap for all six without touching their SARIF copy, which descriptorFor prefers.
	"ALIBABA_ARN":       "CLOUD_RESOURCE_ID",
	"AWS_ARN":           "CLOUD_RESOURCE_ID",
	"AZURE_RESOURCE_ID": "CLOUD_RESOURCE_ID",
	"GCP_RESOURCE_NAME": "CLOUD_RESOURCE_ID",
	"IBM_CRN":           "CLOUD_RESOURCE_ID",
	"OCI_OCID":          "CLOUD_RESOURCE_ID",

	// Families with no descriptor at all before this change; the six parents are defined below.
	"ABA_ROUTING":     "BANK_ACCOUNT",
	"IBAN":            "BANK_ACCOUNT",
	"SWIFT_BIC":       "BANK_ACCOUNT",
	"US_BANK_ACCOUNT": "BANK_ACCOUNT",

	"DEA_NUMBER":          "MEDICAL_ID",
	"INSURANCE_MEMBER_ID": "MEDICAL_ID",
	"MEDICARE_MBI":        "MEDICAL_ID",
	"MRN":                 "MEDICAL_ID",
	"NPI":                 "MEDICAL_ID",

	"PO_BOX":              "PHYSICAL_ADDRESS",
	"US_MILITARY_ADDRESS": "PHYSICAL_ADDRESS",
	"US_RURAL_ROUTE":      "PHYSICAL_ADDRESS",
	"US_STREET_ADDRESS":   "PHYSICAL_ADDRESS",

	"OTPAUTH_URI":    "OTP",
	"OTP_SECRET":     "OTP",
	"RECOVERY_CODES": "OTP",
}

// supplementalDescriptors supplies copy the migrated registry does not have — both for families that
// had no entry at all, and for registry entries that are populated for one consumer and empty for
// another.
//
// Kept OUT of typeDescriptors so typemeta_mirror_test.go keeps asserting exactly what it was written
// to assert: that the migrated map reproduces the legacy formatter maps and nothing else. The registry
// wins any field it defines (see descriptorFor), so this can only ever FILL a gap.
//
// Weights are set relative to what the registry already uses — CREDIT_CARD 10, SECRETS 9,
// CLOUD_RESOURCE_ID 7, EMAIL 5, METADATA 3 — rather than invented on a fresh scale.
var supplementalDescriptors = map[string]TypeDescriptor{
	// A routing number with an account number is enough to move money, and the report did not say so.
	"BANK_ACCOUNT": {
		SARIFShort: "Bank Account Identifier Detected",
		SARIFFull: "A bank account identifier — a US account number, an ABA routing number, an IBAN or " +
			"a SWIFT/BIC code — was detected in the scanned content. A routing number together with an " +
			"account number is sufficient to originate a debit against that account.",
		SARIFHelp: "Remove the account identifier, or replace it with a documented test value. Note that " +
			"routing and account numbers are damaging in COMBINATION: a routing number alone identifies " +
			"only the institution, so check whether an account number appears nearby before deciding a " +
			"finding is low risk. Where account details must be stored, hold them in a payments vault " +
			"rather than in source, logs or shared documents.",
		SARIFSensitivityWeight: 9.0,
		GitLabCheckDesc:        "Bank account identifier",
		GitLabRemediation: "Remove bank account, routing, IBAN or SWIFT/BIC values. Use a documented test " +
			"value in fixtures, and store real payment details in a payments vault.",
		GitLabName: "Bank Account Identifier Detected",
	},

	// Each of these carries a different regulatory weight and the report could not say which.
	"MEDICAL_ID": {
		SARIFShort: "Medical Identifier Detected",
		SARIFFull: "A healthcare identifier — a medical record number, a Medicare Beneficiary " +
			"Identifier, an NPI, a DEA registration number or an insurance member ID — was detected in " +
			"the scanned content. Most of these identify a PATIENT and are protected health information; " +
			"an NPI identifies a PRACTITIONER and is published in a public registry, so it is the least " +
			"sensitive of the group.",
		SARIFHelp: "Treat a patient identifier as protected health information: remove it, or replace it " +
			"with a synthetic value, and check whether the surrounding record must be handled under HIPAA " +
			"or an equivalent regime. A DEA number additionally authorises controlled-substance " +
			"prescribing, so it is a credential as well as an identifier. An NPI on its own is public " +
			"information and usually needs no action — but an NPI beside a patient identifier links a " +
			"named clinician to a named patient.",
		SARIFSensitivityWeight: 8.0,
		GitLabCheckDesc:        "Medical or healthcare identifier",
		GitLabRemediation: "Remove patient identifiers (MRN, Medicare MBI, insurance member ID) or replace " +
			"them with synthetic values, and confirm the record's handling requirements. A DEA number is " +
			"also a prescribing credential. An NPI is published publicly and is usually safe alone.",
		GitLabName: "Medical Identifier Detected",
	},

	"PHYSICAL_ADDRESS": {
		SARIFShort: "Physical Address Detected",
		SARIFFull: "A physical postal address — a street address, a PO box, a rural route or a US " +
			"military (APO/FPO/DPO) address — was detected in the scanned content. An address locates a " +
			"person, and a military address additionally reveals a unit assignment.",
		SARIFHelp: "Remove the address or replace it with a documented example. An address is most " +
			"sensitive in combination with a name or an account identifier, so check what sits beside it " +
			"before judging severity. A military APO/FPO/DPO address should be treated as more sensitive " +
			"than a commercial one because it can disclose a unit's location and posting.",
		SARIFSensitivityWeight: 5.0,
		GitLabCheckDesc:        "Physical address",
		GitLabRemediation: "Remove the postal address or replace it with an example address. Treat an " +
			"APO/FPO/DPO address as more sensitive, since it can reveal a unit assignment.",
		GitLabName: "Physical Address Detected",
	},

	// A one-time-password seed is a permanent second factor, not a transient code.
	"OTP": {
		SARIFShort: "Multi-Factor Authentication Secret Detected",
		SARIFFull: "A multi-factor authentication secret — a TOTP/HOTP shared secret, an otpauth:// " +
			"provisioning URI or a set of account recovery codes — was detected in the scanned content. " +
			"These are not transient codes: the SEED generates every future code for the account, so " +
			"disclosing it defeats the second factor permanently until the account is re-enrolled.",
		SARIFHelp: "Treat this as a credential disclosure, not a configuration mistake. Re-enrol the " +
			"account's second factor and regenerate its recovery codes; removing the value from the file " +
			"does not undo the exposure, because whoever saw the seed can still generate codes. Provisioning " +
			"URIs are commonly pasted from a QR-code export, so check for others nearby.",
		SARIFSensitivityWeight: 9.0,
		GitLabCheckDesc:        "Multi-factor authentication secret",
		GitLabRemediation: "Re-enrol the account's second factor and regenerate recovery codes — the seed " +
			"generates all future codes, so deleting the value is not sufficient. Then remove the value " +
			"and store any required seed in a secret manager.",
		GitLabName: "MFA Secret Detected",
	},

	// The two types with no family at all get their own entries, keyed by themselves.
	"DATE_OF_BIRTH": {
		SARIFShort: "Date of Birth Detected",
		SARIFFull: "A date of birth was detected in the scanned content. A date of birth is a common " +
			"identity-verification factor and, combined with a name, is frequently enough to pass a " +
			"knowledge-based authentication check.",
		SARIFHelp: "Remove the date of birth or replace it with a synthetic one. Judge severity by what " +
			"sits beside it: a date alone is weak, while a date next to a name or an account number is a " +
			"usable identity-verification pair. Note that a date of birth has a very small search space, " +
			"so hashing or truncating one does not make it private.",
		SARIFSensitivityWeight: 6.0,
		GitLabCheckDesc:        "Date of birth",
		GitLabRemediation: "Remove the date of birth or replace it with synthetic test data. It is an " +
			"identity-verification factor, especially alongside a name.",
		GitLabName: "Date of Birth Detected",
	},

	// GitLab-only supplements. Each of these keys already has SARIF copy in the migrated registry and
	// no gitlab entry, because the two legacy formatter maps had different key sets. Filling only the
	// missing fields leaves the SARIF side exactly as migrated.
	"SECRETS": {
		GitLabCheckDesc: "Secret or API key",
		GitLabRemediation: "Treat the value as compromised: rotate or revoke the credential first, then " +
			"remove it from the file. Deleting the text does not undo the exposure. Store the replacement " +
			"in a secret manager or an environment variable, never in source or logs.",
	},
	"CLOUD_RESOURCE_ID": {
		GitLabCheckDesc: "Cloud resource identifier",
		GitLabRemediation: "Replace the identifier with a variable, a parameter or a service-discovery " +
			"lookup. These identifiers embed account, subscription, project or tenant anchors that reveal " +
			"ownership and infrastructure layout, so scrub them from anything shared outside your " +
			"organization.",
		GitLabName: "Cloud Resource Identifier Detected",
	},
	"SOCIAL_MEDIA": {
		GitLabCheckDesc: "Social media handle",
		GitLabRemediation: "Remove the handle or replace it with an example account. A handle links a " +
			"record to a real, publicly searchable identity.",
	},
	"PASSPORT": {
		GitLabCheckDesc: "Passport number",
		GitLabRemediation: "Remove the passport number or replace it with a synthetic value. It is a " +
			"government-issued travel document number and a strong identity-verification factor.",
	},
	"PERSON_NAME": {
		GitLabCheckDesc: "Personal name",
		GitLabRemediation: "Remove the name or replace it with a placeholder. A name is most sensitive in " +
			"combination with an identifier or an address, so check what appears beside it.",
	},

	"DRIVERS_LICENSE": {
		SARIFShort: "Driver's License Number Detected",
		SARIFFull: "A driver's license number was detected in the scanned content. A license number is a " +
			"government-issued identity document number, and in many jurisdictions its format encodes " +
			"personal details such as a date of birth or a name fragment.",
		SARIFHelp: "Remove the license number or replace it with a synthetic value. Because several " +
			"jurisdictions derive the number from the holder's name and date of birth, the number itself " +
			"can disclose those details even without them appearing in the text. Formats vary by " +
			"jurisdiction, so verify a finding against the issuing state's pattern before dismissing it.",
		SARIFSensitivityWeight: 7.0,
		GitLabCheckDesc:        "Driver's license number",
		GitLabRemediation: "Remove the driver's license number or replace it with a synthetic value. In " +
			"several jurisdictions the number encodes the holder's name and date of birth.",
		GitLabName: "Driver's License Detected",
	},
}

// descriptorFor returns the descriptor for a key, taking each field from the migrated registry when
// it has one and from the supplement otherwise.
//
// A PER-FIELD merge rather than "registry wins whole": several registry entries are populated for one
// consumer and empty for another — SECRETS has SARIF copy and a weight of 9 but no gitlab
// description, CLOUD_RESOURCE_ID likewise, PASSPORT and PERSON_NAME have SARIF copy and no gitlab
// remediation. Preferring the registry wholesale would leave those gaps open for every sub-type
// beneath them, which is 17 types with no gitlab description and 18 with no remediation.
//
// The registry always wins a field it defines, so nothing here can shadow migrated copy — which is
// what keeps typemeta_mirror_test.go meaningful.
func descriptorFor(key string) (TypeDescriptor, bool) {
	reg, inReg := typeDescriptors[key]
	sup, inSup := supplementalDescriptors[key]
	switch {
	case inReg && inSup:
		return mergeDescriptor(reg, sup), true
	case inReg:
		return reg, true
	case inSup:
		return sup, true
	}
	return TypeDescriptor{}, false
}

// mergeDescriptor fills each empty field of primary from secondary.
func mergeDescriptor(primary, secondary TypeDescriptor) TypeDescriptor {
	out := primary
	if out.SARIFShort == "" {
		out.SARIFShort = secondary.SARIFShort
	}
	if out.SARIFFull == "" {
		out.SARIFFull = secondary.SARIFFull
	}
	if out.SARIFHelp == "" {
		out.SARIFHelp = secondary.SARIFHelp
	}
	if out.SARIFSensitivityWeight == 0 {
		out.SARIFSensitivityWeight = secondary.SARIFSensitivityWeight
	}
	if out.GitLabCheckDesc == "" {
		out.GitLabCheckDesc = secondary.GitLabCheckDesc
	}
	if out.GitLabRemediation == "" {
		out.GitLabRemediation = secondary.GitLabRemediation
	}
	if out.GitLabName == "" {
		out.GitLabName = secondary.GitLabName
	}
	return out
}

// DescribeType returns the descriptor a consumer should display for a detection type, filling each
// field that the type itself does not define from its family.
//
// FIELD BY FIELD, not all-or-nothing: the registry's key sets differ per consumer by design, so a
// type can have its own SARIF copy while inheriting a gitlab remediation. Taking the parent wholesale
// on the first empty field would overwrite copy the type does define.
//
// Inheritance is a single hop deliberately. Every mapping in typeParent is sub-type → family, and a
// chain would mean a family is itself a sub-type of something — which is not true of any of them and
// would invite a cycle. resolveOnce is asserted by TestInheritanceIsASingleHop.
func DescribeType(detectionType string) TypeDescriptor {
	own, hasOwn := descriptorFor(detectionType)

	parentKey, hasParent := typeParent[detectionType]
	if !hasParent {
		return own
	}
	parent, ok := descriptorFor(parentKey)
	if !ok {
		// A mapping to a family with no descriptor. Returning the type's own (possibly empty)
		// descriptor keeps the consumer's existing generic fallback, which is strictly better than
		// panicking in a formatter — and TestEveryParentInTheMapHasADescriptor fails the build for it.
		return own
	}
	if !hasOwn {
		return parent
	}

	merged := own
	if merged.SARIFShort == "" {
		merged.SARIFShort = parent.SARIFShort
		merged.SARIFFull = parent.SARIFFull
		merged.SARIFHelp = parent.SARIFHelp
	} else {
		// Short is present; Full and Help can still be individually absent.
		if merged.SARIFFull == "" {
			merged.SARIFFull = parent.SARIFFull
		}
		if merged.SARIFHelp == "" {
			merged.SARIFHelp = parent.SARIFHelp
		}
	}
	if merged.SARIFSensitivityWeight == 0 {
		merged.SARIFSensitivityWeight = parent.SARIFSensitivityWeight
	}
	if merged.GitLabCheckDesc == "" {
		merged.GitLabCheckDesc = parent.GitLabCheckDesc
	}
	if merged.GitLabRemediation == "" {
		merged.GitLabRemediation = parent.GitLabRemediation
	}
	if merged.GitLabName == "" {
		merged.GitLabName = parent.GitLabName
	}
	return merged
}

// TypeFamily returns the family a detection type inherits its description from, or "" when the type
// stands alone. Exported for the documentation generator, which groups the checks page by family.
func TypeFamily(detectionType string) string {
	return typeParent[detectionType]
}

// TypesWithoutDescription returns every KnownTypes entry that, after inheritance, still has no SARIF
// short description — the remaining debt, sorted.
//
// Exported so the gate and the documentation can report the same number instead of two hand-counts
// that drift, which is how #662's own headline figures ("24 documented / 40 undocumented") came to be
// wrong in both halves: the real split at the time of filing was 15 and 49.
func TypesWithoutDescription() []string {
	var out []string
	for _, t := range KnownTypes() {
		if DescribeType(t).SARIFShort == "" {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

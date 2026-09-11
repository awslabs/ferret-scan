// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package core

import "sort"

// TypeDescriptor is the per-Match.Type (sub-type) metadata that the output
// formatters look up. It is the single source of truth for type-keyed display
// strings that were previously scattered across the SARIF and gitlab-sast
// formatter packages (v2 gap 3.3). It is keyed by Match.Type — the SUB-TYPE a
// validator emits (e.g. "VISA", "AWS_ACCESS_KEY", "AUTHOR_INFO"), NOT the
// validator name.
//
// IMPORTANT — per-field presence, not per-key presence: the legacy formatter
// maps had DIFFERENT key sets. A SARIF description exists for EMAIL but not for
// VISA; a gitlab description exists for VISA but not for AWS_ARN. So a field
// left at its zero value means "this consumer had no entry for this type and
// must fall back to its own generic default." Each accessor below replicates
// its origin map's exact key set and fallback, so migrating to this registry is
// byte-identical. Do NOT collapse the empty fields into shared values.
type TypeDescriptor struct {
	// SARIF rule description (origin: sarif/constants.go RuleDescriptions).
	// Empty SARIFShort means the type had no SARIF entry → SARIF generic fallback.
	SARIFShort string
	SARIFFull  string
	SARIFHelp  string

	// SARIF sensitivity weight 0–10 (origin: sarif/mapper.go sensitivityWeights).
	// Zero means "no entry" → SARIF default of 5.0 (the legacy `==0 → 5.0` quirk).
	SARIFSensitivityWeight float64

	// gitlab-sast LIVE strings (origin: gitlab-sast/sanitizer.go). The mapper's
	// own message/description maps are dead (overwritten in formatter.go), so
	// only the sanitizer's two maps are migrated here.
	// Empty GitLabCheckDesc → gitlab "Sensitive data (<type>)" fallback.
	GitLabCheckDesc string
	// Empty GitLabRemediation → gitlab generic "Review the detected…" fallback.
	GitLabRemediation string

	// GitLabName is the gitlab-sast vulnerability display name (origin:
	// gitlab-sast/mapper.go generateVulnerabilityName/nameMap). It is keyed by
	// VALIDATOR NAME (e.g. CREDIT_CARD), not sub-type, so sub-types like VISA
	// have no entry and fall back to the mapper's strings.Title("…")+" Detected"
	// rule. Empty GitLabName → that fallback. Note this is NOT always equal to
	// SARIFShort (e.g. SECRETS differs: "Secret/API Key Detected" vs "Secret or
	// API Key Detected"), so it is a distinct field.
	GitLabName string
}

// sarifCloudDesc is the shared SARIF rule description for every cloud-provider
// resource identifier sub-type (origin: sarif/constants.go cloudResourceDescription).
var sarifCloudDesc = TypeDescriptor{
	SARIFShort: "Cloud Resource Identifier Detected",
	SARIFFull:  "A cloud provider resource identifier (e.g. AWS ARN, Azure resource ID, GCP resource name, OCI OCID, IBM CRN, or Alibaba ARN) was detected in the scanned content. These identifiers can expose account, subscription, project, or tenant identity and infrastructure layout.",
	SARIFHelp:  "Cloud resource identifiers embed account/subscription/project anchors that reveal ownership and infrastructure topology. Avoid hardcoding them in source, logs, or shared documents. Use variables, parameters, or service discovery instead, and scrub identifiers from artifacts shared outside your organization.",
}

// ccRemediation is the shared gitlab remediation string for credit-card types.
const ccRemediation = "Remove or mask credit card numbers. Consider using tokenization for legitimate payment processing needs."

// typeDescriptors is the union of every type-keyed metadata entry from the
// legacy formatter maps, copied verbatim. A field is populated ONLY when the
// corresponding legacy map had that key; see TypeDescriptor for why.
//
// The typemeta_mirror_test.go test asserts this is a faithful, byte-for-byte
// mirror of the legacy maps before any formatter is migrated to read from it.
var typeDescriptors = func() map[string]TypeDescriptor {
	m := map[string]TypeDescriptor{}

	// --- SARIF + sensitivity, validator-name-level keys ---
	m["EMAIL"] = TypeDescriptor{
		SARIFShort:             "Email Address Detected",
		SARIFFull:              "An email address was detected in the scanned content. Email addresses can be considered personally identifiable information (PII) and may need to be protected depending on your compliance requirements.",
		SARIFHelp:              "Email addresses can be considered PII in many regulatory frameworks (GDPR, CCPA, etc.). Consider whether this email address should be present in the code or if it should be stored in a secure configuration system. If this is a test email or example, consider using example.com domain or clearly marking it as test data.",
		SARIFSensitivityWeight: 5.0,
		GitLabCheckDesc:        "Email address",
		GitLabRemediation:      "Remove email addresses or replace with example addresses (e.g., user@domain.example).",
	}
	m["SSN"] = TypeDescriptor{
		SARIFShort:             "Social Security Number Detected",
		SARIFFull:              "A Social Security Number (SSN) pattern was detected in the scanned content. SSNs are highly sensitive personally identifiable information (PII) that must be protected under various regulations.",
		SARIFHelp:              "Social Security Numbers are protected under numerous regulations including GDPR, HIPAA, and various state privacy laws. SSNs should never be stored in source code, configuration files, or logs. Remove this SSN immediately and ensure it is stored in a secure, encrypted system with appropriate access controls. Consider implementing tokenization or other data protection mechanisms.",
		SARIFSensitivityWeight: 10.0,
		GitLabCheckDesc:        "Social Security Number",
		GitLabRemediation:      "Remove Social Security Numbers from code and documentation. Use test data or anonymized identifiers instead.",
	}
	m["CREDIT_CARD"] = TypeDescriptor{
		SARIFShort:             "Credit Card Number Detected",
		SARIFFull:              "A credit card number pattern was detected in the scanned content. Credit card numbers are sensitive financial information that must be protected under PCI DSS and other regulations.",
		SARIFHelp:              "Credit card numbers must be protected according to PCI DSS requirements. They should never be stored in source code, logs, or unencrypted databases. Remove this credit card number immediately and ensure any payment processing uses PCI-compliant systems. Consider using tokenization services provided by payment processors.",
		SARIFSensitivityWeight: 10.0,
		GitLabCheckDesc:        "Credit card number",
		GitLabRemediation:      ccRemediation,
	}
	m["PHONE"] = TypeDescriptor{
		SARIFShort:             "Phone Number Detected",
		SARIFFull:              "A phone number was detected in the scanned content. Phone numbers can be considered personally identifiable information (PII) depending on context and jurisdiction.",
		SARIFHelp:              "Phone numbers may be considered PII under various privacy regulations. Evaluate whether this phone number should be present in the code. If it's for testing purposes, use clearly fake numbers (e.g., 555-0100 to 555-0199 in North America). For production use, store phone numbers in secure configuration systems with appropriate access controls.",
		SARIFSensitivityWeight: 5.0,
		GitLabCheckDesc:        "Phone number",
		GitLabRemediation:      "Remove phone numbers or replace with example numbers (e.g., 555-0123).",
	}
	m["IP_ADDRESS"] = TypeDescriptor{
		SARIFShort:             "IP Address Detected",
		SARIFFull:              "An IP address was detected in the scanned content. IP addresses can be considered personally identifiable information under GDPR and other privacy regulations.",
		SARIFHelp:              "IP addresses are considered personal data under GDPR and similar regulations. Evaluate whether this IP address should be hardcoded. Consider using configuration files, environment variables, or service discovery mechanisms instead. If this is for testing, clearly document it as test data.",
		SARIFSensitivityWeight: 4.0,
		GitLabCheckDesc:        "IP address",
		GitLabRemediation:      "Remove IP addresses or replace with example addresses (e.g., 192.0.2.1).",
	}
	m["PASSPORT"] = TypeDescriptor{
		SARIFShort:             "Passport Number Detected",
		SARIFFull:              "A passport number pattern was detected in the scanned content. Passport numbers are highly sensitive personally identifiable information that must be protected.",
		SARIFHelp:              "Passport numbers are protected under various privacy and identity theft prevention regulations. They should never be stored in source code or logs. Remove this passport number immediately and ensure it is stored in a secure, encrypted system with strict access controls and audit logging.",
		SARIFSensitivityWeight: 10.0,
	}
	m["PERSON_NAME"] = TypeDescriptor{
		SARIFShort:             "Person Name Detected",
		SARIFFull:              "A person's name was detected in the scanned content. Names are considered personally identifiable information (PII) under various privacy regulations.",
		SARIFHelp:              "Person names are considered PII under GDPR, CCPA, and other privacy regulations. Evaluate whether this name should be present in the code. If it's test data, use clearly fictional names or anonymized identifiers. For production use, ensure names are stored securely with appropriate access controls and data retention policies.",
		SARIFSensitivityWeight: 6.0,
	}
	m["SECRETS"] = TypeDescriptor{
		SARIFShort:             "Secret or API Key Detected",
		SARIFFull:              "A potential secret, API key, password, or authentication token was detected in the scanned content. Exposed secrets can lead to unauthorized access and security breaches.",
		SARIFHelp:              "Secrets, API keys, and passwords should never be stored in source code or version control. Remove this secret immediately and rotate it if it has been committed. Use secret management systems like AWS Secrets Manager, HashiCorp Vault, or environment variables for storing sensitive credentials. Implement pre-commit hooks to prevent future secret commits.",
		SARIFSensitivityWeight: 9.0,
	}
	m["INTELLECTUAL_PROPERTY"] = TypeDescriptor{
		SARIFShort:             "Potential Intellectual Property Detected",
		SARIFFull:              "Content that may contain intellectual property markers (copyright notices, trademarks, patents) was detected. This could indicate third-party IP that requires proper attribution or licensing.",
		SARIFHelp:              "Ensure that any third-party intellectual property is properly licensed and attributed. Review your organization's policies on using external code and content. If this is your organization's IP, ensure proper copyright notices are in place. For third-party content, verify compliance with license terms.",
		SARIFSensitivityWeight: 7.0,
		GitLabCheckDesc:        "Intellectual property",
		GitLabRemediation:      "Review and remove proprietary information. Ensure compliance with intellectual property policies.",
	}
	m["METADATA"] = TypeDescriptor{
		SARIFShort:             "Sensitive Metadata Detected",
		SARIFFull:              "Sensitive metadata was detected in file properties. This may include author names, organization information, document history, or other potentially sensitive information embedded in file metadata.",
		SARIFHelp:              "File metadata can contain sensitive information that persists even when the visible content is sanitized. Review the detected metadata and determine if it should be removed. Consider using metadata scrubbing tools before sharing documents externally. Implement policies for metadata handling in your document management processes.",
		SARIFSensitivityWeight: 3.0,
		GitLabCheckDesc:        "Sensitive metadata",
		GitLabRemediation:      "Review and remove sensitive metadata from files before committing to version control.",
	}
	m["SOCIAL_MEDIA"] = TypeDescriptor{
		SARIFShort:             "Social Media Handle Detected",
		SARIFFull:              "A social media handle or username was detected in the scanned content. Social media identifiers can be used to link to personal profiles and may be considered PII in some contexts.",
		SARIFHelp:              "Social media handles can be used to identify individuals and may be considered personal information. Evaluate whether these handles should be present in the code. If they're for testing, use clearly fake handles. For production use, consider whether this information should be stored in a configuration system with appropriate access controls.",
		SARIFSensitivityWeight: 3.0,
	}
	m["VIN"] = TypeDescriptor{
		SARIFShort:             "Vehicle Identification Number Detected",
		SARIFFull:              "A Vehicle Identification Number (VIN) was detected in the scanned content. VINs can be used to identify vehicle owners and access personal information such as registration, insurance, and accident history.",
		SARIFHelp:              "VINs are linked to vehicle owner identity and can reveal personal information through public databases. They should not be stored in source code or logs. Remove VINs and use anonymized identifiers for testing. For production systems, store VINs in encrypted databases with appropriate access controls.",
		SARIFSensitivityWeight: 6.0,
		GitLabCheckDesc:        "Vehicle Identification Number",
		GitLabRemediation:      "Remove Vehicle Identification Numbers from code and documentation. VINs can be used to identify vehicle owners and their personal information.",
	}

	// --- Cloud sub-types: shared SARIF description, distinct 7.0 weights ---
	for _, k := range []string{"AWS_ARN", "AZURE_RESOURCE_ID", "GCP_RESOURCE_NAME", "OCI_OCID", "IBM_CRN", "ALIBABA_ARN", "CLOUD_RESOURCE_ID"} {
		d := sarifCloudDesc
		d.SARIFSensitivityWeight = 7.0
		m[k] = d
	}

	// --- gitlab-only sub-types (no SARIF description/weight; SARIF falls back) ---
	// Credit-card brand sub-types: gitlab description + remediation only.
	ccBrands := map[string]string{
		"VISA":             "Visa credit card",
		"MASTERCARD":       "Mastercard credit card",
		"AMERICAN_EXPRESS": "American Express credit card",
		"DISCOVER":         "Discover credit card",
		"JCB":              "JCB credit card",
		"DINERS_CLUB":      "Diners Club credit card",
	}
	for k, desc := range ccBrands {
		m[k] = TypeDescriptor{GitLabCheckDesc: desc, GitLabRemediation: ccRemediation}
	}
	// Secret/other gitlab sub-types. Note: GetCheckTypeDescription and
	// getRemediationGuidance have DIFFERENT key coverage — preserve that exactly
	// (e.g. SLACK_TOKEN/COMPANY_INFO have a description but NO remediation, so
	// they keep hitting gitlab's generic remediation fallback).
	m["API_KEY"] = TypeDescriptor{GitLabCheckDesc: "API key", GitLabRemediation: "Remove API keys and store them securely using environment variables or secret management systems."}
	m["AWS_ACCESS_KEY"] = TypeDescriptor{GitLabCheckDesc: "AWS access key", GitLabRemediation: "Remove AWS credentials immediately and rotate them. Use IAM roles or environment variables instead."}
	m["GITHUB_TOKEN"] = TypeDescriptor{GitLabCheckDesc: "GitHub token", GitLabRemediation: "Remove GitHub tokens and regenerate them. Use GitHub Actions secrets or environment variables instead."}
	m["SLACK_TOKEN"] = TypeDescriptor{GitLabCheckDesc: "Slack token"}
	m["GPS"] = TypeDescriptor{GitLabCheckDesc: "GPS coordinates", GitLabRemediation: "Remove GPS coordinates or replace with approximate/example coordinates if location data is needed for testing."}
	m["SOCIAL_MEDIA_CLUSTER"] = TypeDescriptor{GitLabCheckDesc: "Social media information"}
	m["PII_PERSON"] = TypeDescriptor{GitLabCheckDesc: "Personal information", GitLabRemediation: "Remove personal information or replace with anonymized test data."}
	m["PII_LOCATION"] = TypeDescriptor{GitLabCheckDesc: "Location information"}
	m["PII_ORGANIZATION"] = TypeDescriptor{GitLabCheckDesc: "Organization information"}
	m["DOCUMENT_COMMENTS"] = TypeDescriptor{GitLabCheckDesc: "Document comments"}
	m["AUTHOR_INFO"] = TypeDescriptor{GitLabCheckDesc: "Author information"}
	m["COMPANY_INFO"] = TypeDescriptor{GitLabCheckDesc: "Company information"}

	// --- gitlab-sast vulnerability display names (name tier, gap 3.3) ---
	// Verbatim from gitlab-sast/mapper.go generateVulnerabilityName's nameMap,
	// keyed by validator name. Applied as an overlay so a key can carry both a
	// GitLabCheckDesc (above) and a GitLabName without re-listing. Keys absent
	// here (incl. all sub-types) keep the mapper's strings.Title fallback.
	gitlabNames := map[string]string{
		"CREDIT_CARD":           "Credit Card Number Detected",
		"SSN":                   "Social Security Number Detected",
		"PASSPORT":              "Passport Number Detected",
		"EMAIL":                 "Email Address Detected",
		"PHONE":                 "Phone Number Detected",
		"IP_ADDRESS":            "IP Address Detected",
		"SECRETS":               "Secret/API Key Detected",
		"INTELLECTUAL_PROPERTY": "Intellectual Property Detected",
		"SOCIAL_MEDIA":          "Social Media Handle Detected",
		"VIN":                   "Vehicle Identification Number Detected",
		"METADATA":              "Sensitive Metadata Detected",
	}

	// --- SARIF copy for the types that previously fell back to the generic
	// "Sensitive data of type X was detected in the scanned content" (#662).
	//
	// Fifteen of the 64 types KnownTypes() lists had bespoke SARIF copy; these are the
	// other 49. That generic string is the ENTIRE explanation a reviewer sees in a
	// code-scanning UI, and it was what an AWS secret access key, an IBAN and every
	// card brand except the CREDIT_CARD parent all got.
	//
	// Applied READ-MODIFY-WRITE, the same shape the gitlabNames loop below uses, and for
	// the same reason: it can only ever SET the three SARIF fields. A first attempt
	// rewrote each m["X"] = TypeDescriptor{...} literal instead and silently dropped
	// existing gitlab copy — it found 6 types with gitlab fields by pattern-matching the
	// source when there are actually 20, because several are assigned in a loop rather
	// than as a literal (the card brands share one remediation string). TestTypeMeta_
	// KnownTypesResolve caught it. Reading a field back out of the map cannot make that
	// mistake.
	//
	// SARIFSensitivityWeight is deliberately NOT set here, so it keeps its existing
	// value — 0 for these types, which the SARIF mapper turns into its 5.0 default and
	// hence an unchanged rank. Choosing per-type weights is a scoring judgement, and
	// bundling it into a documentation change would hide it.
	//
	// GitLab fields are likewise untouched: gitlab-sast output is byte-identical after
	// this change. Writing gitlab copy for these types is worth doing and is a separate
	// change, because its remediation strings have a different audience and the existing
	// asymmetry (SLACK_TOKEN has a description but no remediation) is deliberate.
	for k, c := range map[string]struct{ short, full, help string }{
		"ABA_ROUTING": {
			short: "ABA Routing Number Detected",
			full:  "A nine-digit ABA routing number was detected. It falls in an assigned Federal Reserve prefix range and passes the ABA check-digit formula, so it identifies a real US financial institution. A routing number alone is not secret — banks publish theirs — but paired with an account number it is everything needed to originate an ACH debit.",
			help:  "Check whether an account number appears nearby: the PAIR is the disclosure, and this tool reports US_BANK_ACCOUNT separately. A routing number on its own in a payment integration is usually legitimate configuration, but it should still come from a secret store rather than a committed file, so a change of banking partner does not require a code change.",
		},
		"AMERICAN_EXPRESS": {
			short: "American Express Card Number Detected",
			full:  "A payment card number in the American Express range was detected. It passed the Luhn check digit and its issuer identification number (IIN) is one American Express issues, and it is 15 digits rather than 16. Primary account numbers are cardholder data under PCI DSS and must not be stored in source, logs or configuration.",
			help:  "If this is a real card number, treat it as a PCI DSS incident: remove it from the file AND from version-control history, then have the card reissued, because history rewriting does not recall a number an attacker may already have cloned. If it is test data, use the brand's published test numbers, which are Luhn-valid but declined by every processor.",
		},
		"API_KEY_OR_SECRET": {
			short: "API Key or Secret Detected",
			full:  "A value in the shape of an API key or shared secret was detected, assigned to a name that indicates it is a credential. The specific service is not identified, so the scope of access cannot be inferred from the value alone.",
			help:  "Identify the service from the surrounding code before deciding urgency; a generic match can be anything from a public analytics key to an administrative token. If it grants access, revoke and reissue it, then load it from a secret manager or environment variable at runtime.",
		},
		"APPLE_CORPORATE": {
			short: "Apple Corporate Email Address Detected",
			full:  "An email address on an Apple corporate domain was detected.",
			help:  "Treat as a business address: identifies a person and their employer, is a phishing target, and does not belong in committed fixtures. Use the reserved example.com domain instead.",
		},
		"APPLICATION_INFO": {
			short: "Authoring Application Metadata Detected",
			full:  "Application metadata was detected in a document's properties, recording the software and often the exact version used to create the file.",
			help:  "Not personal data, but useful to an attacker: a precise application version narrows which known vulnerabilities apply to the sender's environment, and a fleet-wide version tells them what to target. Strip document properties on external publication.",
		},
		"AUTHOR_INFO": {
			short: "Document Author Metadata Detected",
			full:  "Author metadata was detected in a document's properties. This field survives copying, emailing and conversion, and it records who created the file rather than anything visible in its contents.",
			help:  "The risk is that it is invisible: a document reviewed for content still carries the author's name, and in many organisations that is a username. Strip document properties before publishing externally — most office suites offer a document inspector for exactly this.",
		},
		"AWS_ACCESS_KEY": {
			short: "AWS Access Key ID Detected",
			full:  "An AWS access key ID was detected. The ID is not itself a secret, but it identifies a specific IAM principal and is half of a long-lived credential pair — so its presence indicates long-lived keys are in use, and the matching secret access key is often nearby or in the same history.",
			help:  "Search the file and the repository history for the matching secret access key; a key ID with its secret is a usable credential. Prefer eliminating the credential class rather than rotating it: IAM roles, instance profiles or IAM Roles Anywhere remove the long-lived pair entirely. If the pair was exposed, deactivate the key and review CloudTrail for use you did not authorise.",
		},
		"AWS_SECRET_ACCESS_KEY": {
			short: "AWS Secret Access Key Detected",
			full:  "An AWS secret access key was detected. This is the secret half of a long-lived AWS credential pair and grants every permission attached to its IAM principal, for as long as the key stays active.",
			help:  "Treat this as an active compromise, not a hygiene issue. Deactivate and delete the key immediately, then review CloudTrail for unauthorised use — an exposed key is typically exercised within minutes of reaching a public repository. Replace it with a role rather than a new key pair.",
		},
		"BUSINESS": {
			short: "Business Email Address Detected",
			full:  "An email address on a domain that is not a known consumer, disposable, educational or government provider was detected — so it is most likely a corporate or organisational address. A business address identifies both a person and their employer.",
			help:  "Business addresses are frequently published, which lowers the confidentiality concern, but they are the primary target for phishing and credential stuffing, so a harvested list has real value. Remove them from committed fixtures; use the reserved example.com domain instead.",
		},
		"COMPANY_INFO": {
			short: "Company Metadata Detected",
			full:  "Company metadata was detected in a document's properties, recording the organisation configured in the authoring application.",
			help:  "Usually low sensitivity, since the company is often obvious from the document itself. It matters when a document is meant to be attributable to someone else — a white-labelled report, or a template reused by a partner — where the metadata contradicts the visible branding.",
		},
		"DATE_OF_BIRTH": {
			short: "Date of Birth Detected",
			full:  "A date of birth was detected, labelled as such by nearby text rather than inferred from the digits — any date can look like a birth date, so the label is what makes this a finding. Date of birth is a quasi-identifier: weak alone, but combined with a name or postcode it identifies most people uniquely.",
			help:  "Judge this by what it sits beside. A birth date in a record with a name, address or member ID is a re-identification risk and often the field that makes a dataset personal data. If the data must be retained, consider storing only the year, or an age band, which usually serves the same purpose.",
		},
		"DEA_NUMBER": {
			short: "DEA Registration Number Detected",
			full:  "A DEA registration number was detected and it passes the DEA check-digit rule. It identifies a practitioner authorised to prescribe controlled substances.",
			help:  "A DEA number is used to write prescriptions, so exposure enables prescription fraud in the practitioner's name — a different risk from ordinary PII, and one the practitioner will want to know about. Remove it and notify the registrant if it was exposed.",
		},
		"DINERS_CLUB": {
			short: "Diners Club Card Number Detected",
			full:  "A payment card number in the Diners Club range was detected. It passed the Luhn check digit and its issuer identification number (IIN) is one Diners Club issues, which is 14 digits. Primary account numbers are cardholder data under PCI DSS and must not be stored in source, logs or configuration.",
			help:  "If this is a real card number, treat it as a PCI DSS incident: remove it from the file AND from version-control history, then have the card reissued, because history rewriting does not recall a number an attacker may already have cloned. If it is test data, use the brand's published test numbers, which are Luhn-valid but declined by every processor.",
		},
		"DISCOVER": {
			short: "Discover Card Number Detected",
			full:  "A payment card number in the Discover range was detected. It passed the Luhn check digit and its issuer identification number (IIN) is one Discover issues. Primary account numbers are cardholder data under PCI DSS and must not be stored in source, logs or configuration.",
			help:  "If this is a real card number, treat it as a PCI DSS incident: remove it from the file AND from version-control history, then have the card reissued, because history rewriting does not recall a number an attacker may already have cloned. If it is test data, use the brand's published test numbers, which are Luhn-valid but declined by every processor.",
		},
		"DISPOSABLE": {
			short: "Disposable Email Address Detected",
			full:  "An email address on a known disposable or temporary-mail provider was detected. These mailboxes are created to receive a single message and are often publicly readable by anyone who knows the address.",
			help:  "Low privacy sensitivity — the mailbox is intended to be throwaway — but a strong signal for abuse detection: disposable addresses in a user table usually mean sign-up abuse, trial farming or bypassed verification. Worth reviewing as a fraud indicator rather than a data-protection one.",
		},
		"DOCKER_TOKEN": {
			short: "Docker Registry Token Detected",
			full:  "A Docker registry credential was detected. It authenticates pushes and pulls for a registry namespace.",
			help:  "A push credential is a supply-chain risk: an attacker who can push a tag can have it deployed by anything that pulls that tag. Revoke it in the registry, then use a short-lived token issued by CI, and pin images by digest so a replaced tag cannot silently change what you run.",
		},
		"DOCUMENT_COMMENTS": {
			short: "Document Comments Detected",
			full:  "Comments or tracked annotations were detected in a document. Comments are frequently invisible in the default view and are not removed by exporting or printing to PDF in every tool.",
			help:  "Comments are where the candid content lives: pricing rationale, negotiating positions, names of individuals, and text deleted from the visible document. Review them explicitly, then accept or remove all tracked changes and delete all comments before sending a document outside the organisation.",
		},
		"DRIVERS_LICENSE": {
			short: "Driver's License Number Detected",
			full:  "A driver's license number was detected in a format one or more US states issue. State formats differ widely and most have no checksum, so a nearby state name or label is what raises confidence. A license number is a government identifier commonly accepted as proof of identity.",
			help:  "Treat as a government identifier: it is used for identity verification, so exposure supports identity theft rather than just profiling. Unlike a card it cannot be reissued quickly. Remove it, and prefer storing a verification RESULT rather than the number itself.",
		},
		"EDUCATIONAL": {
			short: "Educational Email Address Detected",
			full:  "An email address on an educational domain was detected. These identify a person and their institution, and frequently belong to students.",
			help:  "Student data attracts additional obligations in several jurisdictions — FERPA in the US, and age-related provisions elsewhere — so an educational address can raise the compliance bar above an ordinary business address. Confirm whether the dataset is subject to those rules.",
		},
		"GITHUB": {
			short: "GitHub Email Address Detected",
			full:  "An email address associated with GitHub — including the noreply forms GitHub issues for commit authorship — was detected.",
			help:  "A noreply address is designed to be public and needs no remediation; it exists so that commits do not expose a real mailbox. A non-noreply GitHub address should be treated as a business address. Check which form this is before acting.",
		},
		"GITHUB_TOKEN": {
			short: "GitHub Token Detected",
			full:  "A GitHub token was detected. Its prefix identifies it as a GitHub credential — personal access, OAuth, app installation or refresh — and the scopes attached to it determine what an attacker can read or push.",
			help:  "Assume the repositories and organisations that token can reach are compromised, including any CI secrets reachable from a workflow it can trigger. Revoke it in GitHub settings, then prefer a fine-grained token or a short-lived GITHUB_TOKEN supplied by Actions over a long-lived personal token. GitHub also scans public pushes and may have revoked it already.",
		},
		"GITLAB_TOKEN": {
			short: "GitLab Token Detected",
			full:  "A GitLab token was detected. Depending on type it may grant repository, registry, or full API access to a project or group for the life of the token.",
			help:  "Assume every project the token can reach is compromised, including package registries and CI variables. Revoke it in GitLab, then use a project access token with the narrowest scope, or a CI job token that expires with the job.",
		},
		"GMAIL": {
			short: "Gmail Address Detected",
			full:  "A Gmail address was detected. A consumer mailbox is personal data and, unlike a role address, it identifies an individual rather than a function.",
			help:  "Personal addresses carry more privacy weight than corporate ones: they usually persist for life and are reused across services, so they are effective join keys between datasets. Replace with example.com in fixtures and keep real addresses in a system with access control.",
		},
		"GOOGLE_CLOUD_API_KEY": {
			short: "Google Cloud API Key Detected",
			full:  "A Google Cloud API key was detected. API keys identify a project rather than a principal and are often unrestricted by default, so the same key may reach several enabled services.",
			help:  "Check the key's API and application restrictions in the console — an unrestricted key is usable by anyone who has the string. Regenerate it, then add both API restrictions and application restrictions, or replace it with a service account and Workload Identity where the calling service supports it.",
		},
		"GOVERNMENT": {
			short: "Government Email Address Detected",
			full:  "An email address on a government domain was detected. It identifies a public-sector employee and their agency.",
			help:  "Usually published, so rarely confidential in itself — but a government address is a high-value phishing target and its presence may indicate the surrounding data relates to public-sector work with its own handling rules. Remove from fixtures and use example.com.",
		},
		"IBAN": {
			short: "IBAN Detected",
			full:  "An International Bank Account Number was detected and it passes the ISO 13616 mod-97 checksum, so it is a structurally valid account identifier rather than a coincidental string. An IBAN names both the institution and the account, which is why it is used directly as a payment destination in SEPA and many other schemes.",
			help:  "An IBAN is a payment destination on its own — more directly actionable than a US routing number, which needs an account number beside it. Remove it from the file and supply it from a secret store. If it appeared in a public repository, tell the account holder: an IBAN is often all that is needed to initiate a direct debit.",
		},
		"IMAGE_METADATA": {
			short: "Image Metadata Detected",
			full:  "Metadata was detected in an image's EXIF, IPTC or XMP blocks. Depending on the capture device this can include GPS coordinates, a precise timestamp, a device serial number and the owner's name — none of it visible in the picture.",
			help:  "GPS coordinates are the field to check first: they can place a person at a location and time to within metres, and they survive most resizing and cropping. Strip metadata before publishing images, and be aware that a serial number links every photograph taken by the same camera.",
		},
		"INSURANCE_MEMBER_ID": {
			short: "Insurance Member ID Detected",
			full:  "A health insurance member identifier was detected. Formats are payer-specific with no common checksum, so this is a contextual match. A member ID is the key used to look up coverage and claims, which is why it is a frequent target for medical identity theft.",
			help:  "Treat as PHI. Confirm the match against surrounding text, since payer formats vary widely. Member IDs combined with a name and date of birth are enough to attempt fraudulent claims.",
		},
		"JCB": {
			short: "JCB Card Number Detected",
			full:  "A payment card number in the JCB range was detected. It passed the Luhn check digit and its issuer identification number (IIN) is one JCB issues. Primary account numbers are cardholder data under PCI DSS and must not be stored in source, logs or configuration.",
			help:  "If this is a real card number, treat it as a PCI DSS incident: remove it from the file AND from version-control history, then have the card reissued, because history rewriting does not recall a number an attacker may already have cloned. If it is test data, use the brand's published test numbers, which are Luhn-valid but declined by every processor.",
		},
		"JWT_TOKEN": {
			short: "JWT Detected Detected",
			full:  "A JSON Web Token was detected. The header and payload are base64url-encoded, not encrypted, so any claims inside — subject, email, roles, tenant — are readable by anyone holding the token. The signature does not protect confidentiality, only integrity.",
			help:  "Read the payload before judging severity: it may itself contain PII, and the token authenticates as its subject until it expires. If it is live, revoke the session or rotate the signing key, and shorten token lifetimes. Never commit tokens as fixtures — mint one at test time instead, since a committed token teaches readers that checking one into source is acceptable.",
		},
		"LAST_MODIFIED_BY": {
			short: "Last-Modified-By Metadata Detected",
			full:  "The last-modified-by property was detected in a document's metadata. It names the most recent editor, and because it updates on every save it often reveals a reviewer or approver who is not the stated author.",
			help:  "Frequently more revealing than the author field: it can expose who reviewed a document before release, and in a chain of edits it discloses internal workflow. Strip document properties before publishing.",
		},
		"MASTERCARD": {
			short: "Mastercard Card Number Detected",
			full:  "A payment card number in the Mastercard range was detected. It passed the Luhn check digit and its issuer identification number (IIN) is one Mastercard issues. Primary account numbers are cardholder data under PCI DSS and must not be stored in source, logs or configuration.",
			help:  "If this is a real card number, treat it as a PCI DSS incident: remove it from the file AND from version-control history, then have the card reissued, because history rewriting does not recall a number an attacker may already have cloned. If it is test data, use the brand's published test numbers, which are Luhn-valid but declined by every processor.",
		},
		"MEDICARE_MBI": {
			short: "Medicare Beneficiary Identifier Detected",
			full:  "A Medicare Beneficiary Identifier was detected and it matches the CMS format — eleven characters, position-specific letters and digits, with excluded letters that make coincidental matches unlikely. The MBI replaced the SSN-based HICN precisely so that a Medicare number would stop being an SSN, but it remains PHI and directly identifies a beneficiary.",
			help:  "Treat this as PHI under HIPAA. Remove it from the file and check whether it needs to be reported as a disclosure under your breach-assessment process; an MBI plus a name or date of birth is a strong identification.",
		},
		"MRN": {
			short: "Medical Record Number Detected",
			full:  "A Medical Record Number was detected. MRNs are assigned per institution with no national format or checksum, so this is a contextual match — a nearby label is what distinguishes it from any other identifier. Within its issuing organisation an MRN is a direct patient key.",
			help:  "Treat as PHI. Because MRNs have no standard format, confirm the finding against the surrounding text before acting. An MRN is only meaningful to the issuing institution, which limits external misuse but not internal over-exposure.",
		},
		"NPI": {
			short: "National Provider Identifier Detected",
			full:  "A ten-digit National Provider Identifier was detected and it passes the CMS Luhn check. An NPI identifies a healthcare provider and is published in the NPPES public registry, so the number itself is not confidential — but it is a strong link between a record and a named clinician, which makes surrounding patient data far easier to attribute.",
			help:  "Lower urgency than patient identifiers, because the NPI is public. What matters is context: an NPI beside diagnoses, dates of service or patient identifiers turns a de-identified record into an attributable one, which affects whether a dataset still counts as de-identified.",
		},
		"OTPAUTH_URI": {
			short: "OTP Provisioning URI Detected",
			full:  "An otpauth:// provisioning URI was detected. This is the payload behind an authenticator QR code and it carries the shared TOTP secret in its query string, so it is enough to enrol a new device and generate valid codes indefinitely.",
			help:  "Treat it as a second-factor compromise: anyone with this URI can produce the same codes as the legitimate authenticator, and the user gets no signal that they are doing so. Re-enrol the account, which issues a fresh secret and invalidates this one.",
		},
		"OTP_SECRET": {
			short: "OTP Shared Secret Detected",
			full:  "A TOTP or HOTP shared secret was detected, typically base32-encoded. The secret is the entire basis of one-time-code generation: it does not expire and codes derived from it are indistinguishable from the legitimate user's.",
			help:  "Re-enrol the account so a new secret is issued. Storing a seed in source also means every environment that shares the file shares the second factor, which defeats per-user MFA.",
		},
		"PO_BOX": {
			short: "PO Box Address Detected",
			full:  "A Post Office box address was detected. A PO box is a mail destination rather than a dwelling, so it reveals less than a street address — but it is still a contactable location tied to whoever rents it.",
			help:  "Lower sensitivity than a residential street address. Treat it as contact information: fine in published material, not something to accumulate in logs or test fixtures alongside names.",
		},
		"RECOVERY_CODES": {
			short: "Account Recovery Codes Detected",
			full:  "Multi-factor recovery codes were detected. These are single-use bypasses for MFA, issued as a set, and each one is enough to complete an authentication without the second factor.",
			help:  "Recovery codes defeat the control that MFA exists to provide, so a leaked set reduces the account to password-only. Regenerate the codes, which invalidates the leaked set, and store them in a password manager rather than any file that could be committed or shared.",
		},
		"SLACK_TOKEN": {
			short: "Slack Token Detected",
			full:  "A Slack token was detected. Slack tokens read and post as the user or app they belong to, so message history, channel membership and files in scope are all reachable.",
			help:  "Message history is often the most sensitive thing an organisation has in one place — treat a leaked token as disclosure of everything the token could read. Rotate it in the Slack app configuration and review the audit log for API calls you did not make.",
		},
		"SSH_PRIVATE_KEY": {
			short: "SSH Private Key Detected",
			full:  "An SSH private key block was detected. If it is unencrypted — no passphrase — it is directly usable, and grants whatever access its matching public key has been authorised for on any host.",
			help:  "An unencrypted private key in a repository is a host-access credential, and the blast radius is every machine listing its public key in authorized_keys. Generate a new key pair, remove the old public key from every authorized_keys and deploy-key list, and keep private keys out of repositories entirely — use an agent or a certificate authority.",
		},
		"STRIPE_API_KEY": {
			short: "Stripe API Key Detected",
			full:  "A Stripe API key was detected. A live secret key can move money, read customer records and issue refunds; a restricted or test key is limited to what its configuration allows.",
			help:  "Check whether the prefix indicates a LIVE secret key — that is a financial and PII incident, not a hygiene one. Roll the key in the Stripe dashboard, which invalidates it immediately, then review recent API activity. Use restricted keys scoped to the endpoints a service actually calls.",
		},
		"SWIFT_BIC": {
			short: "SWIFT/BIC Code Detected",
			full:  "A SWIFT/BIC business identifier code was detected — eight or eleven characters naming a financial institution and optionally a branch. Unlike an account number a BIC is public directory information, so on its own it is low sensitivity; it matters as corroboration that surrounding text is banking data.",
			help:  "A BIC alone rarely needs remediation. Treat it as a signal to look for account identifiers nearby: an IBAN or account number on the same record is the actual disclosure. If this is payment configuration, it still belongs in deployment configuration rather than in source.",
		},
		"TEMPLATE_INFO": {
			short: "Document Template Metadata Detected",
			full:  "Template metadata was detected in a document's properties. It records the template the document was created from, frequently as a full filesystem path.",
			help:  "The path is the disclosure, not the template name: it can expose a username, an internal share name and a directory layout, all of which help an attacker map an internal environment. Strip document properties before publishing.",
		},
		"US_BANK_ACCOUNT": {
			short: "US Bank Account Number Detected",
			full:  "A US bank account number was detected. Account numbers have no checksum and no fixed length, so this is a contextual match — a nearby banking keyword is what distinguishes it from any other digit string. With a routing number it is sufficient to originate an ACH debit.",
			help:  "Confirm it against the surrounding text before acting, since account numbers cannot be validated structurally. If real, remove it and rotate the account if it has been exposed in a public repository; unlike a card, a bank account cannot be reissued quickly, so notify the account holder.",
		},
		"US_MILITARY_ADDRESS": {
			short: "US Military Address Detected",
			full:  "A US military address was detected — an APO, FPO or DPO destination with an AA, AE or AP state code. These route mail to service members abroad or afloat.",
			help:  "Handle with more care than an ordinary address, not less: a military address indicates the addressee's affiliation and can imply deployment or location, which is information about the person beyond their contact details.",
		},
		"US_RURAL_ROUTE": {
			short: "US Rural Route Address Detected",
			full:  "A US rural route or highway contract route address was detected. These identify a delivery route and box rather than a street, and are used where street addressing is absent.",
			help:  "Treat as a residential address. Rural routes cover sparsely populated areas, so a route and box number can be MORE identifying than a street address in a city, not less.",
		},
		"US_STREET_ADDRESS": {
			short: "US Street Address Detected",
			full:  "A US street address was detected — a number, a street name and a recognised street-type suffix. An address is personal data when it is a residence, and it is a strong quasi-identifier: address with a surname identifies a household.",
			help:  "Distinguish a residential address from a business one, which is usually published and needs no remediation. If residential, it is personal data under GDPR and CCPA and belongs in a system with access control, not in source or logs.",
		},
		"VISA": {
			short: "Visa Card Number Detected",
			full:  "A payment card number in the Visa range was detected. It passed the Luhn check digit and its issuer identification number (IIN) is one Visa issues. Primary account numbers are cardholder data under PCI DSS and must not be stored in source, logs or configuration.",
			help:  "If this is a real card number, treat it as a PCI DSS incident: remove it from the file AND from version-control history, then have the card reissued, because history rewriting does not recall a number an attacker may already have cloned. If it is test data, use the brand's published test numbers, which are Luhn-valid but declined by every processor.",
		},
	} {
		d := m[k] // zero value if k had no entry at all; existing entry otherwise
		d.SARIFShort = c.short
		d.SARIFFull = c.full
		d.SARIFHelp = c.help
		m[k] = d
	}

	// --- gitlab-sast copy, filling every gap rather than the ones #662 first noticed.
	//
	// The SARIF loop above closed 49 of 64. gitlab-sast was WORSE: 45 of 64 had no check
	// description and 49 had no remediation, including types that DID have SARIF copy
	// (PASSPORT, PERSON_NAME and all six cloud-resource identifiers). A gitlab consumer
	// therefore read "Sensitive data (X)" with a generic "Review the detected..." for
	// two-thirds of everything this tool reports.
	//
	// FILL-IF-EMPTY, not assign. Every one of the 20 pre-existing gitlab values is left
	// exactly as it was, including the card brands' shared remediation string, which is
	// assigned by a loop rather than a literal and is the value an earlier attempt at
	// this change silently clobbered.
	//
	// One deliberate behaviour change beyond filling gaps: types that had a description
	// but no remediation (SLACK_TOKEN, AUTHOR_INFO, COMPANY_INFO, DOCUMENT_COMMENTS) now
	// get one. That asymmetry came from the legacy maps this registry replaced rather
	// than from a decision -- a finding with no remediation tells a reviewer what was
	// found and nothing about what to do -- so TestTypeMeta_KnownTypesResolve is updated
	// with the reason rather than worked around.
	for k, c := range map[string]struct{ desc, rem string }{
		"ABA_ROUTING": {
			desc: "ABA routing number",
			rem:  "Move banking coordinates into configuration a deployment supplies. If an account number appears on the same record, treat the pair as a payment-credential exposure.",
		},
		"ALIBABA_ARN": {
			desc: "Alibaba Cloud resource identifier",
			rem:  "Remove the resource identifier and supply resource identifiers from deployment configuration. They name real infrastructure, which helps an attacker map an environment and target it directly.",
		},
		"AMERICAN_EXPRESS": {
			desc: "American Express card number",
			rem:  "Remove the card number and use the brand's published test PAN instead. If it is real, have the card reissued — scrubbing the file does not undo the exposure.",
		},
		"API_KEY_OR_SECRET": {
			desc: "API key or secret",
			rem:  "Revoke the credential first, then remove it from the file and from version-control history. Rewriting history does not un-disclose a secret that has already been fetched.",
		},
		"APPLE_CORPORATE": {
			desc: "Apple corporate email address",
			rem:  "Replace with an example.com address, as for any business email in a fixture.",
		},
		"APPLICATION_INFO": {
			desc: "Authoring application metadata",
			rem:  "Strip document properties. Precise version strings help an attacker select exploits for your environment.",
		},
		"AUTHOR_INFO": {
			desc: "Document author metadata",
			rem:  "Strip document properties before external publication. Author metadata survives copying and is not visible in the document body.",
		},
		"AWS_ACCESS_KEY": {
			desc: "AWS access key ID",
			rem:  "Revoke the credential first, then remove it from the file and from version-control history. Rewriting history does not un-disclose a secret that has already been fetched.",
		},
		"AWS_ARN": {
			desc: "AWS resource ARN",
			rem:  "Remove the ARN and supply resource identifiers from deployment configuration. They name real infrastructure, which helps an attacker map an environment and target it directly.",
		},
		"AWS_SECRET_ACCESS_KEY": {
			desc: "AWS secret access key",
			rem:  "Revoke the credential first, then remove it from the file and from version-control history. Rewriting history does not un-disclose a secret that has already been fetched.",
		},
		"AZURE_RESOURCE_ID": {
			desc: "Azure resource ID",
			rem:  "Remove the resource ID and supply resource identifiers from deployment configuration. They name real infrastructure, which helps an attacker map an environment and target it directly.",
		},
		"BUSINESS": {
			desc: "Business email address",
			rem:  "Replace with an address on the reserved example.com domain. Business addresses are the main target for phishing lists.",
		},
		"COMPANY_INFO": {
			desc: "Company metadata",
			rem:  "Low risk in general. Strip it when a document is meant to be attributed to another party.",
		},
		"DATE_OF_BIRTH": {
			desc: "Date of birth",
			rem:  "Remove or coarsen the date — a year or age band usually serves the purpose. Combined with a name it is enough to identify most individuals.",
		},
		"DEA_NUMBER": {
			desc: "DEA registration number",
			rem:  "Remove the DEA number and notify the registrant if it was exposed — the practical risk is prescription fraud in their name.",
		},
		"DINERS_CLUB": {
			desc: "Diners Club card number",
			rem:  "Remove the card number and use the brand's published test PAN instead. If it is real, have the card reissued — scrubbing the file does not undo the exposure.",
		},
		"DISCOVER": {
			desc: "Discover card number",
			rem:  "Remove the card number and use the brand's published test PAN instead. If it is real, have the card reissued — scrubbing the file does not undo the exposure.",
		},
		"DISPOSABLE": {
			desc: "Disposable email address",
			rem:  "Low privacy risk, but review as an abuse signal — disposable addresses in a user table usually indicate sign-up abuse.",
		},
		"DOCKER_TOKEN": {
			desc: "Docker registry token",
			rem:  "Revoke the credential first, then remove it from the file and from version-control history. Rewriting history does not un-disclose a secret that has already been fetched.",
		},
		"DOCUMENT_COMMENTS": {
			desc: "Document comments",
			rem:  "Review and delete comments and tracked changes before external distribution — they hold content that is not visible in the document body.",
		},
		"DRIVERS_LICENSE": {
			desc: "Driver's license number",
			rem:  "Remove the license number. Store the outcome of an identity check rather than the identifier, which cannot be reissued quickly.",
		},
		"EDUCATIONAL": {
			desc: "Educational email address",
			rem:  "Remove and check obligations: student data can attract FERPA or age-related requirements beyond ordinary personal data.",
		},
		"GCP_RESOURCE_NAME": {
			desc: "Google Cloud resource name",
			rem:  "Remove the resource name and supply resource identifiers from deployment configuration. They name real infrastructure, which helps an attacker map an environment and target it directly.",
		},
		"GITHUB": {
			desc: "GitHub email address",
			rem:  "A noreply form is intended to be public and needs no action. Treat any other GitHub address as a business email.",
		},
		"GITHUB_TOKEN": {
			desc: "GitHub token",
			rem:  "Revoke the credential first, then remove it from the file and from version-control history. Rewriting history does not un-disclose a secret that has already been fetched.",
		},
		"GITLAB_TOKEN": {
			desc: "GitLab token",
			rem:  "Revoke the credential first, then remove it from the file and from version-control history. Rewriting history does not un-disclose a secret that has already been fetched.",
		},
		"GMAIL": {
			desc: "Gmail address",
			rem:  "Replace with an example.com address. Personal mailboxes are long-lived and act as join keys across datasets.",
		},
		"GOOGLE_CLOUD_API_KEY": {
			desc: "Google Cloud API key",
			rem:  "Revoke the credential first, then remove it from the file and from version-control history. Rewriting history does not un-disclose a secret that has already been fetched.",
		},
		"GOVERNMENT": {
			desc: "Government email address",
			rem:  "Replace with example.com in fixtures. Government addresses are high-value phishing targets even when published.",
		},
		"IBAN": {
			desc: "IBAN",
			rem:  "Remove the IBAN and supply payment destinations from a secret store. An IBAN is directly actionable, so treat public exposure as an incident.",
		},
		"IBM_CRN": {
			desc: "IBM Cloud resource name (CRN)",
			rem:  "Remove the CRN and supply resource identifiers from deployment configuration. They name real infrastructure, which helps an attacker map an environment and target it directly.",
		},
		"IMAGE_METADATA": {
			desc: "Image metadata",
			rem:  "Strip EXIF/IPTC/XMP before publishing images. GPS coordinates and device serial numbers survive resizing and are invisible in the picture.",
		},
		"INSURANCE_MEMBER_ID": {
			desc: "Insurance member ID",
			rem:  "Remove the member ID and handle it as PHI. Verify the match — payer formats vary, so detection is contextual.",
		},
		"JCB": {
			desc: "JCB card number",
			rem:  "Remove the card number and use the brand's published test PAN instead. If it is real, have the card reissued — scrubbing the file does not undo the exposure.",
		},
		"JWT_TOKEN": {
			desc: "JSON Web Token",
			rem:  "Revoke the credential first, then remove it from the file and from version-control history. Rewriting history does not un-disclose a secret that has already been fetched.",
		},
		"LAST_MODIFIED_BY": {
			desc: "Last-modified-by metadata",
			rem:  "Strip document properties before publication — this field can disclose reviewers and internal workflow.",
		},
		"MASTERCARD": {
			desc: "Mastercard card number",
			rem:  "Remove the card number and use the brand's published test PAN instead. If it is real, have the card reissued — scrubbing the file does not undo the exposure.",
		},
		"MEDICARE_MBI": {
			desc: "Medicare Beneficiary Identifier",
			rem:  "Remove the MBI and handle it as PHI under HIPAA, including a breach assessment if it was exposed outside its intended audience.",
		},
		"MRN": {
			desc: "Medical Record Number",
			rem:  "Remove the MRN and handle it as PHI. Confirm the match first — MRNs have no standard format, so detection is contextual.",
		},
		"NPI": {
			desc: "National Provider Identifier",
			rem:  "Public in the NPPES registry, so rarely a disclosure alone. Review whether it re-identifies patient data held nearby.",
		},
		"OCI_OCID": {
			desc: "Oracle Cloud identifier (OCID)",
			rem:  "Remove the OCID and supply resource identifiers from deployment configuration. They name real infrastructure, which helps an attacker map an environment and target it directly.",
		},
		"OTPAUTH_URI": {
			desc: "OTP provisioning URI",
			rem:  "Re-enrol the account to issue a new TOTP secret. The URI contains the shared secret, so it is a second-factor compromise rather than a configuration nit.",
		},
		"OTP_SECRET": {
			desc: "OTP shared secret",
			rem:  "Re-enrol to issue a new secret, and keep seeds in a secret manager. A committed seed makes the second factor shared rather than per-user.",
		},
		"PASSPORT": {
			desc: "Passport number",
			rem:  "Remove the passport number. It is a government identity document number, cannot be reissued quickly, and supports identity theft rather than just profiling.",
		},
		"PERSON_NAME": {
			desc: "Person name",
			rem:  "Replace real names with obviously fictional ones. A name is a weak identifier alone but combines with a date of birth or address to identify an individual.",
		},
		"PO_BOX": {
			desc: "PO Box address",
			rem:  "Usually lower risk than a street address. Avoid pairing it with names in logs or fixtures.",
		},
		"RECOVERY_CODES": {
			desc: "MFA recovery codes",
			rem:  "Revoke the credential first, then remove it from the file and from version-control history. Rewriting history does not un-disclose a secret that has already been fetched.",
		},
		"SLACK_TOKEN": {
			desc: "Slack token",
			rem:  "Revoke the credential first, then remove it from the file and from version-control history. Rewriting history does not un-disclose a secret that has already been fetched.",
		},
		"SSH_PRIVATE_KEY": {
			desc: "SSH private key",
			rem:  "Revoke the credential first, then remove it from the file and from version-control history. Rewriting history does not un-disclose a secret that has already been fetched.",
		},
		"STRIPE_API_KEY": {
			desc: "Stripe API key",
			rem:  "Revoke the credential first, then remove it from the file and from version-control history. Rewriting history does not un-disclose a secret that has already been fetched.",
		},
		"SWIFT_BIC": {
			desc: "SWIFT/BIC code",
			rem:  "Usually benign on its own — check for an account number or IBAN nearby, which would be the real disclosure. Keep payment configuration out of source.",
		},
		"TEMPLATE_INFO": {
			desc: "Document template metadata",
			rem:  "Strip document properties. Template paths often expose usernames and internal share layout.",
		},
		"US_BANK_ACCOUNT": {
			desc: "US bank account number",
			rem:  "Remove the account number and supply banking details at deployment time. Account numbers cannot be validated structurally, so confirm the finding before closing it.",
		},
		"US_MILITARY_ADDRESS": {
			desc: "US military address (APO/FPO/DPO)",
			rem:  "Remove military addresses. They disclose affiliation and can imply deployment, beyond ordinary contact information.",
		},
		"US_RURAL_ROUTE": {
			desc: "US rural route address",
			rem:  "Treat as residential. In sparsely populated areas a route and box number is highly identifying.",
		},
		"US_STREET_ADDRESS": {
			desc: "US street address",
			rem:  "Remove residential addresses; business addresses are usually public. Address plus surname identifies a household.",
		},
		"VISA": {
			desc: "Visa card number",
			rem:  "Remove the card number and use the brand's published test PAN instead. If it is real, have the card reissued — scrubbing the file does not undo the exposure.",
		},
	} {
		d := m[k]
		if d.GitLabCheckDesc == "" {
			d.GitLabCheckDesc = c.desc
		}
		if d.GitLabRemediation == "" {
			d.GitLabRemediation = c.rem
		}
		m[k] = d
	}

	for k, name := range gitlabNames {
		d := m[k] // zero value if k had no SARIF/sensitivity entry
		d.GitLabName = name
		m[k] = d
	}

	return m
}()

// TypeMeta returns the descriptor for a Match.Type and whether the type has any
// registry entry. Callers should gate on the SPECIFIC field they consume (e.g.
// SARIFShort != "") and keep their own fallback when it is empty — see
// TypeDescriptor.
func TypeMeta(t string) (TypeDescriptor, bool) {
	d, ok := typeDescriptors[t]
	return d, ok
}

// knownDetectionTypes is every detection type this tool can put in a report.
//
// It exists because a SARIF rule carries a helpUri, and a helpUri has to point at
// something. Measured by scanning this repository with every check enabled: 59 rules
// were emitted and ALL 59 helpUris were 404 -- they pointed into docs/checks/, a
// directory that has never existed. Every finding in every SARIF report a consumer
// has opened carried a dead documentation link.
//
// Deliberately SEPARATE from typeDescriptors. That map means "this type has bespoke
// per-formatter copy", and only 24 of these 59 do; the rest fall back to the generic
// SARIF description, which is existing correct behaviour this list does not change.
// Conflating the two would mean either inventing prose for 35 types or leaving them
// undocumented. Membership here means only "the tool can emit it, so
// docs/checks.md must carry an anchor for it".
//
// Derived by enumerating the rules the tool ACTUALLY emitted, not by reading
// validator source: sub-types are what reach a report (a credit card emits VISA; a
// bank account emits ABA_ROUTING / IBAN / SWIFT_BIC / US_BANK_ACCOUNT), and those
// are the strings the helpUri is built from. TestEveryEmittedTypeIsKnown keeps the
// list honest against real scan output.
var knownDetectionTypes = []string{
	"APPLICATION_INFO",  // METADATA sub-type; absent from the first draft of this list
	"AUTHOR_INFO",       // METADATA sub-type; absent from the first draft of this list
	"COMPANY_INFO",      // METADATA sub-type; absent from the first draft of this list
	"LAST_MODIFIED_BY",  // METADATA sub-type; absent from the first draft of this list
	"TEMPLATE_INFO",     // METADATA sub-type; absent from the first draft of this list
	"ABA_ROUTING",       // generic SARIF copy today
	"ALIBABA_ARN",       // generic SARIF copy today
	"AMERICAN_EXPRESS",  // generic SARIF copy today
	"API_KEY_OR_SECRET", // generic SARIF copy today
	"APPLE_CORPORATE",   // generic SARIF copy today
	"AWS_ACCESS_KEY",
	"AWS_ARN",               // generic SARIF copy today
	"AWS_SECRET_ACCESS_KEY", // generic SARIF copy today
	"AZURE_RESOURCE_ID",     // generic SARIF copy today
	"BUSINESS",              // generic SARIF copy today
	"CREDIT_CARD",
	"DATE_OF_BIRTH", // generic SARIF copy today
	"DEA_NUMBER",    // generic SARIF copy today
	"DINERS_CLUB",   // generic SARIF copy today
	"DISCOVER",      // generic SARIF copy today
	"DISPOSABLE",    // generic SARIF copy today
	"DOCKER_TOKEN",  // generic SARIF copy today
	"DOCUMENT_COMMENTS",
	"DRIVERS_LICENSE", // generic SARIF copy today
	"EDUCATIONAL",     // generic SARIF copy today
	"EMAIL",
	"GCP_RESOURCE_NAME", // generic SARIF copy today
	"GITHUB",            // generic SARIF copy today
	"GITHUB_TOKEN",
	"GITLAB_TOKEN",         // generic SARIF copy today
	"GMAIL",                // generic SARIF copy today
	"GOOGLE_CLOUD_API_KEY", // generic SARIF copy today
	"GOVERNMENT",           // generic SARIF copy today
	"IBAN",                 // generic SARIF copy today
	"IBM_CRN",              // generic SARIF copy today
	"IMAGE_METADATA",       // generic SARIF copy today
	"INSURANCE_MEMBER_ID",  // generic SARIF copy today
	"INTELLECTUAL_PROPERTY",
	"IP_ADDRESS",
	"JCB",          // generic SARIF copy today
	"JWT_TOKEN",    // generic SARIF copy today
	"MASTERCARD",   // generic SARIF copy today
	"MEDICARE_MBI", // generic SARIF copy today
	"MRN",          // generic SARIF copy today
	"NPI",          // generic SARIF copy today
	"OCI_OCID",     // generic SARIF copy today
	"OTPAUTH_URI",  // generic SARIF copy today
	"OTP_SECRET",   // generic SARIF copy today
	"PASSPORT",
	"PERSON_NAME",
	"PHONE",
	"PO_BOX",         // generic SARIF copy today
	"RECOVERY_CODES", // generic SARIF copy today
	"SLACK_TOKEN",
	"SSH_PRIVATE_KEY", // generic SARIF copy today
	"SSN",
	"STRIPE_API_KEY",      // generic SARIF copy today
	"SWIFT_BIC",           // generic SARIF copy today
	"US_BANK_ACCOUNT",     // generic SARIF copy today
	"US_MILITARY_ADDRESS", // generic SARIF copy today
	"US_RURAL_ROUTE",      // generic SARIF copy today
	"US_STREET_ADDRESS",   // generic SARIF copy today
	"VIN",
	"VISA", // generic SARIF copy today
}

// KnownTypes returns every detection type this tool can report, sorted.
//
// Exported so the documentation page and the SARIF rule builder are driven by the
// SAME list. A type that can be reported but has no documentation anchor is a link
// that 404s, which is precisely what this list exists to make impossible.
func KnownTypes() []string {
	out := make([]string, len(knownDetectionTypes))
	copy(out, knownDetectionTypes)
	sort.Strings(out)
	return out
}

// knownTypeSet is knownDetectionTypes as a set, built once.
var knownTypeSet = func() map[string]bool {
	m := make(map[string]bool, len(knownDetectionTypes))
	for _, t := range knownDetectionTypes {
		m[t] = true
	}
	return m
}()

// IsKnownType reports whether t is a detection type documented in docs/checks.md.
//
// The SARIF rule builder uses this to decide whether to append an anchor to a
// finding's helpUri. It is deliberately the only consumer that needs to care: an
// unknown type still gets a URI pointing at a committed page, so an incomplete list
// costs anchor precision and never link validity.
func IsKnownType(t string) bool { return knownTypeSet[t] }

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package core

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

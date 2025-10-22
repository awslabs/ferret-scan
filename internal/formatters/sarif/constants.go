// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package sarif

// SARIF specification constants
const (
	// SARIFSchemaURL is the URL to the SARIF 2.1.0 JSON schema
	SARIFSchemaURL = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/refs/heads/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

	// SARIFVersion is the SARIF specification version
	SARIFVersion = "2.1.0"
)

// Tool metadata constants
const (
	// ToolName is the name of the ferret-scan tool
	ToolName = "Ferret Scan"

	// ToolInformationURI is the URL to the ferret-scan repository
	ToolInformationURI = "https://github.com/awslabs/ferret-scan"
)

// SARIF level constants
const (
	// LevelError indicates a serious issue that should be addressed
	LevelError = "error"

	// LevelWarning indicates a potential issue
	LevelWarning = "warning"

	// LevelNote indicates an informational message
	LevelNote = "note"

	// LevelNone indicates a suppressed result
	LevelNone = "none"
)

// SARIF suppression kind constants
const (
	// SuppressionKindInSource indicates the suppression is defined in source code
	SuppressionKindInSource = "inSource"

	// SuppressionKindExternal indicates the suppression is defined externally
	SuppressionKindExternal = "external"
)

// RuleDescription contains the description information for a detection rule
type RuleDescription struct {
	Short string
	Full  string
	Help  string
}

// RuleDescriptions maps detection types to their rule descriptions
var RuleDescriptions = map[string]RuleDescription{
	"EMAIL": {
		Short: "Email Address Detected",
		Full:  "An email address was detected in the scanned content. Email addresses can be considered personally identifiable information (PII) and may need to be protected depending on your compliance requirements.",
		Help:  "Email addresses can be considered PII in many regulatory frameworks (GDPR, CCPA, etc.). Consider whether this email address should be present in the code or if it should be stored in a secure configuration system. If this is a test email or example, consider using example.com domain or clearly marking it as test data.",
	},
	"SSN": {
		Short: "Social Security Number Detected",
		Full:  "A Social Security Number (SSN) pattern was detected in the scanned content. SSNs are highly sensitive personally identifiable information (PII) that must be protected under various regulations.",
		Help:  "Social Security Numbers are protected under numerous regulations including GDPR, HIPAA, and various state privacy laws. SSNs should never be stored in source code, configuration files, or logs. Remove this SSN immediately and ensure it is stored in a secure, encrypted system with appropriate access controls. Consider implementing tokenization or other data protection mechanisms.",
	},
	"CREDIT_CARD": {
		Short: "Credit Card Number Detected",
		Full:  "A credit card number pattern was detected in the scanned content. Credit card numbers are sensitive financial information that must be protected under PCI DSS and other regulations.",
		Help:  "Credit card numbers must be protected according to PCI DSS requirements. They should never be stored in source code, logs, or unencrypted databases. Remove this credit card number immediately and ensure any payment processing uses PCI-compliant systems. Consider using tokenization services provided by payment processors.",
	},
	"PHONE": {
		Short: "Phone Number Detected",
		Full:  "A phone number was detected in the scanned content. Phone numbers can be considered personally identifiable information (PII) depending on context and jurisdiction.",
		Help:  "Phone numbers may be considered PII under various privacy regulations. Evaluate whether this phone number should be present in the code. If it's for testing purposes, use clearly fake numbers (e.g., 555-0100 to 555-0199 in North America). For production use, store phone numbers in secure configuration systems with appropriate access controls.",
	},
	"IP_ADDRESS": {
		Short: "IP Address Detected",
		Full:  "An IP address was detected in the scanned content. IP addresses can be considered personally identifiable information under GDPR and other privacy regulations.",
		Help:  "IP addresses are considered personal data under GDPR and similar regulations. Evaluate whether this IP address should be hardcoded. Consider using configuration files, environment variables, or service discovery mechanisms instead. If this is for testing, clearly document it as test data.",
	},
	"PASSPORT": {
		Short: "Passport Number Detected",
		Full:  "A passport number pattern was detected in the scanned content. Passport numbers are highly sensitive personally identifiable information that must be protected.",
		Help:  "Passport numbers are protected under various privacy and identity theft prevention regulations. They should never be stored in source code or logs. Remove this passport number immediately and ensure it is stored in a secure, encrypted system with strict access controls and audit logging.",
	},
	"PERSON_NAME": {
		Short: "Person Name Detected",
		Full:  "A person's name was detected in the scanned content. Names are considered personally identifiable information (PII) under various privacy regulations.",
		Help:  "Person names are considered PII under GDPR, CCPA, and other privacy regulations. Evaluate whether this name should be present in the code. If it's test data, use clearly fictional names or anonymized identifiers. For production use, ensure names are stored securely with appropriate access controls and data retention policies.",
	},
	"SECRETS": {
		Short: "Secret or API Key Detected",
		Full:  "A potential secret, API key, password, or authentication token was detected in the scanned content. Exposed secrets can lead to unauthorized access and security breaches.",
		Help:  "Secrets, API keys, and passwords should never be stored in source code or version control. Remove this secret immediately and rotate it if it has been committed. Use secret management systems like AWS Secrets Manager, HashiCorp Vault, or environment variables for storing sensitive credentials. Implement pre-commit hooks to prevent future secret commits.",
	},
	"INTELLECTUAL_PROPERTY": {
		Short: "Potential Intellectual Property Detected",
		Full:  "Content that may contain intellectual property markers (copyright notices, trademarks, patents) was detected. This could indicate third-party IP that requires proper attribution or licensing.",
		Help:  "Ensure that any third-party intellectual property is properly licensed and attributed. Review your organization's policies on using external code and content. If this is your organization's IP, ensure proper copyright notices are in place. For third-party content, verify compliance with license terms.",
	},
	"METADATA": {
		Short: "Sensitive Metadata Detected",
		Full:  "Sensitive metadata was detected in file properties. This may include author names, organization information, document history, or other potentially sensitive information embedded in file metadata.",
		Help:  "File metadata can contain sensitive information that persists even when the visible content is sanitized. Review the detected metadata and determine if it should be removed. Consider using metadata scrubbing tools before sharing documents externally. Implement policies for metadata handling in your document management processes.",
	},
	"SOCIAL_MEDIA": {
		Short: "Social Media Handle Detected",
		Full:  "A social media handle or username was detected in the scanned content. Social media identifiers can be used to link to personal profiles and may be considered PII in some contexts.",
		Help:  "Social media handles can be used to identify individuals and may be considered personal information. Evaluate whether these handles should be present in the code. If they're for testing, use clearly fake handles. For production use, consider whether this information should be stored in a configuration system with appropriate access controls.",
	},
}

// GetRuleDescription returns the rule description for a given detection type
// If the type is not found, it returns a generic description
func GetRuleDescription(detectionType string) RuleDescription {
	if desc, exists := RuleDescriptions[detectionType]; exists {
		return desc
	}

	// Return generic description for unknown types
	return RuleDescription{
		Short: detectionType + " Detected",
		Full:  "Sensitive data of type " + detectionType + " was detected in the scanned content.",
		Help:  "Review this finding to determine if the detected data should be present in the code. Consider whether it should be stored in a secure configuration system instead.",
	}
}

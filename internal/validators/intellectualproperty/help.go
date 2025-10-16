// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package intellectualproperty

import "ferret-scan/internal/help"

// Ensure we're using the same Validator type defined in validator.go
// This is just a reference to make the compiler happy - no need to redefine all fields

// GetCheckInfo returns standardized information about this check
func (v *Validator) GetCheckInfo() help.CheckInfo {
	// Create a new CheckInfo struct
	info := help.CheckInfo{}

	// Set basic information
	info.Name = "INTELLECTUAL_PROPERTY"
	info.ShortDescription = "Detects intellectual property identifiers and references"
	info.DetailedDescription = `This validator detects various types of intellectual property references including:
- Patent numbers (US, EP, JP, CN, WO formats)
- Trademark symbols and references (™, ®, TM, R)
- Copyright notices (© symbol, year ranges, copyright statements)
- Trade secret and confidentiality markings
- Internal company URLs and domain patterns (requires configuration)

IMPORTANT: Internal URL detection requires explicit configuration in ferret.yaml.
Without configuration, only patents, trademarks, copyrights, and trade secrets will be detected.

The validator analyzes both the format of potential matches and their surrounding context
to determine the likelihood that they represent actual intellectual property references.`

	// Set patterns
	info.Patterns = []string{
		"Patent numbers (e.g., US9123456, US 9,123,456)",
		"Trademark symbols (™, ®) and references (TM, R)",
		"Copyright notices (© YYYY Company Name)",
		"Trade secret and confidentiality markings",
		"Internal company URLs and domain patterns",
	}

	// Set supported formats
	info.SupportedFormats = []string{
		"US, EP, JP, CN, WO patent number formats",
		"Trademark symbols (™, ®) and text references (TM, R)",
		"Copyright notices with year and owner information",
		"Confidentiality and trade secret markings",
		"Internal URL patterns (REQUIRES configuration in ferret.yaml)",
	}

	// Set confidence factors
	info.ConfidenceFactors = []help.ConfidenceFactor{
		{
			Name:        "Format Validation",
			Description: "Checks if the format matches expected patterns for IP references",
			Weight:      30,
		},
		{
			Name:        "Contextual Keywords",
			Description: "Analyzes surrounding text for IP-related terminology",
			Weight:      25,
		},
		{
			Name:        "Symbol Presence",
			Description: "Checks for official IP symbols (©, ™, ®)",
			Weight:      15,
		},
		{
			Name:        "Not Example/Test",
			Description: "Ensures the reference is not an example or test pattern",
			Weight:      20,
		},
		{
			Name:        "Specific Format Rules",
			Description: "Applies type-specific validation rules",
			Weight:      10,
		},
	}

	// Set keywords
	info.PositiveKeywords = v.positiveKeywords
	info.NegativeKeywords = v.negativeKeywords

	// Set configuration information
	info.ConfigurationInfo = "IMPORTANT: Internal URL detection requires explicit configuration. The validator no longer includes hardcoded patterns.\n\n" +
		"Custom internal URL patterns and intellectual property patterns can ONLY be configured through the ferret.yaml configuration file.\n\n" +
		"Configuration file example:\n" +
		"```\n" +
		"validators:\n" +
		"  intellectual_property:\n" +
		"    # Internal URL patterns to detect (REQUIRED for internal URL detection)\n" +
		"    internal_urls:\n" +
		"      - \"http[s]?:\\/\\/.*\\.internal\\.example\\.com\"\n" +
		"      - \"http[s]?:\\/\\/.*\\.corp\\.example\\.com\"\n" +
		"      - \"http[s]?:\\/\\/wiki\\.example\\.com\"\n" +
		"      # AWS patterns (if using AWS)\n" +
		"      - \"http[s]?:\\/\\/.*\\.s3\\.amazonaws\\.com\"\n" +
		"      # Azure patterns (if using Azure)\n" +
		"      - \"http[s]?:\\/\\/.*\\.blob\\.core\\.windows\\.net\"\n" +
		"      # GCP patterns (if using GCP)\n" +
		"      - \"http[s]?:\\/\\/.*\\.appspot\\.com\"\n" +
		"    \n" +
		"    # Custom intellectual property patterns (optional)\n" +
		"    intellectual_property_patterns:\n" +
		"      patent: \"\\b(US|EP|JP|CN|WO)[ -]?(\\d{1,3}[,.]?\\d{3}[,.]?\\d{3}|\\d{1,3}[,.]?\\d{3}[,.]?\\d{2}[A-Z]\\d?)\\b\"\n" +
		"      trademark: \"\\b(\\w+\\s*[™®]|\\w+\\s*\\(TM\\)|\\w+\\s*\\(R\\)|\\w+\\s+Trademark|\\w+\\s+Registered\\s+Trademark)\\b\"\n" +
		"      copyright: \"(©|\\(c\\)|\\(C\\)|Copyright|\\bCopyright\\b)\\s*\\d{4}[-,]?(\\d{4})?\\s+[A-Za-z0-9\\s\\.,]+\"\n" +
		"      trade_secret: \"\\b(Confidential|Trade\\s+Secret|Proprietary|Company\\s+Confidential|Internal\\s+Use\\s+Only|Restricted|Classified)\\b\"\n" +
		"```\n\n" +
		"To use a configuration file:\n" +
		"- Create a ferret.yaml file in your current directory\n" +
		"- Run ferret-scan with the --config flag: ferret-scan --config ferret.yaml --file document.txt\n" +
		"- Or use a specific profile: ferret-scan --config ferret.yaml --profile company-specific --file document.txt\n\n" +
		"Without configuration, internal URL detection will be disabled. Other IP types (patents, trademarks, copyrights, trade secrets) will still work.\n\n" +
		"See the documentation in docs/configuration.md and docs/INTERNAL_URL_MIGRATION_GUIDE.md for more details."

	// Set examples
	info.Examples = []string{
		"ferret-scan --file document.txt --checks INTELLECTUAL_PROPERTY",
		"ferret-scan --file document.txt --checks INTELLECTUAL_PROPERTY --confidence high",
		"ferret-scan --config ferret.yaml --file document.txt --checks INTELLECTUAL_PROPERTY",
		"ferret-scan --config ferret.yaml --profile company-specific --file document.txt",
		"ferret-scan --file contract.pdf --verbose --checks INTELLECTUAL_PROPERTY",
	}

	return info
}

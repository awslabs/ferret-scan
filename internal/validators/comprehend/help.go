// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package comprehend

// GENAI_DISABLED: This entire file has been disabled as part of GenAI feature removal
// The Validator type and AWS SDK v2 required for this functionality have been removed
// to reduce binary size and eliminate cloud service dependencies.

/*
import "ferret-scan/internal/help"

// GetCheckInfo returns help information for the Comprehend PII validator
func (v *Validator) GetCheckInfo() help.CheckInfo {
	return help.CheckInfo{
		Name:             "COMPREHEND_PII",
		ShortDescription: "AI-powered PII detection using Amazon Comprehend (GenAI mode)",
		DetailedDescription: `The Comprehend PII validator uses Amazon Comprehend's machine learning models to detect
personally identifiable information (PII) and protected health information (PHI) in text content.

This validator requires the --enable-genai flag and AWS credentials. It sends text content to
Amazon Comprehend service for analysis, which incurs AWS costs.

The validator can detect various types of sensitive information including:
- Social Security Numbers (SSN)
- Credit card numbers
- Email addresses and phone numbers
- Names and addresses
- AWS credentials
- Passport numbers
- Driver's license numbers
- And many other PII types

Results include confidence scores and risk level assessments.`,

		Patterns: []string{
			"SSN (Social Security Numbers)",
			"CREDIT_DEBIT_NUMBER (Credit/debit card numbers)",
			"EMAIL (Email addresses)",
			"PHONE (Phone numbers)",
			"NAME/PERSON (Personal names)",
			"ADDRESS (Physical addresses)",
			"DATE_TIME (Dates and times)",
			"AWS_ACCESS_KEY/AWS_SECRET_KEY (AWS credentials)",
			"PASSWORD (Passwords)",
			"PASSPORT (Passport numbers)",
			"DRIVER_ID (Driver's license numbers)",
			"PIN (Personal identification numbers)",
		},

		SupportedFormats: []string{
			"Text content from any file type",
			"Extracted text from PDFs, Office documents",
			"OCR text from images (when used with Textract)",
			"Plain text files",
		},

		ConfidenceFactors: []help.ConfidenceFactor{
			{
				Name:        "Comprehend ML Confidence",
				Description: "Amazon Comprehend's machine learning confidence score",
				Weight:      80.0,
			},
			{
				Name:        "PII Type Sensitivity",
				Description: "Adjustment based on sensitivity of detected PII type",
				Weight:      20.0,
			},
		},

		PositiveKeywords: []string{
			// Comprehend uses ML models, not keyword-based detection
		},

		NegativeKeywords: []string{
			// Comprehend uses ML models, not keyword-based detection
		},

		ConfigurationInfo: `The Comprehend PII validator is enabled with the --enable-genai flag and requires:

1. AWS credentials configured (aws configure, environment variables, or IAM role)
2. IAM permission: comprehend:DetectPiiEntities
3. Internet connection to AWS Comprehend service
4. AWS costs apply (~$0.0001 per 100 characters)

Configuration options:
- AWS region can be specified with --textract-region flag
- Validator is automatically enabled when --enable-genai is used

Cost considerations:
- Amazon Comprehend charges per 100-character unit
- Typical costs: $0.001 per 1000 characters
- Use --debug flag to see cost estimates`,

		Examples: []string{
			"ferret-scan --file document.txt --enable-genai --checks COMPREHEND_PII",
			"ferret-scan --file *.pdf --enable-genai --textract-region us-west-2",
			"ferret-scan --file sensitive-data.docx --enable-genai --debug",
			"ferret-scan --file scanned-forms.pdf --enable-genai --format json",
		},
	}
}
*/

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metadata

import "ferret-scan/internal/help"

// GetCheckInfo implements the HelpProvider interface
func (v *Validator) GetCheckInfo() help.CheckInfo {
	return help.CheckInfo{
		Name:             "METADATA",
		ShortDescription: "Detects PII and PHI in file metadata with preprocessor-aware validation",
		DetailedDescription: `The METADATA check extracts and analyzes metadata from various file types
to identify potential PII (Personally Identifiable Information) and PHI (Protected Health Information).

This enhanced validator uses preprocessor-aware validation to provide targeted detection
based on the specific type of metadata being processed:

IMAGE METADATA:
- GPS coordinates (latitude, longitude, altitude, GPS timestamps)
- Device information (camera make/model, serial numbers, device IDs)
- EXIF data containing personal information (artist, creator, copyright holder)
- Software paths containing usernames

DOCUMENT METADATA:
- Author and creator information (author, lastmodifiedby, manager)
- Personal comments and descriptions (comments, description, keywords)
- Copyright and ownership information
- Software paths containing usernames

AUDIO METADATA:
- Artist and performer identity (artist, performer, composer, conductor)
- Recording location and venue information
- Contact information (management, booking, social media)
- Copyright and label information (publisher, record label)
- ID3 tag fields containing personal information (TPE1-4)

VIDEO METADATA:
- GPS coordinates and location data (xyz coordinates, recording location)
- Device and camera information (camera make/model, recording device)
- Creator information (recorded by, director, producer, cinematographer)
- Copyright and production company information

The validator applies preprocessor-specific confidence scoring and validation patterns
to improve accuracy and reduce false positives.`,
		Patterns: []string{
			"Author/Creator information",
			"Email addresses",
			"GPS coordinates",
			"Phone numbers",
			"Copyright information",
			"Device identifiers",
			"Timestamps",
		},
		SupportedFormats: []string{
			"Images (JPG, PNG, GIF, TIFF, WebP)",
			"Videos (MP4, MOV, AVI, MKV)",
			"Audio (MP3, FLAC, WAV, OGG)",
			"Documents (PDF, DOCX, DOC)",
			"Spreadsheets (XLSX, XLS)",
		},
		ConfidenceFactors: []help.ConfidenceFactor{
			{
				Name:        "Preprocessor-Aware Validation",
				Description: "Applies specific validation patterns based on metadata source (image, document, audio, video)",
				Weight:      50,
			},
			{
				Name:        "GPS and Location Data",
				Description: "Identifies GPS coordinates and location information with enhanced altitude detection",
				Weight:      60,
			},
			{
				Name:        "Device Information",
				Description: "Detects camera, recording device, and hardware identifiers",
				Weight:      40,
			},
			{
				Name:        "Creator and Author Fields",
				Description: "Checks for author, creator, artist, or owner fields that may contain names",
				Weight:      30,
			},
			{
				Name:        "Contact Information",
				Description: "Identifies management, booking, and social media contact details",
				Weight:      50,
			},
			{
				Name:        "Comments and Descriptions",
				Description: "Analyzes user-generated comments and descriptions for sensitive content",
				Weight:      50,
			},
			{
				Name:        "Copyright and Rights",
				Description: "Identifies copyright and rights information that may contain personal/business details",
				Weight:      30,
			},
			{
				Name:        "Contextual Keywords",
				Description: "Analyzes surrounding text for privacy-related terms",
				Weight:      10,
			},
		},
		PositiveKeywords: []string{
			"personal", "private", "confidential", "sensitive", "contact",
			"address", "phone", "email", "name", "author", "owner", "copyright", "rights",
		},
		NegativeKeywords: []string{
			"example", "test", "sample", "demo", "placeholder",
			"anonymous", "unknown", "default", "template",
		},
		Examples: []string{
			// Image metadata examples
			"GPSLatitude: 40.7128",
			"Camera_Make: Canon",
			"Artist: John Smith Photography",
			"UserComment: Family vacation 2024",

			// Document metadata examples
			"Author: Jane Doe",
			"LastModifiedBy: john.smith@company.com",
			"Manager: Sarah Johnson",
			"Comments: Confidential client information",

			// Audio metadata examples
			"Artist: The Beatles",
			"Management: contact@beatlesmanagement.com",
			"Venue: Abbey Road Studios",
			"TPE1: John Lennon",

			// Video metadata examples
			"Recorded_By: David Smith",
			"Recording_Location: New York Studio",
			"xyz: +40.7128-074.0060+000.125/",
			"Camera_Model: Sony FX6",
		},
	}
}

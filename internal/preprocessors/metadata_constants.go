// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

// ProcessorType constants for specialized metadata preprocessors
const (
	ProcessorTypeImageMetadata  = "image_metadata"
	ProcessorTypePDFMetadata    = "pdf_metadata"
	ProcessorTypeOfficeMetadata = "office_metadata"
	ProcessorTypeAudioMetadata  = "audio_metadata"
	ProcessorTypeVideoMetadata  = "video_metadata"
)

// Format constants for processed content
const (
	FormatImageMetadata  = "image_metadata"
	FormatPDFMetadata    = "pdf_metadata"
	FormatOfficeMetadata = "office_metadata"
	FormatAudioMetadata  = "audio_metadata"
	FormatVideoMetadata  = "video_metadata"
)

// Preprocessor name constants
const (
	PreprocessorNameImage  = "image_metadata_preprocessor"
	PreprocessorNamePDF    = "pdf_metadata_preprocessor"
	PreprocessorNameOffice = "office_metadata_preprocessor"
	PreprocessorNameAudio  = "audio_metadata_preprocessor"
	PreprocessorNameVideo  = "video_metadata_preprocessor"
)

// File type constants for error handling and logging
const (
	FileTypeImage  = "image"
	FileTypePDF    = "pdf"
	FileTypeOffice = "office"
	FileTypeAudio  = "audio"
	FileTypeVideo  = "video"
)

// Common metadata field names for consistent formatting
const (
	MetadataFieldTitle              = "Title"
	MetadataFieldAuthor             = "Author"
	MetadataFieldSubject            = "Subject"
	MetadataFieldKeywords           = "Keywords"
	MetadataFieldCreator            = "Creator"
	MetadataFieldProducer           = "Producer"
	MetadataFieldCreationDate       = "CreationDate"
	MetadataFieldModificationDate   = "ModificationDate"
	MetadataFieldPageCount          = "PageCount"
	MetadataFieldWordCount          = "WordCount"
	MetadataFieldCharacterCount     = "CharacterCount"
	MetadataFieldDescription        = "Description"
	MetadataFieldCategory           = "Category"
	MetadataFieldApplication        = "Application"
	MetadataFieldApplicationVersion = "ApplicationVersion"
	MetadataFieldCompany            = "Company"
	MetadataFieldLastModifiedBy     = "LastModifiedBy"
	MetadataFieldManager            = "Manager"
	MetadataFieldComments           = "Comments"
	MetadataFieldContentStatus      = "ContentStatus"
	MetadataFieldIdentifier         = "Identifier"
	MetadataFieldLanguage           = "Language"
	MetadataFieldRevision           = "Revision"
	MetadataFieldPDFVersion         = "PDFVersion"
	MetadataFieldEncrypted          = "Encrypted"
)

// Date format constant for consistent date formatting
const (
	MetadataDateFormat = "2006:01:02 15:04:05-07:00"
)

// Common exclusion keys for properties formatting
var (
	CommonDateExclusionKeys = []string{
		"CreationDate",
		"ModificationDate",
	}
)

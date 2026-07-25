// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"github.com/awslabs/ferret-scan/v2/internal/preprocessors"
)

// RegisterDefaultPreprocessors registers all built-in preprocessors
func RegisterDefaultPreprocessors(router *FileRouter) {
	// Plain text preprocessor factory (highest priority for actual text files)
	router.RegisterPreprocessor("plaintext", func(config map[string]interface{}) preprocessors.Preprocessor {
		enableRedaction := true // Default to enabled for backward compatibility
		if val, ok := config["enable_redaction"].(bool); ok {
			enableRedaction = val
		}
		return preprocessors.NewPlainTextPreprocessorWithConfig(enableRedaction)
	})

	// Document text extractor factory (for binary documents like PDF, DOCX)
	router.RegisterPreprocessor("text", func(config map[string]interface{}) preprocessors.Preprocessor {
		return preprocessors.NewTextPreprocessor()
	})

	// Image metadata preprocessor factory (for EXIF data from images)
	router.RegisterPreprocessor("image_metadata", func(config map[string]interface{}) preprocessors.Preprocessor {
		processor := preprocessors.NewImageMetadataPreprocessor()
		// Set observer for debug logging
		if router.observer != nil {
			processor.SetObserver(router.observer)
		}
		return processor
	})

	// PDF metadata preprocessor factory (for PDF document metadata)
	router.RegisterPreprocessor("pdf_metadata", func(config map[string]interface{}) preprocessors.Preprocessor {
		processor := preprocessors.NewPDFMetadataPreprocessor()
		processor.SetRouter(router)
		// Set observer for debug logging
		if router.observer != nil {
			processor.SetObserver(router.observer)
		}
		return processor
	})

	// Office metadata preprocessor factory (for Office document metadata)
	router.RegisterPreprocessor("office_metadata", func(config map[string]interface{}) preprocessors.Preprocessor {
		processor := preprocessors.NewOfficeMetadataPreprocessor()
		processor.SetRouter(router)
		// Set observer for debug logging
		if router.observer != nil {
			processor.SetObserver(router.observer)
		}
		return processor
	})

	// Audio metadata preprocessor factory (for audio file metadata)
	router.RegisterPreprocessor("audio_metadata", func(config map[string]interface{}) preprocessors.Preprocessor {
		processor := preprocessors.NewAudioMetadataPreprocessor()
		// Set observer for debug logging
		if router.observer != nil {
			processor.SetObserver(router.observer)
		}
		return processor
	})

	// Video metadata preprocessor factory (for video file metadata)
	router.RegisterPreprocessor("video_metadata", func(config map[string]interface{}) preprocessors.Preprocessor {
		processor := preprocessors.NewVideoMetadataPreprocessor()
		processor.SetRouter(router)
		// Set observer for debug logging
		if router.observer != nil {
			processor.SetObserver(router.observer)
		}
		return processor
	})
}

// CreateRouterConfig creates the configuration map passed to preprocessor factories.
func CreateRouterConfig(enableRedaction bool) map[string]interface{} {
	return map[string]interface{}{
		"enable_redaction": enableRedaction,
	}
}

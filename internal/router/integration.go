// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"ferret-scan/internal/preprocessors"
)

// RegisterDefaultPreprocessors registers all built-in preprocessors
func RegisterDefaultPreprocessors(router *FileRouter) {
	// Plain text preprocessor factory (highest priority for actual text files)
	router.RegisterPreprocessor("plaintext", func(config map[string]interface{}) preprocessors.Preprocessor {
		return preprocessors.NewPlainTextPreprocessor()
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

	// GENAI_DISABLED: Textract preprocessor factory (GenAI)
	// router.RegisterPreprocessor("textract", func(config map[string]interface{}) preprocessors.Preprocessor {
	//	region := "us-east-1"
	//	if r, ok := config["genai_region"].(string); ok && r != "" {
	//		region = r
	//	}
	//
	//	enabled := false
	//	if genaiEnabled, ok := config["enable_genai"].(bool); ok {
	//		enabled = genaiEnabled
	//	}
	//
	//	if genaiServices, ok := config["genai_services"].(map[string]bool); ok {
	//		if textractEnabled, exists := genaiServices["textract"]; exists {
	//			enabled = enabled && textractEnabled
	//		}
	//	}
	//
	//	processor := preprocessors.NewTextractPreprocessor(region)
	//	processor.SetEnabled(enabled)
	//	return processor
	// })

	// GENAI_DISABLED: Transcribe preprocessor factory (GenAI)
	// router.RegisterPreprocessor("transcribe", func(config map[string]interface{}) preprocessors.Preprocessor {
	//	region := "us-east-1"
	//	if r, ok := config["genai_region"].(string); ok && r != "" {
	//		region = r
	//	}
	//
	//	enabled := false
	//	if genaiEnabled, ok := config["enable_genai"].(bool); ok {
	//		enabled = genaiEnabled
	//	}
	//
	//	if genaiServices, ok := config["genai_services"].(map[string]bool); ok {
	//		if transcribeEnabled, exists := genaiServices["transcribe"]; exists {
	//			enabled = enabled && transcribeEnabled
	//		}
	//	}
	//
	//	if enabled {
	//		processor := preprocessors.NewTranscribePreprocessor(region)
	//		// Set custom bucket if provided
	//		if bucket, ok := config["transcribe_bucket"].(string); ok && bucket != "" {
	//			processor.SetBucket(bucket)
	//		}
	//		return processor
	//	}
	//	return nil
	// })
}

// GENAI_DISABLED: CreateRouterConfig creates configuration map for preprocessors
func CreateRouterConfig(enableGenAI bool, genaiServices map[string]bool, genaiRegion string) map[string]interface{} {
	return map[string]interface{}{
		// GENAI_DISABLED: "enable_genai":   enableGenAI,
		// GENAI_DISABLED: "genai_services": genaiServices,
		// GENAI_DISABLED: "genai_region":   genaiRegion,
	}
}

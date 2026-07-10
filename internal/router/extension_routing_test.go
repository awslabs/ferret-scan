// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"testing"

	"github.com/awslabs/ferret-scan/internal/preprocessors"
)

// TestExtensionRouting_MatchesPreprocessorCapability is the drift guard (v2 gap
// 5.3): the routing gate (isBinaryDocument / getMetadataTypeForExtension) must
// never classify an extension as processable that NO registered preprocessor can
// actually handle. Before the fix, the router carried its own broader hardcoded
// list, so e.g. a .heic file passed the gate then hit a mid-pipeline
// "no preprocessor can handle file" error. Now both derive from the shared
// FileExtensionValidator, so the gate and the workers agree.
func TestExtensionRouting_MatchesPreprocessorCapability(t *testing.T) {
	fr := NewFileRouter(false)
	RegisterDefaultPreprocessors(fr)
	// Actually instantiate the preprocessors (registration only stores factories;
	// fr.preprocessors is empty until InitializePreprocessors runs) — mirrors
	// core.ScanFile's setup.
	fr.InitializePreprocessors(CreateRouterConfig(false, nil, "", false))

	// The full set the old router list claimed to support.
	exts := []string{
		".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".odt", ".ods", ".odp",
		".pdf",
		".jpg", ".jpeg", ".png", ".gif", ".tiff", ".tif", ".bmp", ".webp",
		".heic", ".heif", ".raw", ".cr2", ".nef", ".arw",
		".mp4", ".mov", ".avi", ".mkv", ".wmv", ".flv", ".webm", ".m4v", ".3gp", ".ogv",
		".mp3", ".flac", ".wav", ".ogg", ".m4a", ".aac", ".wma", ".opus",
	}

	for _, ext := range exts {
		gated := isBinaryDocument(ext)
		// Does any registered preprocessor actually accept this extension?
		probe := "sample" + ext
		canHandle := false
		for _, p := range fr.preprocessors {
			if p.CanProcess(probe) {
				canHandle = true
				break
			}
		}
		// The gate must not claim to process what nothing can handle, and must not
		// reject what a preprocessor can handle — they must agree exactly.
		if gated != canHandle {
			t.Errorf("%s: gate isBinaryDocument=%v but preprocessor-capable=%v (drift)", ext, gated, canHandle)
		}
		// getMetadataTypeForExtension must return a concrete type iff gated in.
		mt := getMetadataTypeForExtension(ext)
		if gated && mt == "none" {
			t.Errorf("%s: gated in but metadata type resolved to none", ext)
		}
		if !gated && mt != "none" {
			t.Errorf("%s: not gated in but metadata type = %q (expected none)", ext, mt)
		}
	}
}

// TestExtensionRouting_SupportedTypesUnchanged pins the extensions that were
// genuinely supported before AND after the fix, so this refactor cannot silently
// drop a real capability.
func TestExtensionRouting_SupportedTypesUnchanged(t *testing.T) {
	want := map[string]string{
		".docx": "office_metadata", ".xlsx": "office_metadata", ".pptx": "office_metadata",
		".odt": "office_metadata", ".ods": "office_metadata", ".odp": "office_metadata",
		".pdf": "document_metadata",
		".jpg": "image_metadata", ".jpeg": "image_metadata", ".png": "image_metadata",
		".gif": "image_metadata", ".tiff": "image_metadata", ".tif": "image_metadata",
		".bmp": "image_metadata", ".webp": "image_metadata",
		".mp4": "video_metadata", ".mov": "video_metadata", ".m4v": "video_metadata",
		".mp3": "audio_metadata", ".flac": "audio_metadata", ".wav": "audio_metadata", ".m4a": "audio_metadata",
	}
	for ext, mt := range want {
		if !isBinaryDocument(ext) {
			t.Errorf("%s: expected still-supported (isBinaryDocument=true), got false", ext)
		}
		if got := getMetadataTypeForExtension(ext); got != mt {
			t.Errorf("%s: metadata type = %q, want %q", ext, got, mt)
		}
	}
}

// TestExtensionRouting_UnsupportedTypesSkipped pins that the previously-drifting
// extensions (gated in by the old list but handled by no preprocessor) now route
// to a clean "unsupported" skip instead of a mid-pipeline error.
func TestExtensionRouting_UnsupportedTypesSkipped(t *testing.T) {
	skipped := []string{
		".doc", ".xls", ".ppt", // legacy binary Office (only OOXML/ODF are handled)
		".heic", ".heif", ".raw", ".cr2", ".nef", ".arw",
		".avi", ".mkv", ".wmv", ".flv", ".webm", ".3gp", ".ogv",
		".ogg", ".aac", ".wma", ".opus",
	}
	for _, ext := range skipped {
		if isBinaryDocument(ext) {
			t.Errorf("%s: expected unsupported (isBinaryDocument=false), got true", ext)
		}
		if got := getMetadataTypeForExtension(ext); got != "none" {
			t.Errorf("%s: metadata type = %q, want none", ext, got)
		}
	}
}

// TestExtensionRouting_ValidatorConstructs is a light guard that the shared
// validator the gate delegates to is non-nil and usable.
func TestExtensionRouting_ValidatorConstructs(t *testing.T) {
	if preprocessors.NewFileExtensionValidator() == nil {
		t.Fatal("NewFileExtensionValidator returned nil")
	}
}

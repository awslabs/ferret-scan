// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"image"
	"image/color"
	"image/gif"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

func writeGIF(t *testing.T, path string) {
	t.Helper()
	img := image.NewPaletted(image.Rect(0, 0, 4, 4), color.Palette{color.Black, color.White})
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create gif: %v", err)
	}
	defer f.Close()
	if err := gif.Encode(f, img, nil); err != nil {
		t.Fatalf("encode gif: %v", err)
	}
}

func writePNG(t *testing.T, path string) {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 4, 4))
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create png: %v", err)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		t.Fatalf("encode png: %v", err)
	}
}

// TestRedactGIF_FailsSafe verifies that formats without a real metadata-stripping
// implementation (GIF/TIFF/BMP/WEBP) no longer copy the original through and
// report success. Previously redactGenericImageMetadata io.Copy'd the file
// verbatim — leaving EXIF/GPS/serial metadata intact — yet returned Success:true
// with Confidence:0.5.
func TestRedactGIF_FailsSafe(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.gif")
	out := filepath.Join(dir, "out.gif")
	writeGIF(t, in)

	r := NewImageMetadataRedactor(nil, nil)
	result, err := r.RedactDocument(in, out, nil, redactors.RedactionSimple)

	if err == nil {
		t.Fatal("expected RedactDocument to fail for GIF, got nil error")
	}
	if result != nil {
		t.Errorf("expected nil result on failure, got %+v", result)
	}
	if !strings.Contains(err.Error(), "not implemented") {
		t.Errorf("error should explain redaction is unimplemented, got: %v", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Errorf("no output file should remain when redaction is refused; stat err = %v", statErr)
	}
}

// TestRedactPNG_StillWorks guards against over-correction: PNG (and JPEG) have a
// real decode/re-encode strip path and must continue to succeed.
func TestRedactPNG_StillWorks(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.png")
	out := filepath.Join(dir, "out.png")
	writePNG(t, in)

	r := NewImageMetadataRedactor(nil, nil)
	result, err := r.RedactDocument(in, out, nil, redactors.RedactionSimple)
	if err != nil {
		t.Fatalf("PNG redaction should succeed, got error: %v", err)
	}
	if result == nil || !result.Success {
		t.Fatalf("expected successful redaction result, got %+v", result)
	}
	if _, statErr := os.Stat(out); statErr != nil {
		t.Errorf("expected redacted PNG output to exist: %v", statErr)
	}
}

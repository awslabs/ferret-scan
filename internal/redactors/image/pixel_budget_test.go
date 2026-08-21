// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"image"
	"image/jpeg"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// writeGrayJPEG writes an all-white greyscale JPEG of the given dimensions.
//
// Greyscale and uniform so the file stays small relative to its pixel count — which is the whole
// point of the shape under test: a few kilobytes on disk declaring an enormous decoded size.
func writeGrayJPEG(t *testing.T, path string, w, h int) {
	t.Helper()
	img := image.NewGray(image.Rect(0, 0, w, h))
	for i := range img.Pix {
		img.Pix[i] = 0xFF
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Fatalf("close %s: %v", path, err)
		}
	}()
	if err := jpeg.Encode(f, img, &jpeg.Options{Quality: 90}); err != nil {
		t.Fatalf("encode %s: %v", path, err)
	}
}

// An image declaring more pixels than the budget must be REFUSED, and the refusal must say so.
//
// Stripping metadata decodes the pixels and re-encodes them, so peak memory follows the DECLARED
// width x height — a number out of the file. Measured end to end on a 20000x20000 JPEG that is 4.47MB
// on disk: 0.77GB of peak RSS before this change, 0.03GB after, because the file is now refused before
// anything is decoded. Heap grew linearly with the declaration, so a larger one went further until the
// process was OOM-killed (#378).
//
// The dimensions here are declared rather than materialised: the fixture is generated at a size the
// test can afford, and the budget is lowered for the duration instead. Generating a real 400M-pixel
// image would cost the test the very memory the change exists to avoid.
func TestOversizeImageIsRefusedNotDecoded(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "big.jpg")
	out := filepath.Join(dir, "out.jpg")

	// 600x600 = 360,000 pixels, against a budget of 1,000 for this test.
	writeGrayJPEG(t, in, 600, 600)

	restore := maxRedactablePixels
	defer func() { maxRedactablePixels = restore }()
	maxRedactablePixels = 1000

	r := NewImageMetadataRedactor(nil, nil)
	result, err := r.RedactDocument(in, out, nil, redactors.RedactionSimple)

	if err == nil {
		t.Fatal("an image past the pixel budget was accepted: peak memory then follows the " +
			"DECLARED dimensions, which an attacker chooses")
	}
	if result != nil {
		t.Errorf("expected a nil result on refusal, got %+v", result)
	}
	// The numbers have to be in the message: an operator needs to know which limit was hit and by
	// how much, or the only remedy is guesswork.
	for _, want := range []string{"600x600", "360000", "1000"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal message %q does not mention %q", err.Error(), want)
		}
	}
	// Fail-safe: no output file may survive a refusal, or it would be mistaken for a redacted copy.
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Errorf("an output file survived the refusal (stat err = %v) — that is indistinguishable "+
			"from a successfully redacted document", statErr)
	}
}

// The other direction: an image INSIDE the budget must still be redacted.
//
// Without this, `return error` unconditionally would pass the test above, and the redactor would stop
// stripping metadata from every image — a leak dressed as a memory fix.
func TestImageWithinTheBudgetIsStillRedacted(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "ok.jpg")
	out := filepath.Join(dir, "out.jpg")
	writeGrayJPEG(t, in, 64, 64)

	r := NewImageMetadataRedactor(nil, nil)
	result, err := r.RedactDocument(in, out, nil, redactors.RedactionSimple)
	if err != nil {
		t.Fatalf("an image well inside the budget was refused: %v", err)
	}
	if result == nil || !result.Success {
		t.Fatalf("expected a successful result, got %+v", result)
	}
	if _, statErr := os.Stat(out); statErr != nil {
		t.Errorf("expected a redacted output file: %v", statErr)
	}
}

// The budget must be compared against the DECLARED dimensions, so the check has to happen before any
// pixel decode. Asserted by allocation, because that is the property that matters and the only one a
// timing measurement cannot fake: a refusal that still decoded first would be just as slow and just as
// memory-hungry as no refusal at all.
func TestRefusalHappensBeforeAnyPixelDecode(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "big.jpg")
	out := filepath.Join(dir, "out.jpg")

	// 2000x2000 = 4M pixels, so a full greyscale decode is ~4MB — an order of magnitude above the
	// ceiling asserted below, and unmistakable if it happens.
	writeGrayJPEG(t, in, 2000, 2000)

	restore := maxRedactablePixels
	defer func() { maxRedactablePixels = restore }()
	maxRedactablePixels = 1000

	r := NewImageMetadataRedactor(nil, nil)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	_, err := r.RedactDocument(in, out, nil, redactors.RedactionSimple)

	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc

	if err == nil {
		t.Fatal("the oversize image was not refused, so this measurement is meaningless")
	}

	const ceiling = 1 << 20 // 1MB; the pixels alone would be ~4MB
	if allocated > ceiling {
		t.Errorf("refusing a 4M-pixel image allocated %d bytes (> %d): the pixels are being decoded "+
			"before the budget is consulted, which is the cost the budget exists to avoid",
			allocated, ceiling)
	}
}

// Reading dimensions must not decode pixels either.
//
// extractImageMetadata used image.Decode to read three header fields, so a large image was
// materialised in full for its width, height and colour model — and then again by the re-encode.
// Measured: removing this one decode took peak RSS on the 20000x20000 fixture from 0.77GB to 0.40GB,
// which is what proves the two decodes were both happening.
func TestMetadataExtractionDoesNotDecodePixels(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "big.jpg")
	writeGrayJPEG(t, in, 2000, 2000) // 4M pixels, ~4MB decoded

	r := NewImageMetadataRedactor(nil, nil)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	meta, err := r.extractImageMetadata(in, FormatJPEG)

	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc

	if err != nil {
		t.Fatalf("extractImageMetadata: %v", err)
	}

	// Non-vacuity first: the dimensions must actually have been read, or a function that returned an
	// empty struct would pass the allocation bound trivially.
	if meta.Dimensions.Width != 2000 || meta.Dimensions.Height != 2000 {
		t.Fatalf("dimensions = %dx%d, want 2000x2000 — the header was not read, so the allocation "+
			"bound below proves nothing", meta.Dimensions.Width, meta.Dimensions.Height)
	}
	if meta.ColorModel == "" {
		t.Error("ColorModel is empty: DecodeConfig reports one, and it is part of reported metadata")
	}

	const ceiling = 1 << 20 // 1MB; a full decode of 4M greyscale pixels is ~4MB
	if allocated > ceiling {
		t.Errorf("reading dimensions allocated %d bytes (> %d): image.Decode is back, so every large "+
			"image is materialised twice — once for three header fields and once for the re-encode",
			allocated, ceiling)
	}
}

// The shipped budget must stay above real photography, or the fix trades a DoS for refusing ordinary
// files. 61MP is the largest full-frame sensor sold; phone output is far smaller.
func TestShippedBudgetAdmitsRealCameras(t *testing.T) {
	const largestRealSensorPixels = 61_000_000
	if maxRedactablePixels <= int64(largestRealSensorPixels) {
		t.Errorf("maxRedactablePixels = %d, which would refuse a %d-pixel photograph from a camera "+
			"people actually own", maxRedactablePixels, largestRealSensorPixels)
	}
	// And it must stay well under the shape it exists to refuse.
	const bombPixels = 400_000_000
	if maxRedactablePixels >= int64(bombPixels) {
		t.Errorf("maxRedactablePixels = %d does not refuse the %d-pixel shape this guards against",
			maxRedactablePixels, bombPixels)
	}
}

// A header DecodeConfig cannot read leaves Dimensions at zero, so the budget is not consulted for
// that file. That is safe only because the decoder the budget protects reads the same header and
// fails the same way — this pins that reasoning rather than leaving it as an assumption.
//
// The failure must also be fail-safe: no output file may survive, or an unredacted copy would be
// indistinguishable from a redacted one.
func TestUnreadableHeaderFailsSafeRatherThanDecoding(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "truncated.jpg")
	out := filepath.Join(dir, "out.jpg")

	// A JPEG SOI marker and nothing else: enough for format detection to route it here, not enough
	// for either DecodeConfig or Decode.
	if err := os.WriteFile(in, []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10}, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	r := NewImageMetadataRedactor(nil, nil)

	// Non-vacuity: the premise is that dimensions really are unknown, which is what makes the
	// budget a no-op for this file.
	meta, err := r.extractImageMetadata(in, FormatJPEG)
	if err != nil {
		t.Fatalf("extractImageMetadata: %v", err)
	}
	if meta.Dimensions.Width != 0 || meta.Dimensions.Height != 0 {
		t.Fatalf("dimensions = %dx%d, want 0x0 — this test is about the case where the header could "+
			"not be read, and it no longer exercises it", meta.Dimensions.Width, meta.Dimensions.Height)
	}

	if _, err := r.RedactDocument(in, out, nil, redactors.RedactionSimple); err == nil {
		t.Error("a file whose header cannot be decoded was reported as redacted")
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Errorf("an output file survived the failure (stat err = %v)", statErr)
	}
}

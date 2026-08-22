// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"strings"
	"testing"
)

// The file's own NAME and PATH must not become scannable content.
//
// createMinimalImageMetadata put both in exifData.Tags, and tags are rendered into the text the
// validators read — so the tool scanned its own input path and reported findings from it. Measured
// at main @ 0610b7e on two PNGs with BYTE-IDENTICAL content (sha 258c3a962b02796a) differing only
// in filename:
//
//	asset_64@5x.png  ->  2 x EMAIL HIGH 90    "64@5x.png" parses as local@domain.tld
//	asset_64_5x.png  ->  no findings
//
// and `grep -c @5x` on the bytes is 0. The public AWS icon package holds 328 such files; every
// macOS and iOS asset directory is full of them. On that corpus: EMAIL 656 -> 0, plus 10
// IMAGE_METADATA findings whose reported text WAS the path.
//
// It generalised past the name: a file inside a directory called "claim-449-87-4100" reported SSN
// MEDIUM 60 on byte-identical content, while a .txt in the same directory reported nothing — the
// same exposure was type-dependent. And redaction returned rc=0 having written a "redacted" copy to
// an output path that still contained the SSN, so the finding was unredactable by construction
// (#444).
//
// Asserted on the FORMATTED metadata rather than end to end, because that string is what reaches the
// validators and because these are in-package methods over a plain map.
func TestFileNameAndPathAreNotScannableContent(t *testing.T) {
	imp := NewImageMetadataPreprocessor()

	// The exact shapes that produced findings, as a path a scan could really encounter.
	const path = "/scan/claim-449-87-4100/asset_64@5x.png"

	meta, err := imp.createMinimalImageMetadata(path)
	if err != nil {
		t.Fatalf("createMinimalImageMetadata: %v", err)
	}

	for _, tag := range []string{"FileName", "FilePath"} {
		if v, present := meta.Tags[tag]; present {
			t.Errorf("tag %q is still set to %q — tags become scannable content, so the tool "+
				"reports findings from its own input path", tag, v)
		}
	}

	formatted := imp.formatImageMetadata(meta)
	for _, leaked := range []string{
		"asset_64@5x.png",   // the @Nx name that parses as an email address
		"claim-449-87-4100", // a directory name carrying a value
		path,                // the whole path
	} {
		if strings.Contains(formatted, leaked) {
			t.Errorf("%q reaches the scanned text:\n--- formatted ---\n%s", leaked, formatted)
		}
	}
}

// FileExtension is deliberately KEPT.
//
// It describes the file's TYPE rather than reproducing a caller's string, so it cannot carry a value
// out of the scanned tree. Pinned so a later cleanup does not remove it as collateral and quietly
// change what a no-EXIF image reports.
func TestFileExtensionSurvives(t *testing.T) {
	imp := NewImageMetadataPreprocessor()

	meta, err := imp.createMinimalImageMetadata("/scan/photo.PNG")
	if err != nil {
		t.Fatalf("createMinimalImageMetadata: %v", err)
	}
	if got := meta.Tags["FileExtension"]; got != "PNG" {
		t.Errorf("FileExtension = %q, want %q", got, "PNG")
	}
	if !strings.Contains(imp.formatImageMetadata(meta), "PNG") {
		t.Error("FileExtension no longer reaches the formatted metadata")
	}
}

// A path with no extension must not panic or produce a stray tag.
func TestMinimalMetadataOnAnAwkwardPath(t *testing.T) {
	imp := NewImageMetadataPreprocessor()

	for _, path := range []string{
		"/scan/noextension",
		"/scan/.hidden",
		"trailing.dot.",
		"",
	} {
		t.Run(path, func(t *testing.T) {
			meta, err := imp.createMinimalImageMetadata(path)
			if err != nil {
				t.Fatalf("createMinimalImageMetadata(%q): %v", path, err)
			}
			if _, present := meta.Tags["FilePath"]; present {
				t.Error("FilePath tag reappeared")
			}
			if _, present := meta.Tags["FileName"]; present {
				t.Error("FileName tag reappeared")
			}
			// Must still be usable: the formatter runs over whatever is there.
			_ = imp.formatImageMetadata(meta)
		})
	}
}

// The struct's FilePath FIELD is still populated, and that is correct.
//
// It is how the preprocessor and the router identify the file being handled; only the TAGS become
// scannable content. Keeping the distinction explicit, because "remove the path" applied to both
// would break the pipeline rather than fix a false positive.
func TestFilePathFieldIsStillSet(t *testing.T) {
	imp := NewImageMetadataPreprocessor()

	const path = "/scan/photo.png"
	meta, err := imp.createMinimalImageMetadata(path)
	if err != nil {
		t.Fatalf("createMinimalImageMetadata: %v", err)
	}
	if meta.FilePath != path {
		t.Errorf("FilePath field = %q, want %q — the field identifies the file and is not "+
			"scanned; only the tags were the problem", meta.FilePath, path)
	}
}

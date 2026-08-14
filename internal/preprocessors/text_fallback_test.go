// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"os"
	"path/filepath"
	"testing"
)

// writeFile puts content at dir/name and returns the path.
func writeFile(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// textWithFinding is a body every scan of it should find something in, so a test
// that gets zero findings has failed rather than merely matched nothing.
var textWithFinding = []byte("let ssn = \"796-58-4123\"\nlet key = \"AKIAIOSFODNN7EXAMPLE\"\n")

// binaryBytes is unambiguously not text: nulls, invalid UTF-8, no long printable
// run for the ASCII-ratio fallback to latch onto.
var binaryBytes = []byte{0x00, 0x01, 0x02, 0x03, 0xff, 0xfe, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x7f, 0x80, 0x00}

// TestUnlistedTextExtensionsAreClaimed is the recall hole this fallback closes.
//
// The extension allowlist held ~45 entries and every extension below was absent,
// so the file scanned as zero findings while the CLI printed "No matches found"
// and exited 0. .tf/.tfvars and .properties are the costly ones — a Terraform
// variables file and a Java properties file are two of the likeliest places on
// disk to find a live credential.
func TestUnlistedTextExtensionsAreClaimed(t *testing.T) {
	ptp := NewPlainTextPreprocessor()
	dir := t.TempDir()

	// The three that prompted this (a mobile source tree), plus the wider set of
	// text formats nobody had enumerated.
	exts := []string{
		".swift", ".kt", ".kts", // reported: iOS + Android sources
		".tf", ".tfvars", ".properties", // credentials live here
		".m", ".mm", ".dart", ".scala", ".groovy", ".gradle",
		".jsx", ".tsx", ".vue", ".svelte",
		".proto", ".graphql", ".lua", ".pl", ".r", ".ex", ".exs", ".erl", ".clj",
		".cc", ".cxx", ".hh", ".editorconfig", ".gitattributes",
	}
	for _, ext := range exts {
		t.Run(ext, func(t *testing.T) {
			p := writeFile(t, dir, "sample"+ext, textWithFinding)
			if !ptp.CanProcess(p) {
				t.Errorf("text bytes named %q are not claimed, so the file is never read", ext)
			}
		})
	}
}

// TestBinaryBytesRefusedWhateverTheExtension keeps the fallback honest. Claiming an
// unlisted extension has to remain a decision about the BYTES; if it degraded into
// "claim everything", the text extractor would be handed compiled objects, archives
// and images, and the null-byte gate that keeps binary out of the scanner would be
// the only thing left standing.
func TestBinaryBytesRefusedWhateverTheExtension(t *testing.T) {
	ptp := NewPlainTextPreprocessor()
	dir := t.TempDir()

	for _, name := range []string{"blob.xyz", "blob.frobnicate", "blob.o", "blob.class", "blob"} {
		t.Run(name, func(t *testing.T) {
			p := writeFile(t, dir, name, binaryBytes)
			if ptp.CanProcess(p) {
				t.Errorf("binary bytes in %q were claimed as text", name)
			}
		})
	}
}

// TestMediaExtensionsStayWithTheirExtractor guards the one deliberate exclusion.
//
// Image, video and audio files route to a metadata extractor that knows how to read
// them. They are not the failing case this fallback exists for, and claiming them
// would change behavior for every media file rather than recovering an unscanned
// one.
//
// The list is derived from FileExtensionValidator rather than hardcoded, so if an
// extension is added there this test covers it automatically instead of drifting —
// drift between a hardcoded copy and this validator is the original sin behind the
// bug being fixed here (see the .heic case in internal/router).
func TestMediaExtensionsStayWithTheirExtractor(t *testing.T) {
	ptp := NewPlainTextPreprocessor()
	v := NewFileExtensionValidator()
	dir := t.TempDir()

	var media []string
	media = append(media, v.GetImageExtensions()...)
	media = append(media, v.GetVideoExtensions()...)
	media = append(media, v.GetAudioExtensions()...)
	if len(media) == 0 {
		t.Fatal("validator reported no media extensions; the assertion would be vacuous")
	}

	for _, ext := range media {
		t.Run(ext, func(t *testing.T) {
			// Text bytes, so only the extension exclusion can prevent the claim.
			p := writeFile(t, dir, "sample"+ext, textWithFinding)
			if ptp.CanProcess(p) {
				t.Errorf("%q was claimed as text; it must route to its metadata extractor", ext)
			}
		})
	}
}

// TestRealContainerStillDeclined pins that the fallback did not weaken the
// container sniff. A well-formed Office file is a ZIP, so its bytes are binary and
// this preprocessor must keep declining it — that is what leaves the Office
// extractor to win on a real document.
func TestRealContainerStillDeclined(t *testing.T) {
	ptp := NewPlainTextPreprocessor()
	dir := t.TempDir()

	// ZIP local file header ("PK\x03\x04") followed by binary payload: the shape of
	// every OOXML container.
	zipish := append([]byte("PK\x03\x04"), binaryBytes...)
	for _, name := range []string{"real.docx", "real.xlsx", "real.pptx"} {
		t.Run(name, func(t *testing.T) {
			p := writeFile(t, dir, name, zipish)
			if ptp.CanProcess(p) {
				t.Errorf("%q looks like a real container but was claimed as text", name)
			}
		})
	}

	// And the mislabelled case still works: text bytes under a container name.
	p := writeFile(t, dir, "mislabelled.docx", textWithFinding)
	if !ptp.CanProcess(p) {
		t.Error("text bytes named .docx are not claimed; the container sniff regressed")
	}
}

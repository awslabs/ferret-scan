// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractofficelib

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #379 part 2: every embedded part was inflated and written to temp TWICE per scan.
//
// extractEmbeddedImages materialised each part, used nothing but the returned path's existence,
// and deleted the lot on return; ExtractEmbeddedMediaForProcessing then extracted every part
// again. Measured before the fix: a .docx with two parts produced FOUR temp files.
//
// The fix is not "stop extracting" — that would change what the scanner sees. The metadata loop's
// extraction IS its admission decision: a part that is over-cap or over-budget is excluded from
// EmbeddedMediaCount and from the EmbeddedMedia_N_* indices, and those properties are rendered
// into the text every validator scans. So the loop still INFLATES each part, to io.Discard, and
// only the write to disk is gone.
//
// Testing this without polling the filesystem: a read-only TMPDIR makes os.CreateTemp fail. Before
// the fix that failure propagated as an admission refusal and the part vanished from the count;
// after it, the loop needs no temp file and the count is unaffected. That is a deterministic
// discriminator — no timing, no sampling. (Polling TMPDIR does work, but only with multi-megabyte
// parts; at small sizes the files are created and unlinked faster than a shell loop can see them,
// which is how the doubled extraction stayed invisible.)

// countProperty returns the EmbeddedMediaCount value, or "" when the key is absent.
func countProperty(t *testing.T, md *Metadata) string {
	t.Helper()
	if md == nil || md.Properties == nil {
		return ""
	}
	return md.Properties["EmbeddedMediaCount"]
}

// TestMetadataLoopNeedsNoTempFile is the fix, stated as the property that distinguishes it.
func TestMetadataLoopNeedsNoTempFile(t *testing.T) {
	docx := buildDocxWithParts(t, 2, 4096)

	// A directory that exists but cannot be written to.
	ro := filepath.Join(t.TempDir(), "readonly")
	if err := os.Mkdir(ro, 0o500); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Setenv("TMPDIR", ro)

	// Non-vacuity: the directory must really be unwritable, or this test proves nothing.
	if f, err := os.CreateTemp(ro, "probe_*"); err == nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		t.Skipf("TMPDIR %s is writable (running as a user who ignores mode 0500), so this "+
			"test cannot discriminate", ro)
	}

	md, err := ExtractMetadata(docx)
	if err != nil {
		t.Fatalf("ExtractMetadata: %v", err)
	}

	if got := countProperty(t, md); got != "2" {
		t.Errorf("EmbeddedMediaCount = %q, want \"2\". With an unwritable TMPDIR the metadata "+
			"loop must still admit both parts; needing a temp file here is the doubled "+
			"extraction this fixes.", got)
	}
}

// TestOverCapPartStaysExcludedFromTheCount pins the membership filter, which is why the loop
// still reads each part instead of skipping the read entirely.
//
// If someone "optimises" this by not inflating the bytes, an over-cap part starts being counted
// and the EmbeddedMedia_N_* indices shift — a change to the text the validators scan, i.e. a
// detection change dressed as a performance tweak.
func TestOverCapPartStaysExcludedFromTheCount(t *testing.T) {
	// One admissible part, and one whose DECLARED size is over MaxEmbeddedMediaSize.
	docx := buildDocxWithOversizePart(t)

	md, err := ExtractMetadata(docx)
	if err != nil {
		t.Fatalf("ExtractMetadata: %v", err)
	}

	if got := countProperty(t, md); got != "1" {
		t.Errorf("EmbeddedMediaCount = %q, want \"1\": the over-cap part must not be counted", got)
	}
	// And the survivor must hold index 0 — the indices are positional over the ADMITTED parts.
	if got := md.Properties["EmbeddedMedia_0_Name"]; !strings.HasSuffix(got, "small.png") {
		t.Errorf("EmbeddedMedia_0_Name = %q, want the admitted part at index 0", got)
	}
	if _, present := md.Properties["EmbeddedMedia_1_Name"]; present {
		t.Errorf("EmbeddedMedia_1_Name is present, so the refused part was counted after all")
	}
}

// TestAdmissionVerdictIsSharedByBothForms guards the refactor itself: the temp-writing wrapper and
// the discard form must agree, because the metadata loop's verdict decides membership while the
// scanning loop's decides coverage and disclosure. Two copies of these checks could drift.
func TestAdmissionVerdictIsSharedByBothForms(t *testing.T) {
	docx := buildDocxWithOversizePart(t)

	r, err := zip.OpenReader(docx)
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	defer func() { _ = r.Close() }()

	for _, f := range r.File {
		if !isEmbeddedPartPath(f.Name) {
			continue
		}

		// Each form gets its own budget, so the comparison is of the VERDICT only.
		_, discardErr := admitEmbeddedPart(f, newExtractionBudget(nil), io.Discard)
		tempPath, tempErr := extractImageToTemp(f, newExtractionBudget(nil))
		if tempPath != "" {
			_ = os.Remove(tempPath)
		}

		if (discardErr == nil) != (tempErr == nil) {
			t.Errorf("%s: discard form err=%v but temp form err=%v — the two admission paths "+
				"disagree, which is exactly the drift the shared function exists to prevent",
				f.Name, discardErr, tempErr)
			continue
		}
		if discardErr != nil && tempErr != nil && discardErr.Error() != tempErr.Error() {
			t.Errorf("%s: the two forms refuse with different messages:\n  discard: %v\n  temp:    %v",
				f.Name, discardErr, tempErr)
		}
	}
}

// TestRefusedPartLeavesNoTempFile keeps the MED-3 property: a bomb must not leave a partial file
// behind. The wrapper removes it on every refusal path.
func TestRefusedPartLeavesNoTempFile(t *testing.T) {
	docx := buildDocxWithOversizePart(t)

	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)

	if _, err := ExtractMetadata(docx); err != nil {
		t.Fatalf("ExtractMetadata: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "office_embedded_") {
			t.Errorf("temp file %s survived the run", e.Name())
		}
	}
}

// TestOverCapPartCreatesNoTempFile pins the EARLY declared-size guard in the temp-writing wrapper,
// which the survival test above cannot see: with the guard, a refused part never reaches
// os.CreateTemp; without it, the file is created and then removed, so nothing survives either way.
//
// A read-only TMPDIR makes the difference observable in the ERROR. With the guard the refusal is
// the size message; without it, os.CreateTemp fails first and the caller gets a permission error
// instead — a worse diagnosis for the operator, and one inflate's worth of wasted work.
func TestOverCapPartCreatesNoTempFile(t *testing.T) {
	docx := buildDocxWithOversizePart(t)

	r, err := zip.OpenReader(docx)
	if err != nil {
		t.Fatalf("open zip: %v", err)
	}
	defer func() { _ = r.Close() }()

	ro := filepath.Join(t.TempDir(), "readonly")
	if err := os.Mkdir(ro, 0o500); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Setenv("TMPDIR", ro)
	if f, err := os.CreateTemp(ro, "probe_*"); err == nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		t.Skipf("TMPDIR %s is writable, so this test cannot discriminate", ro)
	}

	var checked int
	for _, f := range r.File {
		if !strings.HasSuffix(f.Name, "big.png") {
			continue
		}
		checked++
		_, err := extractImageToTemp(f, newExtractionBudget(nil))
		if err == nil {
			t.Fatalf("%s was admitted; it declares %d bytes, over the %d-byte cap",
				f.Name, f.UncompressedSize64, MaxEmbeddedMediaSize)
		}
		if !strings.Contains(err.Error(), "over the") {
			t.Errorf("refusal for an over-cap part is %q; want the declared-size message. The "+
				"early guard is gone, so os.CreateTemp ran first and reported its own failure.",
				err.Error())
		}
	}
	if checked == 0 {
		t.Fatal("the oversize part was not found in the fixture, so this test checked nothing")
	}
}

// buildDocxWithOversizePart writes a .docx whose FIRST embedded part declares more than
// MaxEmbeddedMediaSize, followed by one admissible part.
//
// The oversize part is DEFLATED zeros, so the entry's UncompressedSize64 crosses the cap while
// the file on disk stays small — the cap is compared against the declared size, so this is both
// faster and a truer bomb shape than storing the bytes.
//
// Order matters: the refused part comes FIRST so that the admitted one has to be renumbered to
// index 0. That renumbering is the behaviour TestOverCapPartStaysExcludedFromTheCount pins.
func buildDocxWithOversizePart(t *testing.T) string {
	t.Helper()

	const ct = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Default Extension="png" ContentType="image/png"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>`
	const rels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>`
	const doc = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Patient SSN 449-87-4100</w:t></w:r></w:p></w:body></w:document>`

	path := filepath.Join(t.TempDir(), "oversize.docx")
	f, err := os.Create(path) // #nosec G304 -- test-controlled temp path
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			t.Fatalf("close: %v", cerr)
		}
	}()

	z := zip.NewWriter(f)
	for _, kv := range []struct{ name, body string }{
		{"[Content_Types].xml", ct},
		{"_rels/.rels", rels},
		{"word/document.xml", doc},
	} {
		w, werr := z.Create(kv.name)
		if werr != nil {
			t.Fatalf("create %s: %v", kv.name, werr)
		}
		if _, werr = io.WriteString(w, kv.body); werr != nil {
			t.Fatalf("write %s: %v", kv.name, werr)
		}
	}

	// The refused part, first.
	big, err := z.Create("word/media/big.png")
	if err != nil {
		t.Fatalf("create big: %v", err)
	}
	if _, err = io.CopyN(big, zeros{}, int64(MaxEmbeddedMediaSize)+1); err != nil {
		t.Fatalf("write big: %v", err)
	}

	// The admitted part, second.
	small, err := z.Create("word/media/small.png")
	if err != nil {
		t.Fatalf("create small: %v", err)
	}
	if _, err = small.Write(append([]byte("\x89PNG\r\n\x1a\n"), make([]byte, 4096)...)); err != nil {
		t.Fatalf("write small: %v", err)
	}

	if err := z.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return path
}

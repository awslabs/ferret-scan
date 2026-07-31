// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractofficelib

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// validateFilePath used to refuse any path under a hardcoded list of "system
// directories" that included /home/, /var/ and /tmp/. On Linux that is every file
// a user owns, so `ferret-scan --file ~/report.docx` silently lost Office metadata
// extraction — the document's author, company and custom properties were never
// scanned, never reported, and therefore never redacted.
//
// These tests pin the paths that must now work, and the much smaller set that must
// still be refused.

// TestValidateFilePathAcceptsOrdinaryUserPaths is the non-vacuity test for the
// guard change: every path here returned "access to system directory denied"
// before, and every one of them is where real user data lives.
func TestValidateFilePathAcceptsOrdinaryUserPaths(t *testing.T) {
	paths := []string{
		"/home/alice/report.docx",
		"/home/runner/work/ferret-scan/ferret-scan/fixture.docx", // GitHub's Linux runners
		"/var/folders/xy/T/scan-123/book.xlsx",                   // macOS TMPDIR
		"/tmp/scan-123/deck.pptx",
		"/root/audit.docx",
		"/Users/alice/Documents/report.docx",
		"C:\\Users\\alice\\Documents\\report.docx",
		"C:\\Program Files\\CorpApp\\template.docx",
		"/etc/corp-templates/letterhead.docx",
		"/usr/bin/../share/doc/example.docx",
	}

	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			err := validateFilePath(p)
			// The last entry contains ".." and is caught by the traversal check,
			// which is unchanged and deliberately kept.
			if strings.Contains(filepath.Clean(p), "..") {
				if err == nil {
					t.Errorf("validateFilePath(%q) = nil, want the traversal rejection", p)
				}
				return
			}
			if err != nil {
				t.Errorf("validateFilePath(%q) = %v; ordinary user data lives here, and refusing "+
					"it drops Office metadata extraction with no error shown to the user", p, err)
			}
		})
	}
}

// TestValidateFilePathRejects pins what the guard still refuses.
//
// Note the traversal check catches only a ".." that filepath.Clean cannot resolve
// away — i.e. one that escapes above the starting point. "/home/a/../../etc/x"
// cleans to "/etc/x", an ordinary absolute path with no ".." left in it, and is
// accepted. That is correct rather than a hole: it names the same file the caller
// could have named directly, and this function guards neither a sandbox nor a
// document root.
func TestValidateFilePathRejects(t *testing.T) {
	cases := []struct {
		path, why string
	}{
		{"../../etc/passwd", "traversal"},
		{"docs/../../../secret.docx", "traversal"},
		{"https://example.com/report.docx", "URL scheme"},
		{"file:///home/alice/report.docx", "URL scheme"},
	}

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			if err := validateFilePath(tc.path); err == nil {
				t.Errorf("validateFilePath(%q) = nil, want a %s rejection", tc.path, tc.why)
			}
		})
	}
}

// TestValidateFilePathAcceptsRealFilesUnderDeviceLikePaths is the regression for the
// second version of the same mistake.
//
// The first replacement for the /home/-blocking denylist kept a smaller one for the
// kernel pseudo-filesystems: /proc/, /sys/, /dev/. That reproduced the bug one
// directory down. /dev/shm is world-writable tmpfs which scripts and CI use for
// ordinary temporary files, and the files in it are ordinary regular files — so a
// .docx written there was refused, silently losing Office metadata extraction exactly
// as before. The concern behind that list (do not read something with no size that may
// never end) is a property of the file's MODE, not its name, and it now lives in the
// router as an os.FileMode().IsRegular() check.
func TestValidateFilePathAcceptsRealFilesUnderDeviceLikePaths(t *testing.T) {
	for _, p := range []string{
		"/dev/shm/report.docx",     // world-writable tmpfs; a real regular file
		"/dev/shm/tmp/book.xlsx",   // ditto, nested
		"/home/proc/report.docx",   // a directory merely NAMED proc
		"/var/proc/quarterly.docx", // ditto
	} {
		t.Run(p, func(t *testing.T) {
			if err := validateFilePath(p); err != nil {
				t.Errorf("validateFilePath(%q) = %v, want nil.\nThese are ordinary regular "+
					"files. Refusing them by path prefix silently drops Office metadata "+
					"extraction, which is the defect this guard was rewritten to remove.", p, err)
			}
		})
	}
}

// TestValidateFilePathAcceptsNamesContainingDots is the regression for the over-broad
// traversal check. It used to be strings.Contains(cleanPath, ".."), which rejected any
// legitimate name carrying two consecutive dots.
func TestValidateFilePathAcceptsNamesContainingDots(t *testing.T) {
	for _, p := range []string{
		"/home/alice/my..report.docx",
		"/home/alice/notes../summary.xlsx",
		"/home/alice/2024..2025/budget.xlsx",
	} {
		t.Run(p, func(t *testing.T) {
			if err := validateFilePath(p); err != nil {
				t.Errorf("validateFilePath(%q) = %v, want nil.\nAfter filepath.Clean only a "+
					"LEADING \"..\" is a traversal; an interior one is part of a legitimate name.", p, err)
			}
		})
	}
}

// TestValidateFilePathResolvesInteriorDotDot documents the boundary the test above
// describes, so the behavior is pinned rather than merely asserted in prose.
func TestValidateFilePathResolvesInteriorDotDot(t *testing.T) {
	const p = "/home/alice/../../etc/passwd"
	if err := validateFilePath(p); err != nil {
		t.Errorf("validateFilePath(%q) = %v; Clean resolves this to /etc/passwd, which is an "+
			"ordinary absolute path the caller could name directly", p, err)
	}
}

// TestExtractMetadataFromATempPath is the end-to-end half: a real .docx written
// under t.TempDir() — which resolves under /var/ on macOS and /tmp/ on Linux, both
// previously refused — must yield its core properties.
func TestExtractMetadataFromATempPath(t *testing.T) {
	dir := t.TempDir()
	lower := strings.ToLower(filepath.ToSlash(dir))
	refusedBefore := strings.HasPrefix(lower, "/var/") || strings.HasPrefix(lower, "/tmp/") ||
		strings.HasPrefix(lower, "/home/") || strings.Contains(lower, ":/users/")
	if !refusedBefore && runtime.GOOS != "windows" {
		t.Skipf("t.TempDir() = %q is not under a previously-refused root, so this platform "+
			"cannot exercise the regression", dir)
	}

	path := filepath.Join(dir, "report.docx")
	if err := os.WriteFile(path, buildMinimalDOCX(t), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	meta, err := ExtractMetadata(path)
	if err != nil {
		t.Fatalf("ExtractMetadata(%s): %v — the path guard refused an ordinary temp path, "+
			"which is also every path under a Linux user's home directory", path, err)
	}
	if meta.Creator != "Jane Analyst" {
		t.Errorf("Creator = %q, want %q; core properties were not extracted", meta.Creator, "Jane Analyst")
	}
	if meta.LastModifiedBy != "Ops Reviewer" {
		t.Errorf("LastModifiedBy = %q, want %q", meta.LastModifiedBy, "Ops Reviewer")
	}
}

// TestCorePropertiesPartNameIsCaseInsensitive covers the metadata extractor's own
// share of the part-name problem: its file index was keyed by exact name, so
// "docProps/Core.xml" was a different part and the author vanished while the scan
// still reported success.
func TestCorePropertiesPartNameIsCaseInsensitive(t *testing.T) {
	for _, partName := range []string{
		"docProps/core.xml",
		"docProps/Core.xml",
		"DOCPROPS/CORE.XML",
		"docprops/core.xml",
	} {
		t.Run(partName, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "report.docx")
			if err := os.WriteFile(path, buildDOCXWithCorePart(t, partName), 0o600); err != nil {
				t.Fatalf("write fixture: %v", err)
			}

			meta, err := ExtractMetadata(path)
			if err != nil {
				t.Fatalf("ExtractMetadata: %v", err)
			}
			if meta.Creator != "Jane Analyst" {
				t.Errorf("Creator = %q, want %q: core properties at %q were not found, so the "+
					"document's author was never scanned", meta.Creator, "Jane Analyst", partName)
			}
		})
	}
}

const testXMLDecl = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`

func testCoreProps() string {
	return testXMLDecl +
		`<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" ` +
		`xmlns:dc="http://purl.org/dc/elements/1.1/">` +
		`<dc:creator>Jane Analyst</dc:creator>` +
		`<cp:lastModifiedBy>Ops Reviewer</cp:lastModifiedBy>` +
		`</cp:coreProperties>`
}

func buildMinimalDOCX(t *testing.T) []byte {
	t.Helper()
	return buildDOCXWithCorePart(t, "docProps/core.xml")
}

func buildDOCXWithCorePart(t *testing.T, corePart string) []byte {
	t.Helper()
	doc := testXMLDecl +
		`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` +
		`<w:body><w:p><w:r><w:t>Employee SSN 449-87-4100 on file.</w:t></w:r></w:p></w:body></w:document>`

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, p := range []struct{ name, body string }{
		{"_rels/.rels", testXMLDecl + `<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
			`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>` +
			`</Relationships>`},
		{corePart, testCoreProps()},
		{"word/document.xml", doc},
	} {
		w, err := zw.Create(p.name)
		if err != nil {
			t.Fatalf("zip create %q: %v", p.name, err)
		}
		if _, err := w.Write([]byte(p.body)); err != nil {
			t.Fatalf("zip write %q: %v", p.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

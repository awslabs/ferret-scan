// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package embedded

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestSafeExtNeverYieldsAPathComponent is the security contract.
//
// The value SafeExt returns is concatenated into a filesystem path when an embedded
// part is materialized as a temp file, and the input is a zip entry name, which is
// entirely producer-controlled. So whatever the entry is called, the output must be
// a dot followed by 1-10 characters drawn from [a-z0-9], or the ".bin" fallback, and
// nothing else — not "sanitized", but incapable of carrying a separator, a parent
// reference, a NUL or an absolute path in the first place (BSC1: validate untrusted
// input against an allowlist at the sink).
func TestSafeExtNeverYieldsAPathComponent(t *testing.T) {
	hostile := []string{
		"../../../../etc/passwd",
		"word/media/../../../../etc/passwd.jpg",
		"/etc/shadow.jpg",
		"C:\\Windows\\System32\\evil.jpg",
		"..\\..\\..\\evil.png",
		"word/media/x.jpg\x00.exe",
		"word/media/evil.jpg/../../escape.jpg",
		"word/media/.jpg",
		"word/media/....jpg",
		"word/media/x." + strings.Repeat("a", 4096),
		strings.Repeat("../", 512) + "deep.jpg",
		"word/media/x.JPG",
		"word/media/x.JpEg",
		"",
		".",
		"..",
		"/",
		"word/media/noextension",
		"word/media/trailingdot.",
		"word/embeddings/a!b.docx",
		"word/media/\n\r\t.png",
	}

	for _, name := range hostile {
		ext, ok := SafeExt(name)
		if !ok {
			// Refusing is always a safe answer; there is nothing to check.
			if ext != "" {
				t.Errorf("SafeExt(%q) returned ok=false but ext=%q; a rejected part must "+
					"yield no extension at all", name, ext)
			}
			continue
		}

		// The result must match the character class: a dot plus 1-10 ASCII
		// alphanumerics, lower-cased. That is the allowlist -- deliberately a class
		// rather than a table of known types, so an embedded .svg can be materialized
		// and handed to the pipeline instead of being dropped for not being enumerated.
		if !wellFormedExt(ext) {
			t.Errorf("SafeExt(%q) = %q, which is outside the permitted character class "+
				"(a dot plus 1-10 ASCII alphanumerics). The result must be built from the "+
				"allowlist, never passed through from the entry name.", name, ext)
		}
		if strings.ContainsAny(ext, `/\`) {
			t.Errorf("SafeExt(%q) = %q contains a path separator", name, ext)
		}
		if strings.Contains(ext, "..") {
			t.Errorf("SafeExt(%q) = %q contains a parent reference", name, ext)
		}
		if strings.ContainsRune(ext, 0) {
			t.Errorf("SafeExt(%q) = %q contains a NUL", name, ext)
		}
		if ext != strings.ToLower(ext) {
			t.Errorf("SafeExt(%q) = %q is not lower-cased", name, ext)
		}
		if !strings.HasPrefix(ext, ".") || len(ext) < 2 {
			t.Errorf("SafeExt(%q) = %q is not a well-formed extension. A bare dot reaches "+
				"this when the entry name ends in one, and filepath.Ext returns it "+
				"verbatim.", name, ext)
		}
		// The decisive property: joining it into a directory cannot escape that
		// directory.
		//
		// Compared with filepath.Dir rather than a hardcoded "/tmp/sandbox/" prefix.
		// The literal form passed on Unix and failed every case on Windows, where
		// filepath.Join yields \tmp\sandbox\embedded.bin -- a test bug, not a product
		// one, and the kind that makes a green local run hide a red CI.
		sandbox := filepath.Join(string(filepath.Separator)+"tmp", "sandbox")
		joined := filepath.Join(sandbox, "embedded"+ext)
		if filepath.Dir(joined) != sandbox {
			t.Errorf("SafeExt(%q) = %q escapes the sandbox when joined: %s (want parent %s)",
				name, ext, joined, sandbox)
		}
	}
}

// wellFormedExt mirrors SafeExt's permitted character class, so the test states the
// contract independently rather than calling the code under test to grade itself.
func wellFormedExt(ext string) bool {
	if len(ext) < 2 || len(ext) > 11 || ext[0] != '.' {
		return false
	}
	for i := 1; i < len(ext); i++ {
		c := ext[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// TestSafeExtFallsBackRatherThanDroppingThePart.
//
// A part whose name yields no usable extension must still be materialized, so the
// byte-sniffing preprocessors get a chance at it. Dropping it for the SHAPE OF ITS NAME
// is how coverage silently disappears: 6 extension-less embedded parts turned up in a
// 334-file corpus.
func TestSafeExtFallsBackRatherThanDroppingThePart(t *testing.T) {
	for _, name := range []string{
		"word/embeddings/oleObject1",              // no extension at all
		"word/media/trailingdot.",                 // filepath.Ext returns a bare "."
		"word/media/x." + strings.Repeat("a", 64), // absurdly long
		"word/media/weird.\u00e9\u00e8",           // non-ASCII
	} {
		ext, ok := SafeExt(name)
		if !ok {
			t.Errorf("SafeExt(%q) refused; the part would never be examined at all", name)
			continue
		}
		if ext != fallbackExt {
			t.Errorf("SafeExt(%q) = %q, want the fallback %q", name, ext, fallbackExt)
		}
		if !wellFormedExt(ext) {
			t.Errorf("the fallback %q is itself malformed", ext)
		}
	}
}

// TestSafeExtAdmitsTheRealSpellings — the guard must not reject legitimate parts.
//
// A rejection here is not merely inconvenient: an admitted-on-read, rejected-on-write
// part is a finding the tool reports and cannot redact.
func TestSafeExtAdmitsTheRealSpellings(t *testing.T) {
	for _, name := range []string{
		"word/media/image1.jpg",
		"word/media/image1.JPEG",
		"word/media/image1.png",
		"word/embeddings/oleObject1.docx",
		"xl/embeddings/oleObject1.xlsx",
		"ppt/embeddings/oleObject1.pptx",
		"word/embeddings/Microsoft_Word_97_-_2003_Document1.doc",
		"word/embeddings/attachment.pdf",
		"word/media/audio1.wav",
	} {
		if ext, ok := SafeExt(name); !ok {
			t.Errorf("SafeExt(%q) rejected a part the extractor admits (ext=%q); the read "+
				"and write sides must admit the same set", name, ext)
		}
	}
}

// TestRecursesIsDerivedFromKind keeps the two from drifting.
//
// Recurses used to be its own switch listing the container extensions a second
// time. An extension in one list and not the other is precisely the divergence this
// package exists to prevent, so the relationship is asserted rather than trusted.
func TestRecursesIsDerivedFromKind(t *testing.T) {
	for ext, kind := range kindByExt {
		name := "word/embeddings/part" + ext
		want := kind == KindDocument
		if got := Recurses(name); got != want {
			t.Errorf("Recurses(%q) = %v, but Kind = %q so it should be %v",
				name, got, kind, want)
		}
	}
	// A non-container must never be reported as recursing, or the depth bound would
	// be charged against leaves and legitimate nesting would be refused early.
	for _, name := range []string{
		"word/media/image1.jpg",
		"word/media/audio1.mp3",
		"word/embeddings/legacy.doc",
	} {
		if Recurses(name) {
			t.Errorf("Recurses(%q) = true for a leaf format", name)
		}
	}
}

// TestOpaqueFormatsAreAlwaysDispatchedNotSkipped.
//
// ResidueInspectable decides whether "a byte scan found nothing" may be read as "the
// part is clean". The polarity is what matters, and it is asymmetric:
//
//	inspectable  -> nothing found means leave the part alone (protects innocent content)
//	opaque       -> nothing found means we cannot see, so always dispatch (fails loudly
//	                if no redactor can rewrite it)
//
// Getting it backwards either vandalizes clean parts or ships a value hidden in a
// compressed stream.
func TestOpaqueFormatsAreAlwaysDispatchedNotSkipped(t *testing.T) {
	// PDF text lives in FlateDecode streams, so a byte scan proves nothing.
	if ResidueInspectable("word/embeddings/attachment.pdf") {
		t.Error("PDF is marked residue-inspectable, but its text is compressed. A value " +
			"inside a FlateDecode stream would be invisible to the byte scan, the part " +
			"would be skipped as harmless, and the container written with the value in it.")
	}

	// Audio tags are stored UNCOMPRESSED -- ID3v2 text frames, RIFF INFO, Vorbis
	// comments, MP4 ilst atoms. Marking them opaque would make every embedded clip
	// block its container even when the clip holds nothing, which is the mistake an
	// earlier revision of this file made.
	for _, name := range []string{
		"word/media/audio1.mp3",
		"word/media/audio1.wav",
		"word/media/audio1.m4a",
		"word/media/audio1.flac",
	} {
		if !ResidueInspectable(name) {
			t.Errorf("ResidueInspectable(%q) = false; audio tags are uncompressed, so "+
				"over-marking them opaque makes one harmless clip stop a whole document "+
				"from being written", name)
		}
	}

	// The formats whose text is in the clear, or which the scan inflates.
	for _, name := range []string{
		"word/media/image1.jpg",           // EXIF in the clear
		"word/embeddings/oleObject1.docx", // deflated, but the scan inflates members
		"word/embeddings/legacy.doc",      // OLE streams in the clear
	} {
		if !ResidueInspectable(name) {
			t.Errorf("ResidueInspectable(%q) = false for a format the scan can read", name)
		}
	}
}

// TestEveryAdmittedTypeIsInspectableOrOpaqueOnPurpose keeps the two sets in step.
//
// A type admitted for scanning is either provably clean-checkable or explicitly
// declared opaque. There is no third state, and a new admission silently landing in
// the wrong one is how a leak gets reintroduced.
func TestEveryAdmittedTypeIsInspectableOrOpaqueOnPurpose(t *testing.T) {
	declaredOpaque := map[string]bool{".pdf": true}

	for _, ext := range AdmittedExts() {
		name := "part" + ext
		gotOpaque := !ResidueInspectable(name)
		if gotOpaque != declaredOpaque[ext] {
			t.Errorf("%s: opaque=%v but this test declares opaque=%v. Reconcile the two: "+
				"an admitted type whose byte scan is unsound MUST be opaque so it is "+
				"always dispatched, and one whose scan is sound must NOT be, so clean "+
				"parts are left untouched.", ext, gotOpaque, declaredOpaque[ext])
		}
	}

	// And every declared-opaque entry must actually be admitted, or the entry is stale.
	admitted := map[string]bool{}
	for _, e := range AdmittedExts() {
		admitted[e] = true
	}
	for ext := range declaredOpaque {
		if !admitted[ext] {
			t.Errorf("%s is declared opaque but is not admitted; drop the stale entry", ext)
		}
	}
}

// TestXMLEscapeVariantsCoverEscapedSpellings.
//
// A value stored in an OOXML part is escaped, so the raw literal from a Match need not
// occur in the bytes. A residue scan looking only for the literal would call such a
// part clean.
func TestXMLEscapeVariantsCoverEscapedSpellings(t *testing.T) {
	got := XMLEscapeVariants("Ben & Jerry <b>")
	if len(got) != 2 {
		t.Fatalf("XMLEscapeVariants returned %d variants (%v), want the raw and escaped forms",
			len(got), got)
	}
	if got[0] != "Ben & Jerry <b>" {
		t.Errorf("variant[0] = %q, want the raw form first", got[0])
	}
	if !strings.Contains(got[1], "&amp;") || !strings.Contains(got[1], "&lt;") {
		t.Errorf("variant[1] = %q, want XML-escaped", got[1])
	}

	// A value needing no escaping must not allocate a duplicate.
	if plain := XMLEscapeVariants("452-11-9384"); len(plain) != 1 {
		t.Errorf("XMLEscapeVariants(%q) returned %d variants, want 1", "452-11-9384", len(plain))
	}
}

// TestKindIsCaseInsensitive — a zip entry name is producer-controlled data and
// nothing makes the conventional spelling normative. A case-sensitive predicate in
// this same area previously let a part named word/Document.xml be detected and then
// survive redaction in cleartext.
func TestKindIsCaseInsensitive(t *testing.T) {
	for _, pair := range [][2]string{
		{".JPG", ".jpg"},
		{".DOCX", ".docx"},
		{".PDF", ".pdf"},
		{".Doc", ".doc"},
	} {
		if got, want := Kind(pair[0]), Kind(pair[1]); got != want || got == "" {
			t.Errorf("Kind(%q) = %q but Kind(%q) = %q; they must agree and be non-empty",
				pair[0], got, pair[1], want)
		}
	}
}

// TestBoundsAreMeaningful guards the two numbers themselves.
//
// A zero or negative depth would refuse all descent (silently losing the coverage
// the read side already has); an enormous one would restore the unbounded recursion
// the bound was added to stop.
func TestBoundsAreMeaningful(t *testing.T) {
	if MaxDepth < 1 {
		t.Errorf("MaxDepth = %d refuses all descent, so no embedded part is ever examined "+
			"or redacted", MaxDepth)
	}
	if MaxDepth > 10 {
		t.Errorf("MaxDepth = %d is deep enough to be a decompression-bomb amplifier; the "+
			"bound exists because a 7KB document embedding itself nine times was followed "+
			"all nine levels", MaxDepth)
	}
	if BudgetBytes <= 0 {
		t.Errorf("BudgetBytes = %d would reject every document", BudgetBytes)
	}
}

// TestIsPartPathCoversBothConventions — "/media/" alone was not enough. Word stores
// an embedded DOCUMENT under word/embeddings/ as an OLE object, and that path was
// never considered, so a document attached to a document was invisible.
func TestIsPartPathCoversBothConventions(t *testing.T) {
	for _, name := range []string{
		"word/media/image1.jpg",
		"word/embeddings/oleObject1.docx",
		"xl/media/image1.png",
		"ppt/embeddings/oleObject1.xlsx",
		"WORD/MEDIA/IMAGE1.JPG",
	} {
		if !IsPartPath(name) {
			t.Errorf("IsPartPath(%q) = false; this part holds an embedded file", name)
		}
	}
	for _, name := range []string{
		"word/document.xml",
		"docProps/core.xml",
		"[Content_Types].xml",
		"mediafile.jpg", // no /media/ segment
	} {
		if IsPartPath(name) {
			t.Errorf("IsPartPath(%q) = true for a part that is not an embedded file", name)
		}
	}
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractofficelib

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/olefixture"
)

// Body text must be recovered from EVERY stream, not four allowlisted names.
//
// A .doc keeps a large fraction of its text outside WordDocument: 1Table/0Table hold
// revision marks, comments and fast-save text; Data and ObjectPool hold embedded
// content. The extractor allowlisted WordDocument/Workbook/Book/PowerPoint Document,
// so a value living anywhere else was never reported — and since only reported
// findings are redacted, it survived into the "redacted" copy in cleartext.
//
// Measured on a real 690KB .doc: 1Table held 14 recoverable printable runs no
// validator ever saw. That is the normal on-disk layout of an edited Word document,
// not a constructed attack. See #266.

// buildDoc writes an OLE compound file with the given streams.
//
// NOTE the fixture builder fits 3 streams plus the root in one directory sector, so
// tests stay at or below three.
func buildDoc(t *testing.T, streams []olefixture.Stream) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "legacy.doc")
	if err := os.WriteFile(path, olefixture.MustBuild(streams), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func extractBody(t *testing.T, path string) string {
	t.Helper()
	md := &Metadata{Properties: map[string]string{}}
	_, body, err := extractLegacyOfficeMetadata(path, md)
	if err != nil {
		t.Fatalf("extractLegacyOfficeMetadata: %v", err)
	}
	return body
}

// TestNonAllowlistedStreamsAreScanned is the regression.
func TestNonAllowlistedStreamsAreScanned(t *testing.T) {
	const (
		inBody   = "Cover page. Nothing sensitive in the main body stream at all."
		inTable  = "Reviewer comment: Employee SSN: 447-62-9183 confidential"
		inData   = "Embedded blob: contact sarah.morgan@example.com here"
		ssn      = "447-62-9183"
		email    = "sarah.morgan@example.com"
		bodyText = "Cover page"
	)

	body := extractBody(t, buildDoc(t, []olefixture.Stream{
		{Name: "WordDocument", Data: []byte(inBody)},
		{Name: "1Table", Data: []byte(inTable)},
		{Name: "Data", Data: []byte(inData)},
	}))

	if !strings.Contains(body, bodyText) {
		t.Errorf("WordDocument text missing from the recovered body; the allowlist removal "+
			"must not cost the streams that already worked. Got %d bytes.", len(body))
	}
	if !strings.Contains(body, ssn) {
		t.Errorf("the SSN in 1Table did not reach the recovered body. It is therefore never "+
			"reported, and an unreported value is never redacted — it stays in the output "+
			"file the report calls redacted. Body was %d bytes.", len(body))
	}
	if !strings.Contains(body, email) {
		t.Errorf("the value in the Data stream did not reach the recovered body")
	}
}

// TestOtherUnnamedStreamsAreAlsoScanned — the point is default-scan, not a longer list.
//
// The failure mode being fixed is "a stream nobody thought of", so a test that only
// covers 1Table and Data would let the next allowlist through.
func TestOtherUnnamedStreamsAreAlsoScanned(t *testing.T) {
	for _, name := range []string{"0Table", "ObjectPool", "Ctls", "MsoDataStore", "Xyzzy"} {
		t.Run(name, func(t *testing.T) {
			body := extractBody(t, buildDoc(t, []olefixture.Stream{
				{Name: "WordDocument", Data: []byte("Cover page only, nothing here.")},
				{Name: name, Data: []byte("Hidden away: Employee SSN: 447-62-9183 end")},
			}))
			if !strings.Contains(body, "447-62-9183") {
				t.Errorf("a value in the %q stream was not recovered. Body scanning must not "+
					"depend on recognising the stream name.", name)
			}
		})
	}
}

// TestPropertyStreamsStillParseAsProperties — the inversion must not swallow them.
//
// A property stream must reach applyLegacyProperties, not the printable-run
// scavenger. If it fell through to the default branch, the author would stop
// appearing as AUTHOR_INFO metadata and instead surface as loose body text with no
// field attribution.
func TestPropertyStreamsStillParseAsProperties(t *testing.T) {
	const author = "Margaret Chen"
	path := buildDoc(t, []olefixture.Stream{
		{Name: "WordDocument", Data: []byte("Cover page only.")},
		{Name: "\x05SummaryInformation", Data: olefixture.SummaryInformation(map[uint32]string{4: author})},
	})

	md := &Metadata{Properties: map[string]string{}}
	got, _, err := extractLegacyOfficeMetadata(path, md)
	if err != nil {
		t.Fatalf("extractLegacyOfficeMetadata: %v", err)
	}
	if got.Author != author {
		t.Errorf("Author = %q, want %q: the property stream must still be PARSED as "+
			"properties rather than scavenged as body text", got.Author, author)
	}
}

// TestStructuralBytesYieldNothing — the conservative-scavenger guarantee.
//
// Scanning every stream is only safe because recoverPrintableRuns emits nothing for
// bookkeeping bytes. If it started emitting them, every legacy document would gain
// junk findings, which is its own kind of harm.
func TestStructuralBytesYieldNothing(t *testing.T) {
	// Binary noise with no printable run at or above the minimum length.
	noise := make([]byte, 4096)
	for i := range noise {
		noise[i] = byte(i % 7) // all below 0x20, never printable
	}
	body := extractBody(t, buildDoc(t, []olefixture.Stream{
		{Name: "WordDocument", Data: []byte("Real content here for the body.")},
		{Name: "Data", Data: noise},
	}))
	if strings.Count(body, "\n") > 3 {
		t.Errorf("binary noise produced %d lines of recovered text; the scavenger must stay "+
			"conservative or every legacy document gains junk findings:\n%q",
			strings.Count(body, "\n"), body)
	}
}

// TestPerStreamSizeCapIsEnforced guards the bomb bound.
//
// An OLE container declares its own stream sizes, so an unbounded io.ReadAll here
// would be a decompression-bomb hole. That bound matters MORE now that every stream is
// scanned rather than four allowlisted names.
//
// Nothing asserted it before: raising the cap to 1<<62 compiled and the whole suite
// still passed. The constant became a var purely so this test can lower it and observe
// the truncation, rather than needing a 50MB fixture.
func TestPerStreamSizeCapIsEnforced(t *testing.T) {
	original := maxLegacyStreamBytes
	t.Cleanup(func() { maxLegacyStreamBytes = original })

	// A stream far larger than the cap we are about to set.
	const marker = "TAIL-MARKER-SHOULD-NOT-APPEAR"
	big := strings.Repeat("A", 4096) + marker
	path := buildDoc(t, []olefixture.Stream{
		{Name: "WordDocument", Data: []byte("Cover page only.")},
		{Name: "1Table", Data: []byte(big)},
	})

	// Uncapped first, to prove the fixture's tail IS reachable.
	if body := extractBody(t, path); !strings.Contains(body, marker) {
		t.Fatalf("the fixture's tail is not recoverable even uncapped; this test would " +
			"pass vacuously")
	}

	maxLegacyStreamBytes = 64
	body := extractBody(t, path)
	if strings.Contains(body, marker) {
		t.Errorf("with the cap at 64 bytes the stream tail still reached the body, so the "+
			"per-stream io.LimitReader is not bounding the read. Body was %d bytes.", len(body))
	}
}

// TestDefaultStreamCapIsSane asserts the shipped VALUE, not just the mechanism.
//
// TestPerStreamSizeCapIsEnforced lowers the cap to observe truncation, which proves
// io.LimitReader is wired — but because it sets the value explicitly, it keeps passing
// when the DEFAULT is raised. Measured: a mutation setting the default to 1<<62
// compiled and that test still passed. Both assertions are needed.
func TestDefaultStreamCapIsSane(t *testing.T) {
	const (
		floor   = int64(1 << 20)   // 1MB: below this, real documents get truncated
		ceiling = int64(512 << 20) // 512MB: above this it is not a bound worth having
	)
	if maxLegacyStreamBytes < floor || maxLegacyStreamBytes > ceiling {
		t.Errorf("maxLegacyStreamBytes = %d, want between %d and %d. An OLE container "+
			"declares its own stream sizes, so this is the only thing standing between a "+
			"crafted .doc and an unbounded read — and it now applies to EVERY stream, not "+
			"the four the old allowlist named.", maxLegacyStreamBytes, floor, ceiling)
	}
}

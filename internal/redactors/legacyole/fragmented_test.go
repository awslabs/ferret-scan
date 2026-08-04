// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package legacyole

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/richardlehane/mscfb"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/olefixture"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// A CFB stream is a CHAIN of sectors that need not be adjacent or in order — which
// is exactly what a real allocator leaves behind after a document has been edited.
// The extractor reads through mscfb, so it sees each stream REASSEMBLED into
// contiguous logical bytes and reports matches found there.
//
// Redaction therefore has to work in the same coordinate space. Searching the raw
// file instead misses any value straddling a boundary between two non-adjacent
// sectors, and the failure is the worst kind: the value IS reported, so the report
// says it was handled, while the output still contains it.
//
// Measured before the fix, on a 10-sector .doc whose logical sectors 1 and 2 sat at
// disk sectors 12 and 4: the extractor reported an SSN at logical offset 1019, the
// raw file held no contiguous copy of it, and RedactDocument returned Success=true
// with ZERO mappings while the SSN stayed in the output.

// fragmentedFixture returns a .doc whose body stream is laid out so a value spans
// two distant disk sectors, plus the logical offset of that value.
//
// The stream must be at or over the 4096-byte cutoff or a reader routes it through
// the mini FAT and the sector placement is ignored — which would make this test
// vacuous rather than failing.
func fragmentedFixture(t *testing.T, secret string) []byte {
	t.Helper()

	body := bytes.Repeat([]byte{' '}, 5120) // 10 sectors, over the mini cutoff
	copy(body[0:], "Employee record. Filler text to keep the run long enough.")
	// Straddle the logical sector-1/sector-2 boundary at offset 1024: the first
	// half of the value lands in one sector, the rest in the next.
	copy(body[1014:], "SSN: "+secret+" end of record here.")
	copy(body[1100:], "trailing filler text so the run passes the minimum length")

	// Logical order 3,12,4,... so logical sectors 1 and 2 are at disk 12 and 4.
	raw, err := olefixture.BuildFragmented([]olefixture.FragmentedStream{{
		Name:    olefixture.StreamWordDocument,
		Data:    body,
		Sectors: []uint32{3, 12, 4, 5, 6, 7, 8, 9, 10, 11},
	}})
	if err != nil {
		t.Fatalf("building the fragmented fixture: %v", err)
	}
	return raw
}

func TestRedaction_ValueStraddlingNonAdjacentSectors(t *testing.T) {
	const secret = "449-87-4100"
	raw := fragmentedFixture(t, secret)

	// --- the two preconditions that keep this test honest --------------------
	//
	// Without both, it could pass while exercising nothing: if the value were not
	// in the logical stream the extractor would never report it, and if it WERE
	// contiguous in the raw file a raw-file search would find it anyway.
	doc, err := mscfb.New(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("mscfb rejected the fragmented fixture: %v", err)
	}
	var logical []byte
	for entry, e := doc.Next(); e == nil; entry, e = doc.Next() {
		if entry.Name == olefixture.StreamWordDocument {
			logical, _ = io.ReadAll(entry)
		}
	}
	if !bytes.Contains(logical, []byte(secret)) {
		t.Fatalf("fixture invalid: the logical stream (%d bytes) does not contain the "+
			"value, so the extractor would never report it and this test would assert "+
			"nothing", len(logical))
	}
	if bytes.Contains(raw, []byte(secret)) {
		t.Fatal("fixture invalid: the value IS contiguous in the raw file, so a raw-file " +
			"search would find it and this test would not exercise the chain-aware path")
	}

	// --- redact and read the output back through mscfb -----------------------
	dir := t.TempDir()
	in := filepath.Join(dir, "frag.doc")
	out := filepath.Join(dir, "redacted.doc")
	if err := os.WriteFile(in, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	r := NewLegacyOLERedactor(nil, nil)
	res, err := r.RedactDocument(in, out, []detector.Match{
		{Text: secret, Type: "SSN", Confidence: 100},
	}, redactors.RedactionFormatPreserving)
	if err != nil {
		t.Fatalf("RedactDocument: %v", err)
	}
	if len(res.RedactionMap) == 0 {
		t.Fatal("the value was not located at all, so RedactDocument reported success " +
			"with no mappings and shipped a cleartext copy")
	}

	after := streamContents(t, out)
	body, ok := after[olefixture.StreamWordDocument]
	if !ok {
		t.Fatal("no WordDocument stream in the output; the assertion below would be vacuous")
	}
	if bytes.Contains(body, []byte(secret)) {
		t.Errorf("the value survives at logical offset %d of the redacted stream — it was "+
			"REPORTED as redacted, which is worse than not detecting it",
			bytes.Index(body, []byte(secret)))
	}
}

// The container must survive a write that spans two sectors: a replacement written
// through the chain touches two distant regions, and getting the second half's
// offset wrong would corrupt whatever sits there.
func TestRedaction_FragmentedWritePreservesContainer(t *testing.T) {
	const secret = "449-87-4100"
	raw := fragmentedFixture(t, secret)

	dir := t.TempDir()
	in := filepath.Join(dir, "frag.doc")
	out := filepath.Join(dir, "redacted.doc")
	if err := os.WriteFile(in, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	r := NewLegacyOLERedactor(nil, nil)
	if _, err := r.RedactDocument(in, out, []detector.Match{
		{Text: secret, Type: "SSN", Confidence: 100},
	}, redactors.RedactionFormatPreserving); err != nil {
		t.Fatalf("RedactDocument: %v", err)
	}

	redacted, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(redacted) != len(raw) {
		t.Fatalf("output is %d bytes, input was %d", len(redacted), len(raw))
	}
	// The header and the FAT/directory/mini-FAT sectors must be byte-identical:
	// only stream content is eligible for overwriting.
	const structural = olefixture.SectorSize * 4 // header + FAT + dir + mini FAT
	if !bytes.Equal(raw[:structural], redacted[:structural]) {
		t.Error("a structural sector was modified; a chain-aware write must land only in " +
			"stream content or the container becomes unreadable")
	}

	// Every stream must still read back at its declared size.
	before := streamContents(t, in)
	after := streamContents(t, out)
	for name, b := range before {
		a, ok := after[name]
		if !ok {
			t.Errorf("stream %q disappeared from the output", name)
			continue
		}
		if len(a) != len(b) {
			t.Errorf("stream %q changed size from %d to %d bytes", name, len(b), len(a))
		}
	}
}

// A non-ASCII value stored as UTF-16LE is the ordinary case for legacy Word
// property values, and it was invisible to redaction: toUTF16LE returned nil for
// any non-ASCII rune, so the wide pass was skipped, nothing was found, and
// RedactDocument reported Success with zero mappings while the name stayed in the
// output. Most of the world's names are affected, so this is not an edge case.
func TestRedaction_NonASCIIPropertyValueIsRemoved(t *testing.T) {
	for _, author := range []string{
		"Jane Analyst", // ASCII control: must keep working
		"José Ramírez",
		"Zoë Müller",
		"Björn Öhlund",
		"日本語の名前",
	} {
		t.Run(author, func(t *testing.T) {
			// The property stream stores names as UTF-16LE, which is where the wide
			// pass is the only thing that can reach them.
			summary := olefixture.SummaryInformationWide(map[uint32]string{
				olefixture.PropAuthor: author,
			})
			onDisk := olefixture.UTF16LE(author)
			if len(onDisk) == 0 || !bytes.Contains(summary, onDisk) {
				t.Fatalf("fixture invalid: the UTF-16LE form of %q is not in the property "+
					"stream, so this test would assert nothing", author)
			}

			dir := t.TempDir()
			in := filepath.Join(dir, "wide.doc")
			out := filepath.Join(dir, "redacted.doc")
			if err := os.WriteFile(in, olefixture.MustBuild([]olefixture.Stream{
				{Name: olefixture.StreamWordDocument, Data: []byte("padding text long enough to recover")},
				{Name: olefixture.StreamSummaryInformation, Data: summary},
			}), 0o600); err != nil {
				t.Fatal(err)
			}

			r := NewLegacyOLERedactor(nil, nil)
			res, err := r.RedactDocument(in, out, []detector.Match{
				{Text: author, Type: "AUTHOR_INFO", Confidence: 60},
			}, redactors.RedactionFormatPreserving)
			if err != nil {
				t.Fatalf("RedactDocument: %v", err)
			}
			if len(res.RedactionMap) == 0 {
				t.Fatalf("%q was not located; the redactor reported success with no "+
					"mappings and the name stays in the output", author)
			}

			for name, content := range streamContents(t, out) {
				if bytes.Contains(content, onDisk) {
					t.Errorf("%q survives as UTF-16LE in stream %q of the redacted output",
						author, name)
				}
			}
		})
	}
}

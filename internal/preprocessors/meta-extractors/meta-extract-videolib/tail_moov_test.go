// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractvideolib

import (
	"context"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

// countingReaderAt wraps a file and records every byte the walk actually reads.
//
// This is the only way to state the property that matters: a movie's media payload must never be
// read. A timing assertion could not distinguish "skipped by arithmetic" from "read quickly from
// page cache", and it would flake on CI besides.
type countingReaderAt struct {
	r     io.ReaderAt
	bytes int64
	reads int64
}

func (c *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := c.r.ReadAt(p, off)
	atomic.AddInt64(&c.bytes, int64(n))
	atomic.AddInt64(&c.reads, 1)
	return n, err
}

// ssnFixture is a value the SSN validator recognises, so a recovered moov is provable by a finding
// rather than only by a populated struct.
const ssnFixture = "452-11-9384"

// A moov after the mdat must be found, and must produce exactly what the same moov produces when it
// is written first.
//
// This is #398. ffmpeg and every camera measured write moov LAST by default; faststart is a second
// pass. The previous walk charged a 10MB budget for every box it STEPPED OVER — including the mdat
// it skipped with a bare seek and never read — so a 12MB movie exhausted a "metadata" allowance
// while costing no memory, then stopped with a bare break and returned nil. The file was reported as
// a complete, clean scan.
//
// The two layouts are compared against each other rather than against a hardcoded string, so the
// test also fails if some future change makes one layout's extracted text differ from the other's.
func TestTailMoovIsScannedLikeAFrontMoov(t *testing.T) {
	dir := t.TempDir()

	// 12MB of declared mdat: past the old 10MB budget, and created as a hole so the fixture costs
	// no memory and no disk.
	const mdatBytes = 12 << 20
	udta := []byte{}
	udta = append(udta, textAtom(itunesAtom("cmt"), "Employee SSN "+ssnFixture)...)
	udta = append(udta, textAtom(itunesAtom("ART"), "Marcus Whitfield")...)

	tail := buildISOFile(t, filepath.Join(dir, "tail.mp4"), mdatBytes, false, udta)
	front := buildISOFile(t, filepath.Join(dir, "front.mp4"), mdatBytes, true, udta)

	tailMeta, err := ExtractVideoMetadataWithContext(context.Background(), tail)
	if err != nil {
		t.Fatalf("tail-moov extraction: %v", err)
	}
	frontMeta, err := ExtractVideoMetadataWithContext(context.Background(), front)
	if err != nil {
		t.Fatalf("front-moov extraction: %v", err)
	}

	if !strings.Contains(tailMeta.Description, ssnFixture) {
		t.Errorf("Description = %q, want it to contain the SSN: the moov sits past the old 10MB "+
			"budget, so its metadata was never read and the file scanned clean", tailMeta.Description)
	}
	if tailMeta.Author == "" {
		t.Error("Author is empty for the tail-moov file")
	}

	// A healthy file must not warn, or the disclosure becomes noise operators learn to ignore.
	if tailMeta.ExtractionWarning != "" {
		t.Errorf("a well-formed tail-moov file produced a warning (%q); only genuine coverage loss "+
			"may disclose", tailMeta.ExtractionWarning)
	}

	if tailMeta.ToProcessedContent() != frontMeta.ToProcessedContent() {
		t.Errorf("the two layouts produced different text.\n tail: %q\nfront: %q\nA file's box order "+
			"must not change what is reported", tailMeta.ToProcessedContent(), frontMeta.ToProcessedContent())
	}
}

// The media payload must never be read, and the walk's reads must be bounded by the metadata it
// parses rather than by the file's size.
//
// Asserted by counting bytes, not by timing. A 200MB declared mdat is stepped over with arithmetic:
// no read, no allocation, not even a seek.
func TestSkippedBoxesAreNeverRead(t *testing.T) {
	dir := t.TempDir()
	const mdatBytes = 200 << 20

	udta := textAtom(itunesAtom("cmt"), "Employee SSN "+ssnFixture)
	path := buildISOFile(t, filepath.Join(dir, "big.mp4"), mdatBytes, false, udta)

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	counter := &countingReaderAt{r: f}
	// Walk the top level exactly as the extractor does, through the instrumented reader.
	var cur int64
	var boxes int
	for cur+BoxHeaderSize <= info.Size() {
		boxType, total, hdrLen, err := readTopLevelHeaderAt(counter, cur, info.Size())
		if err != nil {
			t.Fatalf("header at %d: %v", cur, err)
		}
		boxes++
		if boxType == "moov" {
			data := make([]byte, total-hdrLen)
			if _, err := io.ReadFull(io.NewSectionReader(counter, cur+hdrLen, total-hdrLen), data); err != nil {
				t.Fatalf("read moov: %v", err)
			}
		}
		cur += total
	}

	// Headers plus the moov payload only. Nothing near the 200MB of declared media.
	const generousCeiling = 64 << 10
	if counter.bytes > generousCeiling {
		t.Errorf("the walk read %d bytes from a file with %d bytes of declared media (%d boxes): a "+
			"skipped box is being READ instead of stepped over, which is the 100MB-per-8-byte-header "+
			"allocation this fix removed", counter.bytes, int64(mdatBytes), boxes)
	}
	if counter.bytes == 0 {
		t.Fatal("the walk read nothing at all, so the bound above is vacuous")
	}
}

// Allocation must be bounded by the moov, not by the file.
//
// This is the shape of the repo's 4KB-file-to-8.62GB-RSS incident: an allocation sized from a
// DECLARED number. Measured end to end before this fix, 16 files of 80 bytes each whose ftyp declared
// 100MB drove 631MB of resident memory at exit 0 with no disclosure.
func TestWalkAllocationIsBoundedByMoovNotFileSize(t *testing.T) {
	dir := t.TempDir()
	const mdatBytes = 64 << 20

	udta := textAtom(itunesAtom("cmt"), "Employee SSN "+ssnFixture)
	path := buildISOFile(t, filepath.Join(dir, "alloc.mp4"), mdatBytes, false, udta)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	meta, err := ExtractVideoMetadataWithContext(context.Background(), path)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}

	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc

	const ceiling = 8 << 20 // the moov here is a few hundred bytes; 8MB is enormous headroom
	if allocated > ceiling {
		t.Errorf("extracting a file with %d bytes of DECLARED media allocated %d bytes (> %d): the "+
			"allocation is sized from a declared number rather than from what the file really holds",
			int64(mdatBytes), allocated, ceiling)
	}
	if !strings.Contains(meta.Description, ssnFixture) {
		t.Error("the SSN was not recovered, so the allocation bound above is vacuous — it would " +
			"hold on an extractor that parses nothing")
	}
}

// Every declared size must be checked against the real end of the file, and a truncation must be
// disclosed rather than silently swallowed.
//
// Case (b) is the one that matters most: an over-declared MOOV must still yield its findings AND
// warn. A fix that only disclosed would lose values a clamp would have kept.
func TestDeclaredSizeIsCheckedAgainstTheRealFile(t *testing.T) {
	dir := t.TempDir()

	// writeRaw assembles a file from literal bytes, so a header can lie about its size.
	writeRaw := func(name string, parts ...[]byte) string {
		p := filepath.Join(dir, name)
		var all []byte
		for _, b := range parts {
			all = append(all, b...)
		}
		if err := os.WriteFile(p, all, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}
	header := func(size uint32, kind string) []byte {
		h := make([]byte, 8)
		binary.BigEndian.PutUint32(h[0:4], size)
		copy(h[4:8], kind)
		return h
	}
	ftyp := box(atom("ftyp"), []byte("isom\x00\x00\x02\x00isomiso2mp41"))
	udtaPayload := box(atom("udta"), textAtom(itunesAtom("cmt"), "Employee SSN "+ssnFixture))

	t.Run("mdat declares more than the file holds", func(t *testing.T) {
		p := writeRaw("overdeclared.mp4", ftyp, header(50<<20, "mdat"), make([]byte, 1024))
		meta, err := ExtractVideoMetadataWithContext(context.Background(), p)
		if err != nil {
			t.Fatalf("extract: %v", err)
		}
		if meta.ExtractionWarning == "" {
			t.Error("an mdat declaring 50MB inside a 1KB file produced no warning: the walk was cut " +
				"short and nothing said so")
		}
	})

	t.Run("moov declares more than the file holds but its values survive", func(t *testing.T) {
		// moov claims 90MB; only the real udta bytes follow.
		p := writeRaw("moovover.mp4", ftyp, header(90<<20, "moov"), udtaPayload)
		meta, err := ExtractVideoMetadataWithContext(context.Background(), p)
		if err != nil {
			t.Fatalf("extract: %v", err)
		}
		if !strings.Contains(meta.Description, ssnFixture) {
			t.Errorf("Description = %q: the over-declared moov was abandoned instead of clamped to "+
				"the file's real end, so values that are genuinely present were lost",
				meta.Description)
		}
		if meta.ExtractionWarning == "" {
			t.Error("the truncation was not disclosed, so the operator cannot tell that more " +
				"metadata may have been missing")
		}
	})

	t.Run("declared size smaller than the header", func(t *testing.T) {
		// Stepping by 4 would walk MISALIGNED through the rest of the file. This is the spin/
		// misalignment class this file already fixed once, in its inner walkers.
		//
		// The warning's CAUSE is asserted, not merely its presence. Without the guard the walk
		// wanders into the udta bytes, eventually reads a garbage header whose declared size runs
		// past the end, and warns about THAT instead — a true disclosure under a false heading,
		// which a presence-only assertion accepts. Removing the guard survived exactly that way.
		p := writeRaw("undersize.mp4", ftyp, header(4, "junk"), udtaPayload)
		meta, err := ExtractVideoMetadataWithContext(context.Background(), p)
		if err != nil {
			t.Fatalf("extract: %v", err)
		}
		if !strings.Contains(meta.ExtractionWarning, "smaller than its") {
			t.Errorf("warning = %q, want it to name the under-length box: a box cannot be smaller "+
				"than its own header, and stepping by that size walks the rest of the file "+
				"misaligned", meta.ExtractionWarning)
		}
	})

	t.Run("size 0 mdat is terminal and disclosed", func(t *testing.T) {
		// Size 0 legally means "extends to the end of the file", so anything after it is
		// unreachable. Disclose rather than guess.
		p := writeRaw("size0.mp4", ftyp, header(0, "mdat"), make([]byte, 4096), box(atom("moov"), udtaPayload))
		meta, err := ExtractVideoMetadataWithContext(context.Background(), p)
		if err != nil {
			t.Fatalf("extract: %v", err)
		}
		if meta.ExtractionWarning == "" {
			t.Error("a size-0 mdat swallowing the rest of the file produced no warning")
		}
	})

	t.Run("64-bit largesize near the int64 ceiling", func(t *testing.T) {
		// The EOF bound must be written as subtraction. Phrased as `off+total > fileSize` it
		// OVERFLOWS to a negative number here, the comparison is false, and the absurd size is
		// accepted — after which `cur += total` sends the offset negative too.
		//
		// The warning's CAUSE is asserted rather than its presence: the overflowing form still
		// produces a warning, because a read at a negative offset fails and the walk reports that it
		// could not follow the structure. Presence alone therefore cannot tell the two apart, and
		// the addition form survived mutation until this assertion named the over-declaration.
		big := make([]byte, 16)
		binary.BigEndian.PutUint32(big[0:4], 1) // size == 1: a 64-bit size follows
		copy(big[4:8], "mdat")
		binary.BigEndian.PutUint64(big[8:16], 1<<63-5)
		p := writeRaw("largesize.mp4", ftyp, big, udtaPayload)

		meta, err := ExtractVideoMetadataWithContext(context.Background(), p)
		if err != nil {
			t.Fatalf("extract: %v", err)
		}
		if !strings.Contains(meta.ExtractionWarning, "declares more bytes than the file holds") {
			t.Errorf("warning = %q, want it to name the over-declaration. A size of 2^63-5 must be "+
				"refused by comparing against the bytes REMAINING, not by adding it to the current "+
				"offset", meta.ExtractionWarning)
		}
	})

	t.Run("64-bit largesize beyond int64 entirely", func(t *testing.T) {
		big := make([]byte, 16)
		binary.BigEndian.PutUint32(big[0:4], 1)
		copy(big[4:8], "mdat")
		binary.BigEndian.PutUint64(big[8:16], ^uint64(0)) // 2^64-1: not representable as int64
		p := writeRaw("hugesize.mp4", ftyp, big, udtaPayload)

		meta, err := ExtractVideoMetadataWithContext(context.Background(), p)
		if err != nil {
			t.Fatalf("extract: %v", err)
		}
		if !strings.Contains(meta.ExtractionWarning, "unrepresentable") {
			t.Errorf("warning = %q, want it to name the unrepresentable size: converting 2^64-1 to "+
				"int64 yields -1, which every subsequent bound check would treat as harmless",
				meta.ExtractionWarning)
		}
	})
}

// Walking must be bounded by work, and hitting that bound must be disclosed rather than truncating
// silently.
//
// Progress-based, with no wall-clock assertion, so it is valid on slow or loaded CI. The budget is
// deliberately large enough that a legitimately fragmented file passes: a tighter 100k ceiling was
// tried and rejected because it LOST a finding the previous code found.
func TestBoxCountBudgetDisclosesRatherThanTruncatingSilently(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "manyboxes.mp4")

	f, err := os.Create(p)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	ftyp := box(atom("ftyp"), []byte("isom\x00\x00\x02\x00isomiso2mp41"))
	if _, err := f.Write(ftyp); err != nil {
		t.Fatalf("write: %v", err)
	}
	free := make([]byte, 8)
	binary.BigEndian.PutUint32(free[0:4], 8)
	copy(free[4:8], "free")
	// One past the budget, so the moov after them is unreachable.
	for i := 0; i <= MaxTopLevelBoxes; i++ {
		if _, err := f.Write(free); err != nil {
			t.Fatalf("write free box %d: %v", i, err)
		}
	}
	if _, err := f.Write(box(atom("moov"), box(atom("udta"), textAtom(itunesAtom("cmt"), "Employee SSN "+ssnFixture)))); err != nil {
		t.Fatalf("write moov: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	meta, err := ExtractVideoMetadataWithContext(context.Background(), p)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if meta.ExtractionWarning == "" {
		t.Error("the box budget was exhausted with no warning: the walk stopped early and the file " +
			"would be reported as completely scanned")
	}
	if !strings.Contains(meta.ExtractionWarning, "top-level boxes") {
		t.Errorf("warning = %q, want it to name the box budget so an operator can tell this from a "+
			"malformed file", meta.ExtractionWarning)
	}
}

// A file with no moov at all yields no metadata, and that has to be said rather than reported as a
// clean, complete scan.
func TestNoMoovIsDisclosed(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "nomoov.mp4"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := f.Write(box(atom("ftyp"), []byte("isom\x00\x00\x02\x00isomiso2mp41"))); err != nil {
		t.Fatalf("write: %v", err)
	}
	mdat := make([]byte, 8)
	binary.BigEndian.PutUint32(mdat[0:4], 8+4096)
	copy(mdat[4:8], "mdat")
	if _, err := f.Write(mdat); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := f.Truncate(int64(len(box(atom("ftyp"), []byte("isom\x00\x00\x02\x00isomiso2mp41")))) + 8 + 4096); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	name := f.Name()
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	meta, err := ExtractVideoMetadataWithContext(context.Background(), name)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if meta.ExtractionWarning == "" {
		t.Error("a file with no moov produced no warning: an empty-but-successful result is " +
			"indistinguishable from a video that genuinely carries no metadata")
	}
	if !strings.Contains(meta.ExtractionWarning, "moov") {
		t.Errorf("warning = %q, want it to name the missing moov", meta.ExtractionWarning)
	}
}

// Every warning reaches stderr and every machine format with no --show-match to gate it, so none of
// them may carry a metadata value.
func TestExtractionWarningsCarryNoPayload(t *testing.T) {
	dir := t.TempDir()
	secret := "Employee SSN " + ssnFixture
	udtaPayload := box(atom("udta"), textAtom(itunesAtom("cmt"), secret))

	header := func(size uint32, kind string) []byte {
		h := make([]byte, 8)
		binary.BigEndian.PutUint32(h[0:4], size)
		copy(h[4:8], kind)
		return h
	}
	ftyp := box(atom("ftyp"), []byte("isom\x00\x00\x02\x00isomiso2mp41"))

	fixtures := map[string][][]byte{
		"over-declared moov": {ftyp, header(90<<20, "moov"), udtaPayload},
		"under-length box":   {ftyp, header(4, "junk"), udtaPayload},
		"size-0 mdat":        {ftyp, header(0, "mdat"), make([]byte, 512), box(atom("moov"), udtaPayload)},
		"no moov":            {ftyp, header(8+512, "mdat"), make([]byte, 512)},
	}

	for name, parts := range fixtures {
		t.Run(name, func(t *testing.T) {
			var all []byte
			for _, b := range parts {
				all = append(all, b...)
			}
			p := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".mp4")
			if err := os.WriteFile(p, all, 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}

			meta, err := ExtractVideoMetadataWithContext(context.Background(), p)
			if err != nil {
				t.Fatalf("extract: %v", err)
			}
			if meta.ExtractionWarning == "" {
				t.Skip("no warning produced for this fixture")
			}
			for _, forbidden := range []string{ssnFixture, secret, "Marcus"} {
				if strings.Contains(meta.ExtractionWarning, forbidden) {
					t.Errorf("warning contains %q: %q. This string reaches stderr and every machine "+
						"format with no --show-match to gate it", forbidden, meta.ExtractionWarning)
				}
			}
		})
	}
}

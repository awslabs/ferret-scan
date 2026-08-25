// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractexiflib

import (
	"bytes"
	"compress/zlib"
	"io"
	"sync/atomic"
	"testing"
)

// #491: the 4MB total budget was consulted AFTER parsePNGText, which is where the zlib inflation
// happens.
//
// So the WORK was bounded by maxPNGChunks * maxPNGTextChunkBytes — 65,536 x 1MB, i.e. 64GB of
// decompression — rather than by the 4MB of text actually kept. Both caps existed and were
// individually correct; they simply did not compose in that order.
//
// Measured on valid PNGs whose only additions are N zTXt chunks, each ~1KB compressed and inflating to
// exactly the 1MB per-chunk cap:
//
//	N chunks   file size   pre-#480      after #480     with this fix
//	2,000      2.1 MB      0.09s/31MB    7.95s/146MB    5.6s
//	20,000     21.2 MB     0.08s/31MB    29.94s/117MB   6.1s
//	65,535     69.4 MB     0.09s/30MB    81.27s/135MB   5.7s
//
// After the fix the cost is FLAT across a 14,000x range in chunk count, because it is bounded by the
// 4MB cap rather than by the file: recovered text is exactly 4.00MB in every case. The residual ~5s is
// the validators reading that 4MB, which is what any PNG legitimately carrying 4MB of text costs, and
// is the separately-tracked systemic quadratic rather than anything this reader controls.
//
// The assertion here is deliberately NOT a clock. Wall-clock bounds are flaky on shared CI, so what is
// pinned is the WORK: bytes actually read from the file, via a counting ReaderAt. That also proves the
// check moved ahead of the READ and not merely ahead of the parse.

// countingReaderAt records how many bytes a reader was asked for.
type countingReaderAt struct {
	inner io.ReaderAt
	bytes atomic.Int64
	calls atomic.Int64
}

func (c *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	c.calls.Add(1)
	n, err := c.inner.ReadAt(p, off)
	c.bytes.Add(int64(n))
	return n, err
}

// bombPNG builds a valid PNG with n zTXt chunks, each inflating to the 1MB per-chunk cap.
func bombPNG(t *testing.T, n int) []byte {
	t.Helper()
	var comp bytes.Buffer
	zw := zlib.NewWriter(&comp)
	if _, err := zw.Write(bytes.Repeat([]byte{'A'}, maxPNGTextChunkBytes)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	chunks := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		// Distinct keywords, so tags do not overwrite one another and the total really accumulates.
		kw := []byte{'K', byte('A' + i%26), byte('a' + (i/26)%26), byte('0' + (i/676)%10)}
		body := append(append(kw, 0, 0), comp.Bytes()...)
		chunks = append(chunks, pngChunk("zTXt", body))
	}
	return pngWith(chunks...)
}

// TestBudgetIsCheckedBeforeTheChunkIsEvenRead is the reported defect, asserted on work done.
//
// 64 chunks of 1MB is 16x the 4MB budget, so at most a handful may be read. If the budget were checked
// after the parse, all 64 would be read AND inflated.
func TestBudgetIsCheckedBeforeTheChunkIsEvenRead(t *testing.T) {
	png := bombPNG(t, 64)
	c := &countingReaderAt{inner: bytes.NewReader(png)}

	tags := map[string]string{}
	extractPNGText(c, int64(len(png)), tags)

	read := c.bytes.Load()
	// Every chunk is ~1KB compressed, so reading all 64 payloads is ~64KB plus headers. Four payloads
	// fill the 4MB budget, so a correct reader touches roughly 4KB of payload plus 64 headers.
	const ceiling = 32 * 1024
	if read > ceiling {
		t.Errorf("read %d bytes from a PNG whose chunks are 16x the %d-byte text budget; a reader that "+
			"consults the budget first touches well under %d. Reading them all means inflating them "+
			"all: 64GB of decompression is reachable that way.",
			read, maxPNGTextTotalBytes, ceiling)
	}

	// NON-VACUITY: the reader must actually have recovered text, or a zero above proves nothing.
	if len(tags) == 0 {
		t.Fatal("no tags recovered at all, so the byte count above is not evidence of anything")
	}
	var total int
	for _, v := range tags {
		total += len(v)
	}
	if total > maxPNGTextTotalBytes {
		t.Errorf("recovered %d bytes of text, over the %d budget", total, maxPNGTextTotalBytes)
	}
	if total < maxPNGTextChunkBytes {
		t.Errorf("recovered only %d bytes; at least one full chunk should fit in the budget", total)
	}
}

// TestWorkDoesNotGrowWithChunkCount is the shape of the fix, stated as a ratio rather than a duration.
//
// The defect was that cost scaled with the number of chunks. After the fix the bytes read are bounded
// by the budget, so a file with 40x more chunks costs barely more to read.
func TestWorkDoesNotGrowWithChunkCount(t *testing.T) {
	measure := func(n int) int64 {
		png := bombPNG(t, n)
		c := &countingReaderAt{inner: bytes.NewReader(png)}
		extractPNGText(c, int64(len(png)), map[string]string{})
		return c.bytes.Load()
	}

	small, large := measure(16), measure(640)
	// Headers are read for every chunk (8 bytes each), so growth is not zero -- but it must be
	// proportional to HEADERS, not to payloads. 624 extra chunks at 8 bytes is ~5KB; 624 extra
	// payloads would be ~624KB.
	if large > small+64*1024 {
		t.Errorf("bytes read grew from %d (16 chunks) to %d (640 chunks). Growth should be header-only "+
			"once the budget is spent, so 40x the chunks must not mean 40x the reading.", small, large)
	}
}

// TestAnEXIfChunkAfterASpentBudgetIsStillFound is why the skip is a `break` out of the switch rather
// than a `return` from the walk.
//
// eXIf is not text and does not draw on the text budget, and it is the one chunk whose loss would be a
// coverage regression rather than a saving. Stopping the walk when the text budget ran out would have
// traded a performance bug for a detection one.
func TestAnEXIfChunkAfterASpentBudgetIsStillFound(t *testing.T) {
	var comp bytes.Buffer
	zw := zlib.NewWriter(&comp)
	if _, err := zw.Write(bytes.Repeat([]byte{'A'}, maxPNGTextChunkBytes)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	// Enough text chunks to exhaust the 4MB budget, THEN an eXIf chunk.
	chunks := make([][]byte, 0, 9)
	for i := 0; i < 8; i++ {
		kw := []byte{'K', byte('A' + i)}
		chunks = append(chunks, pngChunk("zTXt", append(append(kw, 0, 0), comp.Bytes()...)))
	}
	const marker = "II\x2a\x00EXIFPAYLOAD"
	chunks = append(chunks, pngChunk("eXIf", []byte(marker)))

	png := pngWith(chunks...)
	tags := map[string]string{}
	exif := extractPNGText(bytes.NewReader(png), int64(len(png)), tags)

	if len(exif) == 0 {
		t.Fatal("the eXIf chunk was lost because the TEXT budget was spent. eXIf is not text, does " +
			"not draw on that budget, and losing it is a coverage regression -- the walk must continue " +
			"header-only rather than stop.")
	}
	if !bytes.Contains(exif, []byte("EXIFPAYLOAD")) {
		t.Errorf("eXIf payload = %q, want the marker content", exif)
	}
	// The text budget really was spent, or this test proves nothing about the ordering.
	var total int
	for _, v := range tags {
		total += len(v)
	}
	if total < maxPNGTextTotalBytes-maxPNGTextChunkBytes {
		t.Errorf("recovered only %d bytes of text, so the budget was not actually exhausted and this "+
			"case does not exercise the skip path", total)
	}
}

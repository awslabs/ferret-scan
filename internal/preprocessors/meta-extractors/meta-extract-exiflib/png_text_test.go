// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractexiflib

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// #456: a PNG carrying PII in its text chunks was reported clean at exit 0.
//
// Measured before this package could read a chunk: a 210-byte PNG holding tEXt "Author = Employee SSN
// 449-87-4100", iTXt "Description = Call 415-555-0132" and a DEFLATED zTXt "Comment = Card
// 4532-0151-1283-0366" produced 0 findings, while exiftool read all three. After: 3 findings — SSN,
// PHONE and VISA. The VISA is the one that matters most for design, because it lives in a compressed
// chunk and no byte scan over the file could ever have found it.
//
// A second, wider gap was fixed alongside: ExtractExif used to return the moment exif.Decode failed,
// which made the four raw scans below it unreachable for ANY image without EXIF. A 426-byte JPEG with
// an XMP APP1 and no Exif APP1 produced 0 findings while the already-present extractXMP, called
// directly on the same bytes, returned XMP_Creator = "Employee SSN 449-87-4100".

// pngChunk builds one PNG chunk: length, type, data, CRC.
func pngChunk(kind string, data []byte) []byte {
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, uint32(len(data)))
	out = append(out, kind...)
	out = append(out, data...)
	sum := crc32.ChecksumIEEE(append([]byte(kind), data...))
	crc := make([]byte, 4)
	binary.BigEndian.PutUint32(crc, sum)
	return append(out, crc...)
}

// pngWith assembles a minimal but structurally valid PNG around the given extra chunks.
func pngWith(chunks ...[]byte) []byte {
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:], 1)
	binary.BigEndian.PutUint32(ihdr[4:], 1)
	ihdr[8], ihdr[9] = 8, 2 // 8-bit truecolour

	var idatBuf bytes.Buffer
	zw := zlib.NewWriter(&idatBuf)
	_, _ = zw.Write([]byte{0, 0, 0, 0})
	_ = zw.Close()

	out := append([]byte{}, pngSignature...)
	out = append(out, pngChunk("IHDR", ihdr)...)
	for _, c := range chunks {
		out = append(out, c...)
	}
	out = append(out, pngChunk("IDAT", idatBuf.Bytes())...)
	return append(out, pngChunk("IEND", nil)...)
}

func deflate(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatalf("deflate: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("deflate close: %v", err)
	}
	return buf.Bytes()
}

func tagsFromPNG(t *testing.T, png []byte) map[string]string {
	t.Helper()
	tags := map[string]string{}
	extractPNGText(bytes.NewReader(png), int64(len(png)), tags)
	return tags
}

// TestAllThreeTextChunkKindsAreRead is the reported defect. All three layouts differ, and a reader
// that handles only the simplest one still reports the other two clean.
func TestAllThreeTextChunkKindsAreRead(t *testing.T) {
	png := pngWith(
		pngChunk("tEXt", []byte("Author\x00Employee SSN 449-87-4100")),
		pngChunk("zTXt", append([]byte("Comment\x00\x00"), deflate(t, []byte("Card 4532-0151-1283-0366"))...)),
		pngChunk("iTXt", []byte("Description\x00\x00\x00\x00\x00Call 415-555-0132")),
	)

	tags := tagsFromPNG(t, png)
	for key, want := range map[string]string{
		"PNG_Author":      "Employee SSN 449-87-4100",
		"PNG_Comment":     "Card 4532-0151-1283-0366",
		"PNG_Description": "Call 415-555-0132",
	} {
		if got := tags[key]; got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}

// TestCompressedTextIsTheCaseAByteScanCannotReach is why this is a chunk reader and not another
// marker search over the raw file.
func TestCompressedTextIsTheCaseAByteScanCannotReach(t *testing.T) {
	const secret = "Card 4532-0151-1283-0366"

	// Padded with a long repetitive run on purpose. A first version deflated the bare string and its
	// own non-vacuity guard caught the mistake: zlib STORES a short input literally rather than
	// compressing it, so the value was still sitting in the file in cleartext and the test proved
	// nothing about compression. Enough preceding data forces dynamic Huffman coding, after which the
	// value's bytes are bit-packed and no longer byte-aligned anywhere in the stream.
	body := strings.Repeat("filler ", 600) + secret
	png := pngWith(pngChunk("zTXt", append([]byte("Comment\x00\x00"), deflate(t, []byte(body))...)))

	// The premise, asserted rather than assumed: the value is genuinely absent from the file's bytes.
	if bytes.Contains(png, []byte(secret)) {
		t.Fatal("the fixture holds the value in cleartext, so it does not exercise the compressed case")
	}

	got := tagsFromPNG(t, png)["PNG_Comment"]
	if !strings.Contains(got, secret) {
		t.Errorf("PNG_Comment does not contain %q — a value only reachable by inflating the chunk", secret)
	}
}

// TestDeclaredChunkLengthCannotDriveAnAllocation is the #457 class, in a new parser.
//
// A chunk length is a uint32 read out of the file, so it tops out at 4GiB. Measured: a 53-byte PNG
// whose tEXt declares 4294967280.
//
// What actually bounds the memory is maxPNGTextChunkBytes, not the length clamp: a mutation removing
// the clamp SURVIVED this test, because with the cap in place the read is still 1MB and then fails
// past EOF, so no tag appears either way. The clamp remains as a structural check — it stops the walk
// on a chunk that cannot exist rather than attempting the read — but the allocation assertion below is
// the one that would notice if the cap went away. Saying so here rather than letting the comment
// claim a bound it does not provide.
func TestDeclaredChunkLengthCannotDriveAnAllocation(t *testing.T) {
	png := append([]byte{}, pngSignature...)
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:], 1)
	binary.BigEndian.PutUint32(ihdr[4:], 1)
	png = append(png, pngChunk("IHDR", ihdr)...)

	// A tEXt header declaring 4GiB, followed by a handful of real bytes.
	lying := make([]byte, 4)
	binary.BigEndian.PutUint32(lying, 0xFFFFFFF0)
	png = append(png, lying...)
	png = append(png, "tEXt"...)
	png = append(png, "Author\x00short"...)

	// Must return promptly with no tag rather than allocating or panicking.
	tags := tagsFromPNG(t, png)
	if len(tags) != 0 {
		t.Errorf("tags = %v, want none: the chunk declares more bytes than the file holds", tags)
	}

	// And the allocation must stay proportional to the FILE, not to the declaration. 4GiB of
	// declaration against a 53-byte file is the whole point; 64MB is a generous ceiling that still
	// separates "bounded" from "believed the header".
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	extractPNGText(bytes.NewReader(png), int64(len(png)), map[string]string{})
	runtime.ReadMemStats(&after)
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 64<<20 {
		t.Errorf("allocated %.1f MB for a %d-byte file whose chunk declares %d bytes",
			float64(grew)/(1<<20), len(png), 0xFFFFFFF0)
	}
}

// TestCompressedTextIsBounded keeps the reader from handing itself a decompression bomb.
//
// Measured: a 509.7KB PNG whose zTXt inflates to 512MB — 1029x, near zlib's ceiling. The recovered
// text must be capped, and capping is acceptable here because this is DETECTION: reading the first
// megabyte of a value finds anything in it, whereas refusing the chunk reports the image clean.
func TestCompressedTextIsBounded(t *testing.T) {
	huge := bytes.Repeat([]byte("A"), 8<<20) // 8MB, well past the 1MB cap
	png := pngWith(pngChunk("zTXt", append([]byte("Comment\x00\x00"), deflate(t, huge)...)))

	// Non-vacuity: the fixture must really be small while declaring a lot.
	if len(png) > 1<<20 {
		t.Fatalf("fixture is %d bytes; it must be small for the amplification to be the point", len(png))
	}

	got := tagsFromPNG(t, png)["PNG_Comment"]
	if len(got) == 0 {
		t.Fatal("nothing was recovered; the chunk must still be READ, just bounded")
	}
	if len(got) > maxPNGTextChunkBytes {
		t.Errorf("recovered %d bytes from one chunk, cap is %d", len(got), maxPNGTextChunkBytes)
	}
}

// TestManyChunksAreBoundedInTotal covers the axis the per-chunk cap leaves open.
func TestManyChunksAreBoundedInTotal(t *testing.T) {
	var chunks [][]byte
	// 40 chunks x 512KB of recovered text would be 20MB without a total bound.
	for i := 0; i < 40; i++ {
		body := append([]byte("Note"+string(rune('A'+i))+"\x00\x00"), deflate(t, bytes.Repeat([]byte("B"), 512<<10))...)
		chunks = append(chunks, pngChunk("zTXt", body))
	}
	tags := tagsFromPNG(t, pngWith(chunks...))

	total := 0
	for _, v := range tags {
		total += len(v)
	}
	if total > maxPNGTextTotalBytes {
		t.Errorf("recovered %d bytes across %d chunks, total cap is %d", total, len(tags), maxPNGTextTotalBytes)
	}
	if total == 0 {
		t.Error("nothing recovered at all; the total bound must truncate, not refuse everything")
	}
}

// TestZeroLengthChunkDoesNotSpin pins forward progress.
//
// A chunk declaring length 0 advances 12 bytes (header plus CRC), but an arithmetic slip that computed
// the next position as the current one would loop until the chunk budget ran out.
func TestZeroLengthChunkDoesNotSpin(t *testing.T) {
	png := pngWith(pngChunk("tEXt", nil), pngChunk("tEXt", []byte("Author\x00real")))
	tags := tagsFromPNG(t, png)
	if got := tags["PNG_Author"]; got != "real" {
		t.Errorf("PNG_Author = %q, want %q — the walk must step over an empty chunk and carry on", got, "real")
	}
}

// TestLatin1TextIsDecoded matters because tEXt and zTXt are Latin-1 by specification, not UTF-8.
//
// Passing those bytes through unconverted leaves a high byte as invalid UTF-8, so an accented name in
// a Copyright field reaches the validators as replacement characters — a value altered before
// anything looked at it.
func TestLatin1TextIsDecoded(t *testing.T) {
	// 0xE9 is é in Latin-1 and an invalid UTF-8 lead byte on its own.
	png := pngWith(pngChunk("tEXt", []byte("Author\x00Andr\xe9 Gagn\xe9")))
	got := tagsFromPNG(t, png)["PNG_Author"]
	if got != "André Gagné" {
		t.Errorf("PNG_Author = %q, want %q", got, "André Gagné")
	}
	if !strings.ContainsRune(got, 'é') {
		t.Error("the accented character did not survive decoding")
	}
}

// TestKeysArePrefixedSoTheyCannotShadowEXIF guards the shared tag map.
//
// The map is written by the EXIF walker, the four raw scans and this reader. A PNG keyword is
// producer-controlled text and may be anything, including "Make" or "Software", so an unprefixed key
// would let a PNG overwrite a real EXIF tag.
func TestKeysArePrefixedSoTheyCannotShadowEXIF(t *testing.T) {
	tags := map[string]string{"Software": "the real EXIF value"}
	png := pngWith(pngChunk("tEXt", []byte("Software\x00attacker text")))
	extractPNGText(bytes.NewReader(png), int64(len(png)), tags)

	if tags["Software"] != "the real EXIF value" {
		t.Errorf("Software = %q; a PNG keyword overwrote an EXIF tag of the same name", tags["Software"])
	}
	if tags["PNG_Software"] != "attacker text" {
		t.Errorf("PNG_Software = %q, want the PNG value under its own key", tags["PNG_Software"])
	}
}

// TestNotAPNGIsIgnored keeps the reader off files it must not interpret.
func TestNotAPNGIsIgnored(t *testing.T) {
	for _, b := range [][]byte{
		{},
		[]byte("not an image at all"),
		{0xFF, 0xD8, 0xFF, 0xE1}, // a JPEG
		append([]byte{0x89, 'P', 'N', 'G'}, []byte("truncated signature")...),
	} {
		tags := map[string]string{}
		extractPNGText(bytes.NewReader(b), int64(len(b)), tags)
		if len(tags) != 0 {
			t.Errorf("bytes %q produced tags %v", b[:min(len(b), 8)], tags)
		}
	}
}

// TestRawScansRunWithoutEXIF is the second gap, at the level a caller sees.
//
// A JPEG with an XMP APP1 and no Exif APP1 used to return "no EXIF data found" and nothing else, even
// though extractXMP was present and worked. This asserts the value now reaches the tags.
func TestRawScansRunWithoutEXIF(t *testing.T) {
	dir := t.TempDir()
	xmp := []byte("http://ns.adobe.com/xap/1.0/\x00" +
		`<?xpacket begin=""?><x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF ` +
		`xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description ` +
		`xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>Employee SSN 449-87-4100` +
		`</dc:creator></rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end="w"?>`)

	jpg := []byte{0xFF, 0xD8, 0xFF, 0xE1}
	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, uint16(len(xmp)+2))
	jpg = append(jpg, lenBytes...)
	jpg = append(jpg, xmp...)
	jpg = append(jpg, 0xFF, 0xD9)

	path := filepath.Join(dir, "xmp-only.jpg")
	if err := os.WriteFile(path, jpg, 0o600); err != nil {
		t.Fatal(err)
	}

	data, err := ExtractExif(path)
	if err != nil {
		t.Fatalf("ExtractExif returned %v; a JPEG with XMP and no EXIF still has metadata, and the "+
			"code to read it was already here", err)
	}
	var found bool
	for _, v := range data.Tags {
		if strings.Contains(v, "449-87-4100") {
			found = true
		}
	}
	if !found {
		t.Errorf("the XMP value is not in the tags: %v", data.Tags)
	}
}

// TestShortMarkerScansDoNotRunOnAPNG is the false-positive guard, and it is the reason the previous
// test's un-gating is safe.
//
// extractJFIFComment searches for the 2-byte JPEG comment marker 0xFFFE and extractIPTC for
// {0x1C, 0x02}. In compressed data a given 2-byte sequence turns up about once every 64KB, so running
// them over a PNG's IDAT finds noise and promotes it to a tag. Measured on a real 51,700-byte macOS
// icon: extractJFIFComment emitted 51KB of pixel data as JFIF_Comment, and the validators reported
// TWITTER at confidence 100 three times from handles that exist nowhere in the image. Across 1,200
// real images that was 180 of 853 findings; with the gate it is 0.
func TestShortMarkerScansDoNotRunOnAPNG(t *testing.T) {
	dir := t.TempDir()

	// A PNG whose IDAT is arbitrary bytes containing BOTH short markers, shaped so an UNGATED scan
	// really would emit a tag. A first version put 0xFF 0xFE followed by a declared length of 4096
	// into a 200-byte file; extractJFIFComment bounds-checks that length, found it did not fit, and
	// produced nothing — so the mutation that un-gates the scans SURVIVED and the test looked like it
	// was protecting something it was not. The length has to fit and the text has to be non-blank.
	noisy := []byte{0x00, 0x11}
	noisy = append(noisy, 0xFF, 0xFE, 0x00, 0x0A)       // JPEG comment marker, declaring 10 bytes
	noisy = append(noisy, []byte("SSN 449-87")...)      // ... which fit, and are not blank
	noisy = append(noisy, 0x1C, 0x02, 0x05, 0x00, 0x08) // IPTC marker, record type 5
	noisy = append(noisy, []byte("headline")...)
	noisy = append(noisy, bytes.Repeat([]byte{0xAB, 0xCD}, 64)...)
	png := append([]byte{}, pngSignature...)
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:], 1)
	binary.BigEndian.PutUint32(ihdr[4:], 1)
	ihdr[8], ihdr[9] = 8, 2
	png = append(png, pngChunk("IHDR", ihdr)...)
	png = append(png, pngChunk("tEXt", []byte("Author\x00real value"))...)
	png = append(png, pngChunk("IDAT", noisy)...)
	png = append(png, pngChunk("IEND", nil)...)

	path := filepath.Join(dir, "noisy.png")
	if err := os.WriteFile(path, png, 0o600); err != nil {
		t.Fatal(err)
	}

	// Non-vacuity: the markers really are in the file, so a scan that ran would find them.
	if !bytes.Contains(png, []byte{0xFF, 0xFE}) || !bytes.Contains(png, []byte{0x1C, 0x02}) {
		t.Fatal("the fixture lacks the markers, so this test cannot detect an ungated scan")
	}

	data, err := ExtractExif(path)
	if err != nil {
		t.Fatalf("ExtractExif: %v", err)
	}
	for _, k := range []string{"JFIF_Comment", "IPTC_Caption", "IPTC_Headline", "IPTC_Byline"} {
		if v, ok := data.Tags[k]; ok {
			t.Errorf("%s = %q was produced from a PNG; that scan's marker is 2 bytes long and only "+
				"means anything inside a JPEG", k, v[:min(len(v), 40)])
		}
	}
	// And the real PNG text must still be there, so the gate did not disable everything.
	if data.Tags["PNG_Author"] != "real value" {
		t.Errorf("PNG_Author = %q, want %q", data.Tags["PNG_Author"], "real value")
	}
}

// TestNoMetadataAtAllStillReportsNoEXIF keeps the contract the caller branches on.
//
// image_metadata_preprocessor.extractImageMetadataWithFallback matches on the string "no exif data
// found" to decide whether a file is a valid image lacking EXIF or something it should reject. Making
// the raw scans reachable must not turn every empty file into a success.
func TestNoMetadataAtAllStillReportsNoEXIF(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bare.png")
	if err := os.WriteFile(path, pngWith(), 0o600); err != nil { // no text chunks at all
		t.Fatal(err)
	}

	_, err := ExtractExif(path)
	if err == nil {
		t.Fatal("a PNG with no metadata returned success; the caller distinguishes these by the error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "no exif data found") {
		t.Errorf("error is %q; the caller matches on \"no exif data found\"", err.Error())
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestHonestlyLargeChunkIsStillCapped pins the per-chunk READ cap, which the lying-header test above
// cannot reach.
//
// The two bounds protect each other, and that hid a gap: with the length clamp in place, a mutation
// removing the read cap SURVIVED, because a chunk declaring 4GiB in a 53-byte file is rejected by the
// clamp before any allocation happens. The cap only becomes observable when the chunk is HONEST — the
// bytes really are there — and larger than the cap. That is also a real shape: a PNG may legitimately
// carry a multi-megabyte uncompressed comment, and reading all of it into memory to look for a phone
// number is work proportional to the attacker's choice rather than to the metadata.
func TestHonestlyLargeChunkIsStillCapped(t *testing.T) {
	const chunkText = 3 << 20 // 3MB of real, uncompressed text — three times the cap
	body := append([]byte("Comment\x00"), bytes.Repeat([]byte("A"), chunkText)...)
	png := pngWith(pngChunk("tEXt", body))

	// Non-vacuity in both directions: the chunk must be honest (present in full) and over the cap.
	if len(png) < chunkText {
		t.Fatalf("fixture is %d bytes but declares %d of text; the chunk must really be there", len(png), chunkText)
	}
	if chunkText <= maxPNGTextChunkBytes {
		t.Fatalf("fixture text is %d bytes, not larger than the %d cap", chunkText, maxPNGTextChunkBytes)
	}

	got := tagsFromPNG(t, png)["PNG_Comment"]
	if len(got) == 0 {
		t.Fatal("nothing recovered; an oversize chunk must still be READ, just bounded")
	}
	if len(got) > maxPNGTextChunkBytes {
		t.Errorf("recovered %d bytes from one honest chunk, cap is %d — the read follows the "+
			"declaration rather than the bound", len(got), maxPNGTextChunkBytes)
	}
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package audiolib

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The INFO walk inside a LIST chunk had the same pad-byte defect the outer chunk walk had,
// and it went unfixed when the outer one was corrected.
//
// That is the half that matters. The outer walk sees fmt/data/LIST; the INFO walk sees
// IART, ICMT, ICOP, IENG — artist, comment, copyright, engineer — which is where personal
// data actually lives in a WAV. Measured on the shipped binary with two fixtures identical
// but for one byte:
//
//	padded    -> 1 SSN finding, 25MB peak RSS
//	unpadded  -> 0 SSN findings, 1690MB peak RSS, no disclosure at all
//
// Both symptoms come from one cause. Dropping the pad leaves the reader one byte early, so
// the next field's four-byte ID and the first byte of its size are read as the ID, and the
// size is assembled from the rest of that field plus the first byte of its data — a
// nonsense length that both allocates gigabytes and swallows the field. The value's first
// character is consumed as part of the header, so a token at the start of a field is
// truncated past recognition and the finding disappears.

// infoFieldSpec is one LIST/INFO field. pad controls whether the RIFF-required pad byte
// follows an odd-length value, and declaredSize overrides the size header when non-zero so
// a field can claim more data than it holds.
type infoFieldSpec struct {
	id           string
	value        string
	pad          bool
	declaredSize uint32
}

// buildWAVWithInfo assembles a WAV whose LIST/INFO chunk holds the given fields.
//
// fmtSize overrides the declared size of the format chunk when non-zero, and listSize
// overrides the LIST chunk's declared size when non-zero; both exist so a malformed
// container can be built without hand-assembling the whole file.
func buildWAVWithInfo(t *testing.T, path string, fields []infoFieldSpec, fmtSize, listSize uint32) string {
	t.Helper()

	header := func(id string, size uint32) []byte {
		out := append([]byte(id), make([]byte, 4)...)
		binary.LittleEndian.PutUint32(out[4:], size)
		return out
	}

	fmtPayload := make([]byte, 16)
	binary.LittleEndian.PutUint16(fmtPayload[0:], 1)    // PCM
	binary.LittleEndian.PutUint16(fmtPayload[2:], 1)    // mono
	binary.LittleEndian.PutUint32(fmtPayload[4:], 8000) // sample rate
	binary.LittleEndian.PutUint32(fmtPayload[8:], 8000) // byte rate
	binary.LittleEndian.PutUint16(fmtPayload[12:], 1)
	binary.LittleEndian.PutUint16(fmtPayload[14:], 8)

	declaredFmt := uint32(len(fmtPayload))
	if fmtSize != 0 {
		// The payload is truncated to match, because a chunk header is authoritative for
		// where the next chunk starts. A fixture that declares 10 bytes while holding 16 is
		// not a short chunk, it is a file whose every later offset is wrong — and the walk
		// correctly lands mid-payload on it, which tests nothing about the short-chunk guard.
		declaredFmt = fmtSize
		if declaredFmt < uint32(len(fmtPayload)) {
			fmtPayload = fmtPayload[:declaredFmt]
		}
	}
	body := append(header("fmt ", declaredFmt), fmtPayload...)

	infoBody := []byte("INFO")
	for _, f := range fields {
		payload := append([]byte(f.value), 0x00)
		size := uint32(len(payload))
		if f.declaredSize != 0 {
			size = f.declaredSize
		}
		infoBody = append(infoBody, header(f.id, size)...)
		infoBody = append(infoBody, payload...)
		if f.pad && len(payload)%2 == 1 {
			infoBody = append(infoBody, 0x00)
		}
	}

	declaredList := uint32(len(infoBody))
	if listSize != 0 {
		declaredList = listSize
	}
	body = append(body, header("LIST", declaredList)...)
	body = append(body, infoBody...)

	payload := append([]byte("WAVE"), body...)
	riff := append([]byte("RIFF"), make([]byte, 4)...)
	binary.LittleEndian.PutUint32(riff[4:], uint32(len(payload)))
	riff = append(riff, payload...)

	if err := os.WriteFile(path, riff, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// oddValue is 16 characters, so value+NUL is 17 bytes and RIFF requires a pad byte after
// it. Getting this wrong is how a first attempt at this fixture proved nothing: two
// even-length values need no pad, so "omitting" it changed nothing and both files parsed
// identically.
const oddValue = "Q3 Review Master"

// leadingSecret starts with the sensitive token, which is what makes the miss visible. A
// misaligned read eats the value's first byte; with the token in the middle of the value
// the remainder still matches and the bug hides.
const leadingSecret = "452-11-9384 is the SSN on file"

func TestWAVInfoMissingPadRecoversFollowingField(t *testing.T) {
	dir := t.TempDir()
	e := &WAVExtractor{}

	fields := func(pad bool) []infoFieldSpec {
		return []infoFieldSpec{
			{id: "INAM", value: oddValue, pad: pad},
			{id: "ICMT", value: leadingSecret, pad: true},
		}
	}

	if (len(oddValue)+1)%2 != 1 {
		t.Fatalf("fixture is wrong: %q plus its NUL is even, so no pad byte is required and "+
			"omitting one changes nothing", oddValue)
	}

	good, err := e.ExtractMetadata(buildWAVWithInfo(t,
		filepath.Join(dir, "good.wav"), fields(true), 0, 0))
	if err != nil {
		t.Fatalf("compliant WAV: %v", err)
	}
	if !strings.Contains(good.Comment, leadingSecret) {
		t.Fatalf("fixture is wrong: the compliant WAV did not yield the comment (got %q). "+
			"Without this the malformed case below proves nothing.", good.Comment)
	}
	if good.ExtractionWarning != "" {
		t.Errorf("compliant WAV was flagged: %q", good.ExtractionWarning)
	}

	bad, err := e.ExtractMetadata(buildWAVWithInfo(t,
		filepath.Join(dir, "bad.wav"), fields(false), 0, 0))
	if err != nil {
		t.Fatalf("malformed WAV returned an error: %v — extraction should recover the fields it "+
			"can still read", err)
	}
	if !strings.Contains(bad.Comment, leadingSecret) {
		t.Errorf("the INFO field after an unpadded one was lost (comment = %q). The reader was "+
			"left a byte early, so the field's own header absorbed the first byte of its value "+
			"and the token no longer matched — a detection miss, which means the value is never "+
			"redacted either.", bad.Comment)
	}
	if bad.ExtractionWarning == "" {
		t.Error("malformed WAV carries no ExtractionWarning — a recovered file is still not " +
			"RIFF-compliant and the operator should know the tool had to compensate")
	}
	if !strings.Contains(strings.ToLower(bad.ExtractionWarning), "pad byte") {
		t.Errorf("warning = %q, want it to name the pad byte", bad.ExtractionWarning)
	}
	if strings.Contains(bad.ExtractionWarning, "452-11-9384") {
		t.Errorf("the warning leaked the matched value: %q", bad.ExtractionWarning)
	}
}

// maxExtractAlloc bounds what extracting a fixture of a few hundred bytes may allocate.
//
// The sizes being guarded are uint32s read straight out of the file, so when one reaches
// make() the allocation is measured in gigabytes: 3GB for a crafted declaration and 1.7GB
// reached by accident through a single missing pad byte. 8MB leaves generous headroom for
// the extractor's ordinary work while failing by three orders of magnitude if any of those
// paths regresses.
const maxExtractAlloc = 8 << 20

// extractMeasuringAlloc extracts path and reports how many bytes were allocated doing it.
//
// A ceiling on allocation is the assertion that actually distinguishes these guards.
// Asserting only that a warning appears is too weak: an unguarded size underflow ALSO
// produces a warning, because the walk derails and the garbage-chunk-ID disclosure fires.
// The test then passes while the defect is fully present, which is how two of these guards
// first mutation-tested as vacuous.
func extractMeasuringAlloc(t *testing.T, path string) (*AudioMetadata, uint64) {
	t.Helper()

	if info, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if info.Size() > 4096 {
		t.Fatalf("fixture grew to %d bytes; it must stay tiny for an allocation bound to mean "+
			"anything", info.Size())
	}

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	meta, err := (&WAVExtractor{}).ExtractMetadata(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	runtime.ReadMemStats(&after)
	return meta, after.TotalAlloc - before.TotalAlloc
}

// A field's declared size is a uint32 out of the file and it reached make() unchecked, so a
// tiny file could demand an arbitrary allocation. This asserts the allocation is bounded by
// the file rather than by the declaration.
func TestWAVInfoOversizedFieldIsBoundedAndDisclosed(t *testing.T) {
	dir := t.TempDir()
	path := buildWAVWithInfo(t, filepath.Join(dir, "huge.wav"), []infoFieldSpec{
		// Claims 3GB of data while holding four bytes.
		{id: "IART", value: "abc", pad: true, declaredSize: 0xC0000000},
	}, 0, 0)

	meta, allocated := extractMeasuringAlloc(t, path)

	if allocated > maxExtractAlloc {
		t.Errorf("extracting a tiny file allocated %d bytes (> %d) — a size field read straight "+
			"out of the file is reaching make(); a 60-byte fixture drove 6.1GB of peak RSS this "+
			"way, at exit 0", allocated, maxExtractAlloc)
	}
	if meta.ExtractionWarning == "" {
		t.Error("a field declaring more data than its chunk holds produced no warning — the " +
			"field was not read, and undisclosed missing coverage reads as a clean result")
	}
}

// A field whose declared size fits its chunk but runs off the END OF THE FILE must fail
// loudly, not quietly.
//
// os.File.Read returns the bytes it has with a NIL error, so a truncated field used to yield
// a short value and a byte count that no longer matched the file position — the value was
// wrong and every field after it was read from the wrong offset, all reported as a clean
// parse. io.ReadFull turns that into ErrUnexpectedEOF.
func TestWAVTruncatedInfoFieldIsDisclosed(t *testing.T) {
	dir := t.TempDir()
	path := buildWAVWithInfo(t, filepath.Join(dir, "trunc.wav"), []infoFieldSpec{
		{id: "ICMT", value: leadingSecret, pad: true},
		{id: "IART", value: "Second Field Value", pad: true},
	}, 0, 0)

	full, err := os.ReadFile(path) // #nosec G304 -- test-local path
	if err != nil {
		t.Fatal(err)
	}
	// Cut the file in the middle of the FIRST field's value, leaving both the LIST size and
	// the field size claiming data that is no longer there.
	cut := len(full) - len("Second Field Value") - 1 - 8 - len(leadingSecret)/2
	if cut <= 0 || cut >= len(full) {
		t.Fatalf("fixture arithmetic is wrong: cut=%d of %d bytes", cut, len(full))
	}
	if err := os.WriteFile(path, full[:cut], 0o600); err != nil {
		t.Fatal(err)
	}

	meta, err := (&WAVExtractor{}).ExtractMetadata(path)
	if err != nil {
		// Failing the extraction outright is an acceptable disclosure: the caller surfaces it.
		return
	}

	// The assertion that separates ReadFull from Read is about the VALUE, not the warning.
	// Both paths end up warning, because the loop's next header read hits EOF either way.
	// The difference is what gets REPORTED in between: a plain Read fills the head of the
	// buffer and leaves the rest as zeros, and the NUL-trimming in parseInfoField makes that
	// indistinguishable from a genuinely shorter value. So a field that is half present is
	// published as though it were whole.
	//
	// Reporting a value the file does not contain is worse than reporting nothing. It is
	// wrong in the output, and where the cut lands inside a token it also changes what the
	// validators see — the same class of silent detection change as the pad-byte miss.
	if meta.Comment != "" && meta.Comment != leadingSecret {
		t.Errorf("a truncated INFO field was reported as a complete value: got %q, and the file "+
			"holds either the whole of %q or not enough of it to report. A short read returns "+
			"n<len with a nil error, so the missing tail became NUL padding and was trimmed "+
			"away, leaving a value that looks legitimately short.", meta.Comment, leadingSecret)
	}
	if meta.ExtractionWarning == "" {
		t.Errorf("a WAV truncated inside an INFO field parsed clean: comment=%q, warning empty",
			meta.Comment)
	}
}

// A short fmt chunk must cost only its own values. It used to consume 16 bytes regardless
// of what it declared, leaving the walk inside the next chunk.
func TestWAVShortFormatChunkDoesNotDerailLaterFields(t *testing.T) {
	dir := t.TempDir()
	path := buildWAVWithInfo(t, filepath.Join(dir, "shortfmt.wav"), []infoFieldSpec{
		{id: "ICMT", value: leadingSecret, pad: true},
	}, 10, 0) // declares 10 bytes of format data, holds 16

	e := &WAVExtractor{}
	meta, err := e.ExtractMetadata(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(meta.Comment, leadingSecret) {
		t.Errorf("a short fmt chunk cost the LIST/INFO field that follows it (comment = %q) — "+
			"reading a fixed 16 bytes from a chunk declaring 10 left the walk six bytes into "+
			"the next chunk", meta.Comment)
	}
	if meta.ExtractionWarning == "" {
		t.Error("a fmt chunk shorter than the record it declares produced no warning")
	}
	if meta.SampleRate != 0 {
		t.Errorf("SampleRate = %d, want 0: the chunk is too short to hold the format record, "+
			"so any value would be assembled partly from the bytes that follow it and would "+
			"look plausible while being invented", meta.SampleRate)
	}
}

// A LIST chunk declaring a size below its own four-byte form type underflowed the skip
// arithmetic to roughly 4GB. It must cost only that chunk.
func TestWAVUndersizedListChunkIsContained(t *testing.T) {
	dir := t.TempDir()
	// The field declares 3GB as well, because that is what makes the underflow observable.
	// With the guard in place the LIST is rejected before any field is looked at. Without it,
	// `2 - 4` wraps to about 4GB and becomes the budget every field's declared size is
	// checked against — so the bound that is supposed to cap the allocation is handed a
	// ceiling that admits this field. An undersized LIST holding only well-formed fields
	// cannot show this: the fields parse correctly either way.
	path := buildWAVWithInfo(t, filepath.Join(dir, "shortlist.wav"), []infoFieldSpec{
		{id: "ICMT", value: leadingSecret, pad: true, declaredSize: 0xC0000000},
	}, 0, 2) // LIST declares 2 bytes, less than the "INFO" form type

	meta, allocated := extractMeasuringAlloc(t, path)

	// This is the assertion that catches the underflow. `size - listTypeSize` on a size of 2
	// wraps to about 4GB, and that value becomes the budget parseInfoChunks measures every
	// field's declared size against — so the bound that protects the allocation is handed a
	// ceiling large enough to admit anything.
	if allocated > maxExtractAlloc {
		t.Errorf("a LIST chunk declaring %d bytes caused %d bytes to be allocated (> %d) — the "+
			"size is a uint32, so subtracting the four-byte form type wrapped instead of "+
			"failing", 2, allocated, maxExtractAlloc)
	}
	if meta.ExtractionWarning == "" {
		t.Error("an undersized LIST chunk produced no warning — its fields were not read")
	}
	if strings.Contains(meta.ExtractionWarning, "452-11-9384") {
		t.Errorf("the warning leaked a value: %q", meta.ExtractionWarning)
	}
}

// consumePadByte is the shared primitive both walks depend on. It exists precisely because
// the two had diverged, so its contract is pinned directly.
func TestConsumePadByte(t *testing.T) {
	dir := t.TempDir()

	write := func(name string, b []byte) *os.File {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(p) // #nosec G304 -- test-local path
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		return f
	}

	t.Run("even size consumes nothing", func(t *testing.T) {
		f := write("even", []byte{'f', 'm', 't', ' '})
		consumed, missing, err := consumePadByte(f, 4)
		if err != nil || consumed != 0 || missing {
			t.Errorf("got (%d, %v, %v), want (0, false, nil)", consumed, missing, err)
		}
	})

	t.Run("present pad is consumed", func(t *testing.T) {
		f := write("pad", []byte{0x00, 'L', 'I', 'S', 'T'})
		consumed, missing, err := consumePadByte(f, 3)
		if err != nil || consumed != 1 || missing {
			t.Errorf("got (%d, %v, %v), want (1, false, nil)", consumed, missing, err)
		}
	})

	t.Run("absent pad is reported and pushed back", func(t *testing.T) {
		f := write("nopad", []byte{'L', 'I', 'S', 'T'})
		consumed, missing, err := consumePadByte(f, 3)
		if err != nil || consumed != 0 || !missing {
			t.Fatalf("got (%d, %v, %v), want (0, true, nil)", consumed, missing, err)
		}
		// The byte must still be available, or the caller is misaligned anyway.
		var next [4]byte
		if _, err := f.Read(next[:]); err != nil {
			t.Fatal(err)
		}
		if string(next[:]) != "LIST" {
			t.Errorf("next read = %q, want %q: the non-pad byte was not pushed back",
				next[:], "LIST")
		}
	})

	t.Run("EOF after an odd chunk is not an error", func(t *testing.T) {
		f := write("eof", []byte{})
		consumed, missing, err := consumePadByte(f, 3)
		if err != nil || consumed != 0 || missing {
			t.Errorf("got (%d, %v, %v), want (0, false, nil): nothing follows, so nothing "+
				"is missed", consumed, missing, err)
		}
	})
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package audiolib

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A WAV whose chunk layout is not RIFF-compliant must not be reported as clean.
//
// parseChunks skipped a pad byte whenever a chunk's declared size was odd, ASSUMING the
// file was compliant. RIFF does require that pad byte, but a truncated download or a
// sloppy writer can omit it — and then the seek lands ONE BYTE PAST the next chunk header.
// Every subsequent chunk ID is garbage, which the default branch skipped by a nonsense
// size, so the walk ended at EOF, returned nil, and produced an empty result.
//
// Measured on the shipped binary with two fixtures identical but for that pad byte:
//
//	correctly padded  -> 1 finding (SSN, conf 100)
//	unpadded          -> 0 findings, "No matches found.", exit 0, nothing on stderr
//
// An unreadable file was indistinguishable from a clean one. See #312.
//
// The pad byte is detectable rather than assumable — a pad is always 0x00 and a chunk ID's
// first byte is printable ASCII — so this now RECOVERS the metadata instead of only
// disclosing the failure, which turns a silent miss into a finding.

const wavTestValue = "SSN: 452-11-9384"

// writeWAV builds a minimal WAV carrying wavTestValue in a LIST/INFO ICMT comment.
//
// padData controls whether the odd-length data chunk is followed by the pad byte RIFF
// requires. That single byte is the whole difference between the two fixtures.
func writeWAV(t *testing.T, path string, padData bool) string {
	t.Helper()

	chunk := func(id string, payload []byte, pad bool) []byte {
		out := append([]byte(id), make([]byte, 4)...)
		binary.LittleEndian.PutUint32(out[4:], uint32(len(payload)))
		out = append(out, payload...)
		if pad && len(payload)%2 == 1 {
			out = append(out, 0x00)
		}
		return out
	}

	fmtPayload := make([]byte, 16)
	binary.LittleEndian.PutUint16(fmtPayload[0:], 1)    // PCM
	binary.LittleEndian.PutUint16(fmtPayload[2:], 1)    // mono
	binary.LittleEndian.PutUint32(fmtPayload[4:], 8000) // sample rate
	binary.LittleEndian.PutUint32(fmtPayload[8:], 8000) // byte rate
	binary.LittleEndian.PutUint16(fmtPayload[12:], 1)
	binary.LittleEndian.PutUint16(fmtPayload[14:], 8)

	icmt := chunk("ICMT", append([]byte(wavTestValue), 0x00), true)
	info := append([]byte("INFO"), icmt...)

	body := chunk("fmt ", fmtPayload, true)
	body = append(body, chunk("data", []byte{0x01}, padData)...) // odd length: 1 byte
	body = append(body, chunk("LIST", info, true)...)

	payload := append([]byte("WAVE"), body...)
	riff := append([]byte("RIFF"), make([]byte, 4)...)
	binary.LittleEndian.PutUint32(riff[4:], uint32(len(payload)))
	riff = append(riff, payload...)

	if err := os.WriteFile(path, riff, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestWAVMissingPadByteIsRecoveredAndDisclosed(t *testing.T) {
	dir := t.TempDir()
	e := &WAVExtractor{}

	// Control: RIFF-compliant. Must extract, and must NOT be flagged.
	good, err := e.ExtractMetadata(writeWAV(t, filepath.Join(dir, "good.wav"), true))
	if err != nil {
		t.Fatalf("compliant WAV: %v", err)
	}
	if !strings.Contains(good.Comment, wavTestValue) {
		t.Fatalf("fixture is wrong: the compliant WAV did not yield the comment (got %q). "+
			"Without this the malformed case below proves nothing.", good.Comment)
	}
	if good.ExtractionWarning != "" {
		t.Errorf("compliant WAV was flagged: %q — a false warning on a well-formed file "+
			"trains operators to ignore the real ones", good.ExtractionWarning)
	}

	// The defect: identical file minus the pad byte.
	bad, err := e.ExtractMetadata(writeWAV(t, filepath.Join(dir, "bad.wav"), false))
	if err != nil {
		t.Fatalf("malformed WAV returned an error: %v — extraction should recover, not fail, "+
			"because failing discards the metadata it can still read", err)
	}
	if !strings.Contains(bad.Comment, wavTestValue) {
		t.Errorf("malformed WAV lost the comment (got %q) — the walk skipped a pad byte that "+
			"was not there, landing one byte past the next chunk header so every later chunk "+
			"ID was garbage", bad.Comment)
	}
	if bad.ExtractionWarning == "" {
		t.Error("malformed WAV carries no ExtractionWarning — recovery is not a reason to stay " +
			"silent about a file that is not RIFF-compliant and may be truncated")
	}
	if !strings.Contains(strings.ToLower(bad.ExtractionWarning), "pad byte") {
		t.Errorf("warning = %q, want it to name the pad byte so the operator knows what is "+
			"wrong with the file", bad.ExtractionWarning)
	}
	// Payload-free: the warning reaches stderr and every machine format.
	if strings.Contains(bad.ExtractionWarning, "452-11-9384") {
		t.Errorf("the warning leaked the matched value: %q", bad.ExtractionWarning)
	}
}

// A chunk header that is not four printable ASCII bytes means the reader is off a chunk
// boundary. Walking on would skip by a nonsense size and end at EOF reporting success, so
// the walk stops and says so.
func TestWAVUnwalkableChunkHeaderIsDisclosed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "junk.wav")

	body := append([]byte("WAVE"), 0xff, 0xfe, 0x00, 0x01) // garbage where a chunk ID belongs
	body = append(body, 0x04, 0x00, 0x00, 0x00)            // declared size 4
	body = append(body, []byte("junk")...)
	riff := append([]byte("RIFF"), make([]byte, 4)...)
	binary.LittleEndian.PutUint32(riff[4:], uint32(len(body)))
	riff = append(riff, body...)
	if err := os.WriteFile(path, riff, 0o600); err != nil {
		t.Fatal(err)
	}

	e := &WAVExtractor{}
	meta, err := e.ExtractMetadata(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if meta.ExtractionWarning == "" {
		t.Error("an unwalkable chunk layout produced no warning — the run would print " +
			"\"No matches found.\" and exit 0, which is what a clean file prints")
	}
	if strings.Contains(strings.ToLower(meta.ExtractionWarning), "pad byte") {
		t.Errorf("warning = %q, want the unrecognized-header wording rather than the pad-byte "+
			"one; the two conditions have different remedies", meta.ExtractionWarning)
	}
}

// isPrintableChunkID is the boundary test the walk relies on, so its edges are pinned.
func TestIsPrintableChunkID(t *testing.T) {
	cases := []struct {
		id   [4]byte
		want bool
	}{
		{[4]byte{'f', 'm', 't', ' '}, true}, // space is printable (0x20)
		{[4]byte{'L', 'I', 'S', 'T'}, true},
		{[4]byte{'d', 'a', 't', 'a'}, true},
		{[4]byte{0x00, 'a', 'b', 'c'}, false}, // NUL: a consumed pad byte shifted us
		{[4]byte{'a', 'b', 'c', 0x1f}, false}, // just below printable
		{[4]byte{'a', 'b', 'c', 0x7f}, false}, // DEL, just above printable
		{[4]byte{0xff, 0xfe, 0x00, 0x01}, false},
	}
	for _, c := range cases {
		if got := isPrintableChunkID(c.id); got != c.want {
			t.Errorf("isPrintableChunkID(%q) = %v, want %v", c.id, got, c.want)
		}
	}
}

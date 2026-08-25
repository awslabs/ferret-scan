// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package audiolib

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// #457: a declared box/block length was used as an allocation length with no cross-check against
// the file. Measured before the fix, via TotalAlloc around one ExtractMetadata call:
//
//	52-byte .m4a, mvhd declares 0xFFFFFFFF   ->  4096.001 MB allocated
//	 8-byte .flac, block declares 0xFFFFFF   ->    16.004 MB allocated
//
// End to end, a directory holding six of the .m4a form plus one real file — 220KB of input — drove
// 4.03GB of peak RSS in 2.57s; after the fix, 0.03GB in 0.74s.
//
// Why the reproducer needs more than one file: Go does not zero a span it takes fresh from the OS,
// so ONE bomb reserves 4GB that is never written and peak RSS stays near 30MB. Reuse a dirty span
// and the runtime must zero it, faulting every page in. A single-file RSS measurement therefore
// shows nothing, which is how this survived. The allocation itself is visible either way, which is
// why these tests measure TotalAlloc rather than RSS.

// allocatedBy reports the megabytes allocated while extracting from path.
func allocatedBy(t *testing.T, path string) float64 {
	t.Helper()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	if _, err := NewAudioExtractor().ExtractMetadataWithContext(context.Background(), path); err != nil {
		t.Logf("extract returned %v (a parse error is fine; the allocation is what matters)", err)
	}
	runtime.ReadMemStats(&after)
	return float64(after.TotalAlloc-before.TotalAlloc) / (1 << 20)
}

// The budgets are per-site, because the two declarations have very different ceilings and ONE
// shared number is how a guard goes vacuous. A first version used 64MB for both: the .m4a
// declaration is a uint32 and reverting its clamp allocates 4096MB, so 64MB caught it — but the
// .flac length is 24 bits and tops out at 16MiB, so reverting the .flac clamp allocated 16MB, came
// in UNDER the shared budget, and the mutation survived undetected.
//
// Each budget below sits far above what the fixed code needs (~0.005MB) and far below what the
// declaration would buy, so neither is tight enough to flake nor loose enough to miss a revert.
const (
	mvhdAllocationBudgetMB = 64 // vs 4096MB unfixed: a 64x margin
	flacAllocationBudgetMB = 1  // vs 16MB unfixed: a 16x margin
)

func TestMvhdDeclaredSizeCannotDriveTheAllocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bomb.m4a")
	writeFile(t, path, m4aWithMvhdSize(0xFFFFFFFF, 16))

	if got := allocatedBy(t, path); got > mvhdAllocationBudgetMB {
		t.Errorf("allocated %.1f MB for a %d-byte file. The mvhd declaration is a uint32 read out "+
			"of the file, so it must be clamped to the bytes the file actually holds.",
			got, fileSize(t, path))
	}
}

func TestFlacBlockLengthCannotDriveTheAllocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bomb.flac")
	// "fLaC" then a metadata block header: 1 byte (last-block flag | type), 3 bytes big-endian
	// length. 24 bits caps this at 16MiB — smaller than the .m4a case, same defect.
	writeFile(t, path, append([]byte("fLaC"), 0x00, 0xFF, 0xFF, 0xFF))

	if got := allocatedBy(t, path); got > flacAllocationBudgetMB {
		t.Errorf("allocated %.1f MB for a %d-byte file; the block length must be clamped to the file",
			got, fileSize(t, path))
	}
}

// TestLyingMvhdDoesNotInventTimestamps is the correctness half, and it is not a restatement of the
// allocation tests.
//
// The old code sized the buffer to the DECLARED length and tolerated a short read, so the tail
// stayed zeroed and those zeros were parsed as real fields. A declaration far past the end of the
// file therefore produced a creation date and a duration out of bytes that were never in it. Any
// future fix that bounds the allocation but keeps indexing by the declared size would pass the
// tests above and fail this one.
func TestLyingMvhdDoesNotInventTimestamps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lying.m4a")

	// The fixture has to make "invented" distinguishable from "really zero", which a first
	// version did not: it supplied 16 zero payload bytes, so a mutation that padded the buffer
	// and indexed by the declared size read zeros, produced a zero date and duration, and passed.
	//
	// So: supply exactly 8 payload bytes, with a REAL non-zero creation time in bytes 4-7, and
	// let the timescale and duration fields at 12-19 fall past the end of the file. Correct
	// behaviour is to parse none of it, because the arm needs 24 bytes and only 8 exist. Anything
	// that reports a date here read the creation time while pretending the rest was present.
	payload := make([]byte, 8)
	binary.BigEndian.PutUint32(payload[4:], 2082844800+86400) // one day past the MP4 epoch
	mvhd := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(mvhd[0:], 0xFFFFFFFF) // declares 4GiB, supplies 8 bytes
	copy(mvhd[4:], "mvhd")
	copy(mvhd[8:], payload)
	writeFile(t, path, wrapInMoov(mvhd))

	md, err := NewAudioExtractor().ExtractMetadataWithContext(context.Background(), path)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if !md.RecordingDate.IsZero() {
		t.Errorf("RecordingDate = %v, want zero. Only 8 of the declared payload bytes exist, so "+
			"the version-0 arm must not run at all; reporting a date means the declared size was "+
			"used to decide what had been read.", md.RecordingDate)
	}
	if md.Duration != 0 {
		t.Errorf("Duration = %v, want 0: the timescale and duration fields are past the end of "+
			"the file", md.Duration)
	}
}

// TestWellFormedMvhdStillParses is the direction the fix must not break, and the guard against
// "fix" by refusing everything.
//
// Verified separately against 600 real audio files on a macOS host (548 .m4a, 50 .wav, 2 .mp3):
// report output byte-identical before and after, 17 findings, 0 empty outputs.
func TestWellFormedMvhdStillParses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "good.m4a")

	// A version-0 mvhd with a real timescale and duration: 1000 ticks/sec, 42000 ticks = 42s.
	payload := make([]byte, 100)
	binary.BigEndian.PutUint32(payload[4:], 2082844800+1) // creation time, just past the MP4 epoch
	binary.BigEndian.PutUint32(payload[12:], 1000)        // timescale
	binary.BigEndian.PutUint32(payload[16:], 42000)       // duration
	writeFile(t, path, m4aWithMvhdPayload(payload))

	md, err := NewAudioExtractor().ExtractMetadataWithContext(context.Background(), path)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if want := 42 * time.Second; md.Duration != want {
		t.Errorf("Duration = %v, want %v. The clamp must not shorten a payload the file really "+
			"holds — a well-formed mvhd has to parse exactly as before.", md.Duration, want)
	}
	if md.RecordingDate.IsZero() {
		t.Error("RecordingDate is zero for a well-formed mvhd carrying a valid creation time")
	}
}

// m4aWithMvhdSize builds a minimal .m4a whose mvhd declares declared bytes while supplying only
// payloadLen of them.
func m4aWithMvhdSize(declared uint32, payloadLen int) []byte {
	mvhd := make([]byte, 8+payloadLen)
	binary.BigEndian.PutUint32(mvhd[0:], declared)
	copy(mvhd[4:], "mvhd")
	return wrapInMoov(mvhd)
}

// m4aWithMvhdPayload builds a minimal .m4a whose mvhd declares exactly the payload it carries.
func m4aWithMvhdPayload(payload []byte) []byte {
	mvhd := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(mvhd[0:], uint32(8+len(payload)))
	copy(mvhd[4:], "mvhd")
	copy(mvhd[8:], payload)
	return wrapInMoov(mvhd)
}

func wrapInMoov(mvhd []byte) []byte {
	ftyp := make([]byte, 20)
	binary.BigEndian.PutUint32(ftyp[0:], 20)
	copy(ftyp[4:], "ftyp")
	copy(ftyp[8:], "M4A ")
	copy(ftyp[16:], "isom")

	moov := make([]byte, 8)
	binary.BigEndian.PutUint32(moov[0:], uint32(8+len(mvhd)))
	copy(moov[4:], "moov")

	return append(append(ftyp, moov...), mvhd...)
}

func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	return info.Size()
}

// TestClampIsToBytesRemainingNotToFileSize distinguishes the two plausible clamps.
//
// "Clamp to the file size" also bounds the allocation by the input and so passes every test above —
// a mutation doing exactly that survived the first matrix. It is still weaker: a box near the END of
// a large file would allocate the whole file's length instead of the handful of bytes left after it.
// With the CLI's 100MB limit that is a 100MB allocation for an 8-byte payload.
//
// The fixture is SPARSE: the 80MB gap is a hole, so the file costs no disk and the test costs no
// time, while os.Stat still reports 80MB — which is the quantity the wrong clamp would use.
func TestClampIsToBytesRemainingNotToFileSize(t *testing.T) {
	const freeLen = 80 << 20

	path := filepath.Join(t.TempDir(), "late-mvhd.m4a")
	f, err := os.Create(path) // #nosec G304 -- test-controlled temp path
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	ftyp := make([]byte, 20)
	binary.BigEndian.PutUint32(ftyp[0:], 20)
	copy(ftyp[4:], "ftyp")
	copy(ftyp[8:], "M4A ")
	copy(ftyp[16:], "isom")

	// moov spans the free box and the mvhd, so the walk's endPos reaches the mvhd.
	moov := make([]byte, 8)
	binary.BigEndian.PutUint32(moov[0:], uint32(8+(8+freeLen)+16))
	copy(moov[4:], "moov")

	// A free box the walk steps over by arithmetic rather than reading.
	free := make([]byte, 8)
	binary.BigEndian.PutUint32(free[0:], uint32(8+freeLen))
	copy(free[4:], "free")

	// mvhd at the very end: declares 4GiB, supplies 8 bytes.
	mvhd := make([]byte, 16)
	binary.BigEndian.PutUint32(mvhd[0:], 0xFFFFFFFF)
	copy(mvhd[4:], "mvhd")

	for _, b := range [][]byte{ftyp, moov, free} {
		if _, werr := f.Write(b); werr != nil {
			t.Fatalf("write: %v", werr)
		}
	}
	// Skip the payload to leave a hole, then write the mvhd at the end.
	if _, err = f.Seek(int64(freeLen), 1); err != nil {
		t.Fatalf("seek: %v", err)
	}
	if _, err = f.Write(mvhd); err != nil {
		t.Fatalf("write mvhd: %v", err)
	}
	if err = f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Non-vacuity: the whole point is that Stat reports a size far above the bytes remaining
	// after the mvhd header, so the two candidate clamps give very different answers.
	if got := fileSize(t, path); got < freeLen {
		t.Fatalf("fixture is %d bytes, want at least %d — the two clamps would not differ", got, freeLen)
	}

	if got := allocatedBy(t, path); got > mvhdAllocationBudgetMB {
		t.Errorf("allocated %.1f MB for the 8 bytes that follow the mvhd header in an %d MB file. "+
			"The clamp must use the bytes REMAINING from the current offset, not the file's total "+
			"length.", got, freeLen>>20)
	}
}

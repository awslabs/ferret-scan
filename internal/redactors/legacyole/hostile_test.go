// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package legacyole

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/olefixture"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// Structural fields in a compound file are attacker-controlled: a directory entry
// declares its stream's size, the FAT declares each chain, and nothing in the format
// makes those agree with the bytes actually present. Every one of them is eight
// bytes any text editor can change in a file a user was asked to scan.
//
// These tests cover what happens when they lie.

// A declared stream size must not drive allocation.
//
// Measured before the clamp: a 7,168-byte container whose directory entry claimed a
// 2GB stream caused 2,048 MB of allocation, because the logical read preallocated
// the declared size. That is a memory-amplification DoS reachable by editing eight
// bytes of any .doc — the file need not even be a real document.
func TestHostile_DeclaredStreamSizeDoesNotDriveAllocation(t *testing.T) {
	body := bytes.Repeat([]byte{' '}, 5120) // over the mini cutoff, so regular sectors
	copy(body[100:], "Employee SSN: 449-87-4100 recorded here for the record.")
	base := olefixture.MustBuild([]olefixture.Stream{
		{Name: olefixture.StreamWordDocument, Data: body},
	})

	// The first stream entry sits right after the root entry in the directory sector.
	const dirSectorOffset = olefixture.SectorSize * 2 // header + FAT
	const entryOffset = dirSectorOffset + 128         // skip the root entry
	const sizeFieldOffset = entryOffset + 120

	for _, declared := range []uint64{
		5120,      // honest
		1 << 20,   // 1MB
		1 << 28,   // 256MB
		1 << 31,   // 2GB
		1 << 40,   // 1TB
		1<<64 - 1, // the maximum a uint64 can hold
	} {
		t.Run(fmt.Sprintf("declared_%d", declared), func(t *testing.T) {
			lied := append([]byte(nil), base...)
			binary.LittleEndian.PutUint64(lied[sizeFieldOffset:], declared)

			dir := t.TempDir()
			in := filepath.Join(dir, "in.doc")
			out := filepath.Join(dir, "out.doc")
			if err := os.WriteFile(in, lied, 0o600); err != nil {
				t.Fatal(err)
			}

			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)

			r := NewLegacyOLERedactor(nil, nil)
			_, err := r.RedactDocument(in, out, []detector.Match{
				{Text: "449-87-4100", Type: "SSN", Confidence: 100},
			}, redactors.RedactionFormatPreserving)

			runtime.ReadMemStats(&after)
			alloc := int64(after.TotalAlloc) - int64(before.TotalAlloc)

			// Refusing is an acceptable outcome; allocating gigabytes is not.
			// The ceiling is generous (a small multiple of the file plus slack for
			// unrelated test allocation) because this guards an amplification of
			// several ORDERS of magnitude, not a tight constant.
			ceiling := 16*int64(len(lied)) + int64(8<<20)
			if alloc > ceiling {
				t.Errorf("a %d-byte file with a declared stream size of %d caused %.1f MB "+
					"of allocation (ceiling %.1f MB): the declared size is being trusted, "+
					"which makes any .doc a memory-amplification DoS",
					len(lied), declared, float64(alloc)/(1<<20), float64(ceiling)/(1<<20))
			}
			if err != nil {
				return // a clean refusal is fine
			}
		})
	}
}

// An honest file must still redact after the clamp: a size guard that also breaks
// the normal case has traded a DoS for a leak.
func TestHostile_ClampDoesNotBreakHonestFiles(t *testing.T) {
	body := bytes.Repeat([]byte{' '}, 5120)
	copy(body[100:], "Employee SSN: 449-87-4100 recorded here for the record.")
	raw := olefixture.MustBuild([]olefixture.Stream{
		{Name: olefixture.StreamWordDocument, Data: body},
		{Name: olefixture.StreamSummaryInformation, Data: olefixture.SummaryInformation(
			map[uint32]string{olefixture.PropAuthor: "Jane Analyst"})},
	})

	dir := t.TempDir()
	in := filepath.Join(dir, "in.doc")
	out := filepath.Join(dir, "out.doc")
	if err := os.WriteFile(in, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	r := NewLegacyOLERedactor(nil, nil)
	res, err := r.RedactDocument(in, out, []detector.Match{
		{Text: "449-87-4100", Type: "SSN", Confidence: 100},
		{Text: "Jane Analyst", Type: "AUTHOR_INFO", Confidence: 60},
	}, redactors.RedactionFormatPreserving)
	if err != nil {
		t.Fatalf("RedactDocument on an honest file: %v", err)
	}
	if len(res.RedactionMap) != 2 {
		t.Errorf("got %d mappings, want 2 — the size clamp must not cost an honest file "+
			"its redactions", len(res.RedactionMap))
	}
	for name, content := range streamContents(t, out) {
		for _, secret := range []string{"449-87-4100", "Jane Analyst"} {
			if bytes.Contains(content, []byte(secret)) {
				t.Errorf("stream %q still contains %q", name, secret)
			}
		}
	}
}

// A malformed FAT, directory or header must not hang or crash. Each of these is a
// field a user-supplied file controls.
func TestHostile_MalformedStructures(t *testing.T) {
	body := bytes.Repeat([]byte{' '}, 5120)
	copy(body[100:], "Employee SSN: 449-87-4100 recorded here.")
	base := olefixture.MustBuild([]olefixture.Stream{
		{Name: olefixture.StreamWordDocument, Data: body},
	})

	const fatSectorOffset = olefixture.SectorSize * 1
	const dirSectorOffset = olefixture.SectorSize * 2

	cases := []struct {
		name   string
		mutate func([]byte)
		why    string
	}{
		{
			name: "fat_self_loop",
			mutate: func(b []byte) {
				// Sector 3 points at itself: a naive walker never terminates.
				binary.LittleEndian.PutUint32(b[fatSectorOffset+3*4:], 3)
			},
			why: "a self-referential chain must be detected, not followed forever",
		},
		{
			name: "fat_two_cycle",
			mutate: func(b []byte) {
				binary.LittleEndian.PutUint32(b[fatSectorOffset+3*4:], 4)
				binary.LittleEndian.PutUint32(b[fatSectorOffset+4*4:], 3)
			},
			why: "a two-sector cycle is the same hazard one step further out",
		},
		{
			name: "chain_start_out_of_range",
			mutate: func(b []byte) {
				binary.LittleEndian.PutUint32(b[dirSectorOffset+128+116:], 0x00FFFFF0)
			},
			why: "a start sector past the end of the file must not be read",
		},
		{
			name: "directory_start_out_of_range",
			mutate: func(b []byte) {
				binary.LittleEndian.PutUint32(b[48:], 0x00FFFFF0)
			},
			why: "an out-of-range directory sector must not be read",
		},
		{
			name: "zero_fat_sectors",
			mutate: func(b []byte) {
				binary.LittleEndian.PutUint32(b[44:], 0)
			},
			why: "a file claiming no FAT cannot be mapped and must be refused",
		},
		{
			name: "absurd_fat_count",
			mutate: func(b []byte) {
				binary.LittleEndian.PutUint32(b[44:], 0xFFFFFFF0)
			},
			// This one was not hypothetical. The declared count sized a slice
			// capacity, so 0xFFFFFFF0 reserved room for ~137 billion entries -- about
			// 1TB -- and the process did not error, it stalled: 56 seconds under
			// -race before the harness killed it. The count is now clamped to the
			// number of sectors the file could possibly hold.
			why: "an absurd FAT count must not drive a huge allocation",
		},
		{
			name: "implausible_sector_shift",
			mutate: func(b []byte) {
				binary.LittleEndian.PutUint16(b[30:], 40) // 1<<40 bytes per sector
			},
			why: "an implausible sector size must be rejected before any arithmetic on it",
		},
		{
			name: "mini_cutoff_zero",
			mutate: func(b []byte) {
				binary.LittleEndian.PutUint32(b[56:], 0)
			},
			why: "a zero cutoff must fall back to the standard value, not divide by zero",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lied := append([]byte(nil), base...)
			tc.mutate(lied)

			dir := t.TempDir()
			in := filepath.Join(dir, "in.doc")
			if err := os.WriteFile(in, lied, 0o600); err != nil {
				t.Fatal(err)
			}

			// The contract is "terminate, without panicking, and without allocating
			// out of proportion to the file". Either outcome — a refusal or a partial
			// redaction — is acceptable.
			//
			// Both the timeout AND the allocation ceiling are needed. The absurd FAT
			// count case reserved ~1TB of slice capacity, which took 56 SECONDS under
			// -race but only 0.29s without it: a timeout alone passes in a normal run
			// and fails only in the race job, which reads as a flake rather than the
			// memory-amplification bug it is. The allocation assertion catches it in
			// either mode.
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)

			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() {
					if p := recover(); p != nil {
						t.Errorf("panic on %s (%s): %v", tc.name, tc.why, p)
					}
				}()
				r := NewLegacyOLERedactor(nil, nil)
				_, _ = r.RedactDocument(in, filepath.Join(dir, "out.doc"),
					[]detector.Match{{Text: "449-87-4100", Type: "SSN", Confidence: 100}},
					redactors.RedactionFormatPreserving)
			}()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatalf("%s did not terminate within 10s (%s) — a malformed chain is "+
					"being followed without a cycle guard", tc.name, tc.why)
			}

			runtime.ReadMemStats(&after)
			alloc := int64(after.TotalAlloc) - int64(before.TotalAlloc)
			ceiling := 64*int64(len(lied)) + int64(8<<20)
			if alloc > ceiling {
				t.Errorf("%s allocated %.1f MB from a %d-byte file (ceiling %.1f MB): a "+
					"structural field is sizing an allocation, which is a memory "+
					"amplification a user-supplied file controls (%s)",
					tc.name, float64(alloc)/(1<<20), len(lied),
					float64(ceiling)/(1<<20), tc.why)
			}
		})
	}
}

// Redaction cost must stay proportional to the file. The logical-stream mapping
// reassembles each stream, so a per-match reassembly would be quadratic in match
// count — the defect this repository has already fixed twice elsewhere.
//
// This is a regression backstop with an absolute ceiling, not a proof of linearity:
// measured 0.7-1.5ms across 64KB-512KB with the match count scaling alongside, so
// the ceiling sits far above the observed range and only a real blow-up trips it.
func TestHostile_RedactionCostStaysProportional(t *testing.T) {
	if testing.Short() {
		t.Skip("timing-sensitive")
	}

	const ceiling = 3 * time.Second
	for _, kb := range []int{64, 256, 512} {
		body := bytes.Repeat([]byte{' '}, kb*1024)
		matches := 0
		for off := 0; off+64 < len(body); off += 4096 {
			copy(body[off:], "SSN: 449-87-4100 recorded in this document.")
			matches++
		}
		raw := olefixture.MustBuild([]olefixture.Stream{
			{Name: olefixture.StreamWordDocument, Data: body},
		})

		dir := t.TempDir()
		in := filepath.Join(dir, "b.doc")
		if err := os.WriteFile(in, raw, 0o600); err != nil {
			t.Fatal(err)
		}

		start := time.Now()
		r := NewLegacyOLERedactor(nil, nil)
		res, err := r.RedactDocument(in, filepath.Join(dir, "o.doc"),
			[]detector.Match{{Text: "449-87-4100", Type: "SSN", Confidence: 100}},
			redactors.RedactionFormatPreserving)
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("%dKB: %v", kb, err)
		}

		// Non-vacuity: the work has to actually happen, or a fast run proves nothing.
		occ, _ := res.RedactionMap[0].Metadata["occurrences"].(int)
		if occ != matches {
			t.Errorf("%dKB: redacted %d occurrences but the fixture has %d — this timing "+
				"measurement would not reflect the real cost", kb, occ, matches)
		}
		if elapsed > ceiling {
			t.Errorf("%dKB with %d matches took %v, over the %v ceiling: cost is no longer "+
				"proportional to the input", kb, matches, elapsed, ceiling)
		}
	}
}

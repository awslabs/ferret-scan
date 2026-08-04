// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package legacyole

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// Logical-to-file offset mapping for OLE compound file streams.
//
// # Why this exists
//
// A CFB file is a sector-addressed filesystem. A stream's bytes are a CHAIN of
// sectors that need not be adjacent or even in order — exactly what a real
// allocator produces after a document has been edited a few times. The extractor
// reads through mscfb, so it sees each stream REASSEMBLED into contiguous logical
// bytes, and reports matches found there.
//
// Searching the raw file for those same bytes therefore misses any value that
// straddles a sector boundary between two non-adjacent sectors. Measured on a
// 10-sector .doc whose logical sectors 1 and 2 sat at disk sectors 12 and 4: the
// extractor reported an SSN at logical offset 1019, the raw file contained no
// contiguous copy of it, and RedactDocument returned Success=true with zero
// mappings while the SSN stayed in the output. Since only reported findings are
// redacted and this one WAS reported, that is a reported-but-not-redacted leak —
// the worst kind, because the report says the value was handled.
//
// So redaction has to work in the same coordinate space the extractor did: find in
// logical bytes, then write back through the sector chain. That is what this file
// provides.

// streamFragment is one contiguous run of a stream's logical bytes, and where those
// bytes live in the file.
type streamFragment struct {
	logicalStart int // offset within the stream's logical bytes
	fileStart    int // offset within the file
	length       int
}

// streamExtent is one stream: its name and its fragments in logical order.
type streamExtent struct {
	name      string
	size      int
	fragments []streamFragment
}

// cfbLayout is everything needed to map a stream's logical offsets onto the file.
type cfbLayout struct {
	streams []streamExtent
}

const (
	cfbHeaderSize   = 512
	dirEntrySize    = 128
	maxChainSectors = 1 << 22 // ~2GB at 512-byte sectors; a cycle guard, not a limit
)

// parseCFBLayout walks a compound file's header, FAT, mini FAT and directory to
// produce a logical-to-file mapping for every stream.
//
// It is deliberately independent of mscfb: mscfb exposes stream CONTENT but not
// where that content lives, and the whole point here is the where.
func parseCFBLayout(raw []byte) (*cfbLayout, error) {
	if len(raw) < cfbHeaderSize {
		return nil, fmt.Errorf("file too small to hold a compound file header")
	}
	if !isCompoundFile(raw) {
		return nil, fmt.Errorf("not an OLE compound file")
	}

	sectorShift := binary.LittleEndian.Uint16(raw[30:32])
	if sectorShift < 7 || sectorShift > 20 {
		return nil, fmt.Errorf("implausible sector shift %d", sectorShift)
	}
	sectorSize := 1 << sectorShift

	miniShift := binary.LittleEndian.Uint16(raw[32:34])
	if miniShift < 2 || miniShift >= sectorShift {
		return nil, fmt.Errorf("implausible mini sector shift %d", miniShift)
	}
	miniSize := 1 << miniShift

	miniCutoff := int(binary.LittleEndian.Uint32(raw[56:60]))
	if miniCutoff <= 0 {
		miniCutoff = 4096
	}

	fat, err := readFAT(raw, sectorSize)
	if err != nil {
		return nil, err
	}

	// The directory is itself a sector chain.
	dirStart := binary.LittleEndian.Uint32(raw[48:52])
	dirSectors, err := followChain(fat, dirStart)
	if err != nil {
		return nil, fmt.Errorf("directory chain: %w", err)
	}

	var entries []byte
	for _, sec := range dirSectors {
		off := sectorOffset(sec, sectorSize)
		if off < 0 || off+sectorSize > len(raw) {
			return nil, fmt.Errorf("directory sector %d out of range", sec)
		}
		entries = append(entries, raw[off:off+sectorSize]...)
	}

	// The root entry's chain is the mini stream container; mini sectors are indexed
	// within it, so mini streams cannot be resolved without it.
	var miniContainer []uint32
	if len(entries) >= dirEntrySize {
		rootStart := binary.LittleEndian.Uint32(entries[116:120])
		if rootStart != sectorEndOfChain && rootStart != sectorFree {
			miniContainer, _ = followChain(fat, rootStart)
		}
	}

	miniFATStart := binary.LittleEndian.Uint32(raw[60:64])
	var miniFAT []uint32
	if miniFATStart != sectorEndOfChain && miniFATStart != sectorFree {
		miniSectors, ferr := followChain(fat, miniFATStart)
		if ferr == nil {
			for _, sec := range miniSectors {
				off := sectorOffset(sec, sectorSize)
				if off < 0 || off+sectorSize > len(raw) {
					break
				}
				for i := 0; i+4 <= sectorSize; i += 4 {
					miniFAT = append(miniFAT, binary.LittleEndian.Uint32(raw[off+i:off+i+4]))
				}
			}
		}
	}

	layout := &cfbLayout{}
	for off := 0; off+dirEntrySize <= len(entries); off += dirEntrySize {
		e := entries[off : off+dirEntrySize]
		objType := e[66]
		if objType != dirTypeStream {
			continue
		}
		// A directory entry's declared size is attacker-controlled and need not match
		// what the file can hold. Clamping it to the file length is what keeps a small
		// file from causing a huge allocation: a 7KB container declaring a 2GB stream
		// otherwise made readLogical preallocate 2GB, which is a memory-amplification
		// DoS reachable by editing eight bytes of any .doc.
		//
		// Clamping rather than rejecting is deliberate: a truncated document is a real
		// thing, and redacting the bytes that ARE present beats refusing the file.
		declared := binary.LittleEndian.Uint64(e[120:128])
		if declared == 0 || declared > uint64(len(raw)) {
			if declared == 0 {
				continue
			}
			declared = uint64(len(raw))
		}
		size := int(declared)
		if size <= 0 {
			continue
		}
		start := binary.LittleEndian.Uint32(e[116:120])
		if start == sectorEndOfChain || start == sectorFree {
			continue
		}

		name := decodeDirEntryName(e)

		var frags []streamFragment
		if size < miniCutoff {
			frags, err = mapMiniStream(start, size, miniFAT, miniContainer, sectorSize, miniSize, len(raw))
		} else {
			frags, err = mapRegularStream(start, size, fat, sectorSize, len(raw))
		}
		if err != nil {
			// One unmappable stream must not cost the others: partial coverage still
			// redacts what it can, and the caller reports what it could not locate.
			continue
		}
		layout.streams = append(layout.streams, streamExtent{
			name:      name,
			size:      size,
			fragments: frags,
		})
	}

	if len(layout.streams) == 0 {
		return nil, fmt.Errorf("no mappable streams in the compound file")
	}
	return layout, nil
}

const (
	sectorFree       = 0xFFFFFFFF
	sectorEndOfChain = 0xFFFFFFFE
	sectorFATMarker  = 0xFFFFFFFD
	sectorDIFAT      = 0xFFFFFFFC
	dirTypeStream    = 2
)

// sectorOffset converts a sector number to a file offset. Sector n starts after the
// header, so the header is not part of the numbering.
func sectorOffset(sector uint32, sectorSize int) int {
	if sector >= sectorFATMarker {
		return -1
	}
	return (int(sector) + 1) * sectorSize
}

// readFAT assembles the file allocation table from the DIFAT.
func readFAT(raw []byte, sectorSize int) ([]uint32, error) {
	numFAT := int(binary.LittleEndian.Uint32(raw[44:48]))
	if numFAT <= 0 {
		return nil, fmt.Errorf("compound file declares no FAT sectors")
	}

	// The first 109 FAT sector locations sit in the header.
	difat := make([]uint32, 0, numFAT)
	for i := 76; i+4 <= cfbHeaderSize; i += 4 {
		difat = append(difat, binary.LittleEndian.Uint32(raw[i:i+4]))
	}

	// Additional DIFAT sectors chain from the header, each ending with the next
	// DIFAT sector's number.
	difatStart := binary.LittleEndian.Uint32(raw[68:72])
	numDIFAT := int(binary.LittleEndian.Uint32(raw[72:76]))
	next := difatStart
	for i := 0; i < numDIFAT && next != sectorEndOfChain && next != sectorFree; i++ {
		off := sectorOffset(next, sectorSize)
		if off < 0 || off+sectorSize > len(raw) {
			break
		}
		for j := 0; j+4 <= sectorSize-4; j += 4 {
			difat = append(difat, binary.LittleEndian.Uint32(raw[off+j:off+j+4]))
		}
		next = binary.LittleEndian.Uint32(raw[off+sectorSize-4 : off+sectorSize])
	}

	fat := make([]uint32, 0, numFAT*(sectorSize/4))
	used := 0
	for _, sec := range difat {
		if used >= numFAT {
			break
		}
		if sec == sectorFree || sec >= sectorFATMarker {
			continue
		}
		off := sectorOffset(sec, sectorSize)
		if off < 0 || off+sectorSize > len(raw) {
			continue
		}
		for i := 0; i+4 <= sectorSize; i += 4 {
			fat = append(fat, binary.LittleEndian.Uint32(raw[off+i:off+i+4]))
		}
		used++
	}
	if len(fat) == 0 {
		return nil, fmt.Errorf("could not read any FAT sector")
	}
	return fat, nil
}

// followChain walks a sector chain from start, returning the sectors in order.
//
// A malformed or hostile file can point a chain at itself, so visited sectors are
// tracked: without that this loops forever on input a user can hand us.
func followChain(fat []uint32, start uint32) ([]uint32, error) {
	if start == sectorEndOfChain || start == sectorFree {
		return nil, nil
	}
	var out []uint32
	seen := make(map[uint32]bool)
	cur := start
	for cur != sectorEndOfChain && cur != sectorFree {
		if cur >= sectorFATMarker {
			return nil, fmt.Errorf("chain entered a reserved sector value %#x", cur)
		}
		if int(cur) >= len(fat) {
			return nil, fmt.Errorf("chain leaves the FAT at sector %d", cur)
		}
		if seen[cur] {
			return nil, fmt.Errorf("cycle detected at sector %d", cur)
		}
		seen[cur] = true
		out = append(out, cur)
		if len(out) > maxChainSectors {
			return nil, fmt.Errorf("chain exceeds %d sectors", maxChainSectors)
		}
		cur = fat[cur]
	}
	return out, nil
}

// mapRegularStream maps a stream stored in regular sectors.
func mapRegularStream(start uint32, size int, fat []uint32, sectorSize, fileLen int) ([]streamFragment, error) {
	chain, err := followChain(fat, start)
	if err != nil {
		return nil, err
	}
	var frags []streamFragment
	remaining := size
	logical := 0
	for _, sec := range chain {
		if remaining <= 0 {
			break
		}
		off := sectorOffset(sec, sectorSize)
		if off < 0 || off >= fileLen {
			return nil, fmt.Errorf("sector %d outside the file", sec)
		}
		n := sectorSize
		if n > remaining {
			n = remaining
		}
		if off+n > fileLen {
			n = fileLen - off
		}
		if n <= 0 {
			break
		}
		frags = append(frags, streamFragment{logicalStart: logical, fileStart: off, length: n})
		logical += n
		remaining -= n
	}
	if len(frags) == 0 {
		return nil, fmt.Errorf("stream mapped to no fragments")
	}
	return frags, nil
}

// mapMiniStream maps a stream stored in the mini stream, whose own bytes live in
// the root entry's regular-sector chain.
func mapMiniStream(start uint32, size int, miniFAT, container []uint32, sectorSize, miniSize, fileLen int) ([]streamFragment, error) {
	if len(container) == 0 {
		return nil, fmt.Errorf("no mini stream container")
	}
	chain, err := followChain(miniFAT, start)
	if err != nil {
		return nil, err
	}
	perSector := sectorSize / miniSize
	var frags []streamFragment
	remaining := size
	logical := 0
	for _, mini := range chain {
		if remaining <= 0 {
			break
		}
		idx := int(mini) / perSector
		if idx >= len(container) {
			return nil, fmt.Errorf("mini sector %d outside the container", mini)
		}
		base := sectorOffset(container[idx], sectorSize)
		if base < 0 {
			return nil, fmt.Errorf("mini container sector %d invalid", container[idx])
		}
		off := base + (int(mini)%perSector)*miniSize
		if off >= fileLen {
			return nil, fmt.Errorf("mini sector %d outside the file", mini)
		}
		n := miniSize
		if n > remaining {
			n = remaining
		}
		if off+n > fileLen {
			n = fileLen - off
		}
		if n <= 0 {
			break
		}
		frags = append(frags, streamFragment{logicalStart: logical, fileStart: off, length: n})
		logical += n
		remaining -= n
	}
	if len(frags) == 0 {
		return nil, fmt.Errorf("mini stream mapped to no fragments")
	}
	return frags, nil
}

// decodeDirEntryName reads a directory entry's UTF-16LE name.
//
// Office prefixes property stream names with a non-printable 0x05 byte, which
// mscfb strips when it exposes a name. The same is done here so a name from this
// layout compares equal to the name the extractor reported against.
func decodeDirEntryName(e []byte) string {
	nameLen := int(binary.LittleEndian.Uint16(e[64:66]))
	if nameLen < 2 || nameLen > 64 {
		return ""
	}
	units := make([]uint16, 0, nameLen/2)
	for i := 0; i+1 < nameLen && i+1 < 64; i += 2 {
		u := binary.LittleEndian.Uint16(e[i : i+2])
		if u == 0 {
			break
		}
		units = append(units, u)
	}
	if len(units) == 0 {
		return ""
	}
	// Drop a leading non-printable marker byte, matching mscfb.
	if units[0] < 0x20 {
		units = units[1:]
	}
	return string(utf16.Decode(units))
}

// readLogical assembles a stream's logical bytes from the file.
func (s streamExtent) readLogical(raw []byte) []byte {
	out := make([]byte, 0, s.size)
	for _, f := range s.fragments {
		if f.fileStart < 0 || f.fileStart+f.length > len(raw) {
			continue
		}
		out = append(out, raw[f.fileStart:f.fileStart+f.length]...)
	}
	return out
}

// writeLogical writes repl into the stream at logical offset, following the sector
// chain so a replacement that straddles a fragment boundary lands in both places.
//
// This is the whole point of the mapping: a straddling write is precisely the case
// that a raw-file overwrite gets wrong.
func (s streamExtent) writeLogical(raw []byte, offset int, repl []byte) bool {
	if offset < 0 || offset+len(repl) > s.size {
		return false
	}
	written := 0
	for _, f := range s.fragments {
		if written >= len(repl) {
			break
		}
		fragEnd := f.logicalStart + f.length
		writeAt := offset + written
		if writeAt >= fragEnd || writeAt < f.logicalStart {
			continue
		}
		within := writeAt - f.logicalStart
		n := f.length - within
		if n > len(repl)-written {
			n = len(repl) - written
		}
		dst := f.fileStart + within
		if dst < 0 || dst+n > len(raw) {
			return false
		}
		copy(raw[dst:dst+n], repl[written:written+n])
		written += n
	}
	return written == len(repl)
}

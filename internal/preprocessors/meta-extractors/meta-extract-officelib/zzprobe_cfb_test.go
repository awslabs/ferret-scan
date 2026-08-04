// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// THROWAWAY AUDIT PROBE -- delete before finishing.
// CFB writer cribbed from internal/redactors/legacyole/cfbfixture_test.go, with a
// generalised property-set encoder (any FMTID, any value type, 1 or 2 sets,
// optional dictionary for user-defined/custom properties).

package metaextractofficelib

import (
	"bytes"
	"encoding/binary"
	"testing"
)

const (
	pcfbSectorSize     = 512
	pcfbMiniSectorSize = 64
	pcfbMiniCutoff     = 4096
	pcfbDirEntrySize   = 128

	pcfbFreeSector = 0xFFFFFFFF
	pcfbEndOfChain = 0xFFFFFFFE
	pcfbFATSector  = 0xFFFFFFFD

	pcfbTypeStream = 2
	pcfbTypeRoot   = 5

	pcfbFATLoc     = 0
	pcfbDirLoc     = 1
	pcfbMiniFATLoc = 2
	pcfbFirstData  = 3
)

type pcfbStream struct {
	name string
	data []byte
}

func pbuildCFB(t *testing.T, streams []pcfbStream) []byte {
	t.Helper()
	type placement struct {
		mini       bool
		startEntry uint32
		size       uint32
	}
	places := make([]placement, len(streams))

	miniData := new(bytes.Buffer)
	var miniSectorCount uint32
	for i, s := range streams {
		if len(s.data) >= pcfbMiniCutoff || len(s.data) == 0 {
			continue
		}
		places[i] = placement{mini: true, startEntry: miniSectorCount, size: uint32(len(s.data))}
		n := (len(s.data) + pcfbMiniSectorSize - 1) / pcfbMiniSectorSize
		padded := make([]byte, n*pcfbMiniSectorSize)
		copy(padded, s.data)
		miniData.Write(padded)
		miniSectorCount += uint32(n)
	}

	next := uint32(pcfbFirstData)
	miniStreamStart := uint32(pcfbEndOfChain)
	var miniStreamSectors int
	if miniData.Len() > 0 {
		miniStreamSectors = (miniData.Len() + pcfbSectorSize - 1) / pcfbSectorSize
		miniStreamStart = next
		next += uint32(miniStreamSectors)
	}

	regularSectors := map[int]int{}
	for i, s := range streams {
		if len(s.data) == 0 {
			places[i] = placement{startEntry: pcfbEndOfChain, size: 0}
			continue
		}
		if places[i].mini {
			continue
		}
		n := (len(s.data) + pcfbSectorSize - 1) / pcfbSectorSize
		places[i] = placement{startEntry: next, size: uint32(len(s.data))}
		regularSectors[i] = n
		next += uint32(n)
	}
	totalSectors := int(next)
	if totalSectors > pcfbSectorSize/4 {
		t.Fatalf("fixture needs %d sectors, one FAT sector addresses %d", totalSectors, pcfbSectorSize/4)
	}

	fat := make([]uint32, pcfbSectorSize/4)
	for i := range fat {
		fat[i] = pcfbFreeSector
	}
	fat[pcfbFATLoc] = pcfbFATSector
	fat[pcfbDirLoc] = pcfbEndOfChain
	fat[pcfbMiniFATLoc] = pcfbEndOfChain
	pchain(fat, miniStreamStart, miniStreamSectors)
	for i := range streams {
		if !places[i].mini && regularSectors[i] > 0 {
			pchain(fat, places[i].startEntry, regularSectors[i])
		}
	}

	miniFAT := make([]uint32, pcfbSectorSize/4)
	for i := range miniFAT {
		miniFAT[i] = pcfbFreeSector
	}
	for i := range streams {
		if !places[i].mini {
			continue
		}
		n := (int(places[i].size) + pcfbMiniSectorSize - 1) / pcfbMiniSectorSize
		pchain(miniFAT, places[i].startEntry, n)
	}

	hdr := make([]byte, pcfbSectorSize)
	copy(hdr[0:8], []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1})
	binary.LittleEndian.PutUint16(hdr[24:], 0x003E)
	binary.LittleEndian.PutUint16(hdr[26:], 0x0003)
	binary.LittleEndian.PutUint16(hdr[28:], 0xFFFE)
	binary.LittleEndian.PutUint16(hdr[30:], 9)
	binary.LittleEndian.PutUint16(hdr[32:], 6)
	binary.LittleEndian.PutUint32(hdr[40:], 1)
	binary.LittleEndian.PutUint32(hdr[44:], 1)
	binary.LittleEndian.PutUint32(hdr[48:], pcfbDirLoc)
	binary.LittleEndian.PutUint32(hdr[56:], pcfbMiniCutoff)
	if miniData.Len() > 0 {
		binary.LittleEndian.PutUint32(hdr[60:], pcfbMiniFATLoc)
		binary.LittleEndian.PutUint32(hdr[64:], 1)
	} else {
		binary.LittleEndian.PutUint32(hdr[60:], pcfbEndOfChain)
		binary.LittleEndian.PutUint32(hdr[64:], 0)
	}
	binary.LittleEndian.PutUint32(hdr[68:], pcfbEndOfChain)
	binary.LittleEndian.PutUint32(hdr[72:], 0)
	for i := 76; i < pcfbSectorSize; i += 4 {
		binary.LittleEndian.PutUint32(hdr[i:], pcfbFreeSector)
	}
	binary.LittleEndian.PutUint32(hdr[76:], pcfbFATLoc)

	dir := make([]byte, pcfbSectorSize)
	child := uint32(pcfbFreeSector)
	if len(streams) > 0 {
		child = 1
	}
	pwriteDirEntry(dir[0:pcfbDirEntrySize], "Root Entry", pcfbTypeRoot,
		miniStreamStart, uint32(miniData.Len()), child, pcfbFreeSector)
	for i, s := range streams {
		off := (i + 1) * pcfbDirEntrySize
		if off+pcfbDirEntrySize > len(dir) {
			t.Fatalf("too many streams")
		}
		right := uint32(pcfbFreeSector)
		if i+1 < len(streams) {
			right = uint32(i + 2)
		}
		pwriteDirEntry(dir[off:off+pcfbDirEntrySize], s.name, pcfbTypeStream,
			places[i].startEntry, places[i].size, pcfbFreeSector, right)
	}

	out := make([]byte, 0, pcfbSectorSize*(1+totalSectors))
	out = append(out, hdr...)
	out = append(out, psectorOf(fat)...)
	out = append(out, dir...)
	out = append(out, psectorOf(miniFAT)...)
	if miniStreamSectors > 0 {
		padded := make([]byte, miniStreamSectors*pcfbSectorSize)
		copy(padded, miniData.Bytes())
		out = append(out, padded...)
	}
	for i, s := range streams {
		if places[i].mini || regularSectors[i] == 0 {
			continue
		}
		padded := make([]byte, regularSectors[i]*pcfbSectorSize)
		copy(padded, s.data)
		out = append(out, padded...)
	}
	return out
}

func pchain(table []uint32, start uint32, n int) {
	if n <= 0 || start == pcfbEndOfChain {
		return
	}
	for k := 0; k < n; k++ {
		e := start + uint32(k)
		if int(e) >= len(table) {
			return
		}
		if k == n-1 {
			table[e] = pcfbEndOfChain
		} else {
			table[e] = e + 1
		}
	}
}

func psectorOf(table []uint32) []byte {
	b := make([]byte, pcfbSectorSize)
	for i, v := range table {
		if (i+1)*4 > len(b) {
			break
		}
		binary.LittleEndian.PutUint32(b[i*4:], v)
	}
	return b
}

func pwriteDirEntry(e []byte, name string, objType byte, startSector, size, child, rightSib uint32) {
	for i := range e {
		e[i] = 0
	}
	runes := []rune(name)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(e[i*2:], uint16(r))
	}
	binary.LittleEndian.PutUint16(e[64:], uint16(len(runes)*2+2))
	e[66] = objType
	e[67] = 1
	binary.LittleEndian.PutUint32(e[68:], pcfbFreeSector)
	binary.LittleEndian.PutUint32(e[72:], rightSib)
	binary.LittleEndian.PutUint32(e[76:], child)
	binary.LittleEndian.PutUint32(e[116:], startSector)
	binary.LittleEndian.PutUint64(e[120:], uint64(size))
}

// ---- generalised property-set encoder -------------------------------------

// pval is one typed property value.
type pval struct {
	id  uint32
	enc []byte // full TypedPropertyValue packet
}

func encLPSTR(s string) []byte {
	body := append([]byte(s), 0)
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	v := make([]byte, 8+len(body))
	binary.LittleEndian.PutUint16(v[0:], 0x001E) // VT_LPSTR
	binary.LittleEndian.PutUint16(v[2:], 0)
	binary.LittleEndian.PutUint32(v[4:], uint32(len(s)+1))
	copy(v[8:], body)
	return v
}

// encLPSTRNoNull declares a length that does NOT include a null terminator,
// which a hand-written or non-Office producer can easily emit.
func encLPSTRNoNull(s string) []byte {
	body := []byte(s)
	for len(body)%4 != 0 {
		body = append(body, 'x') // pad with a printable so no 0x00 appears at all
	}
	v := make([]byte, 8+len(body))
	binary.LittleEndian.PutUint16(v[0:], 0x001E)
	binary.LittleEndian.PutUint16(v[2:], 0)
	binary.LittleEndian.PutUint32(v[4:], uint32(len(s)))
	copy(v[8:], body)
	return v
}

func encFILETIME(low, high uint32) []byte {
	v := make([]byte, 12)
	binary.LittleEndian.PutUint16(v[0:], 0x0040) // VT_FILETIME
	binary.LittleEndian.PutUint16(v[2:], 0)
	binary.LittleEndian.PutUint32(v[4:], low)
	binary.LittleEndian.PutUint32(v[8:], high)
	return v
}

func encI2(n uint16) []byte {
	v := make([]byte, 8)
	binary.LittleEndian.PutUint16(v[0:], 0x0002) // VT_I2
	binary.LittleEndian.PutUint16(v[2:], 0)
	binary.LittleEndian.PutUint16(v[4:], n)
	return v
}

// encDictionary encodes a MS-OLEPS Dictionary (non-unicode code page): entry
// count, then id + byte-length + null-terminated chars per entry.
func encDictionary(names map[uint32]string, order []uint32) []byte {
	b := new(bytes.Buffer)
	binary.Write(b, binary.LittleEndian, uint32(len(order)))
	for _, id := range order {
		s := names[id]
		binary.Write(b, binary.LittleEndian, id)
		binary.Write(b, binary.LittleEndian, uint32(len(s)+1))
		b.WriteString(s)
		b.WriteByte(0)
	}
	// pad to 4
	for b.Len()%4 != 0 {
		b.WriteByte(0)
	}
	return b.Bytes()
}

// pbuildSet lays out one property set: header, id/offset table, then payloads in
// table order. Returns the bytes; offsets inside are relative to set start.
func pbuildSet(vals []pval) []byte {
	tableBytes := 8 + len(vals)*8
	offsets := make([]uint32, len(vals))
	cursor := uint32(tableBytes)
	for i, v := range vals {
		offsets[i] = cursor
		cursor += uint32(len(v.enc))
	}
	set := new(bytes.Buffer)
	binary.Write(set, binary.LittleEndian, cursor)
	binary.Write(set, binary.LittleEndian, uint32(len(vals)))
	for i, v := range vals {
		binary.Write(set, binary.LittleEndian, v.id)
		binary.Write(set, binary.LittleEndian, offsets[i])
	}
	for _, v := range vals {
		set.Write(v.enc)
	}
	return set.Bytes()
}

// pbuildStream wraps one or two property sets in a PropertySetStream header.
func pbuildStream(fmtidA []byte, setA []byte, fmtidB []byte, setB []byte) []byte {
	if fmtidB == nil {
		out := make([]byte, 48)
		binary.LittleEndian.PutUint16(out[0:], 0xFFFE)
		binary.LittleEndian.PutUint32(out[4:], 0x00020006)
		binary.LittleEndian.PutUint32(out[24:], 1)
		copy(out[28:44], fmtidA)
		binary.LittleEndian.PutUint32(out[44:], 48)
		return append(out, setA...)
	}
	out := make([]byte, 68)
	binary.LittleEndian.PutUint16(out[0:], 0xFFFE)
	binary.LittleEndian.PutUint32(out[4:], 0x00020006)
	binary.LittleEndian.PutUint32(out[24:], 2)
	copy(out[28:44], fmtidA)
	binary.LittleEndian.PutUint32(out[44:], 68)
	copy(out[48:64], fmtidB)
	binary.LittleEndian.PutUint32(out[64:], uint32(68+len(setA)))
	out = append(out, setA...)
	return append(out, setB...)
}

// FMTIDs in on-disk mixed-endian form.
var (
	fmtidSummary = []byte{0xE0, 0x85, 0x9F, 0xF2, 0xF9, 0x4F, 0x68, 0x10,
		0xAB, 0x91, 0x08, 0x00, 0x2B, 0x27, 0xB3, 0xD9} // {F29F85E0-...}
	fmtidDocSummary = []byte{0x02, 0xD5, 0xCD, 0xD5, 0x9C, 0x2E, 0x1B, 0x10,
		0x93, 0x97, 0x08, 0x00, 0x2B, 0x2C, 0xF9, 0xAE} // {D5CDD502-...}
	fmtidUserDefined = []byte{0x05, 0xD5, 0xCD, 0xD5, 0x9C, 0x2E, 0x1B, 0x10,
		0x93, 0x97, 0x08, 0x00, 0x2B, 0x2C, 0xF9, 0xAE} // {D5CDD505-...} custom props
)

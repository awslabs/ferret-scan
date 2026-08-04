// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package legacyole

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/richardlehane/mscfb"
)

// A minimal but REAL OLE Compound File Binary writer, for tests only.
//
// Without this the end-to-end path is untestable in CI: the only legacy Office
// documents available are on a developer's disk, and a test that depends on one
// is a test that does not run. Asserting on hand-assembled byte slices instead
// would prove nothing about whether a genuine container survives redaction,
// which is the whole risk of patching bytes in place.
//
// # Layout
//
// The header occupies the first 512 bytes and is NOT part of the sector
// numbering (sector n begins at offset (n+1)*512). Sectors are then:
//
//	0        : the single FAT sector
//	1        : the single directory sector
//	2        : the single mini FAT sector
//	3..      : the mini stream chain, then one chain per regular stream
//
// One 512-byte FAT sector holds 128 entries, so this addresses 128 sectors —
// 64KB of file. Fixtures stay well inside that, which is why no DIFAT or
// multi-FAT handling is needed.
//
// # Why the mini stream is not optional
//
// mscfb routes any stream SMALLER THAN 4096 bytes through the mini FAT
// (file.go: `if f.Size < miniStreamCutoffSize`), so a small stream placed in
// regular sectors is unreadable — the reader fails with "minisector number is
// outside minisector range" and returns zero bytes. A real .doc keeps its
// \x05SummaryInformation property stream well under 4096 bytes, so without mini
// stream support a fixture could not carry document properties at all, and the
// metadata half of legacy Office support would have no honest test.
//
// An earlier version of this builder omitted the mini stream and its self-check
// only walked the directory without READING any stream, so it passed while every
// stream returned zero bytes. Hence TestCFBFixtureStreamsReadBackIntact below,
// which reads content back through mscfb — the same call the production code
// makes.
const (
	cfbSectorSize     = 512
	cfbMiniSectorSize = 64
	cfbMiniCutoff     = 4096
	cfbDirEntrySize   = 128

	cfbFreeSector = 0xFFFFFFFF
	cfbEndOfChain = 0xFFFFFFFE
	cfbFATSector  = 0xFFFFFFFD

	// Directory entry object types, per MS-CFB.
	cfbTypeStream = 2
	cfbTypeRoot   = 5

	// Fixed sector assignments (see the layout comment above).
	cfbFATLoc     = 0
	cfbDirLoc     = 1
	cfbMiniFATLoc = 2
	cfbFirstData  = 3
)

// cfbStream is one named stream to place in the fixture.
//
// Name is the name as Office writes it. For a property stream that includes the
// leading 0x05 byte: mscfb strips a non-printable initial character when it
// exposes File.Name, so "\x05SummaryInformation" in the container surfaces as
// "SummaryInformation" — which is what the extractor matches on. Writing the
// name without the prefix would make the fixture disagree with every real
// document.
type cfbStream struct {
	name string
	data []byte
}

// buildCFB assembles a valid compound file containing the given streams.
//
// Streams shorter than 4096 bytes are placed in the mini stream, mirroring what
// Office does, so the fixture exercises the same read path as a real document.
func buildCFB(t *testing.T, streams []cfbStream) []byte {
	t.Helper()

	// Split by the cutoff, preserving input order within each group.
	type placement struct {
		mini       bool
		startEntry uint32 // sector number, or mini sector number when mini
		size       uint32
	}
	places := make([]placement, len(streams))

	// --- mini stream: concatenate small streams on 64-byte boundaries ---------
	miniData := new(bytes.Buffer)
	var miniSectorCount uint32
	for i, s := range streams {
		if len(s.data) >= cfbMiniCutoff || len(s.data) == 0 {
			continue
		}
		places[i] = placement{mini: true, startEntry: miniSectorCount, size: uint32(len(s.data))}
		n := (len(s.data) + cfbMiniSectorSize - 1) / cfbMiniSectorSize
		padded := make([]byte, n*cfbMiniSectorSize)
		copy(padded, s.data)
		miniData.Write(padded)
		miniSectorCount += uint32(n)
	}

	// The mini stream itself lives in regular sectors, as the root entry's chain.
	next := uint32(cfbFirstData)
	miniStreamStart := uint32(cfbEndOfChain)
	var miniStreamSectors int
	if miniData.Len() > 0 {
		miniStreamSectors = (miniData.Len() + cfbSectorSize - 1) / cfbSectorSize
		miniStreamStart = next
		next += uint32(miniStreamSectors)
	}

	// --- regular streams -----------------------------------------------------
	regularSectors := map[int]int{} // stream index -> sector count
	for i, s := range streams {
		if len(s.data) == 0 {
			places[i] = placement{startEntry: cfbEndOfChain, size: 0}
			continue
		}
		if places[i].mini {
			continue
		}
		n := (len(s.data) + cfbSectorSize - 1) / cfbSectorSize
		places[i] = placement{startEntry: next, size: uint32(len(s.data))}
		regularSectors[i] = n
		next += uint32(n)
	}
	totalSectors := int(next)

	if totalSectors > cfbSectorSize/4 {
		t.Fatalf("fixture needs %d sectors but one FAT sector addresses only %d — "+
			"keep test fixtures under %dKB or teach the builder multi-FAT support",
			totalSectors, cfbSectorSize/4, (cfbSectorSize/4)*cfbSectorSize/1024)
	}

	// --- FAT -----------------------------------------------------------------
	fat := make([]uint32, cfbSectorSize/4)
	for i := range fat {
		fat[i] = cfbFreeSector
	}
	fat[cfbFATLoc] = cfbFATSector
	fat[cfbDirLoc] = cfbEndOfChain
	fat[cfbMiniFATLoc] = cfbEndOfChain
	chain(fat, miniStreamStart, miniStreamSectors)
	for i := range streams {
		if !places[i].mini && regularSectors[i] > 0 {
			chain(fat, places[i].startEntry, regularSectors[i])
		}
	}

	// --- mini FAT: one entry per 64-byte mini sector --------------------------
	miniFAT := make([]uint32, cfbSectorSize/4)
	for i := range miniFAT {
		miniFAT[i] = cfbFreeSector
	}
	for i := range streams {
		if !places[i].mini {
			continue
		}
		n := (int(places[i].size) + cfbMiniSectorSize - 1) / cfbMiniSectorSize
		chain(miniFAT, places[i].startEntry, n)
	}

	// --- header --------------------------------------------------------------
	hdr := make([]byte, cfbSectorSize)
	copy(hdr[0:8], []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1})
	binary.LittleEndian.PutUint16(hdr[24:], 0x003E) // minor version
	binary.LittleEndian.PutUint16(hdr[26:], 0x0003) // major version 3 => 512-byte sectors
	binary.LittleEndian.PutUint16(hdr[28:], 0xFFFE) // little-endian marker
	binary.LittleEndian.PutUint16(hdr[30:], 9)      // sector shift: 1<<9 = 512
	binary.LittleEndian.PutUint16(hdr[32:], 6)      // mini sector shift: 1<<6 = 64
	binary.LittleEndian.PutUint32(hdr[40:], 1)      // number of directory sectors
	binary.LittleEndian.PutUint32(hdr[44:], 1)      // number of FAT sectors
	binary.LittleEndian.PutUint32(hdr[48:], cfbDirLoc)
	binary.LittleEndian.PutUint32(hdr[56:], cfbMiniCutoff)
	if miniData.Len() > 0 {
		binary.LittleEndian.PutUint32(hdr[60:], cfbMiniFATLoc)
		binary.LittleEndian.PutUint32(hdr[64:], 1) // one mini FAT sector
	} else {
		binary.LittleEndian.PutUint32(hdr[60:], cfbEndOfChain)
		binary.LittleEndian.PutUint32(hdr[64:], 0)
	}
	binary.LittleEndian.PutUint32(hdr[68:], cfbEndOfChain) // no DIFAT chain
	binary.LittleEndian.PutUint32(hdr[72:], 0)             // no extra DIFAT sectors
	for i := 76; i < cfbSectorSize; i += 4 {
		binary.LittleEndian.PutUint32(hdr[i:], cfbFreeSector)
	}
	binary.LittleEndian.PutUint32(hdr[76:], cfbFATLoc) // DIFAT[0] -> the FAT sector

	// --- directory -----------------------------------------------------------
	// The root entry's chain IS the mini stream, and its size is the mini
	// stream's length: mscfb walks that chain to resolve every mini sector.
	dir := make([]byte, cfbSectorSize)
	child := uint32(cfbFreeSector)
	if len(streams) > 0 {
		child = 1
	}
	writeDirEntry(dir[0:cfbDirEntrySize], "Root Entry", cfbTypeRoot,
		miniStreamStart, uint32(miniData.Len()), child, cfbFreeSector)

	for i, s := range streams {
		off := (i + 1) * cfbDirEntrySize
		if off+cfbDirEntrySize > len(dir) {
			t.Fatalf("fixture has %d streams; one directory sector holds only %d entries "+
				"including the root", len(streams), cfbSectorSize/cfbDirEntrySize)
		}
		// Chain entries as right siblings so mscfb's traversal reaches them all.
		right := uint32(cfbFreeSector)
		if i+1 < len(streams) {
			right = uint32(i + 2)
		}
		writeDirEntry(dir[off:off+cfbDirEntrySize], s.name, cfbTypeStream,
			places[i].startEntry, places[i].size, cfbFreeSector, right)
	}

	// --- assemble ------------------------------------------------------------
	out := make([]byte, 0, cfbSectorSize*(1+totalSectors))
	out = append(out, hdr...)
	out = append(out, sectorOf(fat)...)
	out = append(out, dir...)
	out = append(out, sectorOf(miniFAT)...)
	if miniStreamSectors > 0 {
		padded := make([]byte, miniStreamSectors*cfbSectorSize)
		copy(padded, miniData.Bytes())
		out = append(out, padded...)
	}
	for i, s := range streams {
		if places[i].mini || regularSectors[i] == 0 {
			continue
		}
		padded := make([]byte, regularSectors[i]*cfbSectorSize)
		copy(padded, s.data)
		out = append(out, padded...)
	}
	return out
}

// chain marks a run of n consecutive entries starting at start as one chain.
func chain(table []uint32, start uint32, n int) {
	if n <= 0 || start == cfbEndOfChain {
		return
	}
	for k := 0; k < n; k++ {
		e := start + uint32(k)
		if int(e) >= len(table) {
			return
		}
		if k == n-1 {
			table[e] = cfbEndOfChain
		} else {
			table[e] = e + 1
		}
	}
}

// sectorOf serialises a FAT/mini-FAT table into one little-endian sector.
func sectorOf(table []uint32) []byte {
	b := make([]byte, cfbSectorSize)
	for i, v := range table {
		if (i+1)*4 > len(b) {
			break
		}
		binary.LittleEndian.PutUint32(b[i*4:], v)
	}
	return b
}

// writeDirEntry fills one 128-byte directory entry. The name is UTF-16LE and its
// byte length INCLUDES the terminating null, which is the detail that decides
// whether a parser reads the name or rejects the entry.
func writeDirEntry(e []byte, name string, objType byte, startSector, size, child, rightSib uint32) {
	for i := range e {
		e[i] = 0
	}
	runes := []rune(name)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(e[i*2:], uint16(r))
	}
	binary.LittleEndian.PutUint16(e[64:], uint16(len(runes)*2+2))
	e[66] = objType
	e[67] = 1                                            // black, in the red-black sibling tree
	binary.LittleEndian.PutUint32(e[68:], cfbFreeSector) // left sibling
	binary.LittleEndian.PutUint32(e[72:], rightSib)
	binary.LittleEndian.PutUint32(e[76:], child)
	binary.LittleEndian.PutUint32(e[116:], startSector)
	binary.LittleEndian.PutUint64(e[120:], uint64(size))
}

// buildSummaryInformation encodes an OLE property set stream carrying the given
// SummaryInformation properties, keyed by property ID.
//
// This is the legacy counterpart of docProps/core.xml, and it is where a real
// document's author, company and template path live — so a fixture without it
// could not test the metadata half of legacy Office support at all.
//
// Layout (MS-OLEPS): a 48-byte PropertySetStream header naming one property set
// by FMTID, then that set's own header (byte size, property count), then a
// property ID/offset table, then the values. Offsets are relative to the START of
// the property set, not the stream.
func buildSummaryInformation(props map[uint32]string) []byte {
	// Deterministic order: property IDs ascending. A map range would vary the
	// bytes run to run, which is the same nondeterminism the OOXML builders pin.
	ids := make([]uint32, 0, len(props))
	for id := range props {
		ids = append(ids, id)
	}
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0 && ids[j] < ids[j-1]; j-- {
			ids[j], ids[j-1] = ids[j-1], ids[j]
		}
	}

	// Every value is VT_LPSTR (0x001E): 2-byte type, 2 bytes padding, 4-byte
	// length (INCLUDING the null terminator), then the bytes, padded to 4.
	type encoded struct {
		id  uint32
		val []byte
	}
	var vals []encoded
	for _, id := range ids {
		s := props[id]
		body := append([]byte(s), 0)
		for len(body)%4 != 0 {
			body = append(body, 0)
		}
		v := make([]byte, 8+len(body))
		binary.LittleEndian.PutUint16(v[0:], 0x001E)           // VT_LPSTR
		binary.LittleEndian.PutUint16(v[2:], 0)                // scalar, not vector
		binary.LittleEndian.PutUint32(v[4:], uint32(len(s)+1)) // length with null
		copy(v[8:], body)
		vals = append(vals, encoded{id: id, val: v})
	}

	// Property set: header (8) + ID/offset table (8 per property) + values.
	tableBytes := 8 + len(vals)*8
	set := new(bytes.Buffer)
	offsets := make([]uint32, len(vals))
	cursor := uint32(tableBytes)
	for i, v := range vals {
		offsets[i] = cursor
		cursor += uint32(len(v.val))
	}
	binary.Write(set, binary.LittleEndian, cursor)            // total set size
	binary.Write(set, binary.LittleEndian, uint32(len(vals))) // property count
	for i, v := range vals {
		binary.Write(set, binary.LittleEndian, v.id)
		binary.Write(set, binary.LittleEndian, offsets[i])
	}
	for _, v := range vals {
		set.Write(v.val)
	}

	// PropertySetStream header. FMTID {F29F85E0-4FF9-1068-AB91-08002B27B3D9} is
	// SummaryInformation; msoleps looks up its property-name table by this GUID,
	// so a wrong FMTID yields unnamed properties and the extractor's switch on
	// p.Name would match nothing.
	out := make([]byte, 48)
	binary.LittleEndian.PutUint16(out[0:], 0xFFFE) // byte order
	binary.LittleEndian.PutUint16(out[2:], 0)      // version
	binary.LittleEndian.PutUint32(out[4:], 0x00020006)
	binary.LittleEndian.PutUint32(out[24:], 1) // one property set
	copy(out[28:44], summaryInfoFMTID)
	binary.LittleEndian.PutUint32(out[44:], 48) // the set starts right after
	return append(out, set.Bytes()...)
}

// summaryInfoFMTID is {F29F85E0-4FF9-1068-AB91-08002B27B3D9} in the mixed-endian
// on-disk GUID form: the first three fields little-endian, the last eight bytes
// in order.
var summaryInfoFMTID = []byte{
	0xE0, 0x85, 0x9F, 0xF2,
	0xF9, 0x4F,
	0x68, 0x10,
	0xAB, 0x91, 0x08, 0x00, 0x2B, 0x27, 0xB3, 0xD9,
}

// SummaryInformation property IDs used by the fixtures (MS-OLEPS 2.18).
const (
	propTitle      = 0x00000002
	propSubject    = 0x00000003
	propAuthor     = 0x00000004
	propKeywords   = 0x00000005
	propComments   = 0x00000006
	propTemplate   = 0x00000007
	propLastAuthor = 0x00000008
	propAppName    = 0x00000012
)

// The fixture builder is load-bearing: if it produced something mscfb could not
// read, every test built on it would pass for the wrong reason — the redactor
// would refuse the file, or find nothing to overwrite, and no assertion about
// redaction would actually run.
func TestCFBFixtureIsReadableByProductionCode(t *testing.T) {
	raw := buildCFB(t, []cfbStream{
		{name: "WordDocument", data: []byte("Employee SSN: 449-87-4100 and more text here")},
		{name: "\x05SummaryInformation", data: buildSummaryInformation(map[uint32]string{
			propAuthor: "Jane Analyst",
		})},
	})

	if !isCompoundFile(raw) {
		t.Fatal("builder output does not carry the CFB signature")
	}
	// parseCFBLayout is what RedactDocument calls, so this asserts the fixture is
	// mappable by the LIVE path. It previously called contentRanges, which the
	// logical-stream mapping replaced — a fixture check against a replaced helper
	// could pass while the real redactor could not map the file at all.
	layout, err := parseCFBLayout(raw)
	if err != nil {
		t.Fatalf("production code cannot map the fixture's streams: %v — every test "+
			"built on this fixture would otherwise pass without redacting anything", err)
	}
	if len(layout.streams) < 2 {
		t.Errorf("only %d stream(s) mapped from a two-stream fixture; a stream the "+
			"mapping cannot reach is a stream redaction silently skips", len(layout.streams))
	}
	if len(raw)%cfbSectorSize != 0 {
		t.Errorf("fixture is %d bytes, not a whole number of %d-byte sectors", len(raw), cfbSectorSize)
	}
}

// This is the check the first version of the builder lacked, and its absence hid
// a real defect: contentRanges only WALKS the directory, so a fixture whose
// streams all read back as zero bytes satisfied it completely. Reading the
// content back through mscfb — the same call the extractor makes — is what
// distinguishes "the container parses" from "the container holds the data".
func TestCFBFixtureStreamsReadBackIntact(t *testing.T) {
	const bodyText = "Employee SSN: 449-87-4100 and more text here"

	cases := []struct {
		desc   string
		stream cfbStream
		want   []byte
	}{
		{
			desc:   "small stream (under the 4096-byte mini cutoff, so via the mini FAT)",
			stream: cfbStream{name: "WordDocument", data: []byte(bodyText)},
			want:   []byte(bodyText),
		},
		{
			desc: "large stream (at/over the cutoff, so via regular sectors)",
			stream: cfbStream{name: "WordDocument", data: func() []byte {
				b := make([]byte, cfbMiniCutoff)
				copy(b, bodyText)
				return b
			}()},
			want: []byte(bodyText),
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			raw := buildCFB(t, []cfbStream{tc.stream})
			doc, err := mscfb.New(bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("mscfb rejected the fixture: %v", err)
			}
			var found bool
			for entry, e := doc.Next(); e == nil; entry, e = doc.Next() {
				if entry.Name != "WordDocument" {
					continue
				}
				found = true
				got, rerr := io.ReadAll(entry)
				if rerr != nil {
					t.Fatalf("reading %s: %v — the fixture parses but holds no readable "+
						"data, so any redaction assertion on it would be vacuous",
						entry.Name, rerr)
				}
				if !bytes.Contains(got, tc.want) {
					t.Errorf("stream read back %d bytes without the expected content; "+
						"the fixture does not carry what it claims to", len(got))
				}
			}
			if !found {
				t.Error("no WordDocument entry surfaced from the fixture")
			}
		})
	}
}

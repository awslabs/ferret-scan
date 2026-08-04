// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractofficelib

import (
	"bytes"
	"encoding/binary"
	"io"
	"sort"
	"testing"
	"time"

	"github.com/richardlehane/mscfb"

	"github.com/awslabs/ferret-scan/v2/internal/olefixture"
)

// A minimal but REAL OLE Compound File Binary writer, plus an OLE property-set
// encoder, for tests only.
//
// Legacy Office documents are the one format this package cannot test from
// committed fixtures without checking in an opaque binary, and the only real ones
// available live on a developer's disk — a test that depends on such a file is a
// test that does not run in CI. So the container is synthesized here, exactly as
// the OOXML cases synthesize .docx/.xlsx zips rather than committing them.
//
// # Container layout
//
// The 512-byte header is NOT part of the sector numbering: sector n starts at
// offset (n+1)*512. Sectors are then:
//
//	0   : the single FAT sector
//	1   : the single directory sector
//	2   : the single mini FAT sector
//	3.. : the mini stream chain, then one chain per regular stream
//
// One FAT sector holds 128 entries, addressing 64KB of file, which is far more
// than any fixture needs — hence no DIFAT or multi-FAT handling.
//
// # Why the mini stream is mandatory here
//
// mscfb routes every stream SMALLER THAN 4096 bytes through the mini FAT. A real
// document's property streams are a few hundred bytes, so without mini-stream
// support a fixture simply could not carry document properties: the reader fails
// with "minisector number is outside minisector range" and returns zero bytes.
// Since properties are exactly what the metadata half of legacy support reads,
// that would make every metadata assertion vacuous.
//
// # Stream names
//
// Office writes property streams with a leading 0x05 byte
// ("\x05SummaryInformation"). mscfb strips a non-printable initial character when
// exposing File.Name, so the extractor matches "SummaryInformation". Fixtures use
// the on-disk name WITH the prefix so they agree with real documents.
const (
	cfbSectorSize     = 512
	cfbMiniSectorSize = 64
	cfbMiniCutoff     = 4096
	cfbDirEntrySize   = 128

	cfbFreeSector = 0xFFFFFFFF
	cfbEndOfChain = 0xFFFFFFFE
	cfbFATSector  = 0xFFFFFFFD

	cfbTypeStream = 2
	cfbTypeRoot   = 5

	cfbFATLoc     = 0
	cfbDirLoc     = 1
	cfbMiniFATLoc = 2
	cfbFirstData  = 3
)

// legacyCFBStream is one named stream to place in a fixture.
type legacyCFBStream struct {
	Name string
	Data []byte
}

// buildLegacyCFB assembles a valid compound file containing the given streams.
// Streams under 4096 bytes go through the mini stream, as Office does.
func buildLegacyCFB(t *testing.T, streams []legacyCFBStream) []byte {
	t.Helper()

	type placement struct {
		mini       bool
		startEntry uint32
		size       uint32
	}
	places := make([]placement, len(streams))

	// Small streams are concatenated into the mini stream on 64-byte boundaries.
	miniData := new(bytes.Buffer)
	var miniSectors uint32
	for i, s := range streams {
		if len(s.Data) == 0 || len(s.Data) >= cfbMiniCutoff {
			continue
		}
		places[i] = placement{mini: true, startEntry: miniSectors, size: uint32(len(s.Data))}
		n := (len(s.Data) + cfbMiniSectorSize - 1) / cfbMiniSectorSize
		padded := make([]byte, n*cfbMiniSectorSize)
		copy(padded, s.Data)
		miniData.Write(padded)
		miniSectors += uint32(n)
	}

	// The mini stream itself occupies regular sectors, as the root entry's chain.
	next := uint32(cfbFirstData)
	miniStreamStart := uint32(cfbEndOfChain)
	var miniStreamSectorCount int
	if miniData.Len() > 0 {
		miniStreamSectorCount = (miniData.Len() + cfbSectorSize - 1) / cfbSectorSize
		miniStreamStart = next
		next += uint32(miniStreamSectorCount)
	}

	regular := map[int]int{}
	for i, s := range streams {
		if len(s.Data) == 0 {
			places[i] = placement{startEntry: cfbEndOfChain}
			continue
		}
		if places[i].mini {
			continue
		}
		n := (len(s.Data) + cfbSectorSize - 1) / cfbSectorSize
		places[i] = placement{startEntry: next, size: uint32(len(s.Data))}
		regular[i] = n
		next += uint32(n)
	}

	if int(next) > cfbSectorSize/4 {
		t.Fatalf("fixture needs %d sectors but one FAT sector addresses only %d — keep "+
			"fixtures under %dKB", next, cfbSectorSize/4, (cfbSectorSize/4)*cfbSectorSize/1024)
	}

	fat := filled(cfbSectorSize / 4)
	fat[cfbFATLoc] = cfbFATSector
	fat[cfbDirLoc] = cfbEndOfChain
	fat[cfbMiniFATLoc] = cfbEndOfChain
	cfbChain(fat, miniStreamStart, miniStreamSectorCount)
	for i := range streams {
		if !places[i].mini && regular[i] > 0 {
			cfbChain(fat, places[i].startEntry, regular[i])
		}
	}

	miniFAT := filled(cfbSectorSize / 4)
	for i := range streams {
		if !places[i].mini {
			continue
		}
		n := (int(places[i].size) + cfbMiniSectorSize - 1) / cfbMiniSectorSize
		cfbChain(miniFAT, places[i].startEntry, n)
	}

	hdr := make([]byte, cfbSectorSize)
	copy(hdr[0:8], []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1})
	binary.LittleEndian.PutUint16(hdr[24:], 0x003E)
	binary.LittleEndian.PutUint16(hdr[26:], 0x0003) // major version 3 => 512-byte sectors
	binary.LittleEndian.PutUint16(hdr[28:], 0xFFFE) // little-endian
	binary.LittleEndian.PutUint16(hdr[30:], 9)      // 1<<9  = 512
	binary.LittleEndian.PutUint16(hdr[32:], 6)      // 1<<6  = 64
	binary.LittleEndian.PutUint32(hdr[40:], 1)      // directory sector count
	binary.LittleEndian.PutUint32(hdr[44:], 1)      // FAT sector count
	binary.LittleEndian.PutUint32(hdr[48:], cfbDirLoc)
	binary.LittleEndian.PutUint32(hdr[56:], cfbMiniCutoff)
	if miniData.Len() > 0 {
		binary.LittleEndian.PutUint32(hdr[60:], cfbMiniFATLoc)
		binary.LittleEndian.PutUint32(hdr[64:], 1)
	} else {
		binary.LittleEndian.PutUint32(hdr[60:], cfbEndOfChain)
		binary.LittleEndian.PutUint32(hdr[64:], 0)
	}
	binary.LittleEndian.PutUint32(hdr[68:], cfbEndOfChain) // no DIFAT chain
	binary.LittleEndian.PutUint32(hdr[72:], 0)
	for i := 76; i < cfbSectorSize; i += 4 {
		binary.LittleEndian.PutUint32(hdr[i:], cfbFreeSector)
	}
	binary.LittleEndian.PutUint32(hdr[76:], cfbFATLoc) // DIFAT[0] -> the FAT

	// The root entry's chain IS the mini stream and its size is the mini stream's
	// length; mscfb walks that chain to resolve every mini sector.
	dir := make([]byte, cfbSectorSize)
	child := uint32(cfbFreeSector)
	if len(streams) > 0 {
		child = 1
	}
	writeCFBDirEntry(dir[0:cfbDirEntrySize], "Root Entry", cfbTypeRoot,
		miniStreamStart, uint32(miniData.Len()), child, cfbFreeSector)
	for i, s := range streams {
		off := (i + 1) * cfbDirEntrySize
		if off+cfbDirEntrySize > len(dir) {
			t.Fatalf("fixture has %d streams; one directory sector holds %d entries "+
				"including the root", len(streams), cfbSectorSize/cfbDirEntrySize)
		}
		right := uint32(cfbFreeSector)
		if i+1 < len(streams) {
			right = uint32(i + 2)
		}
		writeCFBDirEntry(dir[off:off+cfbDirEntrySize], s.Name, cfbTypeStream,
			places[i].startEntry, places[i].size, cfbFreeSector, right)
	}

	out := make([]byte, 0, cfbSectorSize*(1+int(next)))
	out = append(out, hdr...)
	out = append(out, cfbSectorOf(fat)...)
	out = append(out, dir...)
	out = append(out, cfbSectorOf(miniFAT)...)
	if miniStreamSectorCount > 0 {
		padded := make([]byte, miniStreamSectorCount*cfbSectorSize)
		copy(padded, miniData.Bytes())
		out = append(out, padded...)
	}
	for i, s := range streams {
		if places[i].mini || regular[i] == 0 {
			continue
		}
		padded := make([]byte, regular[i]*cfbSectorSize)
		copy(padded, s.Data)
		out = append(out, padded...)
	}
	return out
}

func filled(n int) []uint32 {
	t := make([]uint32, n)
	for i := range t {
		t[i] = cfbFreeSector
	}
	return t
}

// cfbChain marks n consecutive entries from start as one chain.
func cfbChain(table []uint32, start uint32, n int) {
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

func cfbSectorOf(table []uint32) []byte {
	b := make([]byte, cfbSectorSize)
	for i, v := range table {
		if (i+1)*4 > len(b) {
			break
		}
		binary.LittleEndian.PutUint32(b[i*4:], v)
	}
	return b
}

// writeCFBDirEntry fills one 128-byte directory entry. The name is UTF-16LE and
// its byte length INCLUDES the terminating null — the detail that decides whether
// a parser reads the name or rejects the entry.
func writeCFBDirEntry(e []byte, name string, objType byte, startSector, size, child, rightSib uint32) {
	for i := range e {
		e[i] = 0
	}
	runes := []rune(name)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(e[i*2:], uint16(r))
	}
	binary.LittleEndian.PutUint16(e[64:], uint16(len(runes)*2+2))
	e[66] = objType
	e[67] = 1 // black
	binary.LittleEndian.PutUint32(e[68:], cfbFreeSector)
	binary.LittleEndian.PutUint32(e[72:], rightSib)
	binary.LittleEndian.PutUint32(e[76:], child)
	binary.LittleEndian.PutUint32(e[116:], startSector)
	binary.LittleEndian.PutUint64(e[120:], uint64(size))
}

// --- OLE property set encoding ----------------------------------------------
//
// This is the legacy counterpart of docProps/core.xml and docProps/app.xml: the
// place a real document's author, company and template path live. Layout per
// MS-OLEPS: a 48-byte PropertySetStream header naming one property set by FMTID,
// then the set's own header (byte size, property count), an ID/offset table, then
// the values. Offsets are relative to the START OF THE PROPERTY SET, not the
// stream — an easy off-by-48 that yields silently empty properties.

// SummaryInformation property IDs (MS-OLEPS 2.18).
const (
	SummaryPropTitle        = 0x00000002
	SummaryPropSubject      = 0x00000003
	SummaryPropAuthor       = 0x00000004
	SummaryPropKeywords     = 0x00000005
	SummaryPropComments     = 0x00000006
	SummaryPropTemplate     = 0x00000007
	SummaryPropLastAuthor   = 0x00000008
	SummaryPropCreateTime   = 0x0000000C
	SummaryPropLastSaveTime = 0x0000000D
	SummaryPropAppName      = 0x00000012
)

// DocumentSummaryInformation property IDs. Company and Manager live HERE, in a
// second property set with a different FMTID — not in SummaryInformation.
const (
	DocSummaryPropCategory      = 0x00000002
	DocSummaryPropManager       = 0x0000000E
	DocSummaryPropCompany       = 0x0000000F
	DocSummaryPropContentStatus = 0x0000001B
	DocSummaryPropLanguage      = 0x0000001C
)

// FMTIDs in on-disk mixed-endian GUID form: first three fields little-endian,
// trailing eight bytes in order. msoleps looks up its property-NAME table by this
// GUID, so a wrong FMTID yields unnamed properties and the extractor's switch on
// Property.Name matches nothing — properties present but silently unmapped.
var (
	// {F29F85E0-4FF9-1068-AB91-08002B27B3D9}
	fmtidSummaryInformation = []byte{
		0xE0, 0x85, 0x9F, 0xF2, 0xF9, 0x4F, 0x68, 0x10,
		0xAB, 0x91, 0x08, 0x00, 0x2B, 0x27, 0xB3, 0xD9,
	}
	// {D5CDD502-2E9C-101B-9397-08002B2CF9AE}
	fmtidDocSummaryInformation = []byte{
		0x02, 0xD5, 0xCD, 0xD5, 0x9C, 0x2E, 0x1B, 0x10,
		0x93, 0x97, 0x08, 0x00, 0x2B, 0x2C, 0xF9, 0xAE,
	}
)

// BuildSummaryInformation encodes a SummaryInformation property stream carrying
// the given string properties.
func BuildSummaryInformation(props map[uint32]string) []byte {
	return buildPropertySet(fmtidSummaryInformation, props, nil)
}

// BuildSummaryInformationWithTimes additionally encodes FILETIME properties, so a
// test can exercise the timestamp path.
func BuildSummaryInformationWithTimes(props map[uint32]string, times map[uint32]uint64) []byte {
	return buildPropertySet(fmtidSummaryInformation, props, times)
}

// BuildDocSummaryInformation encodes a DocumentSummaryInformation property stream.
func BuildDocSummaryInformation(props map[uint32]string) []byte {
	return buildPropertySet(fmtidDocSummaryInformation, props, nil)
}

// buildPropertySet encodes one property set. Property IDs are emitted in ascending
// order so the bytes are stable across runs: ranging a map directly would vary the
// output and any golden built on it would flap.
func buildPropertySet(fmtid []byte, strs map[uint32]string, times map[uint32]uint64) []byte {
	ids := make([]uint32, 0, len(strs)+len(times))
	for id := range strs {
		ids = append(ids, id)
	}
	for id := range times {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	type encoded struct {
		id  uint32
		val []byte
	}
	vals := make([]encoded, 0, len(ids))
	for _, id := range ids {
		if ft, ok := times[id]; ok {
			// VT_FILETIME (0x0040): 2-byte type, 2 bytes padding, 8-byte FILETIME.
			v := make([]byte, 12)
			binary.LittleEndian.PutUint16(v[0:], 0x0040)
			binary.LittleEndian.PutUint64(v[4:], ft)
			vals = append(vals, encoded{id: id, val: v})
			continue
		}
		// VT_LPSTR (0x001E): 2-byte type, 2 bytes padding, 4-byte length INCLUDING
		// the null terminator, then the bytes padded to a 4-byte boundary.
		s := strs[id]
		body := append([]byte(s), 0)
		for len(body)%4 != 0 {
			body = append(body, 0)
		}
		v := make([]byte, 8+len(body))
		binary.LittleEndian.PutUint16(v[0:], 0x001E)
		binary.LittleEndian.PutUint32(v[4:], uint32(len(s)+1))
		copy(v[8:], body)
		vals = append(vals, encoded{id: id, val: v})
	}

	tableBytes := 8 + len(vals)*8
	offsets := make([]uint32, len(vals))
	cursor := uint32(tableBytes)
	for i, v := range vals {
		offsets[i] = cursor
		cursor += uint32(len(v.val))
	}

	set := new(bytes.Buffer)
	_ = binary.Write(set, binary.LittleEndian, cursor)            // total set size
	_ = binary.Write(set, binary.LittleEndian, uint32(len(vals))) // property count
	for i, v := range vals {
		_ = binary.Write(set, binary.LittleEndian, v.id)
		_ = binary.Write(set, binary.LittleEndian, offsets[i])
	}
	for _, v := range vals {
		set.Write(v.val)
	}

	hdr := make([]byte, 48)
	binary.LittleEndian.PutUint16(hdr[0:], 0xFFFE) // byte order
	binary.LittleEndian.PutUint16(hdr[2:], 0)      // version
	binary.LittleEndian.PutUint32(hdr[4:], 0x00020006)
	binary.LittleEndian.PutUint32(hdr[24:], 1) // one property set
	copy(hdr[28:44], fmtid)
	binary.LittleEndian.PutUint32(hdr[44:], 48) // the set begins right after
	return append(hdr, set.Bytes()...)
}

// fileTimeFor converts a date to a Windows FILETIME: 100-nanosecond ticks since
// 1601-01-01 UTC.
func fileTimeFor(year int, month time.Month, day int) uint64 {
	const ticksPerSecond = 10000000
	const secondsGregorianToUnix = 11644473600
	unix := time.Date(year, month, day, 12, 0, 0, 0, time.UTC).Unix()
	return uint64(unix+secondsGregorianToUnix) * ticksPerSecond
}

// --- builder self-checks -----------------------------------------------------

// The builder is load-bearing: a fixture mscfb cannot read would make every test
// built on it pass for the wrong reason, because the extractor would find no
// streams and assert nothing. This reads content back through mscfb — the same
// call the extractor makes — for both size classes, INCLUDING the mini-FAT class
// that property streams always fall into.
func TestLegacyCFBFixtureStreamsReadBackIntact(t *testing.T) {
	const body = "Employee SSN: 449-87-4100 recorded here."
	large := make([]byte, cfbMiniCutoff)
	copy(large, body)

	cases := []struct {
		desc    string
		streams []legacyCFBStream
	}{
		{
			desc: "small streams (under the 4096-byte cutoff, so via the mini FAT)",
			streams: []legacyCFBStream{
				{Name: "WordDocument", Data: []byte(body)},
				{Name: "\x05SummaryInformation", Data: BuildSummaryInformation(
					map[uint32]string{SummaryPropAuthor: "Jane Analyst"})},
			},
		},
		{
			desc: "a large body stream (via regular sectors) beside a small property stream",
			streams: []legacyCFBStream{
				{Name: "WordDocument", Data: large},
				{Name: "\x05SummaryInformation", Data: BuildSummaryInformation(
					map[uint32]string{SummaryPropAuthor: "Jane Analyst"})},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			raw := buildLegacyCFB(t, tc.streams)
			doc, err := mscfb.New(bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("mscfb rejected the fixture: %v", err)
			}
			seen := map[string]int{}
			for entry, e := doc.Next(); e == nil; entry, e = doc.Next() {
				got, rerr := io.ReadAll(entry)
				if rerr != nil {
					t.Fatalf("reading %q: %v — the container parses but holds no readable "+
						"data, so any assertion on it would be vacuous", entry.Name, rerr)
				}
				seen[entry.Name] = len(got)
				if entry.Name == "WordDocument" && !bytes.Contains(got, []byte(body)) {
					t.Errorf("WordDocument read back %d bytes without the expected text", len(got))
				}
			}
			// mscfb strips the leading 0x05, so the property stream must surface
			// under the name the extractor's table matches.
			if _, ok := seen["SummaryInformation"]; !ok {
				t.Errorf("no SummaryInformation entry surfaced; entries were %v — the "+
					"extractor's property-stream table would never match", seen)
			}
			if n := seen["SummaryInformation"]; n == 0 {
				t.Error("SummaryInformation surfaced but read back zero bytes")
			}
		})
	}
}

// The property-set encoder must produce bytes msoleps parses AND name the
// properties the extractor switches on. If the FMTID were wrong the properties
// would parse as unnamed and every metadata assertion would fail for a reason
// unrelated to the code under test — so this pins the encoder independently.
func TestPropertySetEncoderProducesNamedProperties(t *testing.T) {
	cases := []struct {
		desc     string
		stream   []byte
		wantName string
		wantVal  string
	}{
		{"SummaryInformation/Author", BuildSummaryInformation(
			map[uint32]string{SummaryPropAuthor: "Jane Analyst"}), "Author", "Jane Analyst"},
		{"SummaryInformation/Template", BuildSummaryInformation(
			map[uint32]string{SummaryPropTemplate: `\\corp-fs01\t.dot`}), "Template", `\\corp-fs01\t.dot`},
		{"DocumentSummaryInformation/Company", BuildDocSummaryInformation(
			map[uint32]string{DocSummaryPropCompany: "Example Holdings LLC"}), "Company", "Example Holdings LLC"},
		{"DocumentSummaryInformation/Manager", BuildDocSummaryInformation(
			map[uint32]string{DocSummaryPropManager: "Dana Director"}), "Manager", "Dana Director"},
		{"DocumentSummaryInformation/Content status", BuildDocSummaryInformation(
			map[uint32]string{DocSummaryPropContentStatus: "Final"}), "Content status", "Final"},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			md := &Metadata{}
			applyLegacyProperties(tc.stream, md)

			// Prove the encoder round-trips through the production mapping. Which
			// field it lands in is the mapping's business and is asserted in the
			// end-to-end tests; here it is enough that SOMETHING was populated.
			found := md.Author != "" || md.Company != "" || md.Manager != "" ||
				md.Template != "" || md.ContentStatus != "" || md.Category != "" ||
				md.Title != "" || md.Creator != ""
			if !found {
				t.Errorf("a property stream carrying %s=%q populated no Metadata field; "+
					"either the encoder's FMTID is wrong (properties parse unnamed) or the "+
					"extractor's name does not match msoleps's", tc.wantName, tc.wantVal)
			}
		})
	}
}

// Fixture bytes must be identical across calls or any golden built on them flaps.
func TestLegacyCFBFixtureIsDeterministic(t *testing.T) {
	build := func() []byte {
		return buildLegacyCFB(t, []legacyCFBStream{
			{Name: "WordDocument", Data: []byte("Employee SSN: 449-87-4100 recorded here.")},
			{Name: "\x05SummaryInformation", Data: BuildSummaryInformation(map[uint32]string{
				SummaryPropAuthor:     "Jane Analyst",
				SummaryPropLastAuthor: "Ops Reviewer",
				SummaryPropTitle:      "Quarterly Review",
				SummaryPropSubject:    "Numbers",
			})},
		})
	}
	first := build()
	for i := 1; i < 8; i++ {
		if got := build(); !bytes.Equal(first, got) {
			t.Fatalf("call %d produced different bytes (%d vs %d) — property IDs must be "+
				"emitted in a fixed order, not map order", i, len(first), len(got))
		}
	}
}

// docSummaryPropVersion is the packed version of the application that wrote the
// file -- NOT a document revision number.
const docSummaryPropVersion = 0x00000017

// docSummaryPropLinkBase is the HyperlinkBase property ID.
const docSummaryPropLinkBase = 0x00000014

// BuildUserDefinedProperties encodes a user-defined (custom) property stream --
// the legacy counterpart of docProps/custom.xml.
//
// Custom property NAMES are in no reader's built-in table: they live in the set's
// own dictionary at property ID 0, which a reader consults to label IDs 2 and up.
// A stream without that dictionary yields unnamed properties, so writing the
// dictionary is what makes these visible at all.
func BuildUserDefinedProperties(props map[string]string) []byte {
	return olefixture.UserDefinedProperties(props)
}

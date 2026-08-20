// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package olefixture builds OLE Compound File Binary containers for tests.
//
// Legacy Office documents (.doc/.xls/.ppt) are the one format this repository
// cannot test from a committed fixture without checking in an opaque binary, and
// the only real ones available live on a developer's disk — a test that depends on
// such a file is a test that does not run in CI. So the container is synthesized,
// exactly as the golden corpus synthesizes .docx/.xlsx zips rather than committing
// them.
//
// Three packages need this: the redactor, the metadata extractor, and the golden
// corpus. It is a leaf package (no ferret-scan imports) so all three can use one
// implementation. A test-only helper file in each would mean three copies of the
// format's sharp edges, and the format has several.
//
// # Container layout
//
// The 512-byte header is NOT part of the sector numbering: sector n begins at
// offset (n+1)*512. Sectors are then:
//
//	0   : the single FAT sector
//	1   : the single directory sector
//	2   : the single mini FAT sector
//	3.. : the mini stream chain, then one chain per regular stream
//
// One FAT sector holds 128 entries, addressing 64KB of file — far more than any
// fixture needs, so there is no DIFAT or multi-FAT handling. Build returns an error
// rather than a corrupt file if a caller exceeds that.
//
// # Why the mini stream is mandatory
//
// Readers route every stream SMALLER THAN 4096 bytes through the mini FAT. A real
// document's property streams are a few hundred bytes, so a builder without mini
// stream support cannot produce a fixture with readable properties: the reader
// fails with "minisector number is outside minisector range" and returns zero
// bytes. Properties are exactly what the metadata half of legacy Office support
// reads, so that would make every metadata assertion vacuous — which is not
// hypothetical: the first version of this builder had that bug, and its self-check
// only walked the directory without reading a stream, so it passed.
//
// # Stream names
//
// Office writes property streams with a leading 0x05 byte
// ("\x05SummaryInformation"). Readers strip a non-printable initial character when
// exposing the name, so consumers match "SummaryInformation". Fixtures use the
// on-disk name WITH the prefix so they agree with real documents.
package olefixture

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"time"
	"unicode/utf16"
)

// Container structure constants, per MS-CFB.
const (
	SectorSize = 512
	// MiniCutoff is the size at or above which a stream lives in regular sectors.
	// Below it, the stream is stored in the mini stream and addressed by the mini
	// FAT.
	MiniCutoff = 4096

	miniSectorSize = 64
	dirEntrySize   = 128

	freeSector = 0xFFFFFFFF
	endOfChain = 0xFFFFFFFE
	fatSector  = 0xFFFFFFFD

	typeStream = 2
	typeRoot   = 5

	fatLoc     = 0
	dirLoc     = 1
	miniFATLoc = 2
	firstData  = 3

	// entriesPerSector is how many 4-byte FAT entries one sector holds: 128 at a
	// 512-byte sector size.
	entriesPerSector = SectorSize / 4
	// maxHeaderDIFAT is how many FAT sector locations fit in the header. Beyond this
	// a file needs DIFAT sectors, which no fixture is large enough to require:
	// 109 FAT sectors address 109*128 sectors, about 7MB.
	maxHeaderDIFAT = (SectorSize - 76) / 4
)

// Signature is the 8-byte magic every compound file starts with.
var Signature = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}

// Stream is one named stream to place in a container.
type Stream struct {
	// Name is the name as Office writes it, including any leading 0x05 byte for a
	// property stream.
	Name string
	Data []byte
}

// Build assembles a valid compound file containing the given streams. Streams
// under MiniCutoff bytes go through the mini stream, as Office does.
//
// It returns an error rather than a malformed container when a fixture would
// exceed what a single FAT or directory sector can address: a silently corrupt
// fixture makes every test built on it pass for the wrong reason.
func Build(streams []Stream) ([]byte, error) {
	type placement struct {
		mini       bool
		startEntry uint32
		size       uint32
	}
	places := make([]placement, len(streams))

	if max := SectorSize / dirEntrySize; len(streams) > max-1 {
		return nil, fmt.Errorf("olefixture: %d streams requested but one directory "+
			"sector holds %d entries including the root", len(streams), max)
	}

	// Small streams are concatenated into the mini stream on 64-byte boundaries.
	miniData := new(bytes.Buffer)
	var miniSectors uint32
	for i, s := range streams {
		if len(s.Data) == 0 || len(s.Data) >= MiniCutoff {
			continue
		}
		places[i] = placement{mini: true, startEntry: miniSectors, size: uint32(len(s.Data))}
		n := (len(s.Data) + miniSectorSize - 1) / miniSectorSize
		padded := make([]byte, n*miniSectorSize)
		copy(padded, s.Data)
		miniData.Write(padded)
		miniSectors += uint32(n)
	}
	if int(miniSectors) > SectorSize/4 {
		return nil, fmt.Errorf("olefixture: mini stream needs %d mini sectors but one "+
			"mini FAT sector addresses only %d", miniSectors, SectorSize/4)
	}

	// The mini stream itself occupies regular sectors, as the root entry's chain.
	next := uint32(firstData)
	miniStreamStart := uint32(endOfChain)
	var miniStreamSectorCount int
	if miniData.Len() > 0 {
		miniStreamSectorCount = (miniData.Len() + SectorSize - 1) / SectorSize
		miniStreamStart = next
		next += uint32(miniStreamSectorCount)
	}

	regular := make([]int, len(streams))
	for i, s := range streams {
		if len(s.Data) == 0 {
			places[i] = placement{startEntry: endOfChain}
			continue
		}
		if places[i].mini {
			continue
		}
		n := (len(s.Data) + SectorSize - 1) / SectorSize
		places[i] = placement{startEntry: next, size: uint32(len(s.Data))}
		regular[i] = n
		next += uint32(n)
	}

	// The FAT must describe every sector INCLUDING its own, so growing it can push
	// the total past the next multiple and require another FAT sector. Solve for the
	// smallest count that covers itself, rather than assuming one.
	//
	// FAT sectors are appended after the data, so they do not shift any sector number
	// computed above.
	dataSectors := int(next)
	numFAT := 1
	for {
		if dataSectors+numFAT <= numFAT*entriesPerSector {
			break
		}
		numFAT++
		if numFAT > maxHeaderDIFAT {
			return nil, fmt.Errorf("olefixture: fixture needs %d sectors, which would "+
				"require DIFAT sectors (over ~%dMB); keep fixtures smaller",
				dataSectors, maxHeaderDIFAT*entriesPerSector*SectorSize/(1024*1024))
		}
	}
	totalSectors := dataSectors + numFAT

	fat := freeTable(numFAT * entriesPerSector)
	fat[dirLoc] = endOfChain
	fat[miniFATLoc] = endOfChain
	chainRun(fat, miniStreamStart, miniStreamSectorCount)
	for i := range streams {
		if !places[i].mini && regular[i] > 0 {
			chainRun(fat, places[i].startEntry, regular[i])
		}
	}
	// Mark the FAT's own sectors. Sector 0 is the first of them, and the rest sit at
	// the end of the file.
	fatSectorNums := []uint32{fatLoc}
	for i := 1; i < numFAT; i++ {
		fatSectorNums = append(fatSectorNums, uint32(dataSectors+i-1))
	}
	for _, sec := range fatSectorNums {
		if int(sec) < len(fat) {
			fat[sec] = fatSector
		}
	}

	miniFAT := freeTable(SectorSize / 4)
	for i := range streams {
		if !places[i].mini {
			continue
		}
		n := (int(places[i].size) + miniSectorSize - 1) / miniSectorSize
		chainRun(miniFAT, places[i].startEntry, n)
	}

	hdr := make([]byte, SectorSize)
	copy(hdr[0:8], Signature)
	binary.LittleEndian.PutUint16(hdr[24:], 0x003E) // minor version
	binary.LittleEndian.PutUint16(hdr[26:], 0x0003) // major version 3 => 512-byte sectors
	binary.LittleEndian.PutUint16(hdr[28:], 0xFFFE) // little-endian marker
	binary.LittleEndian.PutUint16(hdr[30:], 9)      // sector shift: 1<<9 = 512
	binary.LittleEndian.PutUint16(hdr[32:], 6)      // mini sector shift: 1<<6 = 64
	binary.LittleEndian.PutUint32(hdr[40:], 1)      // directory sector count
	binary.LittleEndian.PutUint32(hdr[44:], uint32(numFAT))
	binary.LittleEndian.PutUint32(hdr[48:], dirLoc)
	binary.LittleEndian.PutUint32(hdr[56:], MiniCutoff)
	if miniData.Len() > 0 {
		binary.LittleEndian.PutUint32(hdr[60:], miniFATLoc)
		binary.LittleEndian.PutUint32(hdr[64:], 1)
	} else {
		binary.LittleEndian.PutUint32(hdr[60:], endOfChain)
		binary.LittleEndian.PutUint32(hdr[64:], 0)
	}
	binary.LittleEndian.PutUint32(hdr[68:], endOfChain) // no DIFAT chain
	binary.LittleEndian.PutUint32(hdr[72:], 0)          // no extra DIFAT sectors
	for i := 76; i < SectorSize; i += 4 {
		binary.LittleEndian.PutUint32(hdr[i:], freeSector)
	}
	// The header's DIFAT lists where the FAT sectors live, in order.
	for i, sec := range fatSectorNums {
		if 76+i*4+4 > SectorSize {
			break
		}
		binary.LittleEndian.PutUint32(hdr[76+i*4:], sec)
	}

	// The root entry's chain IS the mini stream and its size is the mini stream's
	// length; a reader walks that chain to resolve every mini sector.
	dir := make([]byte, SectorSize)
	child := uint32(freeSector)
	if len(streams) > 0 {
		child = 1
	}
	writeDirEntry(dir[0:dirEntrySize], "Root Entry", typeRoot,
		miniStreamStart, uint32(miniData.Len()), child, freeSector)
	for i, s := range streams {
		off := (i + 1) * dirEntrySize
		right := uint32(freeSector)
		if i+1 < len(streams) {
			right = uint32(i + 2)
		}
		writeDirEntry(dir[off:off+dirEntrySize], s.Name, typeStream,
			places[i].startEntry, places[i].size, freeSector, right)
	}

	// The FAT is one flat table split across numFAT sectors, in DIFAT order.
	fatBytes := make([]byte, numFAT*SectorSize)
	for i, v := range fat {
		binary.LittleEndian.PutUint32(fatBytes[i*4:], v)
	}
	fatSlice := func(i int) []byte { return fatBytes[i*SectorSize : (i+1)*SectorSize] }

	out := make([]byte, 0, SectorSize*(1+totalSectors))
	out = append(out, hdr...)
	out = append(out, fatSlice(0)...) // sector 0: the first FAT sector
	out = append(out, dir...)
	out = append(out, tableSector(miniFAT)...)
	if miniStreamSectorCount > 0 {
		padded := make([]byte, miniStreamSectorCount*SectorSize)
		copy(padded, miniData.Bytes())
		out = append(out, padded...)
	}
	for i, s := range streams {
		if places[i].mini || regular[i] == 0 {
			continue
		}
		padded := make([]byte, regular[i]*SectorSize)
		copy(padded, s.Data)
		out = append(out, padded...)
	}
	// Remaining FAT sectors go after the data, which is why appending them cannot
	// shift any sector number assigned above.
	for i := 1; i < numFAT; i++ {
		out = append(out, fatSlice(i)...)
	}
	return out, nil
}

// MustBuild is Build for callers that cannot handle an error, such as a package-level
// fixture in a corpus definition. It panics on a malformed request, which surfaces
// at test setup rather than as a mysterious empty scan result.
func MustBuild(streams []Stream) []byte {
	b, err := Build(streams)
	if err != nil {
		panic(err)
	}
	return b
}

// FragmentedStream is a stream whose sectors are placed at caller-chosen disk
// locations, in logical order.
type FragmentedStream struct {
	Name string
	Data []byte
	// Sectors are disk sector numbers in LOGICAL order, one per sector of Data.
	// Listing them out of ascending order is the point: it reproduces what a real
	// allocator leaves behind after a document has been edited.
	Sectors []uint32
}

// BuildFragmented writes a valid compound file whose stream sectors sit where the
// caller says, so a value can be contiguous in a stream's logical bytes while its
// halves live far apart on disk.
//
// That layout is what separates a correct redactor from one that merely looks
// correct: searching the raw file cannot find such a value, so it is reported by the
// extractor (which reads reassembled logical bytes) and silently left in cleartext
// by the writer. Only regular sectors are used — the mini stream has its own
// indirection and is covered by Build.
func BuildFragmented(streams []FragmentedStream) ([]byte, error) {
	maxSector := uint32(miniFATLoc)
	for _, s := range streams {
		need := (len(s.Data) + SectorSize - 1) / SectorSize
		if need != len(s.Sectors) {
			return nil, fmt.Errorf("olefixture: stream %q is %d bytes = %d sectors but %d "+
				"sectors were given", s.Name, len(s.Data), need, len(s.Sectors))
		}
		if len(s.Data) < MiniCutoff {
			return nil, fmt.Errorf("olefixture: stream %q is %d bytes, under the %d-byte "+
				"cutoff, so a reader routes it through the mini FAT and the requested "+
				"sector placement would be ignored", s.Name, len(s.Data), MiniCutoff)
		}
		for _, sec := range s.Sectors {
			if sec > maxSector {
				maxSector = sec
			}
		}
	}
	if int(maxSector) >= SectorSize/4 {
		return nil, fmt.Errorf("olefixture: sector %d exceeds what one FAT sector addresses (%d)",
			maxSector, SectorSize/4)
	}

	fat := freeTable(SectorSize / 4)
	fat[fatLoc] = fatSector
	fat[dirLoc] = endOfChain
	fat[miniFATLoc] = endOfChain
	for _, s := range streams {
		for i, sec := range s.Sectors {
			if i == len(s.Sectors)-1 {
				fat[sec] = endOfChain
			} else {
				fat[sec] = s.Sectors[i+1]
			}
		}
	}

	hdr := make([]byte, SectorSize)
	copy(hdr[0:8], Signature)
	binary.LittleEndian.PutUint16(hdr[24:], 0x003E)
	binary.LittleEndian.PutUint16(hdr[26:], 0x0003)
	binary.LittleEndian.PutUint16(hdr[28:], 0xFFFE)
	binary.LittleEndian.PutUint16(hdr[30:], 9)
	binary.LittleEndian.PutUint16(hdr[32:], 6)
	binary.LittleEndian.PutUint32(hdr[40:], 1)
	binary.LittleEndian.PutUint32(hdr[44:], 1)
	binary.LittleEndian.PutUint32(hdr[48:], dirLoc)
	binary.LittleEndian.PutUint32(hdr[56:], MiniCutoff)
	binary.LittleEndian.PutUint32(hdr[60:], endOfChain)
	binary.LittleEndian.PutUint32(hdr[64:], 0)
	binary.LittleEndian.PutUint32(hdr[68:], endOfChain)
	binary.LittleEndian.PutUint32(hdr[72:], 0)
	for i := 76; i < SectorSize; i += 4 {
		binary.LittleEndian.PutUint32(hdr[i:], freeSector)
	}
	binary.LittleEndian.PutUint32(hdr[76:], fatLoc)

	dir := make([]byte, SectorSize)
	child := uint32(freeSector)
	if len(streams) > 0 {
		child = 1
	}
	writeDirEntry(dir[0:dirEntrySize], "Root Entry", typeRoot, endOfChain, 0, child, freeSector)
	for i, s := range streams {
		off := (i + 1) * dirEntrySize
		if off+dirEntrySize > len(dir) {
			return nil, fmt.Errorf("olefixture: %d streams exceed one directory sector", len(streams))
		}
		right := uint32(freeSector)
		if i+1 < len(streams) {
			right = uint32(i + 2)
		}
		writeDirEntry(dir[off:off+dirEntrySize], s.Name, typeStream,
			s.Sectors[0], uint32(len(s.Data)), freeSector, right)
	}

	out := make([]byte, SectorSize*(1+int(maxSector)+1))
	copy(out[0:], hdr)
	copy(out[SectorSize*(1+fatLoc):], tableSector(fat))
	copy(out[SectorSize*(1+dirLoc):], dir)
	copy(out[SectorSize*(1+miniFATLoc):], tableSector(freeTable(SectorSize/4)))
	for _, s := range streams {
		for i, sec := range s.Sectors {
			lo := i * SectorSize
			hi := lo + SectorSize
			if hi > len(s.Data) {
				hi = len(s.Data)
			}
			copy(out[SectorSize*(1+int(sec)):], s.Data[lo:hi])
		}
	}
	return out, nil
}

// MustBuildFragmented is BuildFragmented for callers that cannot handle an error.
func MustBuildFragmented(streams []FragmentedStream) []byte {
	b, err := BuildFragmented(streams)
	if err != nil {
		panic(err)
	}
	return b
}

func freeTable(n int) []uint32 {
	t := make([]uint32, n)
	for i := range t {
		t[i] = freeSector
	}
	return t
}

// chainRun marks n consecutive entries from start as one chain.
func chainRun(table []uint32, start uint32, n int) {
	if n <= 0 || start == endOfChain {
		return
	}
	for k := 0; k < n; k++ {
		e := start + uint32(k)
		if int(e) >= len(table) {
			return
		}
		if k == n-1 {
			table[e] = endOfChain
		} else {
			table[e] = e + 1
		}
	}
}

func tableSector(table []uint32) []byte {
	b := make([]byte, SectorSize)
	for i, v := range table {
		if (i+1)*4 > len(b) {
			break
		}
		binary.LittleEndian.PutUint32(b[i*4:], v)
	}
	return b
}

// writeDirEntry fills one 128-byte directory entry. The name is UTF-16LE and its
// byte length INCLUDES the terminating null — the detail that decides whether a
// parser reads the name or rejects the entry.
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
	e[67] = 1 // black, in the red-black sibling tree
	binary.LittleEndian.PutUint32(e[68:], freeSector)
	binary.LittleEndian.PutUint32(e[72:], rightSib)
	binary.LittleEndian.PutUint32(e[76:], child)
	binary.LittleEndian.PutUint32(e[116:], startSector)
	binary.LittleEndian.PutUint64(e[120:], uint64(size))
}

// --- OLE property set encoding ----------------------------------------------
//
// This is the legacy counterpart of docProps/core.xml and docProps/app.xml: where
// a real document's author, company and template path live. Layout per MS-OLEPS: a
// 48-byte PropertySetStream header naming one property set by FMTID, then the set's
// own header (byte size, property count), an ID/offset table, then the values.
//
// Offsets are relative to the START OF THE PROPERTY SET, not the stream — an easy
// off-by-48 that yields silently empty properties rather than a parse error.

// SummaryInformation property IDs (MS-OLEPS 2.18).
const (
	PropTitle        = 0x00000002
	PropSubject      = 0x00000003
	PropAuthor       = 0x00000004
	PropKeywords     = 0x00000005
	PropComments     = 0x00000006
	PropTemplate     = 0x00000007
	PropLastAuthor   = 0x00000008
	PropCreateTime   = 0x0000000C
	PropLastSaveTime = 0x0000000D
	PropAppName      = 0x00000012
)

// DocumentSummaryInformation property IDs. Company and Manager live HERE, in a
// second property set with a different FMTID — not in SummaryInformation.
const (
	PropCategory      = 0x00000002
	PropManager       = 0x0000000E
	PropCompany       = 0x0000000F
	PropContentStatus = 0x0000001B
	PropLanguage      = 0x0000001C
)

// Canonical stream names, including the leading 0x05 byte Office writes.
const (
	StreamSummaryInformation    = "\x05SummaryInformation"
	StreamDocSummaryInformation = "\x05DocumentSummaryInformation"
	StreamWordDocument          = "WordDocument"
	StreamWorkbook              = "Workbook"
	StreamPowerPoint            = "PowerPoint Document"
)

// FMTIDs in on-disk mixed-endian GUID form: the first three fields little-endian,
// the trailing eight bytes in order. A property-set reader looks up its
// property-NAME table by this GUID, so a wrong FMTID yields unnamed properties —
// present in the stream, silently unmapped by any consumer switching on the name.
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

// SummaryInformation encodes a SummaryInformation property stream carrying the
// given string properties.
func SummaryInformation(props map[uint32]string) []byte {
	return propertySet(fmtidSummaryInformation, props, nil)
}

// SummaryInformationWithTimes additionally encodes FILETIME properties, so a test
// can exercise the timestamp path.
func SummaryInformationWithTimes(props map[uint32]string, times map[uint32]uint64) []byte {
	return propertySet(fmtidSummaryInformation, props, times)
}

// SummaryInformationWide encodes the properties as VT_LPWSTR (UTF-16LE) rather than
// VT_LPSTR, which is what Office writes for any value that is not representable in
// the document's code page — in practice, most non-English names.
//
// The distinction is load-bearing for a redactor: a UTF-16LE value shares no bytes
// with its UTF-8 form, so a redactor that searches only the narrow encoding finds
// nothing and reports success while the value stays in the file.
func SummaryInformationWide(props map[uint32]string) []byte {
	return propertySetWide(fmtidSummaryInformation, props)
}

// propertySetWide encodes one property set with UTF-16LE string values.
func propertySetWide(fmtid []byte, strs map[uint32]string) []byte {
	ids := make([]uint32, 0, len(strs))
	for id := range strs {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	type encoded struct {
		id  uint32
		val []byte
	}
	vals := make([]encoded, 0, len(ids))
	for _, id := range ids {
		// VT_LPWSTR (0x001F): 2-byte type, 2 bytes padding, 4-byte length in CODE
		// UNITS including the null terminator, then the UTF-16LE bytes padded to 4.
		units := utf16.Encode([]rune(strs[id]))
		body := make([]byte, 0, (len(units)+1)*2)
		for _, u := range units {
			body = append(body, byte(u), byte(u>>8))
		}
		body = append(body, 0x00, 0x00) // terminator
		for len(body)%4 != 0 {
			body = append(body, 0)
		}
		v := make([]byte, 8+len(body))
		binary.LittleEndian.PutUint16(v[0:], 0x001F)
		binary.LittleEndian.PutUint32(v[4:], uint32(len(units)+1))
		copy(v[8:], body)
		vals = append(vals, encoded{id: id, val: v})
	}

	offsets := make([]uint32, len(vals))
	cursor := uint32(8 + len(vals)*8)
	for i, v := range vals {
		offsets[i] = cursor
		cursor += uint32(len(v.val))
	}

	set := new(bytes.Buffer)
	_ = binary.Write(set, binary.LittleEndian, cursor)
	_ = binary.Write(set, binary.LittleEndian, uint32(len(vals)))
	for i, v := range vals {
		_ = binary.Write(set, binary.LittleEndian, v.id)
		_ = binary.Write(set, binary.LittleEndian, offsets[i])
	}
	for _, v := range vals {
		set.Write(v.val)
	}

	hdr := make([]byte, 48)
	binary.LittleEndian.PutUint16(hdr[0:], 0xFFFE)
	binary.LittleEndian.PutUint32(hdr[4:], 0x00020006)
	binary.LittleEndian.PutUint32(hdr[24:], 1)
	copy(hdr[28:44], fmtid)
	binary.LittleEndian.PutUint32(hdr[44:], 48)
	return append(hdr, set.Bytes()...)
}

// DocSummaryInformation encodes a DocumentSummaryInformation property stream.
func DocSummaryInformation(props map[uint32]string) []byte {
	return propertySet(fmtidDocSummaryInformation, props, nil)
}

// DocSummaryInformationWithVectors additionally encodes VECTOR-valued string
// properties, which is how a real .xls stores its sheet-name list and a real .ppt its
// slide titles (DocumentParts, property 0x0D).
//
// Worth encoding exactly as [MS-OLEPS] specifies, because the whole reason vector
// properties were unreadable is a type-word disagreement: the property type is ONE
// 32-bit value with VT_VECTOR (0x1000) OR'd into the same 16-bit type field, so a
// vector of VT_LPSTR is 0x0000101E — NOT 0x001E with a separate flag word. A fixture
// that encoded it the other way would make a broken reader look correct.
func DocSummaryInformationWithVectors(props map[uint32]string, vectors map[uint32][]string) []byte {
	return propertySetWith(fmtidDocSummaryInformation, props, nil, vectors)
}

// SummaryInformationWithVectors is the same for the SummaryInformation set, where a
// Keywords list may be stored as a vector rather than one delimited string.
func SummaryInformationWithVectors(props map[uint32]string, vectors map[uint32][]string) []byte {
	return propertySetWith(fmtidSummaryInformation, props, nil, vectors)
}

// PropDocumentParts is DocumentSummaryInformation 0x0D: the vector of part names —
// sheet names in a workbook, slide titles in a presentation. msoleps labels it
// "Document parts".
const PropDocumentParts = 0x0000000D

// PropHyperlinks is DocumentSummaryInformation 0x15, also vector-valued.
const PropHyperlinks = 0x00000015

// fmtidUserDefined is {D5CDD502-2E9C-101C-9397-08002B2CF9AE}, the user-defined
// property set. Note it differs from DocumentSummaryInformation's FMTID in ONE
// nibble (101C vs 101B), which is easy to mistype into a set no reader recognises.
var fmtidUserDefined = []byte{
	0x02, 0xD5, 0xCD, 0xD5, 0x9C, 0x2E, 0x1C, 0x10,
	0x93, 0x97, 0x08, 0x00, 0x2B, 0x2C, 0xF9, 0xAE,
}

// UserDefinedProperties encodes a user-defined (custom) property stream: the
// legacy counterpart of docProps/custom.xml.
//
// Unlike the two well-known sets, custom property NAMES are not in any reader's
// built-in table — they live in the set's own dictionary at property ID 0, which a
// reader consults to label IDs 2 and up. A stream without that dictionary yields
// unnamed properties, so the dictionary is what makes these visible at all.
//
// This matters because custom properties are a documented leak channel: a property
// named "ClientSSN" holding a real SSN is exactly the shape that reaches a scanner
// only if the dictionary is parsed.
func UserDefinedProperties(props map[string]string) []byte {
	names := make([]string, 0, len(props))
	for n := range props {
		names = append(names, n)
	}
	sort.Strings(names) // fixed order so the bytes are stable across calls

	// Dictionary blob: entry count, then (property id, name byte length, name).
	dict := new(bytes.Buffer)
	_ = binary.Write(dict, binary.LittleEndian, uint32(len(names)))
	for i, n := range names {
		_ = binary.Write(dict, binary.LittleEndian, uint32(firstCustomPropID+i))
		nb := append([]byte(n), 0)
		_ = binary.Write(dict, binary.LittleEndian, uint32(len(nb)))
		dict.Write(nb)
	}
	for dict.Len()%4 != 0 {
		dict.WriteByte(0)
	}

	// A code page (property ID 1) is required for the reader to decode the
	// dictionary's single-byte names.
	codePage := make([]byte, 8)
	binary.LittleEndian.PutUint16(codePage[0:], 0x0002) // VT_I2
	binary.LittleEndian.PutUint16(codePage[4:], 1252)   // Windows-1252

	type entry struct {
		id  uint32
		val []byte
	}
	entries := []entry{{id: 0, val: dict.Bytes()}, {id: 1, val: codePage}}
	for i, n := range names {
		s := props[n]
		body := append([]byte(s), 0)
		for len(body)%4 != 0 {
			body = append(body, 0)
		}
		v := make([]byte, 8+len(body))
		binary.LittleEndian.PutUint16(v[0:], 0x001E) // VT_LPSTR
		binary.LittleEndian.PutUint32(v[4:], uint32(len(s)+1))
		copy(v[8:], body)
		entries = append(entries, entry{id: uint32(firstCustomPropID + i), val: v})
	}

	offsets := make([]uint32, len(entries))
	cursor := uint32(8 + len(entries)*8)
	for i, e := range entries {
		offsets[i] = cursor
		cursor += uint32(len(e.val))
	}

	set := new(bytes.Buffer)
	_ = binary.Write(set, binary.LittleEndian, cursor)
	_ = binary.Write(set, binary.LittleEndian, uint32(len(entries)))
	for i, e := range entries {
		_ = binary.Write(set, binary.LittleEndian, e.id)
		_ = binary.Write(set, binary.LittleEndian, offsets[i])
	}
	for _, e := range entries {
		set.Write(e.val)
	}

	hdr := make([]byte, 48)
	binary.LittleEndian.PutUint16(hdr[0:], 0xFFFE)
	binary.LittleEndian.PutUint32(hdr[4:], 0x00020006)
	binary.LittleEndian.PutUint32(hdr[24:], 1)
	copy(hdr[28:44], fmtidUserDefined)
	binary.LittleEndian.PutUint32(hdr[44:], 48)
	return append(hdr, set.Bytes()...)
}

// firstCustomPropID is where user-defined property IDs start: 0 is the dictionary
// and 1 is the code page.
const firstCustomPropID = 2

// propertySet encodes one property set. Property IDs are emitted in ascending
// order so the bytes are stable across calls: ranging a map directly would vary the
// output and any golden snapshot built on it would flap.
func propertySet(fmtid []byte, strs map[uint32]string, times map[uint32]uint64) []byte {
	return propertySetWith(fmtid, strs, times, nil)
}

// propertySetWith is propertySet plus VT_VECTOR|VT_LPSTR properties.
func propertySetWith(fmtid []byte, strs map[uint32]string, times map[uint32]uint64, vectors map[uint32][]string) []byte {
	ids := make([]uint32, 0, len(strs)+len(times)+len(vectors))
	for id := range strs {
		ids = append(ids, id)
	}
	for id := range times {
		ids = append(ids, id)
	}
	for id := range vectors {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	type encoded struct {
		id  uint32
		val []byte
	}
	vals := make([]encoded, 0, len(ids))
	for _, id := range ids {
		if elems, ok := vectors[id]; ok {
			// VT_VECTOR|VT_LPSTR (0x101E): the 32-bit type word, a 4-byte element
			// count, then each element as a VT_LPSTR body — 4-byte length INCLUDING
			// the null terminator, then the bytes padded to a 4-byte boundary.
			v := make([]byte, 8)
			binary.LittleEndian.PutUint32(v[0:], 0x0000101E)
			binary.LittleEndian.PutUint32(v[4:], uint32(len(elems)))
			for _, e := range elems {
				// NO padding between elements. A standalone CodePageString property value
				// is padded to a multiple of 4; the elements inside a vector are packed
				// end to end. Verified against three real Excel-written files — in
				// poi_sampless.xls the element lengths run 12, 15, 7 and the next
				// property's type word follows the last byte immediately.
				//
				// A first version of this encoder padded each element, and so did the
				// first version of the decoder that reads them. The two agreed, so every
				// test passed while a real file decoded 2 of 3 sheet names. An encoder
				// that matches a buggy reader is worse than no fixture at all.
				body := append([]byte(e), 0)
				n := make([]byte, 4)
				binary.LittleEndian.PutUint32(n, uint32(len(body)))
				v = append(v, n...)
				v = append(v, body...)
			}
			vals = append(vals, encoded{id: id, val: v})
			continue
		}
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

	offsets := make([]uint32, len(vals))
	cursor := uint32(8 + len(vals)*8)
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

// FileTime converts a date to a Windows FILETIME: 100-nanosecond ticks since
// 1601-01-01 UTC.
func FileTime(year int, month time.Month, day int) uint64 {
	const ticksPerSecond = 10000000
	const secondsGregorianToUnix = 11644473600
	unix := time.Date(year, month, day, 12, 0, 0, 0, time.UTC).Unix()
	return uint64(unix+secondsGregorianToUnix) * ticksPerSecond
}

// UTF16LE encodes a string the way legacy Office stores wide text: UTF-16
// little-endian, with surrogate pairs for anything outside the BMP.
//
// Non-ASCII must be encoded, not refused. A test that needs the on-disk form of
// "José Ramírez" in order to assert it was redacted cannot get it from a function
// that gives up on the first accented character — the assertion would silently
// become vacuous, which is how a real leak in exactly this area went unnoticed.
func UTF16LE(s string) []byte {
	if s == "" {
		return nil
	}
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(units)*2)
	for _, u := range units {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

// LegacyDoc builds a .doc-shaped container: body text in WordDocument plus a
// SummaryInformation property stream. This is the shape most tests want, and
// having one definition of it keeps the corpus, the extractor tests and the
// redactor tests describing the same document.
func LegacyDoc(body string, props map[uint32]string) []byte {
	streams := []Stream{{Name: StreamWordDocument, Data: []byte(body)}}
	if len(props) > 0 {
		streams = append(streams, Stream{
			Name: StreamSummaryInformation,
			Data: SummaryInformation(props),
		})
	}
	return MustBuild(streams)
}

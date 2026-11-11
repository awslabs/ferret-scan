// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package legacyole

import (
	"encoding/binary"
	"strings"

	"github.com/richardlehane/msoleps/types"
)

// Typed property values: the numbers, dates and flags of a legacy property set (#915).
//
// # Why the text overwrite cannot reach them
//
// The metadata extractor decodes every property with msoleps and reports the decoded TEXT. For a
// string property that text is in the stream, 8-bit or UTF-16LE, so overwriteEachEncoding finds it.
// A number is not: a VT_I4 custom property is four little-endian bytes, and the decimal digits the
// report names exist only after decoding. The redactor searched the streams for those digits, found
// nothing, logged legacy_match_not_located and wrote the copy at exit 0 with the value intact, so a
// re-scan of the "redacted" copy reported the same CUSTOM_PROPERTY finding again. Measured on the
// public GovDocs file govdocs1--000696.doc: a 10-digit VT_I4 custom property, reported at
// confidence 60, survived both strategies with files_not_redacted empty and nothing on stderr.
//
// # What is rewritten
//
// A scalar of a fixed-width type that msoleps renders as a number, a date, a flag or a GUID, whose
// rendering IS a reported value, is overwritten with zeros: the same type word and the same width,
// so every offset in the property set stays valid, and the property now decodes to 0 (a FILETIME to
// the epoch, a boolean to false), which discloses nothing. That is the only same-length "token" a
// number has: it holds no '*', and a format-preserving rendering of its digits does not fit its
// bytes, so both strategies write the same zeros.
//
// The rendering is msoleps's own, types.Evaluate over the same bytes the extractor hands it, so the
// two cannot disagree about what the value reads as. Only a property a reported value names is
// touched, and never the dictionary (id 0), the code page (id 1), or the locale and behaviour
// properties (0x80000000 and up): zeroing the code page would change how every string in the set
// decodes.

// typedValue is one fixed-width, non-text scalar in a property-set stream.
type typedValue struct {
	stream    int    // index into cfbLayout.streams
	at        int    // logical offset of the value's bytes, after its 4-byte type word
	vt        uint16 // the property's type
	width     int    // the value's byte width
	rendering string // what msoleps decodes it to, trimmed as the extractor trims it
}

// typedWidths is the byte width of each scalar type msoleps renders as something other than text.
var typedWidths = map[uint16]int{
	0x0002: 2,  // VT_I2
	0x0003: 4,  // VT_I4
	0x0004: 4,  // VT_R4
	0x0005: 8,  // VT_R8
	0x0006: 8,  // VT_CY
	0x0007: 8,  // VT_DATE
	0x000B: 2,  // VT_BOOL
	0x000E: 16, // VT_DECIMAL
	0x0010: 1,  // VT_I1
	0x0011: 1,  // VT_UI1
	0x0012: 2,  // VT_UI2
	0x0013: 4,  // VT_UI4
	0x0014: 8,  // VT_I8
	0x0015: 8,  // VT_UI8
	0x0016: 4,  // VT_INT
	0x0017: 4,  // VT_UINT
	0x0040: 8,  // VT_FILETIME
	0x0048: 16, // VT_CLSID
}

// propertySetStreams names the streams the extractor parses as property sets (its
// legacyPropertyStreams). A typed value in any other stream is never decoded, so never reported.
var propertySetStreams = map[string]bool{
	"SummaryInformation":         true,
	"DocumentSummaryInformation": true,
}

// typedPropertyValues lists every typed scalar in the layout's property-set streams, read from the
// streams' logical bytes.
func typedPropertyValues(layout *cfbLayout, logical [][]byte) []typedValue {
	var out []typedValue
	for i, s := range layout.streams {
		if i >= len(logical) || !propertySetStreams[s.name] {
			continue
		}
		out = append(out, typedValuesInStream(i, logical[i])...)
	}
	return out
}

// typedValuesInStream walks one property-set stream [MS-OLEPS]: a 28-byte header ending in the set
// count, one (FMTID, offset) entry per set, and per set a byte size, a property count and an
// (id, offset) table whose offsets are relative to the set.
//
// Every offset comes from the file, so each is checked against the bytes actually present before it
// is used, in a form that cannot overflow on a 32-bit int. At most two sets are read, as msoleps
// reads at most two.
func typedValuesInStream(stream int, b []byte) []typedValue {
	const (
		headerBytes = 28 // byte order, version, system id, CLSID, set count
		setEntryLen = 20 // FMTID + offset
		tableHeader = 8  // set byte size + property count
		tableEntry  = 8  // property id + offset
		typeWordLen = 4  // type + padding
	)
	if len(b) < headerBytes || binary.LittleEndian.Uint16(b[0:2]) != 0xFFFE {
		return nil
	}
	sets := binary.LittleEndian.Uint32(b[24:28])
	if sets > 2 {
		sets = 2
	}

	var out []typedValue
	for set := 0; set < int(sets); set++ {
		entry := headerBytes + set*setEntryLen
		if entry > len(b)-setEntryLen {
			break
		}
		start := uint64(binary.LittleEndian.Uint32(b[entry+16 : entry+20]))
		if start > uint64(len(b)-tableHeader) {
			continue
		}
		setAt := int(start)
		count := uint64(binary.LittleEndian.Uint32(b[setAt+4 : setAt+8]))
		if count > uint64((len(b)-setAt-tableHeader)/tableEntry) {
			continue
		}
		for k := 0; k < int(count); k++ {
			row := setAt + tableHeader + k*tableEntry
			id := binary.LittleEndian.Uint32(b[row : row+4])
			if id < 2 || id >= 0x80000000 {
				continue // the dictionary, the code page, the locale and behaviour properties
			}
			off := uint64(binary.LittleEndian.Uint32(b[row+4 : row+8]))
			if off > uint64(len(b)-setAt) || uint64(setAt)+off > uint64(len(b)-typeWordLen) {
				continue
			}
			v := setAt + int(off)
			vt := binary.LittleEndian.Uint16(b[v : v+2])
			// msoleps reads its vector/array flag from the two padding bytes, so a non-zero value
			// there is not a scalar to it; a real vector carries 0x1000 in vt and is not listed.
			if binary.LittleEndian.Uint16(b[v+2:v+4]) != 0 {
				continue
			}
			width, ok := typedWidths[vt]
			if !ok || width > len(b)-v-typeWordLen {
				continue
			}
			out = append(out, typedValue{
				stream:    stream,
				at:        v + typeWordLen,
				vt:        vt,
				width:     width,
				rendering: renderTyped(b[v : v+typeWordLen+width]),
			})
		}
	}
	return out
}

// renderTyped is msoleps's rendering of one typed value (its type word and its bytes), trimmed as
// the extractor trims it. The bytes are the file's, so a decoder that panics on some input is
// treated as rendering nothing rather than taking the redaction down with it.
func renderTyped(b []byte) (s string) {
	defer func() {
		if recover() != nil {
			s = ""
		}
	}()
	t, err := types.Evaluate(b)
	if err != nil || t == nil {
		return ""
	}
	return strings.TrimSpace(t.String())
}

// zeroRendering is what a typed value of this type and width reads as once zeroed: "0" for a number,
// the epoch for a FILETIME. It is what the audit entry records as written.
func zeroRendering(vt uint16, width int) string {
	b := make([]byte, 4+width)
	binary.LittleEndian.PutUint16(b[0:2], vt)
	return renderTyped(b)
}

// zeroTypedValues overwrites with zeros every typed value whose rendering is value, writing through
// each stream's sector chain and keeping the logical view in step, and returns how many it
// overwrote and what the first of them now reads as.
//
// A value overwritten by an earlier call is overwritten again, a no-op, and still counted: it was
// located, and it is zero.
func zeroTypedValues(raw []byte, layout *cfbLayout, logical [][]byte, typed []typedValue, value string) (int, string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, ""
	}
	n, written := 0, ""
	for _, tv := range typed {
		if tv.rendering != value {
			continue
		}
		zeros := make([]byte, tv.width)
		if !layout.streams[tv.stream].writeLogical(raw, tv.at, zeros) {
			continue
		}
		copy(logical[tv.stream][tv.at:tv.at+tv.width], zeros)
		if n == 0 {
			written = zeroRendering(tv.vt, tv.width)
		}
		n++
	}
	return n, written
}

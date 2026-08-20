// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractofficelib

import (
	"encoding/binary"
	"unicode/utf16"
)

// Vector-valued property support for legacy OLE property sets.
//
// # Why this exists at all — msoleps cannot read a real vector
//
// A property's type in [MS-OLEPS] is ONE 32-bit value with VT_VECTOR (0x1000) OR'd
// into the same 16-bit type field, so a vector of VT_LPSTR is 0x0000101E. msoleps
// instead reads the TypeID from bytes 0-2 and looks for the vector discriminator in
// bytes 2-4 (types.Evaluate). For a real file that means the id lookup is 0x101E,
// which is in no table, so Evaluate returns I1(0) with ErrUnknownType — and the
// caller discards the error ("ignore errors for now as not all types implemented").
//
// Measured with a probe over msoleps v1.0.6, three encodings of the same property:
//
//	type word 0x101E  (what real writers emit)   -> Int8,               String() == "0"
//	0x001E + flag in the high word (msoleps)     -> Vector of CodeString, String() == ""
//	scalar VT_LPSTR (control)                    -> CodeString,         String() == the value
//
// So a vector property reaches our code as the literal "0". #267 assumed the value
// arrives as "" and can be recovered by type-switching on types.Vector; neither is
// true for a real document, and a type switch never fires because msoleps has already
// collapsed the property to a scalar. The values have to be decoded from the stream.
//
// # What is decoded, and what is not
//
// String vectors only: VT_LPSTR, VT_LPWSTR and VT_BSTR. Those are the leak channel —
// an .xls sheet-name list, a .ppt slide-title list, a Keywords or Hyperlinks list.
// Vectors of numerics, FILETIMEs and VT_VARIANT (Heading pair) carry counts and
// pairing information, not document content, so decoding them would add noise to
// every report for no detection value — the same reasoning that keeps page and word
// counts out of the mapped fields.
//
// # Bounds
//
// Every field is read against the buffer's real length, and the element count is
// bounded by the bytes actually remaining before it is used to size anything. A
// declared count may only be trusted after it has been checked against a real one
// (#350). Both the element count and the total text per property are capped, and the
// cap states that it truncated rather than silently dropping the tail.

const (
	// vtVector is the flag OR'd into a property's type field for a vector.
	vtVector = 0x1000
	// The string type IDs whose vectors carry document content.
	vtBSTR   = 0x0008
	vtLPSTR  = 0x001E
	vtLPWSTR = 0x001F

	// maxVectorElements bounds how many elements of one vector are decoded.
	//
	// A workbook with more than this many sheets, or a deck with more than this many
	// slides, exists but is vanishingly rare; a property claiming more is far more
	// likely to be a crafted count. The tail is not dropped silently — the caller is
	// told how many were left, so a truncation cannot be mistaken for a short list.
	maxVectorElements = 512

	// maxVectorTextBytes bounds the total text decoded from one vector property, so a
	// container cannot turn a few KB of stream into an unbounded metadata field.
	maxVectorTextBytes = 64 * 1024
)

// vectorProperty is one decoded vector-valued property.
type vectorProperty struct {
	// Elements are the decoded strings, in stream order.
	Elements []string
	// Truncated is how many elements were NOT decoded because a cap fired. Zero for
	// every ordinary document.
	Truncated int
}

// legacyVectorStrings decodes the string-valued vector properties of a property-set
// stream, keyed by the property's INDEX in msoleps's Property slice.
//
// Keyed by index rather than by property ID because msoleps.Property carries no ID —
// only a Name and a value. It does, however, build that slice in property-table
// order, set A then set B (msoleps.go), which is exactly the order this walk
// produces. Pairing by index therefore needs no duplicate of msoleps's own name
// tables, and a property whose name only its dictionary knows still gets its name
// from msoleps rather than from a second copy of the vocabulary here.
func legacyVectorStrings(stream []byte) map[int]vectorProperty {
	const (
		headerBytes  = 28 // byte order, version, system id, CLSID, set count
		setEntryLen  = 20 // FMTID + offset
		tableHeader  = 8  // set byte count + property count
		tableEntry   = 8  // property id + offset
		typeWordLen  = 4
		countLen     = 4
		lengthPrefix = 4
	)

	if len(stream) < headerBytes {
		return nil
	}
	setCount := int(binary.LittleEndian.Uint32(stream[24:28]))
	// A property-set stream holds one or two sets; msoleps reads at most two, so
	// walking more would put this index out of step with its Property slice.
	if setCount < 1 {
		return nil
	}
	if setCount > 2 {
		setCount = 2
	}

	out := make(map[int]vectorProperty)
	index := 0

	for set := 0; set < setCount; set++ {
		entry := headerBytes + set*setEntryLen
		if entry+setEntryLen > len(stream) {
			return out
		}
		setStart := int(binary.LittleEndian.Uint32(stream[entry+16 : entry+20]))
		if setStart < 0 || setStart+tableHeader > len(stream) {
			return out
		}
		propCount := int(binary.LittleEndian.Uint32(stream[setStart+4 : setStart+8]))
		// Bound the count by the bytes that could actually hold that many entries,
		// before it is used for anything.
		if propCount < 0 || setStart+tableHeader+propCount*tableEntry > len(stream) {
			return out
		}

		for i := 0; i < propCount; i++ {
			at := setStart + tableHeader + i*tableEntry
			id := binary.LittleEndian.Uint32(stream[at : at+4])
			off := int(binary.LittleEndian.Uint32(stream[at+4 : at+8]))
			// msoleps creates a Property for EVERY table entry, including the
			// dictionary at id 0, which it fills with a Null rather than evaluating.
			// So the index advances for those too or the pairing slips by one.
			propIndex := index
			index++
			if id == 0 {
				continue
			}

			start := setStart + off
			if start < 0 || start+typeWordLen+countLen > len(stream) {
				continue
			}
			typeWord := binary.LittleEndian.Uint32(stream[start : start+typeWordLen])
			if typeWord&vtVector == 0 {
				continue // a scalar: msoleps reads these correctly
			}
			base := typeWord & 0x0FFF
			if base != vtLPSTR && base != vtLPWSTR && base != vtBSTR {
				continue // a vector of non-text: counts and pairs, not content
			}

			elems, truncated := decodeStringVector(stream, start+typeWordLen, base)
			if len(elems) == 0 {
				continue
			}
			out[propIndex] = vectorProperty{Elements: elems, Truncated: truncated}
		}
	}
	return out
}

// decodeStringVector reads an element count at `at`, then that many length-prefixed
// strings of the given base type.
//
// Returns the decoded elements and how many were skipped because a cap fired.
func decodeStringVector(stream []byte, at int, base uint32) ([]string, int) {
	const lengthPrefix = 4

	if at+4 > len(stream) {
		return nil, 0
	}
	declared := int(binary.LittleEndian.Uint32(stream[at : at+4]))
	pos := at + 4

	// The smallest possible element is a 4-byte length prefix, so a count larger than
	// the remaining quarter-bytes cannot be real. Checked BEFORE the count is used to
	// size a loop or a slice.
	if declared < 0 || declared > (len(stream)-pos)/lengthPrefix {
		return nil, 0
	}

	limit := declared
	truncated := 0
	if limit > maxVectorElements {
		truncated = limit - maxVectorElements
		limit = maxVectorElements
	}

	elems := make([]string, 0, limit)
	textBytes := 0
	for i := 0; i < limit; i++ {
		if pos+lengthPrefix > len(stream) {
			truncated += limit - i
			break
		}
		n := int(binary.LittleEndian.Uint32(stream[pos : pos+lengthPrefix]))
		pos += lengthPrefix
		if n < 0 {
			break
		}

		// LPWSTR counts UTF-16 code units; the others count bytes. Either way the
		// stored run is padded to a 4-byte boundary.
		width := 1
		if base == vtLPWSTR {
			width = 2
		}
		raw := n * width
		if raw < 0 || pos+raw > len(stream) {
			truncated += limit - i
			break
		}
		body := stream[pos : pos+raw]
		pos += raw
		// NO padding between elements, and this is the detail that decides whether the
		// walk stays in sync. A standalone CodePageString property value is padded to a
		// multiple of 4; the elements INSIDE a vector are packed end to end. Measured on
		// three real Excel-written files — here is poi_sampless.xls verbatim:
		//
		//	1e100000                       type 0x101E (VT_VECTOR|VT_LPSTR)
		//	03000000                       count = 3
		//	0c000000 "First Sheet\0"       len 12
		//	0f000000 "Sheet Number 2\0"    len 15   <- not a multiple of 4
		//	07000000 "Sheet3\0"            len 7
		//	0c100000 ...                   the NEXT property's type word, immediately
		//
		// A first version padded each element and therefore desynced after any element
		// whose length was not a multiple of 4: on that file it decoded 2 of 3 and
		// reported the third as capped, and on a 3-sheet workbook whose first name was
		// "Sheet1" (7 bytes with its terminator) it decoded 1 of 3. Every hand-built
		// fixture used lengths that happened to be multiples of 4, so all of them passed.

		var s string
		if base == vtLPWSTR {
			s = decodeUTF16LE(body)
		} else {
			s = string(body)
		}
		// LPSTR and LPWSTR lengths INCLUDE the terminator; BSTR does not. Trimming
		// trailing NULs covers all three without depending on which is which, and a
		// NUL inside a metadata string is not text a validator can use anyway.
		s = trimTrailingNULs(s)
		if s == "" {
			continue
		}

		if textBytes+len(s) > maxVectorTextBytes {
			truncated += limit - i
			break
		}
		textBytes += len(s)
		elems = append(elems, s)
	}
	return elems, truncated
}

// decodeUTF16LE converts little-endian UTF-16 bytes to a string, ignoring a trailing
// odd byte rather than reading past the run.
func decodeUTF16LE(b []byte) string {
	units := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		units = append(units, binary.LittleEndian.Uint16(b[i:i+2]))
	}
	return string(utf16.Decode(units))
}

// trimTrailingNULs removes the terminator (and any padding NULs) from a decoded run.
func trimTrailingNULs(s string) string {
	for len(s) > 0 && s[len(s)-1] == 0 {
		s = s[:len(s)-1]
	}
	return s
}

// handleVectorProperty records a multi-valued property, and reports whether it did.
//
// Returns false for a property whose name maps to a single scalar field (Keywords and
// the like): the caller joins those, because a scalar field has nowhere to put a list.
// Returns true once the elements have been recorded.
//
// # One entry per element, and NOT as a custom property
//
// Each element is recorded under its own key, because a joined line invites a match
// ACROSS two unrelated values: two adjacent sheet names read as one string to every
// validator, so "Q3 Forecast" followed by an account number would let a name-plus-number
// rule fire on a pair the document never put together.
//
// They go into Properties rather than CustomProps, and that is a precision decision with
// a measurement behind it. The metadata validator types any field whose name begins
// "Custom_" as CUSTOM_PROPERTY and reports it, by design — a custom property is an
// author-named leak channel. A sheet-name list is not that: measured on an ordinary
// 12-sheet workbook, routing it through CustomProps took the file from 1 finding to 13,
// twelve of them CUSTOM_PROPERTY at MEDIUM on values like "Sheet1", "Q4" and "Chart1",
// all visible at the default confidence. A finding per sheet in every legacy workbook is
// exactly what trains an operator to stop reading findings.
//
// Properties still reach the validators as text, so an SSN or a customer name inside a
// sheet name is detected and redacted — which is the whole point of #267 — without the
// list itself being asserted as a finding.
func handleVectorProperty(metadata *Metadata, name string, vec vectorProperty) bool {
	switch name {
	case "Title", "Subject", "Author", "Keywords", "Comments", "LastAuthor",
		"AppName", "Template", "Company", "Manager", "Category",
		"Content status", "Language", "RevNumber", "Link base":
		// A mapped scalar field. Let the caller join and take its normal path, so a
		// vector-valued Keywords still lands in Metadata.Keywords rather than
		// somewhere the report renders differently.
		return false
	}
	if !isCollectableCustomProperty(name) {
		// A structural vector (Heading pair) is dropped exactly as its scalar
		// equivalents are — but return true so the caller does not then join and
		// record it through the mapped-field path.
		return true
	}

	if metadata.Properties == nil {
		metadata.Properties = make(map[string]string)
	}
	key := propertyKeyBase(name)
	for i, e := range vec.Elements {
		metadata.Properties[key+"_"+itoa(i+1)] = e
	}
	if vec.Truncated > 0 {
		// Say so rather than truncate silently. A reader who cannot tell a short list
		// from a truncated one cannot tell whether the scan covered the document.
		metadata.Properties[key+"_truncated"] = itoa(vec.Truncated) +
			" further value(s) not decoded: vector element cap"
	}
	return true
}

// propertyKeyBase turns a reader-facing property name into a single-token key, so the
// rendered line reads as one field rather than as a sentence: "Document parts" becomes
// "DocumentParts", which is also what the OOXML vocabulary calls the same list.
//
// Each word keeps a capital, because the field name reaches the validators as text and
// the metadata validator reads field names: "Documentparts" is a word no vocabulary
// contains, while "DocumentParts" matches how every other key here is spelled.
func propertyKeyBase(name string) string {
	out := make([]byte, 0, len(name))
	upperNext := false
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == ' ' {
			upperNext = true
			continue
		}
		if upperNext && c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		upperNext = false
		out = append(out, c)
	}
	return string(out)
}

// itoa avoids importing strconv into this file for two calls; the values are small
// counts, never negative.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

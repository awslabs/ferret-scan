// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractvideolib

import (
	"encoding/binary"
	"strings"
)

// Apple writes a video's descriptive metadata as a `keys` table plus an `ilst` whose items are
// numbered rather than four-character-coded, and nothing here decoded that pairing.
//
// # What the container actually holds
//
// Read off a real macOS system recording,
// /System/Library/CoreServices/ControlCenter.app/Contents/Resources/BentoGalleryIntroduction.mov:
//
//	moov
//	  meta                                    <- NOT under udta, and no version/flags word
//	    hdlr  size 34
//	    keys  size 157   version/flags=00000000  entry_count=4
//	      index 1  namespace "mdta"  com.apple.quicktime.make
//	      index 2  namespace "mdta"  com.apple.quicktime.model
//	      index 3  namespace "mdta"  com.apple.quicktime.software
//	      index 4  namespace "mdta"  com.apple.quicktime.creationdate
//	    ilst  size 159
//	      item type 00000001 -> data -> "Apple"
//	      item type 00000002 -> data -> "Mac16,6"
//	      item type 00000003 -> data -> "macOS 15.2 (24C101)"
//	      item type 00000004 -> data -> "2025-06-16T19:12:48-0700"
//
// An item's type word is the 1-based INDEX of its key, so a value is only attributable to a field
// name by pairing the two lists.
//
// # Four separate gaps had to close, not one
//
// The issue described this as "the mapping is not decoded". Reading the code against that real file
// found the value unreachable four times over, and any one of them alone keeps it invisible:
//
//  1. parseMoovBoxWithContext had cases for mvhd, udta and trak but none for meta, and
//     parseMetaBoxWithContext was reachable only from parseUdtaBoxWithContext. A moov-level meta —
//     which is where Apple puts this — was never visited at all.
//  2. parseMetaBoxWithContext skipped 4 bytes unconditionally for a version/flags word. ISO
//     14496-12 declares meta a FullBox so that is right for .mp4; QuickTime's meta is a plain
//     container and has no such word. On the file above the parser therefore read the ASCII of the
//     first child's type, "hdlr", AS ITS SIZE (0x68646c72 = 1,751,411,826), failed the bounds check
//     and broke out immediately — so a QuickTime meta was entirely unparsed, ilst included.
//  3. keys was never decoded, so no index -> name map existed.
//  4. parseIlstBoxWithContext stored unrecognized tags only when isFourCC held. An index-typed
//     item is four bytes and so passes that test, but its "type" renders as unprintable bytes, so
//     the value landed under a garbage key when it landed at all.
//
// # What the reader saw instead
//
// Not nothing, which is what makes this worse than a silent miss. searchAppleMetadataInData scrapes
// raw text for "com.apple.quicktime.<field>" and takes the bytes that follow, and in a keys table
// what follows a key name is the NEXT KEY'S NAME. On the file above that produced, at HEAD:
//
//	CameraMake:          m.apple.quicktime.model        <- the next key's name, minus its first 2 bytes
//	CameraModel:         m.apple.quicktime.software
//	Software:            m.apple.quicktime.creationdate
//	CreationDate_Apple:  data                           <- the child atom's TYPE as a value
//
// against true values of "Apple", "Mac16,6" and "macOS 15.2 (24C101)". So the fields were populated
// with field NAMES, shifted by one entry and truncated by two bytes. 2 of 40 real video files on the
// host that first reproduced this show it.
//
// The issue proposed a raw text scrape and then rejected it, having measured that it "injected junk
// properties". That verdict was right, and the scrape it describes is not hypothetical — it is what
// ships today and what produced the table above. Decoding the two lists properly is what replaces
// it, and the scrape is left in place only as the fallback for files with no keys table.

// appleKeyNamespace is the namespace Apple uses for its reverse-DNS metadata keys. The keys box
// permits others, so this is checked rather than assumed: a key in an unknown namespace is still
// recorded, but it is not allowed to claim a typed field such as CameraMake.
const appleKeyNamespace = "mdta"

// metaKeyEntry is one row of the keys table, kept with its namespace so an unexpected one can be
// recorded without being trusted.
type metaKeyEntry struct {
	namespace string
	name      string
}

// metaChildOffset reports where a meta box's children begin: 0 for QuickTime, 4 for ISO 14496-12.
//
// The two layouts are told apart by trying each and asking whether a box header lands there, rather
// than by the file's brand. A .mov can carry an ISO-style meta and an .mp4 a QuickTime-style one —
// the boxes come from different writers, not from the file extension — so branching on brand
// mis-parses the mixed cases, and mis-parsing is silent here.
//
// Offset 0 is preferred when both are plausible: a FullBox's version/flags word is almost always
// zero, which cannot be a valid box size, so offset 0 failing is the reliable signal rather than
// offset 4 succeeding.
func metaChildOffset(data []byte) int {
	if headerFitsAt(data, 0) {
		return 0
	}
	if headerFitsAt(data, 4) {
		return 4
	}
	// Neither reads as a header. Return the ISO offset so behaviour matches what this function
	// replaced; the caller's own bounds checks then end the walk without reading anything.
	return 4
}

// headerFitsAt reports whether a plausible box header starts at off.
//
// "Plausible" is deliberately weak — a declared size that fits the box and a printable type. It only
// has to separate a real header from a version/flags word, not validate the box.
func headerFitsAt(data []byte, off int) bool {
	if off < 0 || off+8 > len(data) {
		return false
	}
	size := binary.BigEndian.Uint32(data[off : off+4])
	if size < 8 || int64(size) > int64(len(data)-off) {
		return false
	}
	return isPrintableBoxType(data[off+4 : off+8])
}

// isPrintableBoxType reports whether raw is a four-character code a writer would emit.
//
// The 0xA9 copyright prefix is allowed because QuickTime uses it for ©-atoms; otherwise every byte
// must be printable ASCII. An ilst item's index-typed word (0x00000001) fails this, which is what
// keeps metaChildOffset from mistaking an item for a header.
func isPrintableBoxType(raw []byte) bool {
	if len(raw) != 4 {
		return false
	}
	for i, b := range raw {
		if i == 0 && b == itunesAtomPrefix {
			continue
		}
		if b < 0x20 || b > 0x7E {
			return false
		}
	}
	return true
}

// Well-known type indicators from a data box, per the QuickTime metadata format. Only the two text
// forms are named because they are the only ones this reads as text.
const (
	appleDataTypeUTF8    = 1
	appleDataTypeUTF16BE = 2
)

// appleDataValue returns the text a keys-indexed ilst item carries, or "" if it carries none.
//
// A data box declares what its payload IS: a 4-byte type indicator whose low 24 bits are the
// well-known type, then a 4-byte locale. parseItunesTag ignores that word and returns the payload as
// a string whatever it holds, which is fine for the four-character-coded tags it was written for but
// not here — the same real recording that motivated this carries
// com.apple.quicktime.pixeldensity as well-known type 30 with a 16-byte binary payload, and
// stringifying it injected raw bytes into the text the validators scan.
//
// Text is accepted on either of two signals rather than on the indicator alone: the declared type
// says text, OR the payload reads as text anyway. Dropping a value is a SUPPRESSOR — an unreported
// value cannot be redacted — so a writer that mislabels a UTF-8 string as type 0 must not cost a
// finding. What both signals agreeing to reject is binary, which was never a finding to begin with.
func appleDataValue(data []byte) string {
	const indicatorSize = 8 // 4-byte type indicator + 4-byte locale
	offset := 0

	for offset < len(data) {
		boxType, payloadStart, payloadEnd, ok := readChildHeader(data, offset)
		if !ok {
			return ""
		}
		if boxType == "data" && payloadEnd-payloadStart >= indicatorSize {
			wellKnown := binary.BigEndian.Uint32(data[payloadStart:payloadStart+4]) & 0x00FFFFFF
			payload := data[payloadStart+indicatorSize : payloadEnd]

			switch wellKnown {
			case appleDataTypeUTF8, appleDataTypeUTF16BE:
				return strings.TrimSpace(string(payload))
			default:
				if isValidUTF8Subset(payload) {
					return strings.TrimSpace(string(payload))
				}
				return ""
			}
		}
		offset = payloadEnd
	}

	return ""
}

// parseKeysBox decodes a keys box into a 1-based index -> key map.
//
// Layout per QuickTime: a 4-byte version/flags word, a 4-byte entry count, then that many entries of
// [size][namespace][name], where size covers the whole entry. An entry's index is its position in
// the list, counted from 1, and that is what an ilst item's type word refers to.
//
// The declared entry count is used only to stop early, never to size an allocation: it is an
// attacker-controlled 32-bit number, and honouring it as a capacity is how a small file reserves
// gigabytes. The walk is bounded by the box's own bytes instead, which is the one bound the file
// cannot overstate.
func parseKeysBox(data []byte) map[uint32]metaKeyEntry {
	const keysHeaderSize = 8 // version/flags + entry count
	if len(data) < keysHeaderSize {
		return nil
	}

	declared := binary.BigEndian.Uint32(data[4:keysHeaderSize])
	keys := make(map[uint32]metaKeyEntry)

	offset := keysHeaderSize
	var index uint32
	for offset+8 <= len(data) {
		size := int(binary.BigEndian.Uint32(data[offset : offset+4]))
		if size < 8 || offset+size > len(data) {
			break
		}
		index++
		if declared > 0 && index > declared {
			break
		}

		namespace := string(data[offset+4 : offset+8])
		name := strings.TrimRight(string(data[offset+8:offset+size]), "\x00")
		keys[index] = metaKeyEntry{namespace: namespace, name: strings.TrimSpace(name)}

		offset += size
	}

	if len(keys) == 0 {
		return nil
	}
	return keys
}

// appleKeyField maps a reverse-DNS key name to the metadata field it fills.
//
// Keyed on the part after the last dot, so com.apple.quicktime.make and a third-party
// com.example.make both land on CameraMake. The full name is still what gets recorded for anything
// not listed here, because a truncated key name is exactly the corruption this file exists to undo.
var appleKeyField = map[string]string{
	"make":         "CameraMake",
	"model":        "CameraModel",
	"software":     "Software",
	"creationdate": "CreatedDate",
	"description":  "Description",
	"title":        "Title",
	"author":       "Author",
	"artist":       "Author",
	"copyright":    "Copyright",
	"comment":      "Description",
	"displayname":  "Title",
	"location":     "Location",
}

// applyAppleKeyValue records value under the field key names, and reports whether it was consumed.
//
// A value is only allowed to claim a typed field when its key sits in Apple's own namespace; anything
// else is recorded as a property under its full key name. That keeps a third-party writer from
// overwriting CameraMake while still surfacing its value to the validators, which is what matters —
// an unreported value cannot be redacted.
func applyAppleKeyValue(entry metaKeyEntry, value string, metadata *VideoMetadata) bool {
	value = strings.TrimSpace(value)
	if value == "" || entry.name == "" {
		return false
	}

	shortName := entry.name
	if i := strings.LastIndex(shortName, "."); i >= 0 && i+1 < len(shortName) {
		shortName = shortName[i+1:]
	}
	shortName = strings.ToLower(shortName)

	// ISO 6709 positions arrive as com.apple.quicktime.location.ISO6709 and are a coordinate, not a
	// label, so they go through the existing parser rather than into Location as text.
	if strings.HasSuffix(strings.ToLower(entry.name), ".iso6709") {
		parseISO6709Location(value, metadata)
		metadata.Properties[propertyKeyFor(entry.name)] = value
		return true
	}

	field := ""
	if entry.namespace == appleKeyNamespace {
		field = appleKeyField[shortName]
	}

	// The key was decoded from the table, so the raw text scrape must not also guess at it. Recorded
	// even when the value is dropped below, because a scrape "answer" for a key whose real value was
	// binary or unparseable is exactly the garbage this replaces.
	if metadata.decodedAppleKeys == nil {
		metadata.decodedAppleKeys = make(map[string]bool)
	}
	metadata.decodedAppleKeys[entry.name] = true

	claimed := true
	switch field {
	case "CameraMake":
		metadata.CameraMake = value
	case "CameraModel":
		metadata.CameraModel = value
	case "Software":
		metadata.Software = value
	case "Description":
		metadata.Description = value
	case "Title":
		metadata.Title = value
	case "Author":
		metadata.Author = value
	case "Copyright":
		metadata.Copyright = value
	case "Location":
		metadata.Location = value
	case "CreatedDate":
		// A date that will not parse is still text worth scanning, so it falls through to the
		// property rather than being dropped along with the field.
		if parsed, err := parseDate(value); err == nil {
			metadata.CreatedDate = parsed
		} else {
			claimed = false
		}
	default:
		claimed = false
	}

	// Recorded as a property ONLY when no typed field took it. ToProcessedContent emits fields and
	// properties both, so writing the same value to each made one value in the file produce TWO
	// findings — measured on a real .mov, where a single SSN in the description reported at lines 6
	// and 8. The existing four-character-code path sets a field or a property, never both; this
	// follows it.
	if !claimed {
		metadata.Properties[propertyKeyFor(entry.name)] = value
	}
	return true
}

// propertyKeyFor turns a reverse-DNS key name into a readable property key.
//
// "com.apple.quicktime.creationdate" becomes "QuickTime_creationdate"; anything outside Apple's
// prefix keeps its full name, because shortening an unknown vendor's key can collide two different
// fields onto one property.
func propertyKeyFor(name string) string {
	const applePrefix = "com.apple.quicktime."
	if strings.HasPrefix(strings.ToLower(name), applePrefix) {
		return "QuickTime_" + name[len(applePrefix):]
	}
	return name
}

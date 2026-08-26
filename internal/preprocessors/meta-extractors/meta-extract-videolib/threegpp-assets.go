// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractvideolib

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"strings"
)

// 3GPP writes a file's descriptive metadata into udta with its own box names and its own payload
// layout, and none of the twelve were read.
//
// Registering .3gp/.3g2 as scannable extensions is necessary but NOT sufficient, which is the part
// worth recording: with the extension registered and this file absent, a real ffmpeg-written .3gp
// carrying "SSN 449-87-4100" reached the video preprocessor, reported
// `Processor: video_metadata  Status: Success  MimeType: video/3gpp  MajorBrand: 3gp6`, and still
// produced ZERO findings. The container was parsed; the box holding the value simply had no case.
// A "supported format" that extracts nothing is worse than an unsupported one, because the clean
// result now looks authoritative.
//
// # The layout, read off that file
//
// The value sat in moov > udta > dscp, 30 bytes, payload:
//
//	00 00 00 00 15 c7 53 53 4e 20 34 34 39 2d 38 37 2d 34 31 30 30 00
//	^^ version  ^^^^^ language   ^^^^ "SSN 449-87-4100"            ^^ NUL
//	   ^^^^^^^^ flags
//
// So per 3GPP TS 26.244: a 1-byte version, 3 bytes of flags, a 2-byte packed language code (three
// 5-bit values offset from 0x60 — 0x15c7 is "eng"), then NUL-terminated UTF-8.
//
// This is NOT the QuickTime string form that parseStringBox handles, which is a 2-byte text length
// followed by a 2-byte language code. Feeding a 3GPP box to that parser reads the version and flags
// as a length and yields either nothing or four bytes of binary glued to the front of the text —
// which is the corruption parseStringBox's own comment describes fixing for the QuickTime case.

// threeGPPTextHeaderSize is the version, flags and language prefix ahead of the text.
const threeGPPTextHeaderSize = 6

// parse3GPPAssetText returns the UTF-8 text of a 3GPP asset box, or "" if it holds none.
//
// The terminating NUL is optional in practice: some writers omit it on the last box, so the text is
// taken up to the first NUL if there is one and to the end of the payload otherwise. Truncating at a
// NUL that is not there would drop the value, and a dropped value cannot be redacted.
func parse3GPPAssetText(data []byte) string {
	if len(data) <= threeGPPTextHeaderSize {
		return ""
	}

	// A sanity check on the version byte, which is 0 in every writer's output and in the spec. It is
	// the one field that distinguishes this layout from a QuickTime string box whose first two bytes
	// are a text length; without it a mis-routed box would yield plausible-looking rubbish rather
	// than nothing.
	if data[0] != 0 {
		return ""
	}

	text := data[threeGPPTextHeaderSize:]
	if i := bytes.IndexByte(text, 0); i >= 0 {
		text = text[:i]
	}
	return strings.TrimSpace(string(text))
}

// threeGPPLanguage decodes the packed 2-byte language code into an ISO 639-2 string.
//
// Three 5-bit values, each offset from 0x60. Recorded as a property rather than acted on: it is not
// sensitive by itself, but it tells a reader which of several same-named boxes they are looking at
// when a file carries one per language.
func threeGPPLanguage(data []byte) string {
	if len(data) < threeGPPTextHeaderSize {
		return ""
	}
	packed := binary.BigEndian.Uint16(data[4:6])
	out := make([]byte, 0, 3)
	for shift := 10; shift >= 0; shift -= 5 {
		c := byte((packed>>uint(shift))&0x1F) + 0x60
		if c < 'a' || c > 'z' {
			return ""
		}
		out = append(out, c)
	}
	return string(out)
}

// apply3GPPAsset records a 3GPP asset box's text and reports whether the box was one of the twelve.
//
// The mapping follows 3GPP TS 26.244's names, listed from the specification rather than from what one
// fixture happened to contain — a file written by a phone rather than by ffmpeg carries the others,
// and each is free text that can hold a name, an address or an account number.
func apply3GPPAsset(boxType string, data []byte, metadata *VideoMetadata) bool {
	var field string
	switch boxType {
	case "titl":
		field = "Title"
	case "dscp":
		field = "Description"
	case "cprt":
		field = "Copyright"
	case "auth":
		field = "Author"
	case "perf":
		field = "Performer"
	case "gnre":
		field = "Genre"
	case "albm":
		field = "Album"
	case "yrrc":
		field = "RecordingYear"
	case "kywd":
		field = "Keywords"
	case "rtng":
		field = "Rating"
	case "clsf":
		field = "Classification"
	case "perm":
		field = "Permissions"
	default:
		return false
	}

	value := parse3GPPAssetText(data)
	if value == "" {
		// The box WAS one of the twelve — claim it either way, so the caller does not fall through
		// to a parser written for a different layout and turn an empty box into rubbish.
		return true
	}

	claimed := false
	switch field {
	case "Title":
		if metadata.Title == "" {
			metadata.Title, claimed = value, true
		}
	case "Description":
		if metadata.Description == "" {
			metadata.Description, claimed = value, true
		}
	case "Copyright":
		if metadata.Copyright == "" {
			metadata.Copyright, claimed = value, true
		}
	case "Author":
		if metadata.Author == "" {
			metadata.Author, claimed = value, true
		}
	}

	// Recorded as a property only when no typed field took it, which is what the four-character-code
	// path above already does. Writing both emits the value twice, because ToProcessedContent renders
	// fields and properties alike: a single SSN in a real .3gp's dscp reported at lines 6 AND 7 before
	// this. The boxes with no typed field — performer, keywords, classification — still land here,
	// which is what puts their free text in front of the validators.
	if claimed {
		return true
	}

	metadata.Properties[uniqueAssetKey(metadata, field, threeGPPLanguage(data))] = value

	return true
}

// uniqueAssetKey returns a property key that no earlier box has taken.
//
// A container may legitimately carry several boxes of one type — one per language is the common
// case, and 3GPP TS 26.244 does not forbid more — and writing them all to "3GPP_Keywords" means
// each overwrites the last, so only the final one is reported. Every earlier value is then
// unreported, and an unreported value is never redacted: silently keeping one of N is the same
// class of loss as not reading the box at all.
//
// Measured before this: a file with 2,000, 4,000 and 8,000 distinct keyword boxes produced 2
// findings at every size. The count was flat not because the walk was fast but because 7,999
// values were being discarded.
//
// The language code is preferred as the disambiguator because it is meaningful to a reader; a
// numeric suffix is the fallback for same-language duplicates. The number of keys is bounded by the
// bytes of the container, which MaxMoovParse already caps, so this cannot be turned into unbounded
// growth by a small file.
//
// The suffix comes from a COUNTER, not from probing the map for the first free number. The probing
// version was quadratic and measurably so: box k performed k-1 lookups, and on files with 2,000 /
// 4,000 / 8,000 same-type boxes the scan took 334ms / 756ms / 2,189ms — x2.26 then x2.90 per
// doubling, where linear is x2.00. A counter makes each key O(1) and the whole walk linear.
func uniqueAssetKey(metadata *VideoMetadata, field, lang string) string {
	key := "3GPP_" + field
	if _, taken := metadata.Properties[key]; !taken {
		return key
	}

	if lang != "" && lang != "und" {
		withLang := key + "_" + lang
		if _, taken := metadata.Properties[withLang]; !taken {
			return withLang
		}
		key = withLang
	}

	if metadata.assetKeyCounts == nil {
		metadata.assetKeyCounts = make(map[string]int)
	}
	// Starts at 2 because the unsuffixed key is conceptually the first.
	for {
		metadata.assetKeyCounts[key]++
		candidate := key + "_" + strconv.Itoa(metadata.assetKeyCounts[key]+1)
		if _, taken := metadata.Properties[candidate]; !taken {
			return candidate
		}
	}
}

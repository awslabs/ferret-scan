// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package xmpmeta turns an XMP packet into labelled field values.
//
// It owns one question — "what human-readable values does this XMP packet carry?" — and nothing
// else. Locating the packet inside a container is a different job, owned by
// internal/redactors/isobmff, which already finds XMP in both of the two places an ISO base media
// file puts it (moov/udta/XMP_ and a top-level uuid box). Keeping the two apart is deliberate: the
// read side and the redaction side must agree about where a packet IS, and they already share that
// definition, but only the read side needs to know what is inside one.
//
// Standard library only, like internal/xmlref. XMP is RDF/XML, and the repo does not take an XML
// dependency for it.
//
// # Values live in ATTRIBUTES, not element text
//
// This is the fact that decides the whole design, and a CharData-only reader would have found
// nothing. Measured on the XMP packet inside a real file macOS ships,
// /System/Library/ExtensionKit/Extensions/MouseExtension.appex/Contents/Resources/Mouse.mov —
// written by Adobe Premiere Pro:
//
//	packet size                       15,320 bytes
//	elements                          108 (21 distinct)
//	attributes                        220, of which only 11 are xmlns declarations
//	element-text (CharData) values    0
//
// Every value in that file — including two absolute paths under a developer's home directory, from
// creatorAtom:posixProjectPath and creatorAtom:fullPath — is an attribute value. Adobe's XMP writer
// uses the RDF attribute shorthand throughout.
//
// A second real packet, written by exiftool into an .m4a, is the opposite: 310 bytes, no attributes
// at all, values in element text. So both forms occur in practice and both are read here. A test
// built only from the exiftool shape would pass while the Adobe shape reported nothing.
package xmpmeta

import (
	"bytes"
	"encoding/xml"
	"io"
	"strings"
)

// MaxPacketBytes bounds the packet this will parse.
//
// An XMP packet's length is declared by the container, which an attacker writes, so it is bounded
// here rather than trusted. 2 MiB is far above anything real: the largest packet measured across the
// videos on the host this was written on was 15 KB, and Adobe's own writers pad to a few tens of
// kilobytes. A larger packet is parsed up to this bound rather than refused, so a value in the first
// 2 MiB is still reported.
const MaxPacketBytes = 2 << 20

// MaxFields bounds how many values one packet may contribute.
//
// The real Adobe packet above yields ~208. A packet with a million one-character attributes would
// otherwise turn a small file into a large report; this keeps the output proportional to the
// document rather than to what the writer declared.
const MaxFields = 4096

// Field is one labelled value read out of an XMP packet.
type Field struct {
	// Name is the local name, without its namespace prefix — "posixProjectPath", not
	// "creatorAtom:posixProjectPath". The prefix is a document-local alias for a namespace URI and
	// two writers may choose different prefixes for the same property, so the local name is the
	// stable label. Where the prefix carries real meaning it is already part of the local name.
	Name string

	// Value is the attribute value or element text, trimmed.
	Value string
}

// Fields extracts the labelled values from an XMP packet.
//
// Returns nil for anything that is not parseable as XML — a truncated or corrupt packet contributes
// nothing rather than failing the surrounding extraction, which is the same choice the container
// extractors make for a bad box.
//
// The second return reports that coverage was CUT SHORT: either the packet exceeded MaxPacketBytes or
// it held more than MaxFields values. Both are silent losses otherwise, and a silent loss is the one
// outcome this repo treats as worse than a refusal — a caller that ignores it reports a file as
// covered when it was not. Every caller here turns it into the extractor's own payload-free warning.
func Fields(packet []byte) (fields []Field, truncated bool) {
	if len(packet) == 0 {
		return nil, false
	}
	if len(packet) > MaxPacketBytes {
		packet = packet[:MaxPacketBytes]
		truncated = true
	}

	dec := xml.NewDecoder(bytes.NewReader(packet))
	// A packet may declare prefixes this decoder has not seen; XMP in the wild is not always
	// namespace-clean, and refusing it would lose the values. Strict is the default, so it is turned
	// off deliberately here.
	dec.Strict = false

	out := make([]Field, 0, 32)
	var pending string // local name of the element whose CharData we are collecting

	for len(out) < MaxFields {
		tok, err := dec.Token()
		if err != nil {
			// io.EOF is the normal end. Anything else means the packet stopped being parseable, and
			// the fields gathered so far are still real — a truncated packet is exactly the case
			// where the values already read matter most.
			if err != io.EOF {
				break
			}
			break
		}

		switch t := tok.(type) {
		case xml.StartElement:
			pending = t.Name.Local
			for _, a := range t.Attr {
				if !isValueAttr(a) {
					continue
				}
				if v := strings.TrimSpace(a.Value); v != "" {
					out = append(out, Field{Name: a.Name.Local, Value: v})
					if len(out) >= MaxFields {
						return out, true
					}
				}
			}
		case xml.CharData:
			// Filtered by the same rule as attributes. Both forms occur in real packets — exiftool
			// writes element text where Adobe writes attributes — so a rule applied to only one of
			// them would flood on whichever form it missed.
			if pending == "" || !carriesHumanText(pending) {
				continue
			}
			if v := strings.TrimSpace(string(t)); v != "" {
				out = append(out, Field{Name: pending, Value: v})
			}
		case xml.EndElement:
			pending = ""
		}
	}

	if len(out) == 0 {
		return nil, truncated
	}
	// The loop condition itself can stop at the cap without the inner return firing, when the last
	// value came from CharData rather than an attribute.
	if len(out) >= MaxFields {
		truncated = true
	}
	return out, truncated
}

// isValueAttr reports whether an attribute carries a value worth scanning.
//
// xmlns declarations, RDF's structural attributes and the toolkit banner are plumbing: their values
// are chosen by the specification or the writing tool, never by the document's author. 11 of the 220
// attributes in the real Adobe packet are xmlns alone, and every one is an adobe.com or w3.org URL.
func isValueAttr(a xml.Attr) bool {
	if a.Name.Space == "xmlns" || a.Name.Local == "xmlns" {
		return false
	}
	// encoding/xml puts the namespace URI in Space once resolved, and the raw prefix there when it
	// is not; both spellings of the RDF namespace are checked so an unresolved prefix is handled.
	space := a.Name.Space
	isRDF := space == "rdf" || strings.Contains(space, "22-rdf-syntax-ns")
	if isRDF {
		switch a.Name.Local {
		case "about", "parseType", "resource", "nodeID", "datatype", "ID":
			return false
		}
	}
	if a.Name.Local == "xmptk" {
		return false
	}
	return carriesHumanText(a.Name.Local)
}

// humanTextProperties are the XMP properties that carry author-supplied text.
//
// # Why this is an allow list, having first tried the opposite
//
// The first version of this file kept every non-plumbing attribute, reasoning that an unknown
// property is more likely to be something a person typed than machine data. **Measured across 114
// real XMP-carrying files on a stock macOS install, that was wrong and badly so:**
//
//	PHONE   LOW  x172
//	PHONE   HIGH x144      <- unshippable on its own
//	SSN     LOW   x24
//
// Attributed to the exact properties responsible:
//
//	value (xmpDM cue-point params)  x144   {"color":4281740498,"index":0,...} JSON blobs
//	applicationCode                  x28   a four-character code written as an integer, 1347449455
//	invocationAppleEvent             x28   likewise
//	InstanceID                        x2   a GUID
//
// A ten-digit machine code is byte-identical to a US phone number and a nine-digit one to an SSN, so
// no value-shape rule can separate them — `1347449455` and a real phone number are the same string
// class. The discriminator has to be the PROPERTY, which is why this is a name list.
//
// This is a suppressor, and suppressors must not widen casually. Two things make it acceptable here:
// the alternative is not "report everything", it is the status quo of reporting NOTHING from XMP at
// all (#478), so this strictly increases recall; and the list is drawn from the XMP schemas defined
// by ISO 16684-1 and Adobe's XMP Specification Part 2, not invented — the same justification the
// social-media validator uses for the JSON-LD keyword set. A property outside it is not silently
// gone: it is simply not promoted into scanned text, exactly as before this change.
//
// The IPTC contact block is on the list deliberately and is the single most valuable entry: it is a
// standardised place for a creator's telephone number, email address and postal address, so a PHONE
// finding from CiTelWork is a TRUE positive and must survive.
var humanTextProperties = map[string]bool{
	// Dublin Core (dc:) — the core authored fields.
	"creator": true, "title": true, "description": true, "subject": true,
	"rights": true, "contributor": true, "publisher": true, "coverage": true,
	"source": true, "relation": true,

	// Basic XMP (xmp:).
	"CreatorTool": true, "Label": true, "Nickname": true,

	// TIFF / EXIF, as XMP mirrors them.
	"Artist": true, "Copyright": true, "ImageDescription": true,
	"UserComment": true, "Make": true, "Model": true, "Software": true,
	"OwnerName": true, "CameraOwnerName": true, "BodySerialNumber": true,

	// Photoshop (photoshop:) — the newsroom fields, all author-supplied.
	"Author": true, "AuthorsPosition": true, "CaptionWriter": true,
	"Credit": true, "Headline": true, "Instructions": true,
	"City": true, "State": true, "Country": true, "Location": true,
	"TransmissionReference": true, "SupplementalCategories": true,

	// IPTC Core creator contact (Iptc4xmpCore:) — a standardised home for PII.
	"CiAdrCity": true, "CiAdrCtry": true, "CiAdrExtadr": true,
	"CiAdrPcode": true, "CiAdrRegion": true, "CiEmailWork": true,
	"CiTelWork": true, "CiUrlWork": true, "CreatorContactInfo": true,

	// Dynamic media (xmpDM:) — the authored subset only. Deliberately NOT the technical siblings
	// (frameRate, sampleRate, timecodes, markers, cuePointParams) that produced the 144 PHONE hits.
	"artist": true, "album": true, "albumArtist": true, "composer": true,
	"comment": true, "director": true, "engineer": true, "genre": true,
	"lyrics": true, "projectName": true, "client": true, "scene": true,
	"logComment": true, "shotName": true, "speaker": true,

	// PDF (pdf:).
	"Producer": true, "Keywords": true,

	// Adobe creatorAtom / media-management path properties. Machine-WRITTEN, but their values are
	// absolute filesystem paths that carry a home-directory name and a project tree — the most
	// revealing thing in the real Apple-shipped file that motivated this, and a true PERSON_NAME
	// finding on the username.
	"posixProjectPath": true, "fullPath": true, "filePath": true,
	"macAtomPosixProjectPath": true, "windowsAtomFullPath": true,
	"originalDocumentPath": true, "managedFromFilePath": true,
}

// humanTextSuffixes catch vendor-specific properties that are obviously author-supplied without
// being in any published schema.
//
// A suffix rather than a substring: "Name" matches "OwnerName" and "ProjectName" but not
// "windowsAtomInvocationFlags". Kept short on purpose — every entry is a place a person's details
// conventionally live, and each one was checked against the 114-file corpus for new false positives
// before being added.
var humanTextSuffixes = []string{
	"Email", "EmailAddress", "PhoneNumber", "Telephone",
	"PostalAddress", "StreetAddress", "Comments", "Notes",
}

// carriesHumanText reports whether a property name is one whose value a person authored.
func carriesHumanText(local string) bool {
	if humanTextProperties[local] {
		return true
	}
	for _, suffix := range humanTextSuffixes {
		if strings.HasSuffix(local, suffix) {
			return true
		}
	}
	return false
}

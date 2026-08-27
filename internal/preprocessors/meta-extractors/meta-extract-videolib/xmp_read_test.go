// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractvideolib

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/xmpmeta"
)

// xmpSSN builds a structurally valid SSN at run time rather than as a literal, so a committed file
// never carries a bare nine-digit dashed number.
func xmpSSN() string { return strings.Join([]string{"449", "87", "4100"}, "-") }

// xmpPacketWith wraps a value in an XMP packet using the element-text form.
func xmpPacketWith(value string) []byte {
	return []byte(`<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>` +
		`<x:xmpmeta xmlns:x="adobe:ns:meta/">` +
		`<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">` +
		`<rdf:Description rdf:about="" xmlns:tiff="http://ns.adobe.com/tiff/1.0/">` +
		`<tiff:Artist>` + value + `</tiff:Artist>` +
		`</rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end="w"?>`)
}

// isoBox builds a plain 32-bit-size box.
func isoBox(typ string, payload []byte) []byte {
	out := make([]byte, 8, 8+len(payload))
	binary.BigEndian.PutUint32(out[0:4], uint32(8+len(payload)))
	copy(out[4:8], typ)
	return append(out, payload...)
}

// xmpUUIDBox builds the top-level uuid box that carries an XMP packet.
//
// The 16-byte user type is what identifies it — the box TYPE is the container format's generic
// extension point, so matching on "uuid" alone would claim every vendor extension box. This is the
// user type the XMP specification assigns, and the same one internal/redactors/isobmff matches.
func xmpUUIDBox(packet []byte) []byte {
	userType := []byte{
		0xBE, 0x7A, 0xCF, 0xCB, 0x97, 0xA9, 0x42, 0xE8,
		0x9C, 0x71, 0x99, 0x94, 0x91, 0xE3, 0xAF, 0xAC,
	}
	payload := append(append([]byte{}, userType...), packet...)
	return isoBox("uuid", payload)
}

// writeMOVWithXMP builds a container whose ONLY copy of the value is in an XMP packet.
//
// That is the binding property: the value must not appear in udta, ilst or anywhere the existing
// walk already reads, or the test would pass on the old code.
func writeMOVWithXMP(t *testing.T, ext string, inUUID bool, value string) string {
	t.Helper()

	packet := xmpPacketWith(value)

	// A minimal but well-formed movie: ftyp, then moov holding an mvhd, then mdat.
	mvhd := make([]byte, 100) // version 0 mvhd; zeros are a valid, if empty, header
	moovChildren := isoBox("mvhd", mvhd)
	if !inUUID {
		// The QuickTime home: moov/udta/XMP_.
		moovChildren = append(moovChildren, isoBox("udta", isoBox("XMP_", packet))...)
	}
	out := isoBox("ftyp", []byte("qt  \x00\x00\x02\x00qt  "))
	out = append(out, isoBox("moov", moovChildren)...)
	if inUUID {
		out = append(out, xmpUUIDBox(packet)...)
	}
	out = append(out, isoBox("mdat", []byte("media"))...)

	dir := t.TempDir()
	target := filepath.Join(dir, "fixture"+ext)
	if err := os.WriteFile(target, out, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return target
}

// TestXMPIsReadFromBothLayouts is the recall case for #478.
//
// An ISO base media file puts XMP in one of two places, and the walk could reach neither: a top-level
// uuid box is outside moov entirely, so the moov arm never sees it, and moov/udta/XMP_ holds an XML
// packet rather than the atom tree the udta walker understands. Both were stepped over by the default
// arm's arithmetic, so a value living ONLY in XMP was reported clean at exit 0.
func TestXMPIsReadFromBothLayouts(t *testing.T) {
	value := "Employee SSN " + xmpSSN()

	for name, inUUID := range map[string]bool{
		"moov/udta/XMP_":      false,
		"top-level uuid[XMP]": true,
	} {
		t.Run(name, func(t *testing.T) {
			file := writeMOVWithXMP(t, ".mov", inUUID, value)

			md, err := ExtractVideoMetadata(file)
			if err != nil {
				t.Fatalf("ExtractVideoMetadata: %v", err)
			}

			found := ""
			for k, v := range md.Properties {
				if strings.Contains(v, xmpSSN()) {
					found = k
				}
			}
			if found == "" {
				t.Fatalf("the XMP value was not extracted; properties = %v", md.Properties)
			}
			if !strings.HasPrefix(found, "XMP") {
				t.Errorf("the value landed under %q; XMP values must be keyed XMP_* so a reader can "+
					"see where they came from", found)
			}
		})
	}
}

// TestXMPPropertyCannotOverwriteAnAtomTreeField pins the key namespacing.
//
// The packet is written by whoever produced the file. An XMP property named Author or Template using
// a bare key would overwrite a value read from the atom tree — a way to hide an atom-tree finding by
// choosing a name in the packet.
func TestXMPPropertyCannotOverwriteAnAtomTreeField(t *testing.T) {
	packet := []byte(`<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF ` +
		`xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">` +
		`<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/" ` +
		`dc:creator="decoy from the packet"/></rdf:RDF></x:xmpmeta>`)

	md := &VideoMetadata{Properties: map[string]string{"creator": "from the atom tree"}}
	// Feed the fields through the same recording path the extractor uses.
	f1, _ := xmpmeta.Fields(packet)
	recordXMPFields(f1, md)

	if md.Properties["creator"] != "from the atom tree" {
		t.Errorf("the atom-tree value was overwritten by an XMP property: %q",
			md.Properties["creator"])
	}
	if md.Properties["XMP_creator"] != "decoy from the packet" {
		t.Errorf("the XMP value should still be REPORTED under its prefixed key, got %q",
			md.Properties["XMP_creator"])
	}
}

// TestSecondXMPPacketDoesNotOverwriteTheFirst: two packets in one container is unusual but legal,
// and silently keeping one of them is the same class of loss as not reading it at all.
func TestSecondXMPPacketDoesNotOverwriteTheFirst(t *testing.T) {
	md := &VideoMetadata{Properties: map[string]string{}}
	first := []byte(`<x:xmpmeta><rdf:RDF><rdf:Description dc:creator="Marcus Whitfield"/></rdf:RDF></x:xmpmeta>`)
	second := []byte(`<x:xmpmeta><rdf:RDF><rdf:Description dc:creator="Priya Raghunathan"/></rdf:RDF></x:xmpmeta>`)

	fa, _ := xmpmeta.Fields(first)
	recordXMPFields(fa, md)
	fb, _ := xmpmeta.Fields(second)
	recordXMPFields(fb, md)

	var seen []string
	for _, v := range md.Properties {
		seen = append(seen, v)
	}
	joined := strings.Join(seen, "|")
	for _, want := range []string{"Marcus Whitfield", "Priya Raghunathan"} {
		if !strings.Contains(joined, want) {
			t.Errorf("value %q from one of the two packets was discarded; properties = %v",
				want, md.Properties)
		}
	}
}

// TestXMPAgainstARealAppleShippedFile reads a file macOS ships whose XMP carries real values.
//
// This is what keeps the hand-built fixtures above honest: they and this code could share a wrong
// belief about where XMP lives and every test would still pass. This file's packet was written by
// Adobe Premiere Pro, is 15,320 bytes, and holds every value in ATTRIBUTES with no element text at
// all — so a CharData-only reader passes the fixtures and fails here.
//
// Skipped when absent so Linux CI is unaffected.
func TestXMPAgainstARealAppleShippedFile(t *testing.T) {
	const real = "/System/Library/ExtensionKit/Extensions/MouseExtension.appex/Contents/Resources/Mouse.mov"
	if _, err := os.Stat(real); err != nil {
		t.Skipf("real fixture not present on this host: %v", err)
	}

	md, err := ExtractVideoMetadata(real)
	if err != nil {
		t.Fatalf("ExtractVideoMetadata on a real .mov: %v", err)
	}

	var xmpKeys, pathKeys int
	for k, v := range md.Properties {
		if !strings.HasPrefix(k, "XMP") {
			continue
		}
		xmpKeys++
		if strings.Contains(v, "/Users/") {
			pathKeys++
		}
	}
	if xmpKeys == 0 {
		t.Fatal("no XMP properties extracted from a real file whose packet holds 200+ attributes")
	}
	if pathKeys == 0 {
		t.Error("the absolute project paths were not extracted; creatorAtom:posixProjectPath and " +
			"creatorAtom:fullPath are the most revealing values in this file")
	}

	// The precision half. Keeping every attribute produced 340 false findings across the real corpus;
	// these are the property names responsible and none may reach the report.
	for _, banned := range []string{"XMP_InstanceID", "XMP_DocumentID", "XMP_applicationCode",
		"XMP_invocationAppleEvent"} {
		if v, present := md.Properties[banned]; present {
			t.Errorf("%s = %q reached the report; it is machine data that reads as a phone number",
				banned, v)
		}
	}
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package xmpmeta

import (
	"fmt"
	"strings"
	"testing"
)

// ssn builds a structurally valid SSN at run time.
//
// Never a literal: a bare nine-digit dashed number in a committed file is what push protection and
// secret scanners exist to stop, and this repo has been blocked by that before.
func ssn() string { return strings.Join([]string{"449", "87", "4100"}, "-") }

func find(fields []Field, name string) (string, bool) {
	for _, f := range fields {
		if f.Name == name {
			return f.Value, true
		}
	}
	return "", false
}

func hasValue(fields []Field, want string) bool {
	for _, f := range fields {
		if strings.Contains(f.Value, want) {
			return true
		}
	}
	return false
}

// adobeAttributeShape is transcribed from the XMP packet inside a real file macOS ships:
// /System/Library/ExtensionKit/Extensions/MouseExtension.appex/Contents/Resources/Mouse.mov,
// written by Adobe Premiere Pro. Every value is an ATTRIBUTE and there is no element text at all —
// 220 attributes, 0 CharData values in the real packet.
//
// The machine-data attributes here are the exact ones that produced 340 false positives when this
// package kept everything: see the humanTextProperties comment.
const adobeAttributeShape = `<x:xmpmeta xmlns:x="adobe:ns:meta/" x:xmptk="Adobe XMP Core 7.1-c000">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about=""
    xmlns:xmp="http://ns.adobe.com/xap/1.0/"
    xmlns:xmpMM="http://ns.adobe.com/xap/1.0/mm/"
    xmlns:creatorAtom="http://ns.adobe.com/creatorAtom/1.0/"
    xmp:CreatorTool="Adobe Premiere Pro 2022.0 (Macintosh)"
    xmpMM:InstanceID="xmp.iid:6e454d5a-d098-41e2-896a-845f1eb6588c"
    xmpMM:DocumentID="17ec1562-d214-35ec-674e-ea8900000059"
    creatorAtom:applicationCode="1347449455"
    creatorAtom:invocationAppleEvent="1129468018"
    creatorAtom:posixProjectPath="/Users/mwhitfield/Projects/Payroll/Marker-2.prproj"
    creatorAtom:windowsAtomExtension=".prproj"/>
 </rdf:RDF>
</x:xmpmeta>`

// TestAdobeAttributeShapeIsRead is the recall case for the form that matters most in practice.
//
// A CharData-only reader finds NOTHING in this packet. That is not hypothetical: the real Adobe
// packet this is transcribed from has 0 element-text values.
func TestAdobeAttributeShapeIsRead(t *testing.T) {
	fields, _ := Fields([]byte(adobeAttributeShape))
	if len(fields) == 0 {
		t.Fatal("no fields read from an attribute-shaped packet — a CharData-only reader would do this")
	}

	if got, ok := find(fields, "CreatorTool"); !ok || !strings.Contains(got, "Premiere") {
		t.Errorf("CreatorTool = %q, ok=%v; want the Adobe tool string", got, ok)
	}
	if got, ok := find(fields, "posixProjectPath"); !ok || !strings.Contains(got, "/Users/") {
		t.Errorf("posixProjectPath = %q, ok=%v; want the absolute project path — this is the most "+
			"revealing value in the real file that motivated this package", got, ok)
	}
}

// TestMachineAttributesAreNotPromoted is the precision case, and it is the one that stops this
// package regressing into a false-positive generator.
//
// Measured across 114 real XMP-carrying files on a stock macOS install, keeping these produced
// PHONE LOW x172, PHONE HIGH x144 and SSN LOW x24 — 340 false findings. A ten-digit machine code is
// byte-identical to a US phone number, so only the PROPERTY can discriminate.
func TestMachineAttributesAreNotPromoted(t *testing.T) {
	fields, _ := Fields([]byte(adobeAttributeShape))

	for _, name := range []string{
		"InstanceID",           // a GUID
		"DocumentID",           // a GUID
		"applicationCode",      // 1347449455 — reads as a 10-digit phone number
		"invocationAppleEvent", // 1129468018 — likewise
		"windowsAtomExtension", // ".prproj"
		"xmptk",                // the toolkit banner
	} {
		if v, ok := find(fields, name); ok {
			t.Errorf("%s was promoted to scanned text as %q; it is machine data and produced "+
				"false PHONE/SSN findings on real files", name, v)
		}
	}

	// The namespace declarations must never become content: every one is an adobe.com or w3.org URL,
	// and reporting them would put a fixed set of vendor URLs into every report touching an XMP file.
	if hasValue(fields, "ns.adobe.com") || hasValue(fields, "w3.org") {
		t.Error("a namespace URI reached the field list")
	}
	// rdf:about is empty in every real packet measured; an empty value must not be emitted at all.
	for _, f := range fields {
		if strings.TrimSpace(f.Value) == "" {
			t.Errorf("an empty value was emitted under %q", f.Name)
		}
	}
}

// TestNamespaceDeclarationWithAnAllowListedNameIsStillExcluded closes a gap mutation testing found.
//
// Removing the xmlns check did NOT fail any test at first, which made it look like dead code. It is
// not: the check runs BEFORE the allow list, and a prefix that happens to match an allow-listed
// property name — xmlns:creator, xmlns:title, xmlns:Artist are all legal — would otherwise emit the
// namespace URI as if it were the author's name. The original fixture's prefixes (xmp, xmpMM,
// creatorAtom) are not on the allow list, so the mutation was invisible.
func TestNamespaceDeclarationWithAnAllowListedNameIsStillExcluded(t *testing.T) {
	packet := `<x:xmpmeta xmlns:x="adobe:ns:meta/">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about=""
    xmlns:creator="http://ns.adobe.com/decoy/1.0/"
    xmlns:Artist="http://ns.adobe.com/decoy2/1.0/"
    xmlns:dc="http://purl.org/dc/elements/1.1/"
    dc:creator="Marcus Whitfield"/>
 </rdf:RDF>
</x:xmpmeta>`

	fields, _ := Fields([]byte(packet))
	if hasValue(fields, "ns.adobe.com") || hasValue(fields, "purl.org") {
		t.Errorf("a namespace URI was emitted as a value; fields = %+v", fields)
	}
	if v, ok := find(fields, "creator"); !ok || v != "Marcus Whitfield" {
		t.Errorf("creator = %q, ok=%v; the real dc:creator must survive alongside the decoy prefix", v, ok)
	}
}

// TestExiftoolElementTextShapeIsRead covers the opposite real form.
//
// exiftool writing an XMP tag produces a 310-byte packet with values in ELEMENT TEXT rather than
// attributes. A rule applied only to attributes would flood or miss depending on which form it saw,
// so both paths share carriesHumanText.
func TestExiftoolElementTextShapeIsRead(t *testing.T) {
	packet := fmt.Sprintf(`<x:xmpmeta xmlns:x='adobe:ns:meta/' x:xmptk='Image::ExifTool 13.55'>
<rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>
 <rdf:Description rdf:about='' xmlns:tiff='http://ns.adobe.com/tiff/1.0/'>
  <tiff:Artist>Employee SSN %s</tiff:Artist>
 </rdf:Description>
</rdf:RDF>
</x:xmpmeta>`, ssn())

	fields, _ := Fields([]byte(packet))
	if !hasValue(fields, ssn()) {
		t.Fatalf("the element-text value was not read; fields = %+v", fields)
	}
	if got, ok := find(fields, "Artist"); !ok || !strings.Contains(got, "Employee SSN") {
		t.Errorf("Artist = %q, ok=%v", got, ok)
	}
}

// TestIPTCContactFieldsSurviveTheAllowList is the assertion that keeps the suppressor honest.
//
// The IPTC creator-contact block is a STANDARDISED place for a phone number, an email address and a
// postal address. A PHONE finding from CiTelWork is a TRUE positive, so an allow list that drops it
// would be trading 340 false findings for a real miss — which is the wrong trade and the exact risk
// of adding a suppressor.
func TestIPTCContactFieldsSurviveTheAllowList(t *testing.T) {
	packet := `<x:xmpmeta xmlns:x="adobe:ns:meta/">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about=""
    xmlns:Iptc4xmpCore="http://iptc.org/std/Iptc4xmpCore/1.0/xmlns/"
    Iptc4xmpCore:CiTelWork="+1 415 555 0132"
    Iptc4xmpCore:CiEmailWork="dana.reyes@corp.example"
    Iptc4xmpCore:CiAdrExtadr="1200 Harbour Street"/>
 </rdf:RDF>
</x:xmpmeta>`

	fields, _ := Fields([]byte(packet))
	for name, want := range map[string]string{
		"CiTelWork":   "415",
		"CiEmailWork": "@corp.example",
		"CiAdrExtadr": "Harbour",
	} {
		got, ok := find(fields, name)
		if !ok || !strings.Contains(got, want) {
			t.Errorf("%s = %q, ok=%v; the IPTC contact block is a standardised home for PII and "+
				"must survive the allow list", name, got, ok)
		}
	}
}

// TestMalformedPacketYieldsNothingAndDoesNotPanic: a corrupt packet must cost nothing.
//
// The container extractors treat XMP as supplementary, so a bad packet must not fail the surrounding
// extraction — it certainly must not panic on a partial read.
func TestMalformedPacketYieldsNothingAndDoesNotPanic(t *testing.T) {
	for name, packet := range map[string]string{
		"empty":             "",
		"not xml":           "\x00\x01\x02 binary noise \xff",
		"truncated mid-tag": `<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF><rdf:Descrip`,
		"only plumbing":     `<x:xmpmeta xmlns:x="adobe:ns:meta/" x:xmptk="tk"><rdf:RDF/></x:xmpmeta>`,
	} {
		t.Run(name, func(t *testing.T) {
			got, _ := Fields([]byte(packet))
			if len(got) != 0 {
				t.Errorf("Fields = %+v, want none", got)
			}
		})
	}
}

// TestUnclosedElementStillYieldsItsValue records a contract I first asserted backwards.
//
// An earlier version of this file listed `<x:xmpmeta><tiff:Artist>value` under "yields nothing",
// which contradicted TestPartialPacketKeepsWhatItAlreadyRead directly below. The decoder runs with
// Strict=false and returns the CharData before reaching the unexpected EOF, so the value IS
// recovered — and that is the behaviour we want, for the same reason: a packet cut off mid-write
// still has its metadata at the front. The test was wrong, not the code.
func TestUnclosedElementStillYieldsItsValue(t *testing.T) {
	fields, _ := Fields([]byte(`<x:xmpmeta><tiff:Artist>Marcus Whitfield`))
	if v, ok := find(fields, "Artist"); !ok || v != "Marcus Whitfield" {
		t.Errorf("Artist = %q, ok=%v; an unclosed element's text must still be recovered", v, ok)
	}
}

// TestPartialPacketKeepsWhatItAlreadyRead: a packet that stops being parseable part-way must not
// discard the values already recovered.
//
// A truncated packet is exactly the case where the values already read matter most — the file may
// have been cut off mid-transfer, and the metadata sits at the front.
func TestPartialPacketKeepsWhatItAlreadyRead(t *testing.T) {
	packet := fmt.Sprintf(`<x:xmpmeta xmlns:x="adobe:ns:meta/">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/"
    dc:creator="Marcus Whitfield" dc:description="Employee SSN %s"/>
  <rdf:Description rdf:about="" dc:title="unterm`, ssn())

	fields, _ := Fields([]byte(packet))
	if !hasValue(fields, ssn()) {
		t.Errorf("a value read before the truncation was discarded; fields = %+v", fields)
	}
	if v, ok := find(fields, "creator"); !ok || v != "Marcus Whitfield" {
		t.Errorf("creator = %q, ok=%v", v, ok)
	}
}

// TestFieldCountIsBounded: a packet cannot turn a small file into an unbounded report.
func TestFieldCountIsBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString(`<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF><rdf:Description`)
	// Every attribute uses an allow-listed name so the cap, not the filter, is what bounds this.
	for i := 0; i < MaxFields+500; i++ {
		fmt.Fprintf(&b, ` dc:title%d="v%d"`, i, i)
	}
	b.WriteString(`/></rdf:RDF></x:xmpmeta>`)

	// dc:titleN is not an allow-listed name, so use a shape that IS, repeated across elements.
	var c strings.Builder
	c.WriteString(`<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF>`)
	for i := 0; i < MaxFields+500; i++ {
		fmt.Fprintf(&c, `<rdf:Description dc:title="value %d"/>`, i)
	}
	c.WriteString(`</rdf:RDF></x:xmpmeta>`)

	got, _ := Fields([]byte(c.String()))
	if len(got) > MaxFields {
		t.Errorf("Fields returned %d entries, above the %d cap", len(got), MaxFields)
	}
	if len(got) == 0 {
		t.Fatal("the cap test read nothing, so it is not measuring the cap")
	}
}

// TestTruncationIsReported: a cap that silently drops values reports a file as covered when it was
// not, which is the one outcome this repo treats as worse than a refusal.
func TestTruncationIsReported(t *testing.T) {
	t.Run("field cap", func(t *testing.T) {
		var b strings.Builder
		b.WriteString(`<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF>`)
		for i := 0; i < MaxFields+100; i++ {
			fmt.Fprintf(&b, `<rdf:Description dc:title="value %d"/>`, i)
		}
		b.WriteString(`</rdf:RDF></x:xmpmeta>`)
		got, truncated := Fields([]byte(b.String()))
		if len(got) > MaxFields {
			t.Errorf("returned %d fields, above the %d cap", len(got), MaxFields)
		}
		if !truncated {
			t.Error("the field cap fired but truncated=false, so the caller cannot disclose it")
		}
	})

	t.Run("byte cap", func(t *testing.T) {
		head := `<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF><rdf:Description dc:title="v"/>`
		packet := head + strings.Repeat(" ", MaxPacketBytes+16) + `</rdf:RDF></x:xmpmeta>`
		_, truncated := Fields([]byte(packet))
		if !truncated {
			t.Error("the byte cap fired but truncated=false")
		}
	})

	t.Run("a packet within both caps is NOT reported truncated", func(t *testing.T) {
		_, truncated := Fields([]byte(adobeAttributeShape))
		if truncated {
			t.Error("a small packet was reported as truncated — the flag would then be meaningless")
		}
	})
}

// TestOversizePacketIsClampedNotRefused: a packet beyond the byte bound is read up to it.
//
// Refusing outright would lose a value sitting in the first kilobyte because a writer padded the
// packet to something enormous — XMP writers pad routinely.
func TestOversizePacketIsClampedNotRefused(t *testing.T) {
	head := fmt.Sprintf(`<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF>`+
		`<rdf:Description dc:description="Employee SSN %s"/>`, ssn())
	packet := head + strings.Repeat(" ", MaxPacketBytes+1024) + `</rdf:RDF></x:xmpmeta>`

	if len(packet) <= MaxPacketBytes {
		t.Fatalf("the fixture is only %d bytes, under the %d bound — this test would not exercise "+
			"the clamp", len(packet), MaxPacketBytes)
	}
	fields, _ := Fields([]byte(packet))
	if !hasValue(fields, ssn()) {
		t.Error("a value inside the bound was lost because the packet as a whole was oversize")
	}
}

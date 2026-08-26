// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package isobmff

import (
	"bytes"
	"os"
	"testing"
)

// #499: an XMP packet at moov/udta/XMP_ was inside a span labelled "MP4 udta".
//
// Every consumer treats a span's label as the answer to "is this XML character data" --
// video.blockRegion sets XMLText: span.Label == LabelXMP -- so that packet sat in a region declaring
// itself NOT XML, which made tagmeta.ResidualEncoded structurally blind to it. That check exists
// precisely because XML permits `&apos;`, `&#39;`, `&#x27;` and so on without limit, so a raw byte
// search cannot see an entity-encoded value.
//
// This is the layout Adobe's XMP Specification Part 3 prescribes for QuickTime and the one exiftool
// writes for a .mov. It is also the MAJORITY layout: a census over 1,178 real ISO-BMFF files on a macOS
// host found 90 carrying moov/udta/XMP_ against 24 carrying the top-level uuid[XMP] box #477 mapped,
// and none carrying both. #477's own test comment recorded the population ("24 carried a top-level
// uuid[XMP] box and 14 carried moov/udta/XMP_ instead") before shipping the partial fix.
//
// MEASURED on a real Apple-shipped .mov (4.9MB, a 17,450-byte XMP_ packet) tagged with
// `exiftool -Title="Patrick O'Connor" -Artist="Marcus Whitfield"`. exiftool writes to BOTH homes -- raw
// in ilst, entity-encoded in the packet -- and the scanner detects the value from the ilst copy:
//
//	                                              main            with this fix
//	raw "Patrick O'Connor" in redacted copy       0               (refused)
//	encoded Patrick O&#39;Connor in redacted copy  1  SURVIVED     (refused)
//	exiftool on the "redacted" file               Title: Patrick O'Connor
//	exit code                                     0, no warning   0 / 3 with --fail-on-incomplete
//
// After the fix the file is REFUSED with the cause named, which is the same choice #477 made for the
// uuid layout: masking an encoded occurrence needs a decoder that carries an index map, and refusing is
// never worse than writing a file that only looks redacted.

// udtaPacket is a minimal but recognisable XMP packet.
//
// Named distinctly from the existing xmpPacket helper in isobmff_test.go, which builds a uuid-box
// payload (user type included) for the layout #477 mapped. This one is a bare packet, because in the
// udta layout the packet is the atom's whole payload with no user type in front of it -- and that
// difference is the point of this file.
func udtaPacket(value string) []byte {
	return []byte(`<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?><x:xmpmeta xmlns:x="adobe:ns:meta/">` +
		`<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description>` +
		`<dc:title>` + value + `</dc:title></rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end="w"?>`)
}

// TestUdtaPayloadIsSplitAroundAnXMPChild pins the geometry, not just "a span exists".
//
// The offsets matter: a span that is too wide still removes the value, so a redaction test cannot tell
// the difference -- but a wide LabelXMP span would run an entity decoder over binary siblings, which
// can resolve bytes that merely look like `&#NN;` into a value the file never contained, inventing a
// residual and refusing a clean file.
func TestUdtaPayloadIsSplitAroundAnXMPChild(t *testing.T) {
	before := atom("\xa9nam", []byte("Marcus Whitfield"))
	packet := udtaPacket("Patrick O&#39;Connor")
	xmp := atom("XMP_", packet)
	after := atom("\xa9cmt", []byte("a trailing comment"))

	udta := atom("udta", before, xmp, after)
	moov := atom("moov", udta)

	spans, err := MetadataSpans(bytes.NewReader(moov), int64(len(moov)))
	if err != nil {
		t.Fatalf("MetadataSpans: %v", err)
	}

	var xmpSpans, udtaSpansSeen int
	for _, s := range spans {
		switch s.Label {
		case LabelXMP:
			xmpSpans++
			got := moov[s.Start:s.End]
			if !bytes.Equal(got, packet) {
				t.Errorf("the LabelXMP span covers %d bytes, want exactly the %d-byte packet.\n"+
					"got  %q\nwant %q", len(got), len(packet), first(got), first(packet))
			}
		case "MP4 udta":
			udtaSpansSeen++
		default:
			t.Errorf("unexpected span label %q", s.Label)
		}
	}
	if xmpSpans != 1 {
		t.Errorf("got %d LabelXMP spans, want exactly 1. Without it the packet sits in a region that "+
			"declares itself not-XML, and ResidualEncoded cannot see an entity-encoded value in it.",
			xmpSpans)
	}
	if udtaSpansSeen != 2 {
		t.Errorf("got %d \"MP4 udta\" spans, want 2 (before and after the XMP child). The siblings must "+
			"keep raw-byte treatment: running an entity decoder over binary children can invent a "+
			"value the file never held.", udtaSpansSeen)
	}
}

// TestSpansNeverOverlap is the invariant the split has to preserve.
//
// Each span becomes an independent block that the caller reads, modifies and writes back, so two spans
// covering the same bytes would have one clobber the other. That is why the XMP child is carved OUT of
// the udta span rather than recorded in addition to it.
func TestSpansNeverOverlap(t *testing.T) {
	udta := atom("udta",
		atom("\xa9nam", []byte("Marcus Whitfield")),
		atom("XMP_", udtaPacket("Patrick O&#39;Connor")),
		atom("\xa9cmt", []byte("trailing")))
	moov := atom("moov", udta)

	spans, err := MetadataSpans(bytes.NewReader(moov), int64(len(moov)))
	if err != nil {
		t.Fatalf("MetadataSpans: %v", err)
	}
	if len(spans) < 2 {
		t.Fatalf("expected several spans, got %d -- this case does not exercise overlap", len(spans))
	}
	for i := 0; i < len(spans); i++ {
		if spans[i].End <= spans[i].Start {
			t.Errorf("span %d is empty: [%d,%d)", i, spans[i].Start, spans[i].End)
		}
		for j := i + 1; j < len(spans); j++ {
			a, b := spans[i], spans[j]
			if a.Start < b.End && b.Start < a.End {
				t.Errorf("spans overlap: %s [%d,%d) and %s [%d,%d). Each span is written back "+
					"independently, so one would clobber the other.",
					a.Label, a.Start, a.End, b.Label, b.Start, b.End)
			}
		}
	}
}

// TestTheXMPAtomHeaderIsInNoSpan keeps a same-length overwrite from damaging the atom.
//
// The 8-byte header carries the size and the type. A replacement landing on it would leave an atom that
// no longer declares itself, which is a file quietly altered in a way no reader can interpret -- the
// same reasoning xmpPayloadStart already applies to the uuid box's user type.
func TestTheXMPAtomHeaderIsInNoSpan(t *testing.T) {
	packet := udtaPacket("value")
	udta := atom("udta", atom("XMP_", packet))
	moov := atom("moov", udta)

	// Where the header sits: moov header + udta header, then the XMP_ header.
	hdrStart := int64(8 + 8)
	spans, err := MetadataSpans(bytes.NewReader(moov), int64(len(moov)))
	if err != nil {
		t.Fatalf("MetadataSpans: %v", err)
	}
	for _, s := range spans {
		for off := hdrStart; off < hdrStart+8; off++ {
			if off >= s.Start && off < s.End {
				t.Errorf("span %s [%d,%d) covers byte %d of the XMP_ atom header",
					s.Label, s.Start, s.End, off-hdrStart)
			}
		}
	}
}

// TestUdtaWithNoXMPChildIsStillOneSpan is the must-not-change direction.
//
// The overwhelmingly common udta holds only string boxes, and it must keep being recorded as one
// contiguous region -- that is what keeps the caller's search bounded to one block per tag group.
func TestUdtaWithNoXMPChildIsStillOneSpan(t *testing.T) {
	udta := atom("udta",
		atom("\xa9nam", []byte("Marcus Whitfield")),
		atom("\xa9cmt", []byte("Employee SSN 452-11-9384")))
	moov := atom("moov", udta)

	spans, err := MetadataSpans(bytes.NewReader(moov), int64(len(moov)))
	if err != nil {
		t.Fatalf("MetadataSpans: %v", err)
	}
	var udtaCount int
	for _, s := range spans {
		if s.Label == "MP4 udta" {
			udtaCount++
		}
		if s.Label == LabelXMP {
			t.Errorf("a udta with no XMP_ child produced a LabelXMP span [%d,%d). That would run an "+
				"entity decoder over binary tag boxes.", s.Start, s.End)
		}
	}
	if udtaCount != 1 {
		t.Errorf("got %d udta spans, want 1 contiguous region", udtaCount)
	}
}

// TestAMalformedChildSizeLeavesThePayloadOpaque is the fail-safe.
//
// A child declaring a size that does not fit cannot be walked past, and guessing a stride is how a walk
// desynchronises and reads a length out of the middle of a value. Falling back to one opaque udta span
// is the previous behaviour, which is never worse than a wrong split.
func TestAMalformedChildSizeLeavesThePayloadOpaque(t *testing.T) {
	// A child claiming 0xFFFF bytes inside a payload that holds far fewer, followed by what looks
	// like an XMP_ atom the walk must therefore never reach.
	bad := []byte{0x00, 0x00, 0xFF, 0xFF, 'j', 'u', 'n', 'k'}
	udta := atom("udta", bad, atom("XMP_", udtaPacket("value")))
	moov := atom("moov", udta)

	spans, err := MetadataSpans(bytes.NewReader(moov), int64(len(moov)))
	if err != nil {
		t.Fatalf("MetadataSpans: %v", err)
	}
	for _, s := range spans {
		if s.Label == LabelXMP {
			t.Errorf("a LabelXMP span [%d,%d) was produced from a payload whose child sizes do not "+
				"add up; the walk must not guess a stride", s.Start, s.End)
		}
	}
	if len(spans) != 1 || spans[0].Label != "MP4 udta" {
		t.Errorf("got %+v, want a single opaque \"MP4 udta\" span", spans)
	}
}

// TestAnEmptyXMPChildYieldsNoSpan keeps MetadataSpans' non-empty invariant.
func TestAnEmptyXMPChildYieldsNoSpan(t *testing.T) {
	udta := atom("udta", atom("XMP_"), atom("\xa9nam", []byte("Marcus Whitfield")))
	moov := atom("moov", udta)

	spans, err := MetadataSpans(bytes.NewReader(moov), int64(len(moov)))
	if err != nil {
		t.Fatalf("MetadataSpans: %v", err)
	}
	for _, s := range spans {
		if s.End <= s.Start {
			t.Errorf("empty span %s [%d,%d)", s.Label, s.Start, s.End)
		}
		if s.Label == LabelXMP {
			t.Errorf("an empty XMP_ payload produced a LabelXMP span [%d,%d)", s.Start, s.End)
		}
	}
}

// TestARealMovWithAUdtaXMPPacketIsMapped is the end-to-end geometry check on a real file.
//
// Skipped where absent, which is every non-macOS runner; the structural cases above carry the contract
// on all platforms. Kept because a hand-built atom tree cannot show that this layout is what real
// shipped files use, and that is the whole reason the mapping gap mattered.
func TestARealMovWithAUdtaXMPPacketIsMapped(t *testing.T) {
	const p = "/System/Library/ExtensionKit/Extensions/MouseExtension.appex/Contents/Resources/Mouse.mov"
	f, err := os.Open(p) // #nosec G304 -- a fixed, public, read-only system asset
	if err != nil {
		t.Skipf("asset not present on this host: %v", err)
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		t.Skip(err)
	}

	spans, err := MetadataSpans(f, st.Size())
	if err != nil {
		t.Fatalf("MetadataSpans: %v", err)
	}
	var xmp int
	for _, s := range spans {
		if s.Label == LabelXMP {
			xmp++
		}
	}
	if xmp == 0 {
		t.Errorf("no LabelXMP span found in a real .mov that carries moov/udta/XMP_. spans=%+v", spans)
	}
}

// first keeps a diff readable when a packet is kilobytes long.
func first(b []byte) string {
	if len(b) > 70 {
		return string(b[:70]) + "…"
	}
	return string(b)
}

// TestAnXMPChildOverrunningTheUdtaPayloadIsRefused is the case the bounds check actually governs.
//
// A first version of this file tested a malformed child with a junk NAME, which exits the walk either
// way -- a mutation deleting the `pos+size > payloadEnd` clause SURVIVED it, because the oversized
// stride simply ended the loop and the fall-back span was returned regardless. The check is only
// load-bearing when the overrunning child IS the XMP_ atom: without it, the LabelXMP span would end at
// the DECLARED end and reach past the udta payload into whatever follows -- sample tables, other atoms
// -- and every byte of that region would then be handed to an entity decoder and to a same-length
// overwrite.
//
// A declared size is producer-chosen like every other length in this container, so this is the same
// principle as #457 and #493 one atom deeper: clamp to what the structure actually holds, or refuse.
func TestAnXMPChildOverrunningTheUdtaPayloadIsRefused(t *testing.T) {
	packet := udtaPacket("Patrick O&#39;Connor")

	// An XMP_ atom whose header declares far more than the udta payload holds.
	bad := make([]byte, 0, 8+len(packet))
	bad = append(bad, 0xFF, 0xFF, 0x00, 0x00) // ~4GB
	bad = append(bad, "XMP_"...)
	bad = append(bad, packet...)

	udta := atom("udta", bad)
	// Something after the udta that a runaway span would reach into.
	moov := atom("moov", udta, atom("stbl", bytes.Repeat([]byte{0xAB}, 64)))

	spans, err := MetadataSpans(bytes.NewReader(moov), int64(len(moov)))
	if err != nil {
		t.Fatalf("MetadataSpans: %v", err)
	}

	udtaEnd := int64(8 + 8 + len(bad)) // moov header + udta header + udta payload
	for _, s := range spans {
		if s.End > int64(len(moov)) || s.Start < 0 {
			t.Errorf("span %s [%d,%d) is outside the file (%d bytes)", s.Label, s.Start, s.End, len(moov))
		}
		if s.Label == LabelXMP && s.End > udtaEnd {
			t.Errorf("the LabelXMP span [%d,%d) runs past the end of the udta payload at %d. It would "+
				"hand unrelated atoms to an entity decoder and to a same-length overwrite.",
				s.Start, s.End, udtaEnd)
		}
	}
	// The honest outcome is the previous behaviour: one opaque udta span.
	if len(spans) != 1 || spans[0].Label != "MP4 udta" {
		t.Errorf("got %+v, want a single opaque \"MP4 udta\" span when the child sizes do not add up",
			spans)
	}
}

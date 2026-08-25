// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package xmlref

import (
	"strings"
	"testing"
)

// These tests moved here with the decoder, from internal/redactors/tagmeta.
//
// The decoder was written for one caller — the pre-write gate for an XMP packet in a media
// container — and then a second caller needed exactly the same answer: the Office embedded-part
// admission gate was judging a part clean because the reported value was spelled with a numeric
// character reference (#475). Both callers are deciding "is this value PRESENT", and two copies of
// that decision is how the two halves drift apart, with drift meaning one of them certifies a
// leak as clean.
//
// The original failure the decoder exists to prevent, measured on a real .m4a tagged with exiftool:
//
//	card 4532-0151-1283-0366   present RAW twice: the ilst copy and the XMP packet
//	Patrick O'Connor           present RAW once (ilst), and as `Patrick O&#39;Connor` in the packet
//
// Before the XMP packet was mapped as a region, the card's raw copy inside it made the residue check
// refuse the whole file — which INCIDENTALLY also protected the apostrophe value. Mapping the packet
// removed the card's copy, the refusal went away, and the file was written with
// `Patrick O&#39;Connor` still in it: exit 0, no warning, and exiftool read
// `[XMP-dc] Title : Patrick O'Connor` straight out of the "redacted" file.

func TestDecodeResolvesEverySpellingOfOneCharacter(t *testing.T) {
	// XML permits a character reference for any character, in decimal or hex, with arbitrary
	// leading zeros. All five of these are an apostrophe, and a writer picks one: exiftool
	// writes &#39;, which the named-entity list does not even contain.
	for _, spelling := range []string{
		"Patrick O&apos;Connor",
		"Patrick O&#39;Connor",
		"Patrick O&#x27;Connor",
		"Patrick O&#039;Connor",
		"Patrick O&#x0027;Connor",
	} {
		t.Run(spelling, func(t *testing.T) {
			got := string(Decode([]byte(spelling)))
			if got != "Patrick O'Connor" {
				t.Errorf("decoded %q, want %q. Every spelling has to collapse to the form the "+
					"finding was reported in, or the gate is blind to whichever one the writer chose.",
					got, "Patrick O'Connor")
			}
		})
	}
}

// TestDecodeHandlesAReferencePerCharacter is the shape #475 turns up in practice.
//
// The value is not respelled once; each character can carry its own reference, and a real writer
// (or an attacker) may respell only the last digit. Enumerating spellings is combinatorial, which
// is the argument for decoding.
func TestDecodeHandlesAReferencePerCharacter(t *testing.T) {
	for _, spelling := range []string{
		"449-87-410&#48;",            // only the final 0, the case measured in #475
		"&#52;49-87-4100",            // only the first digit
		"449&#45;87&#45;4100",        // both separators
		"&#x34;&#x34;&#x39;-87-4100", // hex, several characters
		"&#052;&#052;&#057;-87-4100", // decimal with leading zeros
	} {
		t.Run(spelling, func(t *testing.T) {
			if got := string(Decode([]byte(spelling))); got != "449-87-4100" {
				t.Errorf("decoded %q, want %q", got, "449-87-4100")
			}
		})
	}
}

// TestDecodeIsXMLNotHTML is why this is not html.UnescapeString.
//
// That function resolves the whole HTML named-entity table, so content holding the literal text
// `&sect;` would decode to a section sign. Inventing a character the XML never contained makes a
// gate refuse a clean file, and the honest scope is what XML 1.0 actually defines.
func TestDecodeIsXMLNotHTML(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"a &amp; b", "a & b"},
		{"&lt;tag&gt;", "<tag>"},
		{"say &quot;hi&quot;", `say "hi"`},
		// Not XML entities: left byte-for-byte alone.
		{"90&deg; turn", "90&deg; turn"},
		{"§ &sect; sign", "§ &sect; sign"},
		{"&nbsp;gap", "&nbsp;gap"},
		// Degenerate references that must not be resolved or panic.
		{"a & b", "a & b"},
		{"unterminated &#39 here", "unterminated &#39 here"},
		{"&;", "&;"},
		{"&#;", "&#;"},
		{"&#xZZ;", "&#xZZ;"},
		{"&#999999999999;", "&#999999999999;"},
		{"&#1114112;", "&#1114112;"}, // one past the last valid code point
	} {
		t.Run(tc.in, func(t *testing.T) {
			if got := string(Decode([]byte(tc.in))); got != tc.want {
				t.Errorf("Decode(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestDecodeLeavesNonEntityBytesUntouched guards the fast path.
//
// This now runs over ARBITRARY EMBEDDED BYTES, not only an XMP packet: the Office gate hands it OLE
// streams, JPEGs and zip members. It must not corrupt bytes it does not understand.
func TestDecodeLeavesNonEntityBytesUntouched(t *testing.T) {
	raw := []byte{0x00, 0xFF, 0x89, 'P', 'N', 'G', 0x0D, 0x0A}
	if got := Decode(raw); string(got) != string(raw) {
		t.Errorf("bytes with no reference were altered: %v -> %v", raw, got)
	}
}

// TestDecodeDoesNotCopyWhenThereIsNoAmpersand pins the documented cost contract.
//
// The Office admission gate calls this on every embedded part, including large binary ones. If the
// no-ampersand path allocated, the gate would pay a full copy of every part in every container --
// and a memory regression there is exactly the shape this repo has shipped before. Asserted by
// identity of the backing array, which is timing-free.
func TestDecodeDoesNotCopyWhenThereIsNoAmpersand(t *testing.T) {
	src := []byte("no references anywhere in these bytes")
	got := Decode(src)
	if len(got) != len(src) || (len(src) > 0 && &got[0] != &src[0]) {
		t.Error("Decode allocated a copy for input with no '&'. The Office gate calls this on " +
			"every embedded part, so the fast path is a memory contract, not an optimisation.")
	}
}

// TestLongLeadingZeroReferenceIsStillDecoded pins the reason the reference scan is not a fixed-width
// window, and it replaces a test that had no teeth.
//
// A first version capped the scan at 12 bytes to bound the work. A mutation removing that cap
// SURVIVED the suite, which was the tell: the only test covering it asserted termination, and
// termination is not the property at risk. The property at risk is the opposite one — a cap makes a
// long-but-legal reference undecodable, and a reference this cannot decode is a value the caller
// cannot see, so the file is written with the value in it. That is a leak introduced to avoid a
// slowdown.
//
// Both of these are a valid apostrophe per XML 1.0, and both must decode.
func TestLongLeadingZeroReferenceIsStillDecoded(t *testing.T) {
	for _, spelling := range []string{
		"Patrick O&#00000000039;Connor",
		"Patrick O&#x00000000027;Connor",
	} {
		t.Run(spelling, func(t *testing.T) {
			if got := string(Decode([]byte(spelling))); got != "Patrick O'Connor" {
				t.Errorf("decoded %q, want %q — a bounded-width reference scan would leave this "+
					"encoded and the value would pass the gate unseen", got, "Patrick O'Connor")
			}
		})
	}
}

// TestBareAmpersandRunTerminates is the work bound, asserted by SHAPE rather than by a clock.
//
// Input here is attacker-supplied and may be a long run of ampersands with no terminator. The
// forward scan stops at the first byte that cannot appear in a reference, so each ampersand costs
// one comparison; a search to the end of the buffer per ampersand would be quadratic. There is no
// timing assertion on purpose — a wall-clock bound is flaky on shared CI — so what this pins is
// that the run is passed through UNCHANGED, which is what a correct scan does.
func TestBareAmpersandRunTerminates(t *testing.T) {
	run := strings.Repeat("&", 200000)
	if got := Decode([]byte(run)); string(got) != run {
		t.Errorf("a run of %d bare ampersands was altered (len %d -> %d)", len(run), len(run), len(got))
	}
}

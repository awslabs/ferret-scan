// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tagmeta

import (
	"bytes"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/xmlref"
)

// The raw-byte search everything else in this package performs is BLIND inside XML.
//
// A value stored in XML character data may be ENTITY-ENCODED, in which case the bytes that were
// reported are simply not present. Measured on a real .m4a given two tags with exiftool:
//
//	card 4532-0151-1283-0366   present RAW twice: the ilst copy and the XMP packet
//	Patrick O'Connor           present RAW once (ilst), and as `Patrick O&#39;Connor` in the packet
//
// Both were reported (VISA 100, PERSON_NAME 91). Before the XMP packet was mapped as a region at
// all, the card's raw copy in the packet made ResidualAnywhere refuse the whole file — which
// INCIDENTALLY also protected the apostrophe value. Mapping the packet removed the card's copy, the
// refusal went away, and the file was written with `Patrick O&#39;Connor` still in it at exit 0 with
// no warning. exiftool read `[XMP-dc] Title : Patrick O'Connor` straight out of the "redacted" file.
//
// So closing one leak re-opened a smaller one behind it. That is the shape this file exists to
// prevent: the write gate must see a value in every spelling the file may hold it in, and XML has
// unboundedly many spellings for one character.
//
// # Why decoding and not a list of encoded spellings
//
// The obvious fix is to widen the search set with the escaped forms — that is what
// embedded.XMLEscapeVariants does on the Office path. It cannot work here. XML permits a character
// reference for ANY character, in decimal or hex, with arbitrary leading zeros: an apostrophe is
// `&apos;`, `&#39;`, `&#x27;`, `&#039;`, `&#x0027;` and so on without limit. exiftool happens to
// write `&#39;`, which the five named-entity substitutions do not produce at all. Enumeration is
// therefore not a narrower fix, it is a wrong one.
//
// Decoding is bounded and exact: it collapses every spelling to the one form the finding was
// reported in.

// The decoder itself lives in internal/xmlref, a stdlib-only leaf.
//
// It moved there when the Office embedded-part admission gate turned out to need exactly the
// same answer (#475): that gate was skipping a part whose reported value was spelled with a
// numeric character reference, judging it clean and leaving the value recoverable at exit 0.
// Two copies of a codec that decides whether a value is PRESENT is how the two halves drift
// apart, and drift here means one of them certifies a leak as clean.
// ResidualEncoded counts reported values that survive inside an XML region in ENTITY-ENCODED form.
//
// This is the companion to ResidualAnywhere, not a replacement: that one catches a value present as
// the bytes that were reported, anywhere in the file, and is the check that must stay. This one
// catches the case it structurally cannot see — a value the file spells differently from the way it
// was reported.
//
// A caller must treat a non-zero result as a REFUSAL to write. It deliberately does not attempt to
// locate the bytes for an overwrite: decoding does not preserve offsets, so redacting the encoded
// occurrence needs a decoder that carries an index map, which is a larger change. Refusing is the
// honest interim, and it is never worse than the behaviour this replaced — before the XMP packet was
// mapped, a file in this situation was refused too, just for a different reason.
//
// Only regions marked XMLText are examined. A binary region cannot hold an entity reference, and
// decoding one would invent values out of bytes that merely look like `&#NN;`.
func ResidualEncoded(buf []byte, regions []Region, matches []detector.Match) int {
	residual := 0
	for _, m := range matches {
		if m.Text == "" {
			continue
		}
		needle := []byte(m.Text)
		for _, rg := range regions {
			if !rg.XMLText {
				continue
			}
			if rg.Start < 0 || rg.End > len(buf) || rg.Start >= rg.End {
				continue
			}
			decoded := xmlref.Decode(buf[rg.Start:rg.End])
			// A raw hit is ResidualAnywhere's job and is already counted there. Counting it
			// again would double-report the same byte and inflate the number in the refusal
			// message, which an operator reads as two distinct survivals.
			if bytes.Contains(decoded, needle) && !bytes.Contains(buf[rg.Start:rg.End], needle) {
				residual++
				break
			}
		}
	}
	return residual
}

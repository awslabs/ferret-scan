// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package tagmeta

import (
	"bytes"
	"strconv"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
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

// decodeXMLEntities returns src with XML character and entity references resolved.
//
// Deliberately NOT html.UnescapeString: that resolves the whole HTML named-entity table, so a
// packet containing the literal text `&sect;` would decode to `§` and could make a value appear
// that the XML never contained. This resolves exactly what XML 1.0 defines — the five predefined
// entities plus numeric character references — and leaves anything else byte-for-byte alone.
//
// The result is for SEARCHING only. Offsets do not survive the transformation, so a caller must not
// use a hit's position here to plan an overwrite; see ResidualEncoded's contract.
func decodeXMLEntities(src []byte) []byte {
	// Nothing to do, and by far the common case: no ampersand means no reference.
	if !bytes.ContainsRune(src, '&') {
		return src
	}

	out := make([]byte, 0, len(src))
	for i := 0; i < len(src); {
		if src[i] != '&' {
			out = append(out, src[i])
			i++
			continue
		}

		// Scan forward over the bytes a reference body may contain, stopping at the terminator or
		// at the first byte that cannot be part of one.
		//
		// Not a fixed-width window. A byte cap would be simpler and would silently FAIL TO DECODE a
		// long-but-legal reference — `&#00000000039;` is a valid apostrophe — and a reference this
		// gate does not decode is a value it does not see, which is the leak it exists to stop. The
		// scan is linear anyway: every byte is examined at most twice, because a run that does not
		// terminate in ';' ends at a byte that cannot appear in a reference, and `&&&&...` therefore
		// costs one comparison per ampersand rather than a search to the end of the buffer.
		j := i + 1
		for j < len(src) && isReferenceByte(src[j]) {
			j++
		}
		if j < len(src) && src[j] == ';' {
			if decoded, ok := resolveReference(src[i+1 : j]); ok {
				out = append(out, decoded...)
				i = j + 1
				continue
			}
		}
		out = append(out, src[i])
		i++
	}
	return out
}

// isReferenceByte reports whether b may appear between '&' and ';' in an XML reference.
//
// Deliberately narrow: '#' for a character reference, and alphanumerics for the digits of a numeric
// one or the name of an entity. Anything else — a space, another '&', a '<' — ends the scan, which
// is what keeps the walk linear on input that is mostly bare ampersands.
func isReferenceByte(b byte) bool {
	return b == '#' ||
		(b >= '0' && b <= '9') ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z')
}

// resolveReference decodes the body of one reference — what sits between '&' and ';'.
func resolveReference(ref []byte) ([]byte, bool) {
	switch string(ref) {
	case "amp":
		return []byte("&"), true
	case "lt":
		return []byte("<"), true
	case "gt":
		return []byte(">"), true
	case "quot":
		return []byte(`"`), true
	case "apos":
		return []byte("'"), true
	}

	if len(ref) < 2 || ref[0] != '#' {
		return nil, false
	}
	digits, base := ref[1:], 10
	if digits[0] == 'x' || digits[0] == 'X' {
		digits, base = digits[1:], 16
	}
	if len(digits) == 0 {
		return nil, false
	}
	// 32 bits is well past any valid code point and keeps a long digit run from overflowing.
	cp, err := strconv.ParseUint(string(digits), base, 32)
	if err != nil || cp > 0x10FFFF {
		return nil, false
	}
	return []byte(string(rune(cp))), true
}

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
			decoded := decodeXMLEntities(buf[rg.Start:rg.End])
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

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package xmlref decodes XML character and entity references, for code that has to
// decide whether a byte sequence is PRESENT in XML rather than parse the XML.
//
// It is a stdlib-only leaf so that any layer can reach it. Three callers need the same
// answer and sit in packages that cannot import each other:
//
//	internal/redactors/office    the embedded-part admission gate, which asks "does this
//	                             part hold a reported value" before handing it over
//	internal/redactors/tagmeta   the write gate for an XMP packet in a media container
//	internal/redactors/office    rewritePartText, which already solves the problem for a
//	                             part it is rewriting, via encoding/xml
//
// # Why this exists rather than a list of escaped spellings
//
// A value stored in XML character data may be reference-encoded, in which case the bytes
// that were reported are simply not present, and a raw byte search is blind to it. The
// obvious fix is to widen the search set with the escaped forms — that is what
// embedded.XMLEscapeVariants does, offering the five predefined entities. It cannot work,
// because '&' also introduces character references, so ANY character at ANY offset can be
// respelled in decimal or hex with arbitrary leading zeros. An apostrophe is `&apos;`,
// `&#39;`, `&#x27;`, `&#039;`, `&#x0027;` and so on without limit, and
// "449-87-41&#48;0", "&#52;49-87-4100" and "449&#45;87&#45;4100" are all the same SSN.
// The spellings are combinatorial: enumeration is not a narrower fix, it is a wrong one.
// Only canonicalizing is complete.
//
// # Why not encoding/xml, and why not html.UnescapeString
//
// encoding/xml is the right tool when you are rewriting a part and can afford to tokenize
// it — office.rewritePartText does exactly that and should keep doing so. It is the wrong
// tool for an admission gate: the gate runs over arbitrary embedded bytes that are often
// not well-formed XML at all (an OLE stream, a JPEG, a nested zip member), and a tokenizer
// error there would mean "cannot see" on precisely the inputs the gate exists to inspect.
// This decoder never fails; it leaves what it does not understand byte-for-byte alone.
//
// html.UnescapeString is wrong for a different reason: it resolves the whole HTML named
// entity table, so content containing the literal text `&sect;` would decode to `§` and
// could make a value APPEAR that the XML never contained. A gate that invents values
// refuses clean files. This resolves exactly what XML 1.0 defines — the five predefined
// entities plus numeric character references — and nothing else.
package xmlref

import (
	"bytes"
	"strconv"
)

// Decode returns src with XML character and entity references resolved.
//
// The result is for SEARCHING only. Offsets do not survive the transformation, so a caller
// must not use a hit's position here to plan an overwrite. A caller that needs to rewrite
// the bytes must either tokenize (see office.rewritePartText) or refuse.
//
// src is returned unmodified, without copying, when it cannot contain a reference.
func Decode(src []byte) []byte {
	// Nothing to do, and by far the common case: no ampersand means no reference. This
	// check is what keeps the gate from paying for a full copy of every embedded part.
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

		// Scan forward over the bytes a reference body may contain, stopping at the
		// terminator or at the first byte that cannot be part of one.
		//
		// Not a fixed-width window. A byte cap would be simpler and would silently FAIL TO
		// DECODE a long-but-legal reference — `&#00000000039;` is a valid apostrophe — and a
		// reference this does not decode is a value the caller does not see, which is the
		// leak it exists to stop. The scan is linear anyway: every byte is examined at most
		// twice, because a run that does not terminate in ';' ends at a byte that cannot
		// appear in a reference, so `&&&&...` costs one comparison per ampersand rather than
		// a search to the end of the buffer.
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
// Deliberately narrow: '#' for a character reference, and alphanumerics for the digits of a
// numeric one or the name of an entity. Anything else — a space, another '&', a '<' — ends
// the scan, which is what keeps the walk linear on input that is mostly bare ampersands.
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

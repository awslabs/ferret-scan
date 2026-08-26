// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractvideolib

import "encoding/binary"

// readChildHeader reads one box header out of an already-buffered parent payload.
//
// ISO 14496-12 gives a box's size word two special values, and the inner walkers here honoured
// neither — each read a bare uint32 and used it directly:
//
//	size == 1  the real size is a 64-bit value in the eight bytes AFTER the type word
//	size == 0  the box runs to the end of its container
//
// Reading 1 as a size means failing the `size < BoxHeaderSize` check and breaking out of the walk, so
// a largesize box did not merely parse wrong — it ENDED the enumeration, taking every later sibling
// with it. readTopLevelHeaderAt already handled both forms; the eleven inner walkers did not, so the
// two halves of the same parser disagreed about the same container.
//
// The 100MB router gate makes the >4GB case that largesize exists for unreachable, but the form is
// legal at any size and writers do emit it for ordinary boxes, so this is reachable on a small file.
//
// Returns the canonical type, the payload bounds, and whether a well-formed header was found. Every
// bound is clamped to the parent payload, which is the one limit the file cannot overstate:
// payloadEnd is derived from len(data), never from the declared size alone.
//
// payloadEnd doubles as the offset of the next sibling, so a caller advances with
// `offset = payloadEnd` — or keeps its existing `offset += size` by taking size as
// payloadEnd - offset, which is the whole box including a 16-byte largesize header.
func readChildHeader(data []byte, offset int) (boxType string, payloadStart, payloadEnd int, ok bool) {
	if offset < 0 || offset+BoxHeaderSize > len(data) {
		return "", 0, 0, false
	}

	declared := int64(binary.BigEndian.Uint32(data[offset : offset+4]))
	rawType := data[offset+4 : offset+8]
	header := int64(BoxHeaderSize)

	switch declared {
	case 1:
		// 64-bit largesize follows the type word.
		if offset+ExtendedBoxSize > len(data) {
			return "", 0, 0, false
		}
		size64 := binary.BigEndian.Uint64(data[offset+BoxHeaderSize : offset+ExtendedBoxSize])
		// Compared as uint64 before the int64 conversion: a value with the top bit set converts to a
		// NEGATIVE int64, which would pass a `>= header` test and then produce a payload slice with
		// end < start. Rejecting it here keeps every caller's arithmetic in range.
		if size64 > uint64(len(data)-offset) {
			return "", 0, 0, false
		}
		declared = int64(size64)
		header = ExtendedBoxSize
	case 0:
		// Runs to the end of the parent.
		declared = int64(len(data) - offset)
	}

	if declared < header || int64(offset)+declared > int64(len(data)) {
		return "", 0, 0, false
	}

	payloadStart = offset + int(header)
	payloadEnd = offset + int(declared)

	// A box whose declared size equals its header is legal and empty; guarding against
	// payloadEnd <= offset is what stops a zero-length box from making the caller's loop spin.
	// declared >= header >= 8 already ensures it, so this is an assertion rather than a branch that
	// fires — but it is cheap, and a spinning walk here previously burned 30s of CPU per file (#377).
	if payloadEnd <= offset {
		return "", 0, 0, false
	}

	return canonicalBoxType(rawType), payloadStart, payloadEnd, true
}

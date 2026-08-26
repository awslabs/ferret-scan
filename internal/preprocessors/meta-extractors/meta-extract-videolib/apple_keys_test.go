// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractvideolib

import (
	"context"
	"encoding/binary"
	"os"
	"strings"
	"testing"
)

// The byte layouts below are transcribed from a real macOS system recording rather than invented, so
// a fixture cannot agree with a wrong belief about the container. Source:
// /System/Library/CoreServices/ControlCenter.app/Contents/Resources/BentoGalleryIntroduction.mov
//
//	moov > meta                      (no version/flags word — QuickTime, not ISO)
//	  hdlr  size 34
//	  keys  size 157  entry_count 4  mdta com.apple.quicktime.{make,model,software,creationdate}
//	  ilst  size 159  items typed 00000001..00000004, each a data box, well-known type 1 (UTF-8)
//	                  values "Apple", "Mac16,6", "macOS 15.2 (24C101)", "2025-06-16T19:12:48-0700"
//
// TestAgainstTheRealFile at the foot of this file reads that file directly when it is present, which
// is what keeps these hand-assembled equivalents honest.

func qtBox(typ string, payload []byte) []byte {
	out := make([]byte, 8, 8+len(payload))
	binary.BigEndian.PutUint32(out[0:4], uint32(8+len(payload)))
	copy(out[4:8], typ)
	return append(out, payload...)
}

// largeBox writes the same box in the 64-bit largesize form: size word 1, real size in the next
// eight bytes.
func largeBox(typ string, payload []byte) []byte {
	out := make([]byte, 16, 16+len(payload))
	binary.BigEndian.PutUint32(out[0:4], 1)
	copy(out[4:8], typ)
	binary.BigEndian.PutUint64(out[8:16], uint64(16+len(payload)))
	return append(out, payload...)
}

// keysTable builds a keys box for the given reverse-DNS names, all in Apple's mdta namespace.
func keysTable(names ...string) []byte {
	payload := make([]byte, 8)                                   // version/flags, then entry count
	binary.BigEndian.PutUint32(payload[4:8], uint32(len(names))) //nolint:gosec // test data
	for _, n := range names {
		entry := make([]byte, 8, 8+len(n))
		binary.BigEndian.PutUint32(entry[0:4], uint32(8+len(n)))
		copy(entry[4:8], "mdta")
		entry = append(entry, n...)
		payload = append(payload, entry...)
	}
	return qtBox("keys", payload)
}

// dataItem builds one ilst item: an index-typed box wrapping a data box of the given well-known type.
func dataItem(index uint32, wellKnown uint32, value string) []byte {
	inner := make([]byte, 8, 8+len(value))
	binary.BigEndian.PutUint32(inner[0:4], wellKnown)
	// bytes 4:8 are the locale indicator, left zero
	inner = append(inner, value...)

	item := make([]byte, 8, 16+len(value))
	binary.BigEndian.PutUint32(item[0:4], 0) // patched below
	binary.BigEndian.PutUint32(item[4:8], index)
	item = append(item, qtBox("data", inner)...)
	binary.BigEndian.PutUint32(item[0:4], uint32(len(item)))
	return item
}

// TestAppleKeysIlstDecodedFromRealLayout is the recall case: the four real values must come out, and
// the key NAMES must not.
//
// Both halves matter. The defect did not merely lose the values — the raw text scrape that stood in
// for a real decode reported each field's value as the NEXT KEY'S NAME, minus its first two bytes, so
// asserting only that CameraMake is non-empty would have passed against the bug.
func TestAppleKeysIlstDecodedFromRealLayout(t *testing.T) {
	meta := qtBox("meta", concat(
		qtBox("hdlr", make([]byte, 26)),
		keysTable(
			"com.apple.quicktime.make",
			"com.apple.quicktime.model",
			"com.apple.quicktime.software",
			"com.apple.quicktime.creationdate",
		),
		qtBox("ilst", concat(
			dataItem(1, appleDataTypeUTF8, "Apple"),
			dataItem(2, appleDataTypeUTF8, "Mac16,6"),
			dataItem(3, appleDataTypeUTF8, "macOS 15.2 (24C101)"),
			dataItem(4, appleDataTypeUTF8, "2025-06-16T19:12:48-0700"),
		)),
	))

	md := &VideoMetadata{Properties: map[string]string{}}
	if err := parseMoovBoxWithContext(context.Background(), meta, md); err != nil {
		t.Fatalf("parse: %v", err)
	}

	for _, tc := range []struct{ field, got, want string }{
		{"CameraMake", md.CameraMake, "Apple"},
		{"CameraModel", md.CameraModel, "Mac16,6"},
		{"Software", md.Software, "macOS 15.2 (24C101)"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.field, tc.got, tc.want)
		}
	}
	if md.CreatedDate.IsZero() {
		t.Error("CreatedDate is zero: Apple writes the zone offset without a colon " +
			"(2025-06-16T19:12:48-0700) and that layout has to be in parseDate's list")
	}

	// The exact corruption the scrape produced. A key name appearing as a value means the index
	// mapping is being ignored again, which no "is it non-empty" assertion would catch.
	for _, field := range []string{md.CameraMake, md.CameraModel, md.Software, md.Description, md.Title} {
		if strings.Contains(field, "apple.quicktime") || strings.Contains(field, "quicktime.") {
			t.Errorf("a field holds a KEY NAME as its value (%q) — the keys/ilst pairing is not "+
				"being decoded and the raw text scrape is answering instead", field)
		}
		if field == "data" {
			t.Errorf("a field holds the literal atom type %q as its value", field)
		}
	}
}

// TestQuickTimeMetaHasNoVersionFlags pins the offset detection both ways.
//
// This is the gap that made a QuickTime meta unparsable in full: the walker skipped four bytes
// unconditionally, so it read the first child's TYPE as that child's SIZE — "hdlr" is 0x68646c72,
// 1,751,411,826 — failed the bounds check and abandoned the box, ilst included.
func TestQuickTimeMetaHasNoVersionFlags(t *testing.T) {
	children := concat(qtBox("hdlr", make([]byte, 26)), qtBox("ilst", nil))

	if got := metaChildOffset(children); got != 0 {
		t.Errorf("QuickTime meta: child offset = %d, want 0", got)
	}

	iso := append([]byte{0, 0, 0, 0}, children...) // version/flags word in front
	if got := metaChildOffset(iso); got != 4 {
		t.Errorf("ISO meta: child offset = %d, want 4", got)
	}

	// The end-to-end consequence, so this is not just a unit test of a helper: the same ilst has to
	// be found under both layouts.
	for name, payload := range map[string][]byte{
		"quicktime": concat(qtBox("hdlr", make([]byte, 26)), qtBox("ilst", dataItem(1, appleDataTypeUTF8, "x"))),
		"iso":       append([]byte{0, 0, 0, 0}, concat(qtBox("hdlr", make([]byte, 26)), qtBox("ilst", dataItem(1, appleDataTypeUTF8, "x")))...),
	} {
		md := &VideoMetadata{Properties: map[string]string{}}
		full := qtBox("meta", concat(keysTable("com.apple.quicktime.description"), payload))
		if name == "iso" {
			full = qtBox("meta", append([]byte{0, 0, 0, 0}, concat(keysTable("com.apple.quicktime.description"), payload[4:])...))
		}
		if err := parseMoovBoxWithContext(context.Background(), full, md); err != nil {
			t.Fatalf("%s: parse: %v", name, err)
		}
		if md.Description == "" {
			t.Errorf("%s layout: the ilst value was not read", name)
		}
	}
}

// TestAppleDataValueHonoursTypeIndicator covers both directions of the text/binary decision.
//
// The real recording carries com.apple.quicktime.pixeldensity as well-known type 30 with a 16-byte
// binary payload, and stringifying it injected raw bytes into the text the validators scan. The
// opposite error matters more, though: dropping a value is a SUPPRESSOR, and an unreported value
// cannot be redacted, so a writer that mislabels UTF-8 must still be read.
func TestAppleDataValueHonoursTypeIndicator(t *testing.T) {
	cases := []struct {
		name      string
		wellKnown uint32
		payload   string
		want      string
	}{
		{"declared UTF-8", appleDataTypeUTF8, "SSN 449-87-4100", "SSN 449-87-4100"},
		{"declared UTF-16", appleDataTypeUTF16BE, "text", "text"},
		{"mislabelled text is still read", 0, "SSN 449-87-4100", "SSN 449-87-4100"},
		{"binary is not stringified", 30, "\x00\x00\x01\x90\x00\x00\x01\x02\x00\x00\x00\xc8\x00\x00\x00\x81", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := appleDataValue(dataItemPayload(tc.wellKnown, tc.payload))
			if got != tc.want {
				t.Errorf("appleDataValue = %q, want %q", got, tc.want)
			}
		})
	}
}

// dataItemPayload returns just the inner bytes of an ilst item — the data box — which is what
// appleDataValue is handed.
func dataItemPayload(wellKnown uint32, value string) []byte {
	inner := make([]byte, 8, 8+len(value))
	binary.BigEndian.PutUint32(inner[0:4], wellKnown)
	inner = append(inner, value...)
	return qtBox("data", inner)
}

// TestOneValueProducesOneEmission guards the duplicate this change introduced and then fixed.
//
// Writing a decoded value to BOTH its typed field and a property doubles it, because
// ToProcessedContent renders fields and properties alike. Measured on a real .3gp: one SSN in the
// dscp box reported at lines 6 AND 7. A recall fix that reports each value twice trades one defect
// for another.
func TestOneValueProducesOneEmission(t *testing.T) {
	meta := qtBox("meta", concat(
		keysTable("com.apple.quicktime.description"),
		qtBox("ilst", dataItem(1, appleDataTypeUTF8, "SSN 449-87-4100")),
	))
	md := &VideoMetadata{Properties: map[string]string{}}
	if err := parseMoovBoxWithContext(context.Background(), meta, md); err != nil {
		t.Fatalf("parse: %v", err)
	}

	if md.Description != "SSN 449-87-4100" {
		t.Fatalf("Description = %q, want the value (the rest of this test is vacuous without it)", md.Description)
	}
	for key, value := range md.Properties {
		if value == md.Description {
			t.Errorf("property %q repeats the value already in Description — one value in the file "+
				"must not be emitted twice", key)
		}
	}
}

// TestScrapeStandsDownForDecodedKeys pins that the fallback does not contradict the table.
//
// Emitting both left a reader with `CameraMake: Apple` and `CameraMake_Apple:
// m.apple.quicktime.model` side by side, and fed the garbage to the validators as well.
func TestScrapeStandsDownForDecodedKeys(t *testing.T) {
	md := &VideoMetadata{Properties: map[string]string{}}
	md.decodedAppleKeys = map[string]bool{"com.apple.quicktime.make": true}
	md.CameraMake = "Apple"

	// A raw region that the scrape would otherwise mine for com.apple.quicktime.make.
	searchAppleMetadataInData("com.apple.quicktime.makecom.apple.quicktime.model", md)

	if got, ok := md.Properties["CameraMake_Apple"]; ok {
		t.Errorf("the scrape wrote CameraMake_Apple = %q for a key the keys table already "+
			"answered", got)
	}
	if md.CameraMake != "Apple" {
		t.Errorf("CameraMake = %q, want it left alone at %q", md.CameraMake, "Apple")
	}
}

// TestAgainstTheRealFile reads the macOS recording the layouts above were transcribed from.
//
// Skipped when absent, so it does not fail on Linux CI, but it is the assertion that keeps the
// hand-assembled fixtures honest: a fixture and the code can share a wrong belief about the
// container and every test still passes. This one cannot.
func TestAgainstTheRealFile(t *testing.T) {
	const real = "/System/Library/CoreServices/ControlCenter.app/Contents/Resources/BentoGalleryIntroduction.mov"
	if _, err := os.Stat(real); err != nil {
		t.Skipf("real fixture not present on this host: %v", err)
	}

	md, err := ExtractVideoMetadata(real)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}

	// These are the values the container actually holds, read with an independent tool.
	for _, tc := range []struct{ field, got, want string }{
		{"CameraMake", md.CameraMake, "Apple"},
		{"CameraModel", md.CameraModel, "Mac16,6"},
		{"Software", md.Software, "macOS 15.2 (24C101)"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %q, want %q", tc.field, tc.got, tc.want)
		}
	}

	// No field or property may hold a key name, and none may hold raw binary. The file carries
	// com.apple.quicktime.pixeldensity as a 16-byte binary payload, which used to be stringified
	// into the scanned text.
	for key, value := range md.Properties {
		if strings.Contains(value, "apple.quicktime") {
			t.Errorf("property %q = %q holds a key name as its value", key, value)
		}
		for _, b := range []byte(value) {
			if b < 0x09 || (b > 0x0D && b < 0x20) {
				t.Errorf("property %q holds a non-text byte 0x%02x — a binary data box is being "+
					"stringified into the text the validators scan", key, b)
				break
			}
		}
	}
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

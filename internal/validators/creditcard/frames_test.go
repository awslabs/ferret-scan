// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package creditcard

import (
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// #905: magnetic-stripe tracks (ISO/IEC 7813) and EMV tag 57 carry a PAN beside bytes the PAN
// pattern's boundary class rejects, so Track 1, tag 57 and URL-encoded Track 2 gave no finding at
// all, and a Track 2 finding ended at '='. A frame now reports its PAN (unless the PAN pattern
// already did) and itself, under the PAN's type with Metadata["card_frame"].
//
// The tests use only what main also has (NewValidator, ValidateContent, string keys), so this file
// compiles against main and fails there by assertion.

// The issue's synthetic values: brand prefix + "0012345678..." + Luhn digit.
const (
	visa16 = "4000001234567899"
	mc16   = "5100001234567895"
	amex15 = "370000123456784"
	disc16 = "6011001234567891"
	visa19 = "4000001234567890124"
	visa13 = "4000001234562"
)

// track1 and track2 build the issue's frames: name PUBLIC/JOHN Q, expiry 2812, service code 101,
// discretionary zeros, padded to the issue's lengths.
func track1(pan, start, end string) string {
	b := start + pan + "^PUBLIC/JOHN Q^2812101"
	return b + strings.Repeat("0", 66-len(b)) + end
}

func track2(pan, start, end string) string {
	b := start + pan + "=2812101"
	return b + strings.Repeat("0", 39-len(b)) + end
}

func emv57(pan, sep, pad string) string {
	b := pan + sep + "2812101"
	b += strings.Repeat("0", 37-len(b))
	if len(b)%2 == 1 {
		b += pad
	}
	return b
}

// framesOf returns the findings whose Metadata names a frame, and the others.
func framesOf(ms []detector.Match) (frames, others []detector.Match) {
	for _, m := range ms {
		if _, ok := m.Metadata["card_frame"]; ok {
			frames = append(frames, m)
		} else {
			others = append(others, m)
		}
	}
	return frames, others
}

func scan(t *testing.T, content string) []detector.Match {
	t.Helper()
	ms, err := NewValidator().ValidateContent(content, "frames.txt")
	if err != nil {
		t.Fatalf("ValidateContent(%q): %v", content, err)
	}
	return ms
}

// TestEachFrameIsReportedWholeWithItsPAN is the issue's acceptance criterion for the 25 frame
// files: one frame finding whose Text is the whole frame and whose Type is its PAN's, and exactly
// one PAN finding per PAN, never two.
func TestEachFrameIsReportedWholeWithItsPAN(t *testing.T) {
	t2 := track2(visa16, ";", "?")
	enc := strings.NewReplacer(";", "%3B", "=", "%3D", "?", "%3F").Replace(t2)
	for _, tc := range []struct {
		name, line, frame, kind, pan, typ string
	}{
		{"track1 visa16", track1(visa16, "%B", "?"), track1(visa16, "%B", "?"), "track1", visa16, "VISA"},
		{"track1 mc16", track1(mc16, "%B", "?"), track1(mc16, "%B", "?"), "track1", mc16, "MASTERCARD"},
		{"track1 amex15", track1(amex15, "%B", "?"), track1(amex15, "%B", "?"), "track1", amex15, "AMERICAN_EXPRESS"},
		{"track1 disc16", track1(disc16, "%B", "?"), track1(disc16, "%B", "?"), "track1", disc16, "DISCOVER"},
		{"track1 visa19", track1(visa19, "%B", "?"), track1(visa19, "%B", "?"), "track1", visa19, "VISA"},
		{"track1 visa13", track1(visa13, "%B", "?"), track1(visa13, "%B", "?"), "track1", visa13, "VISA"},
		{"track1 no sentinels", track1(visa16, "B", ""), track1(visa16, "B", ""), "track1", visa16, "VISA"},
		{"track1 kv", "track1=" + track1(visa16, "%B", "?"), track1(visa16, "%B", "?"), "track1", visa16, "VISA"},
		{"track1 labelled", "Card swipe track 1: " + track1(visa16, "%B", "?"), track1(visa16, "%B", "?"), "track1", visa16, "VISA"},
		{"track1 json", `{"track1": "` + track1(visa16, "%B", "?") + `"}`, track1(visa16, "%B", "?"), "track1", visa16, "VISA"},
		{"track2 visa16", t2, t2, "track2", visa16, "VISA"},
		{"track2 mc16", track2(mc16, ";", "?"), track2(mc16, ";", "?"), "track2", mc16, "MASTERCARD"},
		{"track2 amex15", track2(amex15, ";", "?"), track2(amex15, ";", "?"), "track2", amex15, "AMERICAN_EXPRESS"},
		{"track2 disc16", track2(disc16, ";", "?"), track2(disc16, ";", "?"), "track2", disc16, "DISCOVER"},
		{"track2 visa19", track2(visa19, ";", "?"), track2(visa19, ";", "?"), "track2", visa19, "VISA"},
		{"track2 visa13", track2(visa13, ";", "?"), track2(visa13, ";", "?"), "track2", visa13, "VISA"},
		{"track2 no sentinels", track2(visa16, "", ""), track2(visa16, "", ""), "track2", visa16, "VISA"},
		{"track2 kv", "track2=" + t2, t2, "track2", visa16, "VISA"},
		{"track2 labelled", "Card swipe track 2: " + t2, t2, "track2", visa16, "VISA"},
		{"track2 json", `{"track2": "` + t2 + `"}`, t2, "track2", visa16, "VISA"},
		{"track2 url-encoded", "POST /pay track2=" + enc, enc, "track2", visa16, "VISA"},
		{"emv tag57 kv", "tag57=" + emv57(visa16, "D", "F"), emv57(visa16, "D", "F"), "emv57", visa16, "VISA"},
		{"emv labelled", "Track 2 Equivalent Data: " + emv57(visa16, "D", "F"), emv57(visa16, "D", "F"), "emv57", visa16, "VISA"},
		{"emv lower", "tag57=" + emv57(visa16, "d", "f"), emv57(visa16, "d", "f"), "emv57", visa16, "VISA"},
		{"emv tlv glued", "5713" + emv57(visa16, "D", "F"), emv57(visa16, "D", "F"), "emv57", visa16, "VISA"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ms := scan(t, tc.line)
			frames, others := framesOf(ms)
			if len(frames) != 1 {
				t.Fatalf("%q: want exactly one frame finding, got %d of %d findings: %+v", tc.line, len(frames), len(ms), ms)
			}
			f := frames[0]
			if f.Text != tc.frame || f.Metadata["card_frame"] != tc.kind || f.Type != "CARD_TRACK_DATA" || f.Metadata["card_type"] != tc.typ {
				t.Errorf("frame finding %s %q card_frame=%v card_type=%v; want CARD_TRACK_DATA %q card_frame=%s card_type=%s",
					f.Type, f.Text, f.Metadata["card_frame"], f.Metadata["card_type"], tc.frame, tc.kind, tc.typ)
			}
			if _, ok := f.Metadata["vendor"]; ok {
				t.Errorf("frame finding carries vendor %v; --explain would read it as a kind of card", f.Metadata["vendor"])
			}
			if len(others) != 1 || others[0].Text != tc.pan || others[0].Type != tc.typ {
				t.Errorf("want exactly one %s finding for the PAN %s beside the frame, got %+v", tc.typ, tc.pan, others)
			}
		})
	}
}

// TestAWedgeLineReportsBothTracks: a keyboard-wedge reader writes Track 1 and Track 2 on one line.
// Each is reported whole, and each of the two PAN occurrences has one PAN finding.
func TestAWedgeLineReportsBothTracks(t *testing.T) {
	t1, t2 := track1(visa16, "%B", "?"), track2(visa16, ";", "?")
	frames, others := framesOf(scan(t, t1+t2))
	if len(frames) != 2 || frames[0].Text != t1 || frames[1].Text != t2 ||
		frames[0].Metadata["card_frame"] != "track1" || frames[1].Metadata["card_frame"] != "track2" {
		t.Fatalf("want the two tracks, Track 1 then Track 2, got %+v", frames)
	}
	if len(others) != 2 || others[0].Text != visa16 || others[1].Text != visa16 {
		t.Errorf("want one PAN finding per PAN occurrence, got %+v", others)
	}
}

// TestTheTrack2PANFindingIsUnchanged pins item 2 of the resolution: the PAN pattern already reports
// a Track 2 PAN after ';' and '=' and that finding keeps exactly its Text, type, score, context and
// metadata (no card_frame), so no suppression rule written for it stops matching.
func TestTheTrack2PANFindingIsUnchanged(t *testing.T) {
	line := track2(visa16, ";", "?")
	_, others := framesOf(scan(t, line))
	if len(others) != 1 {
		t.Fatalf("want one PAN finding, got %+v", others)
	}
	m := others[0]
	if m.Text != visa16 || m.Type != "VISA" || m.Confidence != 75 {
		t.Errorf("Track 2 PAN finding %s %q %.1f; want main's VISA %q 75", m.Type, m.Text, m.Confidence, visa16)
	}
	if m.Context.BeforeText != ";" || m.Context.AfterText != line[17:] || m.Context.FullLine != line {
		t.Errorf("context %q / %q / %q moved", m.Context.BeforeText, m.Context.AfterText, m.Context.FullLine)
	}
	if _, ok := m.Metadata["card_frame"]; ok {
		t.Errorf("the PAN finding carries card_frame; only frame findings may")
	}
	if c, _ := m.Metadata["confidence_ceiling"].(float64); c != bareRunCeiling {
		t.Errorf("the PAN finding publishes ceiling %v, want main's %v", m.Metadata["confidence_ceiling"], bareRunCeiling)
	}
}

// TestFrameGatesGateOnlyTheFrame: each structural gate failing alone drops the frame finding and
// keeps the PAN (a Luhn-valid PAN in a frame is never dropped); a Luhn failure drops both.
func TestFrameGatesGateOnlyTheFrame(t *testing.T) {
	const name = "^PUBLIC/JOHN Q^"
	for _, tc := range []struct {
		name, line string
		wantPAN    bool
	}{
		{"track1 luhn", "%B4000001234567898" + name + "2812101000?", false},
		{"track1 month 00", "%B" + visa16 + name + "2800101000?", true},
		{"track1 month 13", "%B" + visa16 + name + "2813101000?", true},
		{"track1 service digit 1", "%B" + visa16 + name + "2812301000?", true},
		{"track1 service digit 2", "%B" + visa16 + name + "2812111000?", true},
		{"track1 service digit 3", "%B" + visa16 + name + "2812108000?", true},
		{"track1 80 chars", "%B" + visa16 + name + "2812101" + strings.Repeat("0", 80-2-16-len(name)-7-1) + "?", true},
		{"track2 luhn", ";4000001234567898=2812101000?", false},
		{"track2 month 13", ";" + visa16 + "=2813101000?", true},
		{"track2 service digit 1", ";" + visa16 + "=2812801000?", true},
		{"track2 41 chars", ";" + visa16 + "=2812101" + strings.Repeat("0", 41-1-16-1-7-1) + "?", true},
		{"emv month 00", "tag57=" + visa16 + "D2800101000F", true},
		{"emv service digit 2", "tag57=" + visa16 + "D2812131000F", true},
		{"emv 39 nibbles", "tag57=" + visa16 + "D2812101" + strings.Repeat("0", 39-16-1-7-1) + "F", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ms := scan(t, tc.line)
			frames, others := framesOf(ms)
			if len(frames) != 0 {
				t.Errorf("%q: a frame that fails a gate must not be reported as a frame, got %+v", tc.line, frames)
			}
			gotPAN := len(others) == 1 && others[0].Text == visa16
			if gotPAN != tc.wantPAN || len(others) > 1 {
				t.Errorf("%q: PAN reported %v (%+v), want %v", tc.line, gotPAN, others, tc.wantPAN)
			}
		})
	}
}

// TestTheLengthLimitsAreInclusive: exactly 79 (Track 1), 40 (Track 2) and 38 nibbles (tag 57) are
// frames; the off-by-one rows above are not.
func TestTheLengthLimitsAreInclusive(t *testing.T) {
	const name = "^PUBLIC/JOHN Q^"
	for _, line := range []string{
		"%B" + visa16 + name + "2812101" + strings.Repeat("0", 79-2-16-len(name)-7-1) + "?",
		";" + visa16 + "=2812101" + strings.Repeat("0", 40-1-16-1-7-1) + "?",
		"tag57=" + visa16 + "D2812101" + strings.Repeat("0", 38-16-1-7-1) + "F",
	} {
		if frames, _ := framesOf(scan(t, line)); len(frames) != 1 {
			t.Errorf("%q (%d bytes): want one frame, got %+v", line, len(line), frames)
		}
	}
}

// TestABrokenLeftEdgeIsNotAFrame: the byte before a frame is checked by hand. A letter or digit
// glued to a bare `B` or to a tag 57 value means the digits are part of a longer token (a hex
// string, an identifier), and nothing is reported, PAN included.
func TestABrokenLeftEdgeIsNotAFrame(t *testing.T) {
	for _, line := range []string{
		"xB" + visa16 + "^PUBLIC/JOHN Q^2812101000",                    // letter before the format code
		"9B" + visa16 + "^PUBLIC/JOHN Q^2812101000",                    // digit before the format code
		"a3f0" + visa16 + "D2812101ab",                                 // the issue's hex decoy
		"x" + visa16 + "D28121010000000000000F",                        // letter before the value
		"tag57=" + visa16 + "D28121010000000000000Fab",                 // a letter after the value
		"ref" + visa16 + "=2812101000000000000000",                     // Track 2 without a sentinel or boundary
		"5714" + emv57(visa16, "D", "F"),                               // TLV length one byte too long
		"570C" + visa16 + "D28121",                                     // TLV length that cuts the service code
		"5713" + emv57("4000001234567898", "D", "F"),                   // TLV value failing Luhn
		"5720" + emv57(visa16, "D", "F") + "00000000",                  // TLV length above 19 bytes
		"57" + "0A" + emv57(visa16, "D", "F")[:20],                     // TLV length below 11 bytes
		";" + visa16 + "2812101000",                                    // no separator
		"%B" + visa16 + "PUBLIC/JOHN Q^2812101000?",                    // no first field separator
		"%B" + visa16 + "^" + strings.Repeat("N", 27) + "^2812101000?", // a 27-character name
	} {
		if ms := scan(t, line); len(ms) != 0 {
			t.Errorf("%q: want no finding, got %+v", line, ms)
		}
	}
}

// TestTLVReadsTheValueByItsLength: inside a hex dump the length byte, not a boundary, delimits the
// value, so a tag 57 glued between other tags is read; lowercase hex is accepted.
func TestTLVReadsTheValueByItsLength(t *testing.T) {
	value := emv57(visa16, "D", "F") // 38 nibbles = 0x13 bytes
	short := visa16 + "d2812101"     // the shortest value, 24 nibbles = 0x0C bytes
	for _, tc := range []struct{ line, want string }{
		{"5A08" + visa16 + "5713" + value + "9F1A020840", value},
		{"5713" + value, value},
		{"9f02060000000010005713" + value + "5f2a020840", value},
		{"570c" + short, short},
	} {
		frames, _ := framesOf(scan(t, tc.line))
		if len(frames) != 1 || frames[0].Text != tc.want || frames[0].Metadata["card_frame"] != "emv57" {
			t.Errorf("%q: want the one emv57 value %q, got %+v", tc.line, tc.want, frames)
		}
	}
}

// TestATrackAfterCaretDelimitedFields: a Track 1 is found after `^`-delimited fields that look like
// the end of a track (an HL7 segment's components, a 7-digit run after a `^`), which an unanchored
// scan from the first `^` would have consumed up to the next white space.
func TestATrackAfterCaretDelimitedFields(t *testing.T) {
	t1 := track1(visa16, "%B", "?")
	for _, line := range []string{
		"x^y^2812101|" + t1,
		"PID|1||12345^^^MRN^AB^20230101|" + t1,
		"OBX|1|ST|^code^2812101^|" + t1 + "|F",
	} {
		frames, _ := framesOf(scan(t, line))
		if len(frames) != 1 || frames[0].Text != t1 {
			t.Errorf("%q: want the one Track 1, got %+v", line, frames)
		}
	}
}

// TestPercentEncodingInBothCases: a form post may encode Track 2's bytes with either case.
func TestPercentEncodingInBothCases(t *testing.T) {
	for _, enc := range []string{
		"%3B" + visa16 + "%3D2812101000%3F",
		"%3b" + visa16 + "%3d2812101000%3f",
		";" + visa16 + "%3D2812101000?",
		"%3B" + visa16 + "=2812101000",
	} {
		frames, others := framesOf(scan(t, "track2="+enc))
		if len(frames) != 1 || frames[0].Text != enc || frames[0].Metadata["card_frame"] != "track2" {
			t.Errorf("%q: want the whole encoded frame, got %+v", enc, frames)
		}
		if len(others) != 1 || others[0].Text != visa16 {
			t.Errorf("%q: want one PAN finding, got %+v", enc, others)
		}
	}
}

// TestFrameConfidence pins the scores: the frame counts as one card word on its line, so it scores
// its PAN's value plus +15 (once), clamped to 100, with no bare-run ceiling; a hard negative still
// takes it to the floor, a soft one does not; a test card's service code (9xx) holds the frame and a
// recovered PAN at 15 with the ceiling published.
func TestFrameConfidence(t *testing.T) {
	type want struct {
		frame, pan float64
		frameCeil  float64 // 0 = no ceiling published
	}
	for _, tc := range []struct {
		name, line string
		want
	}{
		// No keyword: the PAN is held to MEDIUM by the bare-run ceiling (#802); the frame is not.
		{"track1 bare", track1(visa16, "%B", "?"), want{100, 75, 0}},
		{"track2 bare", track2(visa16, ";", "?"), want{100, 75, 0}},
		// A card word on the line: +15 once, not twice.
		{"track2 labelled", "Card swipe track 2: " + track2(visa16, ";", "?"), want{100, 100, 0}},
		// A hard negative in the Track 1 name reaches both, as it does a PAN.
		{"sample surname", "%B" + visa16 + "^SAMPLE/JOHN^2812101000?", want{intrinsicValueFloor, intrinsicValueFloor, 0}},
		{"test card name", "%B" + visa16 + "^TEST/CARD^2812101000?", want{intrinsicValueFloor, intrinsicValueFloor, 0}},
		// A soft negative is overridden by the frame, as by a card word.
		{"order line", "order 5678 " + track2(visa16, ";", "?"), want{100, intrinsicValueFloor, 0}},
		// Service code 9xx: a test card, held like a published test number.
		{"track1 test card", "%B" + visa16 + "^PUBLIC/JOHN Q^2812901000?", want{testValueCeiling, testValueCeiling, testValueCeiling}},
		{"emv test card", "tag57=" + visa16 + "D2812901000F", want{testValueCeiling, testValueCeiling, testValueCeiling}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frames, others := framesOf(scan(t, tc.line))
			if len(frames) != 1 || len(others) != 1 {
				t.Fatalf("%q: want one frame and one PAN finding, got %+v / %+v", tc.line, frames, others)
			}
			if frames[0].Confidence != tc.frame || others[0].Confidence != tc.pan {
				t.Errorf("%q: frame %.1f, PAN %.1f; want %.1f, %.1f", tc.line, frames[0].Confidence, others[0].Confidence, tc.frame, tc.pan)
			}
			ceil, _ := frames[0].Metadata["confidence_ceiling"].(float64)
			if ceil != tc.frameCeil {
				t.Errorf("%q: frame ceiling %v, want %v", tc.line, frames[0].Metadata["confidence_ceiling"], tc.frameCeil)
			}
		})
	}

	// A test card on Track 2: the PAN finding is the PAN pattern's and keeps its score; only the
	// frame is held.
	frames, others := framesOf(scan(t, ";"+visa16+"=2812901000?"))
	if len(frames) != 1 || frames[0].Confidence != testValueCeiling || len(others) != 1 || others[0].Confidence != 75 {
		t.Errorf("Track 2 test card: want frame 15 and the unchanged PAN 75, got %+v / %+v", frames, others)
	}
}

// TestCardFrameIsNeverOnAPANFinding: across every frame shape, a finding whose Text is a PAN alone
// carries no card_frame, and every frame finding does. The census of metadata keys in the golden
// corpus depends on the first half.
func TestCardFrameIsNeverOnAPANFinding(t *testing.T) {
	lines := []string{
		track1(visa16, "%B", "?"), track1(visa16, "B", ""), track2(visa16, ";", "?"), track2(visa16, "", ""),
		"%3B" + visa16 + "%3D2812101000%3F", "tag57=" + emv57(visa16, "D", "F"), "5713" + emv57(visa16, "D", "F"),
		track1(visa16, "%B", "?") + track2(visa16, ";", "?"), "%B" + visa16 + "^PUBLIC/JOHN Q^2813101000?",
	}
	seen := 0
	for _, line := range lines {
		for _, m := range scan(t, line) {
			_, framed := m.Metadata["card_frame"]
			isPAN := m.Text == visa16
			if framed == isPAN {
				t.Errorf("%q: %s %q card_frame=%v", line, m.Type, m.Text, m.Metadata["card_frame"])
			}
			seen++
		}
	}
	if seen < len(lines)*2-1 {
		t.Fatalf("only %d findings over %d lines: the check is vacuous", seen, len(lines))
	}
}

// BenchmarkFrameNearMisses is the frame matchers' worst ordinary cost: one 1 MiB line that passes
// every prefilter (13-digit runs, '^', '=', 'D', a code label) and fails late, on Luhn and on a
// two-digit code, so it reports nothing and all the time is the matching.
func BenchmarkFrameNearMisses(b *testing.B) {
	const unit = "%B4000001234567898^X Y^2812101?;4000001234567898=2812101? cvc 12 4000001234567898D2812101 "
	line := strings.Repeat(unit, (1<<20)/len(unit))
	v := NewValidator()
	b.SetBytes(int64(len(line)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ms, _ := v.ValidateContent(line, "near.txt"); len(ms) != 0 {
			b.Fatalf("near misses reported %d findings", len(ms))
		}
	}
}

// The growth guards (TestFramesStayLinear, TestCodesStayLinear) scan one line of guardLineBytes
// bytes that holds n units (a swipe, a code) and then filler, at n = guardUnits and at
// growthFactor*guardUnits. The line has the same length in both, so the work done once per line,
// which dominates, is the same in both: a scan that does bounded work per unit reads about 1x, and
// one that rereads or copies the line for every frame or code it finds 5-6x. This is the
// dominant-term rule of docs/testing/TEST_PLAN.md, dimension 4. The first version grew the line and
// the units together, so a correct scan read 8x and a regressed one 35-62x, and load slowed the big
// input's term, eight times the findings and their allocations, more than the small one's: with
// other package suites running (load 52-62 on 16 CPUs) TestCodesStayLinear read 30.3x on correct
// code against its limit of 24.
//
// Two instruments, because the defects differ: time catches a step-count regression, which
// allocates nothing, and allocated bytes catch a per-unit copy of the line without the clock's
// noise. A guard fails when either reading passes growthLimit, the same limit with and without
// -race. Measured, plain and -race, idle and with 12-14 package-suite loops running: correct code
// 0.86-1.09x time and 0.92-1.18x bytes, 1.30-1.60x bytes under -race, which allocates more per unit,
// so the worst correct reading is 1.75x under the limit. Regressed, each installed alone, plain /
// -race: a strings.ToLower of the line per frame (appendFrameMatches) 5.0x / 5.1x bytes; the
// camelCase split of the line per frame (labels.identifierDone reset) 6.4x / 6.5x bytes; the line's
// hard-negative question per code (appendCodeCandidates) 5.3x / 5.6x time, since it allocates
// nothing. The lowest regressed reading is 1.79x over the limit.
const (
	guardLineBytes = 512 << 10
	guardUnits     = 4
	growthFactor   = 8
	growthLimit    = 2.8
)

// guardFiller pads a guard's line: no digit, no card or code label, no keyword. Its capital makes
// the line's lower-casing a copy, as it is for most real lines, so the bytes allocated once per
// line dominate the per-unit ones in both guards.
const guardFiller = "Lorem ipsum dolor sit amet "

// growthReading is one size's best time and allocated bytes, and the findings it held.
type growthReading struct {
	best  time.Duration
	bytes uint64
	found int
}

// growth scans the guard line with guardUnits and with growthFactor*guardUnits copies of unit and
// returns the ratios of their best times and of their allocated bytes, with the findings counted by
// count at both. The validator is built outside the measured region, and the collector is paused
// inside it, so a collection never lands in one run and not the other. The two lines are sampled in
// alternating blocks and each keeps its best run, so load that comes and goes reaches both alike.
func growth(t *testing.T, unit string, count func([]detector.Match) int) (timeRatio, byteRatio float64, small, big int) {
	t.Helper()
	v := NewValidator()
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	line := func(n int) string {
		var b strings.Builder
		b.Grow(guardLineBytes + len(guardFiller))
		for i := 0; i < n; i++ {
			b.WriteString(unit)
		}
		for b.Len() < guardLineBytes {
			b.WriteString(guardFiller)
		}
		return b.String()[:guardLineBytes]
	}
	contents := [2]string{line(guardUnits), line(growthFactor * guardUnits)}
	var r [2]growthReading
	run := func(i int) time.Duration {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		start := time.Now()
		ms, err := v.ValidateContent(contents[i], "dense.txt")
		d := time.Since(start)
		runtime.ReadMemStats(&after)
		if err != nil {
			t.Fatal(err)
		}
		if r[i].best == 0 || d < r[i].best {
			r[i].best = d
		}
		// The fewest bytes of any run, like the best time: an allocation the scan did not make
		// (the runtime's, the test framework's) only ever adds.
		if b := after.TotalAlloc - before.TotalAlloc; r[i].bytes == 0 || b < r[i].bytes {
			r[i].bytes = b
		}
		r[i].found = count(ms)
		return d
	}
	// Six blocks of at least one run and 25 ms each, small then big: at least six runs per line.
	for block := 0; block < 6; block++ {
		for i := range r {
			var total time.Duration
			for tries := 0; tries < 1 || total < 25*time.Millisecond && tries < 50; tries++ {
				total += run(i)
			}
		}
	}
	s, b := r[0], r[1]
	if s.found < guardUnits || b.found < growthFactor*s.found {
		t.Fatalf("the second line must hold %dx the findings of the first, at least one per unit: %d then %d",
			growthFactor, s.found, b.found)
	}
	return float64(b.best) / float64(s.best), float64(b.bytes) / float64(s.bytes), s.found, b.found
}

// TestFramesStayLinear: wedge-reader swipes (two frames and two PANs each) on the guard line, 4 then
// 32 of them. Work on the whole line for each frame (a strings.ToLower of the line, or its camelCase
// split, redone per frame in appendFrameMatches) grows with the frames; see growthLimit.
func TestFramesStayLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping complexity test in -short mode")
	}
	swipe := track1(visa16, "%B", "?") + track2(visa16, ";", "?") + " "
	tr, br, small, big := growth(t, swipe, func(ms []detector.Match) int { f, _ := framesOf(ms); return len(f) })
	if tr > growthLimit || br > growthLimit {
		t.Errorf("%dx the frames (%d to %d) on one %d-byte line took %.2fx the time and %.2fx the bytes (limit %.1fx): "+
			"work on the whole line per frame?", growthFactor, small, big, guardLineBytes, tr, br, growthLimit)
	}
	t.Logf("%d to %d frames, time x%.2f, bytes x%.2f", small, big, tr, br)
}

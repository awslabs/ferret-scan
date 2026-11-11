// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package legacyole

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/richardlehane/msoleps"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/olefixture"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// The typed-property half of #915: a reported number, date or flag has no text in any stream, so the
// overwrite never found it, and the copy kept it while the run said "redacted". These tests build the
// value the way Office stores a custom Number (a VT_I4 in the second, user-defined section of
// DocumentSummaryInformation) and read the output back through msoleps, the decoder the extractor
// uses, so "gone" means gone to the next scan and not only to a byte grep that could never see it.

const typedReviewCycle int32 = 1928374650 // ten digits: reported as CUSTOM_PROPERTY, an identifier

// typedDoc is a .doc whose custom properties include the given typed values, beside a string custom
// property and a well-known one that must come through untouched.
func typedDoc(typed map[string]olefixture.TypedValue) []byte {
	return olefixture.MustBuild([]olefixture.Stream{
		{Name: olefixture.StreamWordDocument, Data: []byte("Quarterly review notes; nothing in the body is sensitive.\r")},
		{Name: olefixture.StreamDocSummaryInformation, Data: olefixture.DocSummaryInformationWithCustom(
			map[uint32]string{olefixture.PropCompany: "Fairbanks Holdings"},
			map[string]string{"ReviewNote": "kept as written"},
			typed,
		)},
	})
}

// customProps decodes the DocumentSummaryInformation stream of a container the way the extractor
// does, name -> trimmed rendering.
func customProps(t *testing.T, path string) map[string]string {
	t.Helper()
	streams := streamContents(t, path)
	raw, ok := streams["DocumentSummaryInformation"]
	if !ok {
		t.Fatalf("no DocumentSummaryInformation stream in %s: %v", path, keysOf(streams))
	}
	r, err := msoleps.NewFrom(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("msoleps cannot read the property stream: %v", err)
	}
	out := make(map[string]string, len(r.Property))
	for _, p := range r.Property {
		out[p.Name] = strings.TrimSpace(p.String())
	}
	return out
}

func customPropertyMatch(text string) detector.Match {
	return detector.Match{Text: text, Type: "CUSTOM_PROPERTY", LineNumber: 13, Confidence: 60, Validator: "metadata"}
}

// The headline: a VT_I4 custom property whose value was reported is zeroed in place under both
// strategies, its neighbours and the container stay as they were, and the audit entry says what was
// written. On the parent commit RedactDocument returned success with the four bytes untouched, so the
// first assertion fails there.
func TestRedaction_ZeroesAReportedNumericCustomProperty(t *testing.T) {
	src := writeFixture(t, typedDoc(map[string]olefixture.TypedValue{
		"ReviewCycleID": olefixture.Int32(typedReviewCycle),
		"PageBudget":    olefixture.Int32(12),
	}), "typed.doc")
	before := customProps(t, src)
	if before["ReviewCycleID"] != "1928374650" {
		t.Fatalf("fixture: ReviewCycleID decodes as %q, want 1928374650; every assertion below would be vacuous",
			before["ReviewCycleID"])
	}
	in, err := os.ReadFile(src) // #nosec G304 -- test-controlled temp path
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(in, []byte("1928374650")) || bytes.Contains(in, olefixture.UTF16LE("1928374650")) {
		t.Fatal("fixture: the digits are in the file as text, so this would not test the typed path")
	}

	r := NewLegacyOLERedactor(nil, nil)
	for _, strategy := range r.GetSupportedStrategies() {
		t.Run(strategy.String(), func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "redacted.doc")
			res, err := r.RedactDocument(src, out, []detector.Match{customPropertyMatch("1928374650")}, strategy)
			if err != nil {
				t.Fatalf("RedactDocument: %v", err)
			}
			after := customProps(t, out)
			if got := after["ReviewCycleID"]; got != "0" {
				t.Errorf("ReviewCycleID decodes as %q in the copy, want 0: the reported number survives", got)
			}
			for name, want := range map[string]string{"PageBudget": "12", "ReviewNote": "kept as written", "Company": "Fairbanks Holdings"} {
				if after[name] != want {
					t.Errorf("unreported property %s = %q in the copy, want %q: only the reported value may change", name, after[name], want)
				}
			}
			written, err := os.ReadFile(out) // #nosec G304 -- test-controlled temp path
			if err != nil {
				t.Fatal(err)
			}
			if len(written) != len(in) {
				t.Errorf("size changed from %d to %d bytes", len(in), len(written))
			}
			if diff := differingBytes(in, written); diff != 4 {
				t.Errorf("%d bytes differ, want 4: the VT_I4's own bytes and nothing else", diff)
			}
			if len(res.RedactionMap) != 1 {
				t.Fatalf("RedactionMap has %d entries, want 1", len(res.RedactionMap))
			}
			m := res.RedactionMap[0]
			if m.RedactedText != "0" || m.Metadata["position_method"] != "ole_typed_property_zeroed" || m.Masked {
				t.Errorf("audit entry = %+v: want redacted_text 0, position_method ole_typed_property_zeroed, not masked", m)
			}
		})
	}
}

// Every scalar kind Office writes for a custom property, and the integer widths beside them, is
// zeroed when its rendering is reported. The rendering is taken from msoleps itself, so the test
// asks for exactly what the extractor would report, whatever msoleps makes of the bytes (it reads a
// VT_R8's bits as an integer, for one).
func TestRedaction_ZeroesEveryTypedKind(t *testing.T) {
	cases := map[string]olefixture.TypedValue{
		"Int64":    olefixture.Int64(4111222333444),
		"Uint32":   olefixture.Uint32(3000000001),
		"Float64":  olefixture.Float64Bits(0x400A000000000000),
		"FileTime": olefixture.FileTimeValue(olefixture.FileTime(2019, 3, 14)),
		"Decimal":  {VT: olefixture.VTDecimal, Bytes: []byte{0, 0, 2, 0, 0, 0, 0, 0, 0x39, 0x30, 0, 0, 0, 0, 0, 0}},
	}
	for name, tv := range cases {
		t.Run(name, func(t *testing.T) {
			src := writeFixture(t, typedDoc(map[string]olefixture.TypedValue{name: tv}), "typed.doc")
			reported := customProps(t, src)[name]
			if reported == "" || reported == zeroRendering(tv.VT, len(tv.Bytes)) {
				t.Fatalf("fixture: %s renders as %q, which a zeroed value would read as too", name, reported)
			}
			out := filepath.Join(t.TempDir(), "redacted.doc")
			if _, err := NewLegacyOLERedactor(nil, nil).RedactDocument(src, out,
				[]detector.Match{customPropertyMatch(reported)}, redactors.RedactionSimple); err != nil {
				t.Fatalf("RedactDocument: %v", err)
			}
			if got := customProps(t, out)[name]; got != zeroRendering(tv.VT, len(tv.Bytes)) {
				t.Errorf("%s reads %q in the copy, want its zero %q", name, got, zeroRendering(tv.VT, len(tv.Bytes)))
			}
		})
	}
}

// The code page, locale and behaviour properties are never zeroed, even when a reported value reads
// the same: zeroing the code page changes how every string in the set decodes. The same digits in the
// body are still masked, and the file is written.
func TestTypedPassSparesTheCodePage(t *testing.T) {
	pkg := olefixture.MustBuild([]olefixture.Stream{
		{Name: olefixture.StreamWordDocument, Data: []byte("Reference 1252 appears in the body text.\r")},
		{Name: olefixture.StreamDocSummaryInformation, Data: olefixture.DocSummaryInformationWithCustom(
			nil, map[string]string{"ReviewNote": "kept as written"}, nil)},
	})
	src := writeFixture(t, pkg, "codepage.doc")
	out := filepath.Join(t.TempDir(), "redacted.doc")
	if _, err := NewLegacyOLERedactor(nil, nil).RedactDocument(src, out,
		[]detector.Match{{Text: "1252", Type: "BANK_ROUTING", LineNumber: 1}}, redactors.RedactionSimple); err != nil {
		t.Fatalf("RedactDocument: %v", err)
	}
	if got := customProps(t, out)["CodePage"]; got != "1252" {
		t.Errorf("CodePage reads %q in the copy, want 1252: the code page is the set's, not a value", got)
	}
	if streamContents(t, out)["WordDocument"] == nil || bytes.Contains(streamContents(t, out)["WordDocument"], []byte("1252")) {
		t.Error("the reported digits survive in the body")
	}
}

// A hostile property stream must not crash the walk or yield a value outside the stream: every count
// and offset is the file's. Truncations of a real stream, every 32-bit field forced to its extremes,
// and seeded random corruption.
func TestTypedValuesInStreamToleratesHostileStreams(t *testing.T) {
	valid := olefixture.DocSummaryInformationWithCustom(
		map[uint32]string{olefixture.PropCompany: "Fairbanks Holdings"},
		map[string]string{"ReviewNote": "kept as written"},
		map[string]olefixture.TypedValue{"ReviewCycleID": olefixture.Int32(typedReviewCycle)},
	)
	check := func(b []byte) {
		t.Helper()
		for _, tv := range typedValuesInStream(0, b) {
			if tv.at < 0 || tv.width <= 0 || tv.at+tv.width > len(b) {
				t.Fatalf("value at %d width %d outside a %d-byte stream", tv.at, tv.width, len(b))
			}
		}
	}
	if len(typedValuesInStream(0, valid)) == 0 {
		t.Fatal("the valid stream yields no typed value; the hostile cases below would be vacuous")
	}
	for n := 0; n <= len(valid); n++ {
		check(valid[:n])
	}
	for off := 0; off+4 <= len(valid); off += 4 {
		for _, v := range []uint32{0, 0x7FFFFFFF, 0x80000000, 0xFFFFFFF0, 0xFFFFFFFF} {
			b := append([]byte(nil), valid...)
			binary.LittleEndian.PutUint32(b[off:], v)
			check(b)
		}
	}
	rng := rand.New(rand.NewSource(915)) // #nosec G404 -- deterministic corruption, not security
	for i := 0; i < 2000; i++ {
		b := append([]byte(nil), valid...)
		for k := 0; k < 1+rng.Intn(8); k++ {
			b[rng.Intn(len(b))] = byte(rng.Intn(256))
		}
		check(b)
	}
}

// differingBytes counts the positions at which two equal-length byte slices differ.
func differingBytes(a, b []byte) int {
	n := 0
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			n++
		}
	}
	return n
}

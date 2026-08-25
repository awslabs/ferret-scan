// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractexiflib

import (
	"strings"
	"testing"
)

// #481: a percent-encoded chunk payload costs recall AND precision at the same time.
//
// #480 made the chunk readable; this is the encoding layer behind it. Decoding is unusual in being a
// win on both axes, which is why it is the fix rather than a trade:
//
//	stored in the chunk : Employee%20SSN%20449-87-4100     -> 0 findings
//	the same value      : Employee SSN 449-87-4100         -> SSN
//
// `%20` leaves characters glued to the value so no pattern matches, and only reported findings reach
// the redactor, so that is a silent miss. In the other direction the encoded form generates false
// positives, because percent-encoded XML fragments read as codes.
//
// MEASURED end to end on 2,500 real PNGs from this host, before and after:
//
//	findings                526 -> 130
//	LOST   425, every one RECOVERY_CODES at MEDIUM -- the artefact family, and ZERO in the HIGH band
//	GAINED  29: 6 IP_ADDRESS at HIGH (dotted quads out of decoded network diagrams, genuine),
//	            1 INTELLECTUAL_PROPERTY, and 22 PHONE at LOW/MEDIUM on a bare six-digit run,
//	            which are NEW false positives and are recorded here rather than glossed over.

// TestPercentEncodedChunkIsDecoded is the recall half of the reported defect.
func TestPercentEncodedChunkIsDecoded(t *testing.T) {
	png := pngWith(pngChunk("tEXt", []byte("mxfile\x00Employee%20SSN%20449-87-4100")))
	tags := tagsFromPNG(t, png)

	got := tags["PNG_mxfile"]
	if got != "Employee SSN 449-87-4100" {
		t.Errorf("chunk text = %q, want %q. Undecoded, `%%20` glues characters to the value so no "+
			"pattern matches it, and an unreported value is never redacted.", got, "Employee SSN 449-87-4100")
	}
}

// TestPercentEncodedXMLPayloadIsDecoded is the precision half, and the real-world shape.
//
// draw.io writes the diagram source into a tEXt chunk keyed `mxfile`, run through
// encodeURIComponent. The `%3C`/`%22` runs are what the validators were reading as codes.
func TestPercentEncodedXMLPayloadIsDecoded(t *testing.T) {
	encoded := "%3Cmxfile%3E%3Cdiagram%20name%3D%22Page%22%3ECall%20415-555-0132%3C%2Fdiagram%3E%3C%2Fmxfile%3E"
	png := pngWith(pngChunk("tEXt", []byte("mxfile\x00"+encoded)))
	tags := tagsFromPNG(t, png)

	got := tags["PNG_mxfile"]
	if strings.Contains(got, "%3C") || strings.Contains(got, "%22") {
		t.Errorf("payload still holds percent-encoded markup: %q. Those runs are what the "+
			"validators read as codes -- 425 RECOVERY_CODES came from this family.", got)
	}
	if !strings.Contains(got, "<mxfile>") || !strings.Contains(got, "Call 415-555-0132") {
		t.Errorf("payload did not decode to its markup and text: %q", got)
	}
}

// TestAChunkWithNoValidEscapeIsUntouched is the must-not-mangle direction.
//
// A tEXt value may legitimately contain a percent sign, so the gate exists to leave it alone. The
// last case is the shape that actually occurs: an Adobe XMP packet whose `%` sits inside a URI.
// MEASURED -- those are the only two `%`-bearing real chunks on this host that are not draw.io
// payloads, and a decode leaves them byte-identical, because the `%` is not followed by two hex digits.
func TestAChunkWithNoValidEscapeIsUntouched(t *testing.T) {
	for _, text := range []string{
		"Discount 50% off everything",
		"progress: 100% complete",
		"a bare % on its own",
		"trailing percent at the end %",
		"almost an escape %2 and %Z9 and %",
		`<rdf:li xml:lang="x-default">100% cotton</rdf:li>`,
	} {
		t.Run(text, func(t *testing.T) {
			png := pngWith(pngChunk("tEXt", []byte("Comment\x00"+text)))
			if got := tagsFromPNG(t, png)["PNG_Comment"]; got != text {
				t.Errorf("text was altered: %q -> %q. A percent sign that is not an escape must "+
					"survive, or ordinary metadata is corrupted.", text, got)
			}
		})
	}
}

// TestDecodeIsLenientAboutOneBadEscape is why this is not url.PathUnescape.
//
// PathUnescape fails the WHOLE string on a single malformed escape. A payload that is only partly
// encoded -- markup beside a literal "100% width" -- would then stay entirely encoded, turning a
// precision fix into a recall miss. The valid escapes must resolve and the invalid one must survive.
func TestDecodeIsLenientAboutOneBadEscape(t *testing.T) {
	in := "%3Cnote%3ESSN%20449-87-4100%20at%20100%%20load%3C%2Fnote%3E"
	got := decodePercentEncoded(in)

	if !strings.Contains(got, "SSN 449-87-4100") {
		t.Errorf("a valid escape beside an invalid one did not resolve: %q. url.PathUnescape would "+
			"abandon the whole string here and the value would stay hidden.", got)
	}
	if !strings.Contains(got, "100%") {
		t.Errorf("the bare percent was not preserved: %q", got)
	}
}

// TestPlusIsNotDecodedAsASpace keeps this percent decoding rather than form decoding.
//
// url.QueryUnescape turns '+' into a space, which is application/x-www-form-urlencoded behaviour and
// not what a percent-encoded document means. A diagram label may contain a literal plus.
func TestPlusIsNotDecodedAsASpace(t *testing.T) {
	in := "%3Cnode%3EA+B+C%3C%2Fnode%3E"
	got := decodePercentEncoded(in)
	if !strings.Contains(got, "A+B+C") {
		t.Errorf("decoded %q, which lost the literal plus signs. That is form encoding, not "+
			"percent encoding.", got)
	}
}

// TestGateAndDecoderAgree pins the property that keeps the fast path honest.
//
// hasPercentEscape exists so a chunk that is not encoded never pays for a copy. If it admitted more
// than the decoder resolves the copy would be for nothing; if it admitted less, a value would be left
// encoded and unseen. So the gate must be true exactly when decoding changes something.
func TestGateAndDecoderAgree(t *testing.T) {
	for _, s := range []string{
		"", "plain text", "50% off", "%", "%2", "%ZZ", "trailing %",
		"%20", "a%20b", "%3C%3E", "%3c%3e", "mixed %20 and bare % here",
		"100%2B", "%00", "%7F", "already decoded < >",
	} {
		t.Run(s, func(t *testing.T) {
			changed := decodePercentEncoded(s) != s
			if gate := hasPercentEscape(s); gate != changed {
				t.Errorf("hasPercentEscape(%q) = %v but decoding %s the text. The gate and the "+
					"decoder must agree, or the fast path either copies for nothing or hides a value.",
					s, gate, map[bool]string{true: "CHANGED", false: "did not change"}[changed])
			}
		})
	}
}

// TestBothHexCasesDecode covers encoder disagreement.
//
// Go's url.QueryEscape emits upper case; some JavaScript and Python paths emit lower. A decoder that
// handled one would silently leave half the corpus encoded.
func TestBothHexCasesDecode(t *testing.T) {
	for _, in := range []string{"a%3Cb", "a%3cb", "a%2Fb", "a%2fb"} {
		t.Run(in, func(t *testing.T) {
			if got := decodePercentEncoded(in); strings.Contains(got, "%") {
				t.Errorf("decoded %q -> %q, still holding an escape", in, got)
			}
		})
	}
}

// TestDecodingAppliesToCompressedChunksToo is the case a byte scan could never reach.
//
// zTXt is deflated, so the encoded payload is not in the file's bytes at all. Decoding has to happen
// after inflation, which is why it sits at the extractPNGText boundary rather than in a raw scan.
func TestDecodingAppliesToCompressedChunksToo(t *testing.T) {
	body := deflate(t, []byte("Employee%20SSN%20449-87-4100"))
	png := pngWith(pngChunk("zTXt", append([]byte("mxfile\x00\x00"), body...)))

	if got := tagsFromPNG(t, png)["PNG_mxfile"]; got != "Employee SSN 449-87-4100" {
		t.Errorf("compressed chunk text = %q, want the decoded form. A percent-encoded payload "+
			"inside a deflated chunk is invisible to every byte scan in this package.", got)
	}
}

// TestFullyEncodedChunkDecodesCleanly covers the cheap case: every character respelled.
func TestFullyEncodedChunkDecodesCleanly(t *testing.T) {
	png := pngWith(pngChunk("tEXt", []byte("mxfile\x00"+percentEncodeAll("Employee SSN 449-87-4100"))))

	got := tagsFromPNG(t, png)["PNG_mxfile"]
	if got != "Employee SSN 449-87-4100" {
		t.Errorf("fully-encoded chunk text = %q, want the decoded form", got)
	}
	if strings.Contains(got, "%") {
		t.Errorf("an escape survived in %q", got)
	}
}

// TestDecodingHappensBeforeTheTotalCap pins the ORDERING, and it has to be big to do so.
//
// A first version of this test used a short payload and was VACUOUS: a mutation moving the decode to
// after the cap survived it, because with a payload far under the cap the two orderings are
// indistinguishable. The cap is what makes the ordering observable, so the fixture has to cross it.
//
// Why the ordering matters: the budget counts the text it accumulates, and an encoded payload is up to
// three times the size of its decoded form. Counting the ENCODED length therefore exhausts the 4MB
// total on roughly a third of the real content, and the chunks after that point are dropped
// altogether -- real values lost to an accounting artefact. Truncating first can also cut a `%XX`
// sequence in half.
//
// Five chunks, each at the 1MB per-chunk read cap, so 5MB raw crosses the 4MB total. Decoded first
// they sum to about 1.7MB and all five fit; capped first, the later ones are lost. The SSN sits in the
// LAST chunk, which is the one that disappears.
func TestDecodingHappensBeforeTheTotalCap(t *testing.T) {
	const perChunk = maxPNGTextChunkBytes // 1MB, the per-chunk read cap

	// "%41" decodes to "A", so a 1MB run of it decodes to about 333KB.
	filler := strings.Repeat("%41", perChunk/3)

	chunks := make([][]byte, 0, 5)
	for i := 0; i < 4; i++ {
		chunks = append(chunks, pngChunk("tEXt", []byte("Filler"+string(rune('A'+i))+"\x00"+filler)))
	}
	// The last chunk carries the value, encoded, and is short.
	chunks = append(chunks, pngChunk("tEXt", []byte("mxfile\x00"+percentEncodeAll("Employee SSN 449-87-4100"))))

	tags := tagsFromPNG(t, pngWith(chunks...))

	got, present := tags["PNG_mxfile"]
	if !present {
		t.Fatalf("the last chunk was dropped entirely. Four 1MB ENCODED fillers exhausted the %d-byte "+
			"total budget, which they only do if the budget counts the encoded length -- decoded they "+
			"sum to about 1.7MB and leave plenty of room. tags present: %d", maxPNGTextTotalBytes, len(tags))
	}
	if got != "Employee SSN 449-87-4100" {
		t.Errorf("last chunk text = %q, want the fully decoded value. A cap applied before decoding "+
			"also risks cutting a %%XX sequence in half.", got)
	}
}

// percentEncodeAll respells every byte of s as an uppercase %XX escape.
func percentEncodeAll(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s) * 3)
	for i := 0; i < len(s); i++ {
		b.WriteByte('%')
		b.WriteByte(hex[s[i]>>4])
		b.WriteByte(hex[s[i]&0xF])
	}
	return b.String()
}

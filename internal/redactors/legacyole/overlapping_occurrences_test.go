// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package legacyole

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/olefixture"
	metaextractofficelib "github.com/awslabs/ferret-scan/v2/internal/preprocessors/meta-extractors/meta-extract-officelib"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
	"github.com/awslabs/ferret-scan/v2/internal/redactors/tagmeta"
)

// #916: under format_preserving a reported value survived 18 times in the copy of the public
// poi--PPT95.ppt, while simple left none. The value is a 9-digit run inside a binary pattern of
// "1211" repeated, so it occurs once every four bytes and each occurrence overlaps the next. The
// overwrite resumed after the bytes it had written, so the occurrence starting inside the previous
// one was skipped; simple's mask destroyed it anyway, but the format-preserving rendering keeps the
// value's last four characters, and the one-byte overlap with the next-but-one occurrence was among
// them. That occurrence was left exactly as it was.
//
// replaceLogical now resumes one byte after each occurrence it rewrites, so every occurrence present
// when its value's pass reaches it is rewritten. That is enough because a rendering writes '*' or the
// character already at that position, never a new one (replacement.FormatPreserving keeps characters
// in place and masks the rest; a rendering that does not fit falls back to a mask): a rewrite can
// destroy an occurrence of any value but cannot create one. The production comment is kept to the
// lines it replaced so the self-scan ledger's line-anchored rules below it in redactor.go do not move.

const overlapValue = "121112111" // "1211" "1211" "1": in a run of "1211" it starts every 4 bytes

// overlapRun is n repetitions of "1211" and a closing "1", in which overlapValue occurs at every
// multiple of four up to 4(n-2). The old scan rewrote the occurrences at 0, 12, 24, ..., each
// rendering "*****2111" keeping the first digit of the occurrence 8 bytes on; that occurrence was
// destroyed by the next rewrite when there was one, and left intact at the end of the run when there
// was not, which is the case for n = 4, 7, 10.
func overlapRun(n int) string { return strings.Repeat("1211", n) + "1" }

// overlapRuns is three such runs, separated so no occurrence spans two of them.
func overlapRuns() string { return overlapRun(4) + " " + overlapRun(7) + " " + overlapRun(10) }

// The unit the issue asks for: the same 9-byte pattern at overlapping offsets of one stream is
// rewritten at every offset. On the parent commit one occurrence per run survives under
// format_preserving.
func TestReplaceLogicalRewritesOverlappingOccurrences(t *testing.T) {
	for _, strategy := range []redactors.RedactionStrategy{redactors.RedactionFormatPreserving, redactors.RedactionSimple} {
		t.Run(strategy.String(), func(t *testing.T) {
			buf := []byte("head " + overlapRuns() + " tail")
			if before := countOverlapping(buf, overlapValue); before < 12 {
				t.Fatalf("fixture holds %d occurrence(s); the overlap case needs several per run", before)
			}
			repl := tagmeta.SameLengthRendering(overlapValue, "SSN", strategy).Text
			n := replaceLogical(buf, singleFragmentStream(buf), buf, []byte(overlapValue), []byte(repl))
			if left := countOverlapping(buf, overlapValue); left != 0 {
				t.Errorf("%d of the overlapping occurrences survive under %s (rendering %q, %d rewritten): "+
					"a reported value left verbatim in a copy reported as redacted", left, strategy, repl, n)
			}
			if !strings.HasPrefix(string(buf), "head ") || !strings.HasSuffix(string(buf), " tail") {
				t.Errorf("bytes outside the occurrences changed: %q", buf)
			}
		})
	}
}

// The issue's first hypothesis, pinned: a repeated-digit 9-digit value through the format-preserving
// SSN rendering never comes out as itself. It holds on the parent commit too, so the rendering was
// not the defect; this keeps it that way.
func TestFormatPreservingSSNRenderingNeverEqualsTheValue(t *testing.T) {
	for _, v := range []string{"111111111", "000000000", "999999999", overlapValue, "121121112", "111211211"} {
		r := tagmeta.SameLengthRendering(v, "SSN", redactors.RedactionFormatPreserving).Text
		if r == v || len(r) != len(v) {
			t.Errorf("rendering of %q = %q: it must differ and keep the length", v, r)
		}
	}
}

// End to end through a real container, both strategies: the pattern at overlapping offsets AND at
// two separate offsets of one PowerPoint stream, in 8-bit and in UTF-16LE, is gone from the copy and
// from the text the extractor recovers from it (what the next scan's validators would read).
func TestRedaction_RewritesEveryOccurrenceOfAnOverlappingPattern(t *testing.T) {
	body := "Slide 1 " + overlapValue + " notes.\r" + overlapRuns() + "\rSlide 2 " + overlapValue + "\r"
	pkg := olefixture.MustBuild([]olefixture.Stream{
		{Name: olefixture.StreamPowerPoint, Data: append([]byte(body), olefixture.UTF16LE(overlapRun(7))...)},
	})
	src := writeFixture(t, pkg, "overlap.ppt")
	if countOverlapping(pkg, overlapValue) < 14 || !bytes.Contains(pkg, olefixture.UTF16LE(overlapValue)) {
		t.Fatal("the fixture does not carry the overlapping occurrences it is meant to")
	}

	r := NewLegacyOLERedactor(nil, nil)
	for _, strategy := range r.GetSupportedStrategies() {
		t.Run(strategy.String(), func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "redacted.ppt")
			res, err := r.RedactDocument(src, out, []detector.Match{
				{Text: overlapValue, Type: "SSN", LineNumber: 1, Confidence: 50},
			}, strategy)
			if err != nil || res == nil || !res.Success {
				t.Fatalf("RedactDocument: %v", err)
			}
			written, err := os.ReadFile(out) // #nosec G304 -- test-controlled temp path
			if err != nil {
				t.Fatal(err)
			}
			if len(written) != len(pkg) {
				t.Fatalf("size changed from %d to %d bytes", len(pkg), len(written))
			}
			if n := countOverlapping(written, overlapValue); n != 0 {
				t.Errorf("%d occurrence(s) survive in the copy under %s", n, strategy)
			}
			if n := countOverlapping(written, string(olefixture.UTF16LE(overlapValue))); n != 0 {
				t.Errorf("%d UTF-16LE occurrence(s) survive in the copy under %s", n, strategy)
			}

			md, err := metaextractofficelib.ExtractMetadata(out)
			if err != nil {
				t.Fatalf("the copy no longer extracts: %v", err)
			}
			if text := md.Properties["LegacyBodyText"]; strings.Contains(text, overlapValue) {
				t.Errorf("the text a re-scan reads from the copy still holds the value under %s", strategy)
			}
		})
	}
}

// countOverlapping counts occurrences of v in b, overlapping ones included: bytes.Count does not.
func countOverlapping(b []byte, v string) int {
	n := 0
	for i := 0; i+len(v) <= len(b); i++ {
		if string(b[i:i+len(v)]) == v {
			n++
		}
	}
	return n
}

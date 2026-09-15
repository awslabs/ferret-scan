// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ipaddress

import (
	"fmt"
	"strings"
	"testing"
)

// The producer-signature case (#681): a four-part software version in a document's own
// provenance metadata, reported as an address in the band reviewers read.
//
// # Why this is not just one stray finding
//
// It is unconditional. Every .docx, .xlsx, .pptx, .odt, .ods and .odp written by LibreOffice
// carries the same signature — OOXML in docProps/app.xml <Application>, ODF in meta.xml
// <meta:generator>, both emitted by the metadata preprocessor as one "Application: ..." line —
// so a LibreOffice user got one guaranteed false positive in EVERY document, at 75, on a
// document with no PII in it. Measured on all six formats: 10 of 10 containers, one
// IP_ADDRESS each, and in a clean document that was HALF of all findings.
//
// It also corrupted measurement. During #670 verification a probe read "the same 2 findings as
// the unplanted base file" as a meaningful zero-delta baseline; those two findings were this
// one plus the APPLICATION_INFO from the same element, so the baseline was vacuous and nearly
// hid a genuine leak.
//
// # Why a ceiling and not a veto, and why the predicate is the SHAPE
//
// #681 proposed vetoing a dotted quad found in a producer/version metadata FIELD. Neither half
// of that is available or safe here:
//
//   - The field is not knowable. A metadata value reaches this validator as an ordinary line of
//     the document text: measured, a value in docProps/app.xml and the identical text written as
//     a body paragraph produce byte-identical findings, both with validation_path "document".
//     So "in a metadata field" would really mean "on a line beginning with a label", which a
//     document's own body can write. The secrets validator records why that direction is wrong
//     (a negative list of identifier field names lets an author suppress a real value by
//     relabelling), and ipaddress deliberately has no "header contradicts" arm for the same
//     reason.
//   - A veto would remove the value from the report, and only reported findings reach the
//     redactor.
//
// So the predicate is the RFC 9110 product-token shape that isProductVersionAt already tests —
// bytes adjacent to the value, which an author cannot reach by relabelling a line — and the
// consequence is a ceiling inside LOW rather than a drop.
func TestAProducerSignatureLeavesTheReviewersBand(t *testing.T) {
	// The real strings, as the metadata preprocessor emits them. OOXML and ODF differ in the
	// XML element they come from but normalise to the same "Application: " label, which is why
	// one rule covers all six container formats.
	lines := []struct {
		name string
		line string
	}{
		{"OOXML docProps/app.xml <Application>", "Application: LibreOffice/26.8.0.3$MacOSX_AARCH64 LibreOffice_project/bce0998afefdbc355585ca324285661a2170ba77"},
		{"ODF meta.xml <meta:generator>", "Application: LibreOffice/25.2.5.2$Linux_X86_64 LibreOffice_project/aa8c2d0d1d1a4f0e"},
		// NOT OpenOffice. Its signature is "OpenOffice.org/3.4.1$Unix
		// OpenOffice.org_project/341m1", and 3.4.1 has three parts, not four — it is not a
		// dotted quad and was never reported. #681 names "LibreOffice/OpenOffice"; only the
		// four-part producers collide, which is why the fixtures here are all four-part.
		{"a four-part version with a long build tail", "Application: LibreOffice/7.6.7.2$Windows_X86_64 LibreOffice_project/aa8c2d0d1d1a4f0e6d5a"},
		{"a Generator label", "Generator: LibreOffice/24.8.4.2$MacOSX_AARCH64"},
	}
	for _, tc := range lines {
		t.Run(tc.name, func(t *testing.T) {
			value := productVersionIn(t, tc.line)
			got := confidenceOf(t, tc.line, value)
			if got < 0 {
				t.Fatalf("%s was not reported at all. This must DEMOTE, not drop: only a "+
					"reported finding is handed to the redactor, and the same shape occurs on "+
					"genuine addresses in path segments.", value)
			}
			if got >= 60 {
				t.Errorf("%s reported at %v — MEDIUM (the bands are 90 and 60), so it still "+
					"reaches `--confidence high,medium`. For a LibreOffice user this line is in "+
					"every document they write, and it is never an address (#681).", value, got)
			}
			if got != productVersionCeiling {
				t.Errorf("%s reported at %v, want %v", value, got, productVersionCeiling)
			}
		})
	}
}

// TestAStructuralSuffixStillOutranksTheProducerCeiling is the precedence guard.
//
// A port or a CIDR length is WELDED to the value: nothing that merely precedes the value may
// demote it, because "Gateway/52.94.236.248:8080" is an address whatever comes before it. This
// ordering already existed for ambiguousShapeCap and the lower ceiling must not quietly take it
// over — which it would if the new branch were placed before the suffix test.
func TestAStructuralSuffixStillOutranksTheProducerCeiling(t *testing.T) {
	cases := []struct {
		name  string
		line  string
		value string
	}{
		{"product token then a port", "Gateway/52.94.236.248:8080 is up", "52.94.236.248"},
		{"product token then a CIDR", "Route via Acme/52.94.236.248/24 today", "52.94.236.248"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := confidenceOf(t, tc.line, tc.value)
			if got < 0 {
				t.Fatalf("%s was not reported at all", tc.value)
			}
			if got <= productVersionCeiling {
				t.Errorf("%s reported at %v, at or below the product-version ceiling %v.\n"+
					"A port or CIDR suffix is welded to the value and must outrank a rule that "+
					"reads what PRECEDES it.", tc.value, got, productVersionCeiling)
			}
			if got < 90 {
				t.Errorf("%s reported at %v; a suffixed address is unambiguous and should reach "+
					"HIGH", tc.value, got)
			}
		})
	}
}

// TestAGenuineAddressIsNotDemotedByTheProducerCeiling is the recall half.
//
// A precision rule that also silences real addresses is worse than the noise it removes. The
// URL-authority case is the one that would break first if the rule read "any '/' before the
// value" instead of "a LETTER, then '/'": in "https://52.94.236.248" the byte before the quad
// is itself a '/', which is exactly why the rule inspects the character before the slash.
func TestAGenuineAddressIsNotDemotedByTheProducerCeiling(t *testing.T) {
	cases := []struct {
		name  string
		line  string
		value string
	}{
		{"URL authority", "See https://52.94.236.248/health", "52.94.236.248"},
		{"address in prose", "Server endpoint is 52.94.236.248 for the region", "52.94.236.248"},
		{"labelled address", "Gateway address: 52.94.236.248", "52.94.236.248"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := confidenceOf(t, tc.line, tc.value)
			if got < 0 {
				t.Fatalf("%s was not reported at all — a recall regression", tc.value)
			}
			if got <= productVersionCeiling {
				t.Errorf("%s reported at %v, at or below the product-version ceiling %v: the "+
					"rule has reached a genuine address.", tc.value, got, productVersionCeiling)
			}
		})
	}
}

// TestTheProducerCeilingIsInsideLow pins the number against the band boundaries rather than
// against itself, so a later edit to the constant cannot silently put it back in MEDIUM.
func TestTheProducerCeilingIsInsideLow(t *testing.T) {
	if productVersionCeiling >= 60 {
		t.Errorf("productVersionCeiling = %v, which is MEDIUM or above (the bands are 90 and "+
			"60). The whole point of #681 is that 75 was inside MEDIUM, where reviewers look.",
			productVersionCeiling)
	}
	if productVersionCeiling >= ambiguousShapeCap {
		t.Errorf("productVersionCeiling = %v is not below ambiguousShapeCap = %v; a value whose "+
			"neighbouring bytes identify it as a version cannot be held to a WEAKER bound than a "+
			"context-free one", productVersionCeiling, ambiguousShapeCap)
	}
	if productVersionCeiling <= 0 {
		t.Errorf("productVersionCeiling = %v; clampToCeiling ignores a ceiling <= 0, which would "+
			"make this a silent no-op", productVersionCeiling)
	}
}

// productVersionIn returns the dotted quad that follows the first "<letter>/" in line, so a
// case states its input once instead of repeating the value.
func productVersionIn(t *testing.T, line string) string {
	t.Helper()
	for i := 1; i < len(line); i++ {
		if line[i] != '/' {
			continue
		}
		c := line[i-1]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			continue
		}
		rest := line[i+1:]
		end := strings.IndexFunc(rest, func(r rune) bool {
			return !(r >= '0' && r <= '9' || r == '.')
		})
		if end < 0 {
			end = len(rest)
		}
		cand := strings.TrimRight(rest[:end], ".")
		if strings.Count(cand, ".") == 3 {
			return cand
		}
	}
	t.Fatalf("no product-token dotted quad in %q — the fixture does not exercise the rule", line)
	return ""
}

// TestProductVersionInFindsTheValue keeps the helper above from being the thing that fails.
//
// A helper that silently returned "" would make every want in this file compare against a
// value that was never reported, and confidenceOf would return -1 for a reason unrelated to
// the rule.
func TestProductVersionInFindsTheValue(t *testing.T) {
	got := productVersionIn(t, "Application: LibreOffice/26.8.0.3$MacOSX_AARCH64 x")
	if got != "26.8.0.3" {
		t.Errorf("productVersionIn = %q, want %q", got, "26.8.0.3")
	}
	if _, err := fmt.Sscan(got); err != nil {
		t.Fatalf("unscannable: %v", err)
	}
}

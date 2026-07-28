// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"testing"
)

// The secrets validator finds a single secret through several independent
// detection paths, and every path used to append its own finding. One
// `github_token = "ghp_…"` line was reported three times (the ghp_ provider
// literal, the token assignment pattern, and the base64 entropy pattern), which
// inflates finding counts, writes byte-identical suppression rules for one leak,
// and burns a reviewer's time re-triaging the same value.
//
// The distinction that matters is between one secret matched several ways and
// the same value genuinely written twice on a line. Those are indistinguishable
// in detector.Match (no offset field), so arbitration happens on byte spans
// inside the validator, before that information is discarded.
//
// Provider-prefixed fixtures are assembled with buildTestToken rather than
// written as literals: the literal forms are shaped exactly like live
// credentials, so GitHub push protection rejects them (it blocked this file
// once already). The values are synthetic — do not "simplify" them back.

// TestValidateContent_NoDuplicateSpansPerLine locks the collapse. Each line here
// holds exactly one secret, so exactly one finding per line is correct.
func TestValidateContent_NoDuplicateSpansPerLine(t *testing.T) {
	v := NewValidator()

	cases := []struct {
		name string
		line string
		want string // expected finding Type
	}{
		// AKIA literal + api_?key assignment pattern claim the same bytes.
		{"aws access key in assignment", `apiKey = "AKIAIOSFODNN7EXAMPLE"`, "AWS_ACCESS_KEY"},
		// ghp_ literal + token assignment + base64 entropy: three claims.
		{"github token in assignment", `github_token = "` + buildTestToken("ghp_", "zyxwvu9876543210TSRQPONMLKJIHGFEDCBA") + `"`, "GITHUB_TOKEN"},
		{"stripe key in assignment", `stripe = "` + buildTestToken("sk_live_", "QWERTYuiop1234567890zxcv") + `"`, "STRIPE_API_KEY"},
		{"google api key in assignment", `gcp_api_key = "` + buildTestToken("AIza", "SyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe") + `"`, "GOOGLE_CLOUD_API_KEY"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matches, err := v.ValidateContent(tc.line, "config.txt")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) != 1 {
				for i, m := range matches {
					t.Logf("  [%d] type=%s conf=%.0f method=%v", i, m.Type, m.Confidence, m.Metadata["detection_method"])
				}
				t.Fatalf("one secret on the line, got %d findings (want 1)", len(matches))
			}
			if matches[0].Type != tc.want {
				t.Errorf("Type = %q, want %q", matches[0].Type, tc.want)
			}
		})
	}
}

// TestValidateContent_RepeatedValueOnOneLineStillReportedTwice is the guard that
// keeps the dedup honest. Collapsing on (type, line, text) — the only keys the
// emitted finding carries — would silently merge these two into one and
// under-report a line that really does leak the value twice. Byte spans are what
// tell the two situations apart.
func TestValidateContent_RepeatedValueOnOneLineStillReportedTwice(t *testing.T) {
	v := NewValidator()

	const line = `a = "AKIAIOSFODNN7EXAMPLE" and b = "AKIAIOSFODNN7EXAMPLE"`
	matches, err := v.ValidateContent(line, "config.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	if len(matches) != 2 {
		for i, m := range matches {
			t.Logf("  [%d] type=%s conf=%.0f method=%v", i, m.Type, m.Confidence, m.Metadata["detection_method"])
		}
		t.Fatalf("two distinct occurrences on the line, got %d findings (want 2)", len(matches))
	}
	for _, m := range matches {
		if m.Type != "AWS_ACCESS_KEY" {
			t.Errorf("Type = %q, want AWS_ACCESS_KEY", m.Type)
		}
	}
}

// TestValidateContent_SpecificTypeWinsOverGenericOnSameSpan covers the
// cross-path collision where the two claims disagree about what they found. A
// quoted 40-char AWS secret is matched by the context-gated AWS path
// (AWS_SECRET_ACCESS_KEY, high confidence) and by the generic entropy path
// (API_KEY_OR_SECRET, lower confidence). Reporting both double-counts one leak;
// dropping the specific one would be a downgrade, so the stronger claim must be
// the survivor.
func TestValidateContent_SpecificTypeWinsOverGenericOnSameSpan(t *testing.T) {
	v := NewValidator()

	const content = "aws_secret_access_key = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYzQqWeRtYuI\"\n"
	matches, err := v.ValidateContent(content, "credentials")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	if len(matches) != 1 {
		for i, m := range matches {
			t.Logf("  [%d] type=%s conf=%.0f method=%v", i, m.Type, m.Confidence, m.Metadata["detection_method"])
		}
		t.Fatalf("one secret, got %d findings (want 1)", len(matches))
	}
	if got := matches[0].Type; got != "AWS_SECRET_ACCESS_KEY" {
		t.Errorf("Type = %q, want AWS_SECRET_ACCESS_KEY (the specific claim must not lose to the generic one)", got)
	}
}

// TestValidateContent_DedupDoesNotDropSecretsAcrossLines guards the leak-safe
// direction: collapsing same-span claims must not reduce which lines report a
// secret. Every line here holds a different secret and every one must survive.
func TestValidateContent_DedupDoesNotDropSecretsAcrossLines(t *testing.T) {
	v := NewValidator()

	content := `apiKey = "AKIAIOSFODNN7EXAMPLE"` + "\n" +
		`github_token = "` + buildTestToken("ghp_", "zyxwvu9876543210TSRQPONMLKJIHGFEDCBA") + `"` + "\n" +
		`stripe = "` + buildTestToken("sk_live_", "QWERTYuiop1234567890zxcv") + `"` + "\n" +
		`gcp_api_key = "` + buildTestToken("AIza", "SyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe") + `"` + "\n" +
		`password = "Tr0ub4dor&3xKcd9plus"` + "\n" +
		`token = "Nq7Vb2Xm9Ld4Rt6Yw1Zs8Kj3Hf5Gp0C"` + "\n" +
		`plain AKIAIOSFODNN7EXAMPLE bare` + "\n"
	matches, err := v.ValidateContent(content, "config.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}

	linesWithFindings := make(map[int]int)
	for _, m := range matches {
		linesWithFindings[m.LineNumber]++
	}
	for line := 1; line <= 7; line++ {
		if linesWithFindings[line] == 0 {
			t.Errorf("line %d reports no secret; the dedup must not drop coverage", line)
		}
		if n := linesWithFindings[line]; n > 1 {
			t.Errorf("line %d reports %d findings, want 1", line, n)
		}
	}
	if len(matches) != 7 {
		t.Errorf("total findings = %d, want 7 (one per line)", len(matches))
	}
}

// TestDedupeScopedBySpan_KeepsFirstAndPreservesOrder pins the helper directly:
// equal spans collapse to the first claim, unequal spans all survive, and the
// input order (byte order) is preserved rather than sorted — unstable order
// would move line numbers and therefore suppression hashes between runs.
func TestDedupeScopedBySpan_KeepsFirstAndPreservesOrder(t *testing.T) {
	in := []scopedCandidate{
		{candidate: candidate{text: "aaa", start: 0, end: 3}, method: "high_entropy", threshold: 50},
		{candidate: candidate{text: "bbb", start: 10, end: 13}, method: "high_entropy", threshold: 50},
		{candidate: candidate{text: "aaa", start: 0, end: 3}, method: "keyword_pattern", threshold: 60}, // same span
		{candidate: candidate{text: "ccc", start: 20, end: 23}, method: "keyword_pattern", threshold: 60},
		{candidate: candidate{text: "bbb", start: 10, end: 13}, method: "keyword_pattern", threshold: 60}, // same span
	}
	got := dedupeScopedBySpan(in)

	if len(got) != 3 {
		t.Fatalf("got %d candidates, want 3", len(got))
	}
	wantOrder := []struct {
		start, end int
		method     string
	}{
		{0, 3, "high_entropy"},   // first claim wins
		{10, 13, "high_entropy"}, // first claim wins
		{20, 23, "keyword_pattern"},
	}
	for i, w := range wantOrder {
		if got[i].start != w.start || got[i].end != w.end {
			t.Errorf("[%d] span = (%d,%d), want (%d,%d)", i, got[i].start, got[i].end, w.start, w.end)
		}
		if got[i].method != w.method {
			t.Errorf("[%d] method = %q, want %q (first claim must win)", i, got[i].method, w.method)
		}
	}
}

// TestDedupeScopedBySpan_DoesNotAliasInput guards a subtle aliasing hazard: an
// in-place filter (out := cands[:0]) would overwrite the caller's backing array
// while still reading from it.
func TestDedupeScopedBySpan_DoesNotAliasInput(t *testing.T) {
	in := []scopedCandidate{
		{candidate: candidate{text: "aaa", start: 0, end: 3}, method: "high_entropy"},
		{candidate: candidate{text: "bbb", start: 10, end: 13}, method: "high_entropy"},
		{candidate: candidate{text: "aaa", start: 0, end: 3}, method: "keyword_pattern"},
	}
	got := dedupeScopedBySpan(in)
	got[0].method = "mutated"

	if in[0].method != "high_entropy" {
		t.Errorf("input was aliased: in[0].method = %q, want high_entropy", in[0].method)
	}
}

// TestMergeBySpanKeepStrongest pins the cross-path arbitration: identical spans
// collapse to the higher-confidence finding, different spans all survive, and
// ties keep the incumbent so the outcome depends on merge order alone and never
// on map iteration order.
func TestMergeBySpanKeepStrongest(t *testing.T) {
	mk := func(typ string, conf float64, start, end int) spannedMatch {
		m := spannedMatch{start: start, end: end}
		m.match.Type = typ
		m.match.Confidence = conf
		return m
	}

	t.Run("stronger claim replaces weaker on same span", func(t *testing.T) {
		dst := []spannedMatch{mk("API_KEY_OR_SECRET", 75, 5, 45)}
		got := mergeBySpanKeepStrongest(dst, []spannedMatch{mk("AWS_SECRET_ACCESS_KEY", 90, 5, 45)})
		if len(got) != 1 {
			t.Fatalf("got %d findings, want 1", len(got))
		}
		if got[0].match.Type != "AWS_SECRET_ACCESS_KEY" {
			t.Errorf("Type = %q, want AWS_SECRET_ACCESS_KEY", got[0].match.Type)
		}
	})

	t.Run("weaker claim does not replace stronger", func(t *testing.T) {
		dst := []spannedMatch{mk("AWS_SECRET_ACCESS_KEY", 90, 5, 45)}
		got := mergeBySpanKeepStrongest(dst, []spannedMatch{mk("API_KEY_OR_SECRET", 75, 5, 45)})
		if len(got) != 1 || got[0].match.Type != "AWS_SECRET_ACCESS_KEY" {
			t.Fatalf("stronger claim must survive, got %+v", got)
		}
	})

	t.Run("equal confidence keeps incumbent", func(t *testing.T) {
		dst := []spannedMatch{mk("FIRST", 80, 5, 45)}
		got := mergeBySpanKeepStrongest(dst, []spannedMatch{mk("SECOND", 80, 5, 45)})
		if len(got) != 1 || got[0].match.Type != "FIRST" {
			t.Fatalf("tie must keep incumbent, got %+v", got)
		}
	})

	t.Run("distinct spans all survive in order", func(t *testing.T) {
		dst := []spannedMatch{mk("A", 70, 0, 10)}
		got := mergeBySpanKeepStrongest(dst, []spannedMatch{mk("B", 90, 20, 30), mk("C", 60, 40, 50)})
		if len(got) != 3 {
			t.Fatalf("got %d findings, want 3", len(got))
		}
		for i, want := range []string{"A", "B", "C"} {
			if got[i].match.Type != want {
				t.Errorf("[%d] Type = %q, want %q", i, got[i].match.Type, want)
			}
		}
	})
}

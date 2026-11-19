// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactverify

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/embedded"
)

// The functions below are the implementations SweepRemaining, ResidualTypes and survives had on main
// 3b9780b (#1005), copied verbatim apart from their names: one occurrenceKinds scan of the whole
// document per value. They are the oracle for the one-pass versions (equivalence_test.go) and are
// never called by production code. Do not "fix" them; if the contract changes, change both.

// sweepRemainingReference is the per-value-scan SweepRemaining.
func sweepRemainingReference(text string, matches []detector.Match, replacementFor func(m detector.Match) (string, error)) (string, []string, error) {
	if text == "" || len(matches) == 0 || replacementFor == nil {
		return text, nil, nil
	}

	// Distinct values still present, longest first. Longest-first matters: if both "Jane Smith" and
	// "Jane" are reported, replacing the longer one first stops the shorter from carving it up.
	textBytes := []byte(text)
	seen := map[string]detector.Match{}
	for _, m := range matches {
		if m.Text == "" || len(m.Text) < minSweepLen {
			continue
		}
		if _, dup := seen[m.Text]; dup {
			continue
		}
		// Gate on ANY recognised spelling, not just the literal. A value that appears only wide --
		// which is the case in a file carrying UTF-16 sections -- would otherwise be skipped here and
		// never reach the pair-building below, so the sweep would report success while the floor
		// refused the file. Same predicate as ResidualTypes, deliberately.
		// Standalone only, same rule as the predicate. textBytes is hoisted above the loop: taking
		// []byte(text) here copies the whole document once per candidate.
		if c, _ := occurrenceKinds(textBytes, []byte(m.Text)); c > 0 {
			seen[m.Text] = m
			continue
		}
		for _, alt := range altSpellings(m.Text, m.Text) {
			if c, _ := occurrenceKinds(textBytes, []byte(alt.from)); c > 0 {
				seen[m.Text] = m
				break
			}
		}
	}
	if len(seen) == 0 {
		return text, nil, nil
	}
	values := make([]string, 0, len(seen))
	for v := range seen {
		values = append(values, v)
	}
	sort.Slice(values, func(i, j int) bool {
		if len(values[i]) != len(values[j]) {
			return len(values[i]) > len(values[j])
		}
		return values[i] < values[j] // deterministic for equal lengths
	})

	pairs := make([]string, 0, len(values)*4)
	swept := make([]string, 0, len(values))
	declined := 0
	var mixed []string
	mixedRepl := map[string]string{}
	for _, v := range values {
		repl, err := replacementFor(seen[v])
		if err != nil {
			return text, nil, fmt.Errorf("generating a replacement for a %s value during the completeness sweep: %w", seen[v].Type, err)
		}
		// A replacement that still contains the value cannot remove it. DECLINE THAT ONE VALUE rather
		// than abandoning the document: aborting meant a single self-masking value (a run of asterisks
		// typed as an API key, which #522's guard exists for) produced no artifact for the whole file,
		// turning a disclosed per-match no-op into total redaction failure.
		if repl == "" || strings.Contains(repl, v) {
			declined++
			continue
		}
		swept = append(swept, v)
		if _, emb := occurrenceKinds(textBytes, []byte(v)); emb > 0 {
			// Mixed: some occurrences are the value and some are inside longer tokens.
			mixed = append(mixed, v)
			mixedRepl[v] = repl
			continue
		}
		pairs = append(pairs, v, repl)

		// THE ENFORCER MUST COVER THE PREDICATE. ResidualTypes recognises four spellings; a sweep
		// that removed only the literal would leave the other three, so the floor would refuse a file
		// this pass believed it had cleaned — a predicate and its enforcement disagreeing, which is
		// the same class of defect #459 exists to fix.
		//
		// Measured: one real 1.8MB .txt that file(1) calls ASCII carries a SINGLE contiguous 2,177-byte
		// UTF-16LE region (1,089 NULs, one parity — an earlier note here said "17 interleaved runs", which was
		// a gap histogram of that one run). 15 values there matched in both LE and BE and were removed.
		//
		// This is NOT what fixes the leaks, and the scope matters: every residual value across a 480-file
		// corpus was a LITERAL, and only 1 of 235 text-extension files carried NULs at all. The wide arms exist
		// so the enforcer covers the predicate, not because wide leaks are common. The wide
		// bytes are literal substrings of the decoded content, so a same-length pair removes them; no
		// re-encoding of the document is involved. Note a single wide run matches both LE and BE at
		// different alignments, so both are offered and whichever is present wins.
		//
		// Only spellings actually PRESENT are added. The trie is built from these pairs, and a file
		// with 6,924 matches would otherwise pay for three unused patterns per value.
		for _, alt := range altSpellings(v, repl) {
			if c, emb := occurrenceKinds(textBytes, []byte(alt.from)); c > 0 && emb == 0 {
				pairs = append(pairs, alt.from, alt.to)
			}
		}
	}
	if len(pairs) == 0 && len(mixed) == 0 {
		return text, nil, nil
	}
	_ = declined // reported by the caller via the swept count; see redactText's sweep event

	out := text
	// FAST PATH: values with no embedded occurrence anywhere. Every copy is the value, so a trie pass
	// over all of them at once is both correct and O(len(text)).
	if len(pairs) > 0 {
		out = strings.NewReplacer(pairs...).Replace(out)
	}
	// SLOW PATH: a value that occurs BOTH standalone and embedded. strings.NewReplacer cannot tell the
	// two apart — it rewrites every occurrence — so using it here would rewrite the embedded copy as
	// collateral, which is the corruption the standalone rule exists to prevent. The gate above decides
	// WHETHER to sweep a value; this decides WHICH of its occurrences.
	//
	// Kept off the fast path deliberately: this is one scan per mixed value, and in a 480-file corpus
	// the only instance was the golden fixture's own decoy. Paying O(len(text)) per mixed value is
	// acceptable when the count is ~0 and incorrectness is not.
	for _, v := range mixed {
		out = replaceStandaloneOnly(out, v, mixedRepl[v])
	}
	return out, swept, nil
}

// residualTypesReference is the per-value-scan ResidualTypes.
func residualTypesReference(written []byte, matches []detector.Match) []string {
	if len(written) == 0 || len(matches) == 0 {
		return nil
	}
	seen := map[string]bool{}
	asked := map[string]bool{}
	for _, m := range matches {
		// Scope must match the enforcer's exactly. A value the sweep is forbidden to remove must not
		// be counted as residue, or the artifact becomes permanently unobtainable with no override:
		// one real file's only remaining refusal was a 3-byte HIGH IP_ADDRESS of shape `#::` that the
		// sweep declines by design. minSweepLen and the standalone rule are the shared scope.
		if m.Text == "" || len(m.Text) < minSweepLen {
			continue
		}
		// Dedup by VALUE. The map below is keyed by TYPE and written only AFTER survives() returns, so
		// it suppressed nothing: one real file ran the four-spelling probe 6,924 times over 1.8MB for
		// 1,285 distinct values. Measured 406ms/op, 48.8MB, 96,940 allocs; deduped, 10.8ms and 1.5MB.
		if asked[m.Text] {
			continue
		}
		asked[m.Text] = true
		if seen[m.Type] {
			continue
		}
		if survivesReference(written, m.Text) {
			t := m.Type
			if t == "" {
				t = "UNKNOWN"
			}
			seen[t] = true
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// survivesReference is the per-value-scan survives.
func survivesReference(written []byte, value string) bool {
	if value == "" {
		return false
	}
	// A standalone occurrence only. See occurrenceKinds: a value embedded in a longer token is a
	// different token, and treating it as residue makes the artifact permanently unobtainable for a
	// leak that is not one.
	if c, _ := occurrenceKinds(written, []byte(value)); c > 0 {
		return true
	}
	if w := utf16LE(value); len(w) > 0 {
		if c, _ := occurrenceKinds(written, w); c > 0 {
			return true
		}
	}
	if w := utf16BE(value); len(w) > 0 {
		if c, _ := occurrenceKinds(written, w); c > 0 {
			return true
		}
	}
	// XML character references. The variant set is shared with the office redactor rather than
	// re-derived, because "which escapes matter" is one decision and two copies would drift.
	for _, v := range embedded.XMLEscapeVariants(value) {
		if v != value && bytes.Contains(written, []byte(v)) {
			return true
		}
	}
	return false
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package redactverify answers one question about a file a redactor has just written: does any
// REPORTED value still appear in it?
//
// # Why this is a package and not a method
//
// Output verification was per-redactor POLICY rather than a property of the dispatch point, so four
// redactors verified and three did not, and each new redactor had to remember. #449 was the case where
// one forgot: tagmeta.Residual searched only the ranges it had already rewritten, so a value surviving
// OUTSIDE them was invisible by construction. It shipped a file containing a reported SSN, reported
// success, and exited 0.
//
// The two dispatch points — internal/parallel (top-level files) and internal/redactors (embedded parts
// inside a container) — now apply this as a FLOOR, so a redactor cannot opt out by omission. The
// format-aware checks stay where they are and run on top: this package reads raw bytes and cannot
// inflate a zip member or walk an ISO-BMFF box tree, so it is a backstop, never a replacement.
//
// # Why a leaf package
//
// internal/redactors/tagmeta already has ResidualAnywhere and ResidualEncoded, and reusing them from
// package redactors is impossible: tagmeta imports redactors, so the arrow cannot point back. A leaf
// that depends only on internal/detector and internal/embedded — neither of which imports redactors —
// is importable from both dispatch points and from any redactor. The same shape as
// internal/displaytext, added for the same reason.
//
// # What counts as surviving
//
// Four spellings, each of which has been a real leak in this codebase:
//
//   - the literal bytes;
//   - UTF-16LE and UTF-16BE, because OLE and some ID3 frames store text wide, and a narrow search
//     reads a wide copy as absent;
//   - XML NAMED entity spellings (&amp; &lt; &gt; &quot; &apos;), because an .xlsx storing
//     `O&apos;Connor` is the same value to a reader and a different byte string to a search (#487).
//
// NUMERIC character references are NOT covered. embedded.XMLEscapeVariants produces named entities
// only, so `452-11-93&#56;4` is not recognised — verified: Survives on that spelling returns false
// while the named-entity form returns true. internal/xmlref has a stdlib-only Decode() already used by
// two office callers, so wiring it in is a small follow-up rather than a hole in the design.
//
// It does NOT decode base64, inflate, or decrypt. A value inside a compressed member is invisible here
// and is exactly what the format-aware checks exist for.
package redactverify

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/embedded"
)

// ResidualTypes returns the finding TYPES whose reported value still appears in written,
// deduplicated and sorted so a refusal message is deterministic.
//
// Types rather than values: a refusal message must name what leaked without reprinting the secret,
// which is the same rule that keeps a matched value out of every log line in this tree.
//
// An empty Text is skipped rather than treated as present. bytes.Contains with an empty needle is
// always true, so counting it would make every redaction refuse — a mistake that turns a safety check
// into a denial of service against the tool's own output.
func ResidualTypes(written []byte, matches []detector.Match) []string {
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
		if survives(written, m.Text) {
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

// Survives reports whether value appears in written in any spelling this package recognises.
//
// Exported so a redactor can ask about one value without building a Match, and so a test can pin the
// spellings independently of the type-collecting wrapper above.
func Survives(written []byte, value string) bool { return survives(written, value) }

func survives(written []byte, value string) bool {
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

// utf16LE and utf16BE encode s without a byte-order mark, because the mark appears once at the start
// of a stream and never around an individual field.
func utf16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 0, len(u)*2)
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	return b
}

func utf16BE(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 0, len(u)*2)
	for _, c := range u {
		b = append(b, byte(c>>8), byte(c))
	}
	return b
}

// SweepRemaining removes every remaining occurrence of a reported value from text, returning the new
// text and the values it actually had to replace.
//
// # Why this is separate from locating a match
//
// A redactor does two different jobs and they have different contracts. Locating a reported match at
// its POSITION is best-effort: position correlation can fail, offsets shift as earlier replacements
// are applied, overlapping matches have to be resolved to one span, and the detector deduplicates
// occurrences upstream so a value present 137 times may be reported far fewer times. That job owns
// output fidelity and the audit mapping, and it is right for it to be positional.
//
// Guaranteeing the reported VALUE does not survive is an invariant, not a best effort. Measured on 480
// real files, conflating the two left 143 reported values — including 44 recovery codes and 5 OTP
// secrets — inside 29 files the tool reported as successfully redacted, because unreported copies of a
// reported value were never located (#459).
//
// Keeping the invariant here rather than inside one redactor is the point: the same conflation exists
// in every text-substituting redactor, so a fix inlined in plaintext would be repeated as a bug by the
// next one. This lives beside ResidualTypes so the predicate and its enforcement are one decision in
// one place.
//
// # Why the CALLER opts in
//
// This is a blind text substitution, so it is only valid where the bytes are text. A .docx is a zip
// and a .wav is a chunked binary: sweeping their bytes would corrupt the container while "fixing" a
// leak. So this is NOT applied at the dispatch point, which sees only bytes and cannot know. A
// redactor whose output is text calls it; the dispatch-point ResidualTypes floor catches any redactor
// that should have and did not.
//
// # One pass, not one per value
//
// strings.NewReplacer builds a trie and scans the input once, so the SUBSTITUTION is O(len(text)) with
// the pattern count folded into the automaton rather than O(values x len(text)). Locating matches used
// to rescan the whole document per match and made redaction quadratic; a naive loop of
// strings.ReplaceAll here would reintroduce exactly that.
//
// The candidate SCAN is the part to watch, which is why values are deduplicated before probing: on a
// 1.8MB file with 6,924 matches over 1,285 distinct values, probing per match measured 406ms and 48.8MB
// against 10.8ms and 1.5MB deduplicated.
//
// Replacements are non-overlapping and leftmost-first, and the scan never re-examines what it just
// wrote, so a replacement that happens to contain a reported value cannot cascade.
//
// replacementFor is called at most once per distinct value, which also means a strategy that generates
// a different fake each call (synthetic) yields ONE stable pseudonym per value rather than a different
// one per occurrence — the consistent choice for a reader of the output.
func SweepRemaining(text string, matches []detector.Match, replacementFor func(m detector.Match) (string, error)) (string, []string, error) {
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

// replaceStandaloneOnly replaces only those occurrences of needle in s that no word byte abuts.
//
// Written out rather than composed from strings.Replace because the decision is per occurrence: the
// same byte sequence is the reported value in one position and part of a longer token in another.
func replaceStandaloneOnly(s, needle, repl string) string {
	if needle == "" {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		j := strings.Index(s[i:], needle)
		if j < 0 {
			b.WriteString(s[i:])
			break
		}
		at := i + j
		b.WriteString(s[i:at])
		before := at > 0 && isWordByte(s[at-1])
		after := at+len(needle) < len(s) && isWordByte(s[at+len(needle)])
		if before || after {
			b.WriteString(needle) // embedded: leave it exactly as it was
		} else {
			b.WriteString(repl)
		}
		i = at + len(needle)
	}
	return b.String()
}

// spelling is one alternate encoding of a value paired with the same encoding of its replacement.
type spelling struct{ from, to string }

// altSpellings returns the non-literal spellings ResidualTypes recognises, each paired with the
// replacement written the same way, so a substitution cannot turn a wide leak into a narrow one.
func altSpellings(value, repl string) []spelling {
	out := make([]spelling, 0, 3)
	if le := utf16LE(value); len(le) > 0 {
		out = append(out, spelling{string(le), string(utf16LE(repl))})
	}
	if be := utf16BE(value); len(be) > 0 {
		out = append(out, spelling{string(be), string(utf16BE(repl))})
	}
	// XML character references. The replacement is escaped the same way so an escaped leak is not
	// replaced by unescaped bytes that a later escape pass would mangle.
	rv := embedded.XMLEscapeVariants(repl)
	for i, v := range embedded.XMLEscapeVariants(value) {
		if v == value {
			continue
		}
		to := repl
		if i < len(rv) {
			to = rv[i]
		}
		out = append(out, spelling{v, to})
	}
	return out
}

// minSweepLen is the shortest value the sweep will remove everywhere.
//
// A blind substitution of a very short string does more harm than good: a two- or three-character
// value occurs incidentally throughout ordinary prose, so sweeping it corrupts the document to remove
// a copy that carries no meaning on its own. Four is the shortest length at which a reported value is
// specific enough to be worth removing wherever it appears.
//
// It is a weak guard on its own, and an earlier note here overstated it. LENGTH is not what makes a
// blind substitution unsafe: the repo's golden corpus reports an 11-byte value that also occurs inside
// an unrelated hex constant, far above any plausible floor. occurrenceKinds' standalone rule is what
// actually protects that case; this floor only bounds the damage a pathological 1-3 byte match could do.
//
// ResidualTypes applies the same floor, so the predicate and the enforcer cannot disagree about which
// values are in scope.
//
// A shorter value is still redacted at its reported POSITION by the caller. Only the sweep declines it.
const minSweepLen = 4

// isWordByte reports whether b can be part of an identifier-like token: a letter, a digit, or '_'.
//
// Deliberately narrow and ASCII-only. A multi-byte UTF-8 continuation byte is NOT a word byte here,
// which is what lets a value abutting a non-ASCII character still count as standalone.
func isWordByte(b byte) bool {
	return b == '_' ||
		(b >= '0' && b <= '9') ||
		(b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z')
}

// occurrenceKinds counts how many times needle appears in hay STANDALONE (no word byte abutting it on
// either side) and how many times it appears EMBEDDED inside a longer token.
//
// This is the rule that both the predicate and the enforcer apply, and it exists because the repo's own
// golden corpus proves a blind substring match is not safe. The fixture reports the 11-byte
// INSURANCE_MEMBER_ID `BEEF1234567` on one line, and a separate decoy line reads
// `cache blob 0xDEADBEEF12345678 evicted`, which internal/goldencorpus/corpus.go requires to stay
// clean. The value occurs inside that hex constant. Rewriting it there corrupts data the tool was never
// asked to touch — silently, at exit 0, under every strategy — while a length floor does not help,
// because the value is far longer than any plausible floor.
//
// So: an EMBEDDED occurrence is not the reported value, it is a different token that happens to contain
// those bytes. It is neither swept nor counted as residue. A STANDALONE occurrence is the value, and it
// is both.
func occurrenceKinds(hay, needle []byte) (standalone, embedded int) {
	if len(needle) == 0 || len(hay) < len(needle) {
		return 0, 0
	}
	for i := 0; i+len(needle) <= len(hay); {
		j := bytes.Index(hay[i:], needle)
		if j < 0 {
			break
		}
		at := i + j
		before := at > 0 && isWordByte(hay[at-1])
		after := at+len(needle) < len(hay) && isWordByte(hay[at+len(needle)])
		if before || after {
			embedded++
		} else {
			standalone++
		}
		i = at + 1 // overlapping occurrences are counted, so a repeated value is not undercounted
	}
	return standalone, embedded
}

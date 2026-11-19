// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactverify

import (
	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/embedded"
)

// kinds records whether a needle has at least one STANDALONE and at least one EMBEDDED occurrence in
// a document, by the rule occurrenceKinds applies (no word byte abutting it on either side is
// standalone; any word byte on either side is embedded). It is occurrenceKinds with the counts
// reduced to the two facts every caller of the sweep and the predicate actually reads.
type kinds struct{ standalone, embedded bool }

// scanKinds answers, for every needle at once, what occurrenceKinds(hay, needle) would, in ONE pass
// over hay: an Aho-Corasick automaton over the needles, so the cost is O(len(hay) + total needle
// bytes + occurrences) instead of O(len(hay)) per needle (#1005: the sweep measured 0.10 / 0.20 /
// 0.70 / 2.76 s at 4k / 8k / 16k / 32k distinct values).
//
// The map holds an entry only for a needle with at least one occurrence, so a missing key means
// "absent" and the zero kinds is the right answer for it. Empty needles are ignored, as
// occurrenceKinds ignores them. Overlapping and nested occurrences are all visited, which is what
// occurrenceKinds' i = at+1 stepping does.
//
// A needle containing a byte that never occurs in hay cannot occur, so it never enters the automaton.
// That keeps the UTF-16 and entity spellings, which the sweep probes for every value, out of the
// automaton for the common document that has no NUL byte and no '&'.
//
// shortcut: the automaton holds every needle byte (about 21 bytes per trie node), so the memory is
// proportional to the sum of the distinct needle lengths; upgrade to a compressed trie if a
// document ever reports values totalling hundreds of megabytes.
func scanKinds[H ~string | ~[]byte](hay H, needles []string) map[string]kinds {
	var present [256]bool
	for i := 0; i < len(hay); i++ {
		present[hay[i]] = true
	}

	// Trie in parallel slices; node 0 is the root. A node's children are a singly linked list
	// (first/next), the root's are a dense table because every document byte starts at the root.
	var (
		rootNext [256]int32
		first    = []int32{0}
		next     = []int32{0}
		fail     = []int32{0}
		dict     = []int32{0} // nearest proper suffix node that ends a needle, 0 if none
		term     = []int32{0} // needle index + 1 if a needle ends here
		by       = []byte{0}
		lens     []int32
		names    []string
	)
	child := func(v int32, c byte) int32 {
		if v == 0 {
			return rootNext[c]
		}
		for u := first[v]; u != 0; u = next[u] {
			if by[u] == c {
				return u
			}
		}
		return 0
	}

	idOf := map[string]struct{}{}
nextNeedle:
	for _, n := range needles {
		if n == "" || len(n) > len(hay) {
			continue
		}
		if _, dup := idOf[n]; dup {
			continue
		}
		for i := 0; i < len(n); i++ {
			if !present[n[i]] {
				continue nextNeedle
			}
		}
		v := int32(0)
		for i := 0; i < len(n); i++ {
			c := n[i]
			u := child(v, c)
			if u == 0 {
				u = int32(len(by))
				by = append(by, c)
				first = append(first, 0)
				fail = append(fail, 0)
				dict = append(dict, 0)
				term = append(term, 0)
				if v == 0 {
					next = append(next, 0)
					rootNext[c] = u
				} else {
					next = append(next, first[v])
					first[v] = u
				}
			}
			v = u
		}
		idOf[n] = struct{}{}
		lens = append(lens, int32(len(n)))
		names = append(names, n)
		term[v] = int32(len(lens))
	}
	if len(lens) == 0 {
		return nil
	}

	// Failure and dictionary links, breadth first so a node's suffix is finished before the node.
	queue := make([]int32, 0, len(by))
	for c := 0; c < 256; c++ {
		if u := rootNext[c]; u != 0 {
			queue = append(queue, u)
		}
	}
	for head := 0; head < len(queue); head++ {
		v := queue[head]
		for u := first[v]; u != 0; u = next[u] {
			c := by[u]
			f := fail[v]
			for f != 0 && child(f, c) == 0 {
				f = fail[f]
			}
			fu := child(f, c)
			fail[u] = fu
			if term[fu] != 0 {
				dict[u] = fu
			} else {
				dict[u] = dict[fu]
			}
			queue = append(queue, u)
		}
	}

	found := make([]kinds, len(lens))
	n := len(hay)
	state := int32(0)
	for i := 0; i < n; i++ {
		c := hay[i]
		for state != 0 && child(state, c) == 0 {
			state = fail[state]
		}
		state = child(state, c)
		for u := state; u != 0; u = dict[u] {
			t := term[u]
			if t == 0 {
				continue
			}
			id := t - 1
			end := i + 1
			at := end - int(lens[id])
			if (at > 0 && isWordByte(hay[at-1])) || (end < n && isWordByte(hay[end])) {
				found[id].embedded = true
			} else {
				found[id].standalone = true
			}
		}
	}

	out := make(map[string]kinds, len(lens))
	for id, k := range found {
		if k.standalone || k.embedded {
			out[names[id]] = k
		}
	}
	return out
}

// sweepCandidates returns, for SweepRemaining, the first match of every distinct reported value of at
// least minSweepLen bytes, those values in first-seen order, each value's XML entity variants (computed
// once: embedded.XMLEscapeVariants builds a strings.Replacer per call, which is most of the allocation
// of a sweep), and every spelling of each value for scanKinds.
func sweepCandidates(matches []detector.Match) (first map[string]detector.Match, texts []string, xml map[string][]string, needles []string) {
	first = map[string]detector.Match{}
	xml = map[string][]string{}
	for _, m := range matches {
		if m.Text == "" || len(m.Text) < minSweepLen {
			continue
		}
		if _, dup := first[m.Text]; dup {
			continue
		}
		first[m.Text] = m
		texts = append(texts, m.Text)
		xml[m.Text] = embedded.XMLEscapeVariants(m.Text)
		needles = append(needles, m.Text)
		needles = append(needles, fromsOf(m.Text, xml[m.Text])...)
	}
	return first, texts, xml, needles
}

// fromsOf lists the non-literal spellings of value, in altSpellings' order, given its XML variants.
func fromsOf(value string, xml []string) []string {
	out := make([]string, 0, 3)
	if le := utf16LE(value); len(le) > 0 {
		out = append(out, string(le))
	}
	if be := utf16BE(value); len(be) > 0 {
		out = append(out, string(be))
	}
	for _, v := range xml {
		if v != value {
			out = append(out, v)
		}
	}
	return out
}

// altSpellingsWith is altSpellings given value's XML variants already computed. It is written out
// rather than shared so that the per-value reference in reference_test.go, which calls altSpellings,
// stays an independent oracle: equivalence_test.go fails if the two disagree.
func altSpellingsWith(value, repl string, xml []string) []spelling {
	out := make([]spelling, 0, 3)
	if le := utf16LE(value); len(le) > 0 {
		out = append(out, spelling{string(le), string(utf16LE(repl))})
	}
	if be := utf16BE(value); len(be) > 0 {
		out = append(out, spelling{string(be), string(utf16BE(repl))})
	}
	rv := embedded.XMLEscapeVariants(repl)
	for i, v := range xml {
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

// residual answers survives(written, value) for every reported value from one scanKinds pass.
type residual struct {
	found map[string]kinds
	xml   map[string][]string
}

// scanResidual looks up every spelling survives checks, for the distinct values of at least
// minSweepLen bytes (ResidualTypes' scope), in one pass over written.
func scanResidual(written []byte, matches []detector.Match) *residual {
	r := &residual{xml: map[string][]string{}}
	var needles []string
	for _, m := range matches {
		if len(m.Text) < minSweepLen {
			continue
		}
		if _, dup := r.xml[m.Text]; dup {
			continue
		}
		r.xml[m.Text] = embedded.XMLEscapeVariants(m.Text)
		needles = append(needles, m.Text)
		needles = append(needles, fromsOf(m.Text, r.xml[m.Text])...)
	}
	r.found = scanKinds(written, needles)
	return r
}

// survives is survives(written, value) for a value scanResidual was given: a STANDALONE literal or
// wide copy, or ANY copy of an XML entity variant.
func (r *residual) survives(value string) bool {
	if value == "" {
		return false
	}
	if r.found[value].standalone {
		return true
	}
	if w := utf16LE(value); len(w) > 0 && r.found[string(w)].standalone {
		return true
	}
	if w := utf16BE(value); len(w) > 0 && r.found[string(w)].standalone {
		return true
	}
	for _, v := range r.xml[value] {
		if k := r.found[v]; v != value && (k.standalone || k.embedded) {
			return true
		}
	}
	return false
}

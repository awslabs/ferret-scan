// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package office

// valueTrie finds every occurrence of a set of values in a text in ONE pass over the text
// (Aho-Corasick), however many values there are.
//
// The Office redactor asks two questions of every distinct reported value: "where in the
// extracted text does it first occur, and in which parts" (locateAll) and "does this part
// still hold it" (presence). Asking them with one strings.Index / strings.Contains per value
// is O(values x text): the first occurrence of the i-th distinct value sits about i values
// into the text, so N distinct values cost N^2/2 value-lengths of scanning. Measured on main
// (a73c55d6), a .pptx of distinct e-mails cost 0.73 s of redaction at 8000 values and 2.41 s
// at 16000 (3.3x per doubling), and the profile put 84% of it in strings.Index.
//
// Unlike a strings.Replacer, which consumes the bytes of the value it replaces, this reports
// EVERY occurrence, including a value nested inside a longer one or overlapping another. That
// is what Index and Contains report, so callers keep their exact semantics.
type valueTrie struct {
	// next maps (node << 8 | byte) to the child node. One map for the whole trie, because a
	// map per node costs more than the values themselves.
	next map[uint64]int32
	// firstChild/sibling/edge enumerate a node's children while the failure links are built.
	firstChild []int32
	sibling    []int32
	edge       []byte
	fail       []int32
	// out is the id of the value ending at a node, or -1.
	out []int32
	// dict is the nearest node along the failure chain, excluding the node itself, that ends
	// a value; 0 (the root, which never does) when there is none.
	dict []int32
	// lens is the length in bytes of each value, by id.
	lens []int
}

func trieKey(node int32, b byte) uint64 { return uint64(node)<<8 | uint64(b) }

// newValueTrie indexes values by position: value i has id i. Empty values are ignored, and a
// repeated value keeps the id of its first appearance.
func newValueTrie(values []string) *valueTrie {
	t := &valueTrie{
		next:       make(map[uint64]int32, len(values)*8),
		firstChild: []int32{-1},
		sibling:    []int32{-1},
		edge:       []byte{0},
		out:        []int32{-1},
		lens:       make([]int, len(values)),
	}
	for id, v := range values {
		t.lens[id] = len(v)
		if v == "" {
			continue
		}
		node := int32(0)
		for i := 0; i < len(v); i++ {
			child, ok := t.next[trieKey(node, v[i])]
			if !ok {
				child = int32(len(t.out))
				t.next[trieKey(node, v[i])] = child
				t.firstChild = append(t.firstChild, -1)
				t.sibling = append(t.sibling, t.firstChild[node])
				t.edge = append(t.edge, v[i])
				t.out = append(t.out, -1)
				t.firstChild[node] = child
			}
			node = child
		}
		if t.out[node] < 0 {
			t.out[node] = int32(id)
		}
	}

	t.fail = make([]int32, len(t.out))
	t.dict = make([]int32, len(t.out))
	queue := make([]int32, 0, len(t.out))
	for c := t.firstChild[0]; c >= 0; c = t.sibling[c] {
		queue = append(queue, c) // depth 1: fail = root, dict = root
	}
	for head := 0; head < len(queue); head++ {
		node := queue[head]
		for c := t.firstChild[node]; c >= 0; c = t.sibling[c] {
			f := t.step(t.fail[node], t.edge[c])
			t.fail[c] = f
			if t.out[f] >= 0 {
				t.dict[c] = f
			} else {
				t.dict[c] = t.dict[f]
			}
			queue = append(queue, c)
		}
	}
	return t
}

// step is the automaton transition from state on byte b.
func (t *valueTrie) step(state int32, b byte) int32 {
	for {
		if n, ok := t.next[trieKey(state, b)]; ok {
			return n
		}
		if state == 0 {
			return 0
		}
		state = t.fail[state]
	}
}

// scan calls found(id, start) for every occurrence of every value in text, ordered by the
// occurrence's END; for one value that is also the order of its starts.
func (t *valueTrie) scan(text string, found func(id, start int)) {
	state := int32(0)
	for i := 0; i < len(text); i++ {
		state = t.step(state, text[i])
		for n := state; n != 0; n = t.dict[n] {
			if id := t.out[n]; id >= 0 {
				found(int(id), i+1-t.lens[id])
			}
		}
	}
}

// presence returns, by value id, whether text holds the value, adding to seen.
func (t *valueTrie) presence(text string, seen []bool) {
	t.scan(text, func(id, _ int) { seen[id] = true })
}

// locateAll is locateMatch for every value at once: result[i] is exactly
// locateMatch(extractedText, textPositions, values[i], partCount), for one pass over
// extractedText instead of one per value. A value's first occurrence decides firstOffset;
// its later NON-OVERLAPPING occurrences (the same walk locateMatch makes) name the parts,
// until every part is accounted for.
func locateAll(extractedText string, textPositions []OfficeTextPosition, values []string, partCount int) []matchLocation {
	locs := make([]matchLocation, len(values))
	for i := range locs {
		locs[i].firstOffset = -1
	}
	if len(textPositions) == 0 || len(values) == 0 {
		return locs
	}
	if partCount <= 0 {
		partCount = distinctPartCount(textPositions)
	}
	type walk struct {
		end  int // end of the last counted occurrence
		seen map[string]struct{}
		done bool
	}
	walks := make([]walk, len(values))
	newValueTrie(values).scan(extractedText, func(id, start int) {
		loc, w := &locs[id], &walks[id]
		if loc.firstOffset < 0 {
			loc.firstOffset = start
		}
		if w.done || start < w.end {
			return
		}
		w.end = start + len(values[id])
		pos := positionForOffset(textPositions, start)
		if pos == nil {
			return
		}
		if w.seen == nil {
			w.seen = make(map[string]struct{}, partCount)
		}
		if _, dup := w.seen[pos.FileName]; dup {
			return
		}
		w.seen[pos.FileName] = struct{}{}
		loc.parts = append(loc.parts, *pos)
		w.done = len(w.seen) == partCount
	})
	return locs
}

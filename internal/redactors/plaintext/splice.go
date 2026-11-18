// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package plaintext

import "strings"

// spliceText is the document as redactText rewrites it. The positional pass writes in descending
// document order, so a write usually lands in front of every earlier one and the text after it is
// already final. Rebuilding the whole string for each write (`s[:a] + r + s[b:]`) copied the entire
// document once per match, which made the pass quadratic in the number of matches (#1005): 8,000
// distinct emails spent 4.5 s redacting a file that scanned in 0.9 s.
//
// spliceText keeps the untouched head orig[:cut] and, after it, the rewritten text as a stack of
// chunks. A write at or before cut is O(len(replacement) + bytes between it and the previous write);
// anything that needs the text as one string (a write that reaches past cut, a document-wide
// search, the final result) collapses the stack once and carries on from the collapsed text. The text
// it represents is, at every step, byte-for-byte what the string rebuild produced.
type spliceText struct {
	orig    string
	cut     int      // orig[:cut] is the text before the first rewritten byte
	tail    []string // the text after cut, as chunks in REVERSE order (the last element comes first)
	tailLen int
}

func newSpliceText(s string) *spliceText { return &spliceText{orig: s, cut: len(s)} }

// Len is the length of the current text.
func (s *spliceText) Len() int { return s.cut + s.tailLen }

// String returns the current text, collapsing the pending chunks into it.
func (s *spliceText) String() string {
	s.collapse()
	return s.orig
}

func (s *spliceText) collapse() {
	if len(s.tail) == 0 {
		return
	}
	var b strings.Builder
	b.Grow(s.Len())
	b.WriteString(s.orig[:s.cut])
	for i := len(s.tail) - 1; i >= 0; i-- {
		b.WriteString(s.tail[i])
	}
	s.orig = b.String()
	s.cut = len(s.orig)
	s.tail, s.tailLen = nil, 0
}

// Slice returns the current text[start:end], with the bounds the caller has already checked.
func (s *spliceText) Slice(start, end int) string {
	if end <= s.cut {
		return s.orig[start:end]
	}
	return s.String()[start:end]
}

// Replace is text = text[:start] + repl + text[end:].
func (s *spliceText) Replace(start, end int, repl string) {
	if end > s.cut {
		s.collapse()
	}
	if end < s.cut {
		s.tail = append(s.tail, s.orig[end:s.cut])
		s.tailLen += s.cut - end
	}
	s.tail = append(s.tail, repl)
	s.tailLen += len(repl)
	s.cut = start
}

// lineFrom returns the current text from start up to, not including, the next newline (or the end of
// the text), and false when start is past the end of the text.
func (s *spliceText) lineFrom(start int) (string, bool) {
	if start > s.Len() {
		return "", false
	}
	if start > s.cut {
		t := s.String()
		if i := strings.IndexByte(t[start:], '\n'); i >= 0 {
			return t[start : start+i], true
		}
		return t[start:], true
	}
	if i := strings.IndexByte(s.orig[start:s.cut], '\n'); i >= 0 {
		return s.orig[start : start+i], true
	}
	// The line runs on into rewritten text: join the head's part with chunks up to the first newline.
	var b strings.Builder
	b.WriteString(s.orig[start:s.cut])
	for i := len(s.tail) - 1; i >= 0; i-- {
		if j := strings.IndexByte(s.tail[i], '\n'); j >= 0 {
			b.WriteString(s.tail[i][:j])
			break
		}
		b.WriteString(s.tail[i])
	}
	return b.String(), true
}

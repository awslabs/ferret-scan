// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package detector

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unsafe"
)

// These tests assert two things that pull against each other: that DetachMatches changes no
// VALUE, and that it changes every content-derived POINTER.
//
// The pointer half needs unsafe.StringData. That is the same instrument
// internal/router/structured_sections_test.go already uses to assert the sibling invariant
// (that the router does NOT copy), and it is the only way to see the defect this fixes: a
// zero-length substring is `== ""` yet still carries the document's data pointer and retains
// the whole buffer. A guard written in terms of values cannot distinguish it from a canonical
// empty string, so a guard written in terms of values cannot see the bug.

// aliasSource reports whether s points into src's backing array. Length is deliberately
// ignored: a zero-length view pins just as hard as a long one.
func aliasSource(s, src string) bool {
	if len(src) == 0 {
		return false
	}
	base := uintptr(unsafe.Pointer(unsafe.StringData(src)))
	p := uintptr(unsafe.Pointer(unsafe.StringData(s)))
	return p >= base && p < base+uintptr(len(src))
}

// aliasingPaths walks every exported string reachable from m and returns the paths that still
// point into src.
func aliasingPaths(m *Match, src string) []string {
	var out []string
	walkStrings(reflect.ValueOf(*m), "Match", 0, func(path, s string) {
		if aliasSource(s, src) {
			out = append(out, fmt.Sprintf("%s (len=%d)", path, len(s)))
		}
	})
	return out
}

// walkStrings visits every string reachable from v through exported fields.
func walkStrings(v reflect.Value, path string, depth int, visit func(path, s string)) {
	if depth > 12 || !v.IsValid() {
		return
	}
	switch v.Kind() {
	case reflect.String:
		visit(path, v.String())
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			if t.Field(i).PkgPath != "" { // unexported
				continue
			}
			walkStrings(v.Field(i), path+"."+t.Field(i).Name, depth+1, visit)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			walkStrings(v.Index(i), fmt.Sprintf("%s[%d]", path, i), depth+1, visit)
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			// Keys as well as values: a map keyed by a content substring pins too.
			walkStrings(k, path+".<key>", depth+1, visit)
			walkStrings(v.MapIndex(k), fmt.Sprintf("%s[%v]", path, k), depth+1, visit)
		}
	case reflect.Interface, reflect.Pointer:
		if !v.IsNil() {
			walkStrings(v.Elem(), path+"*", depth+1, visit)
		}
	}
}

// componentsLike stands in for a validator struct stored in Metadata (personname keeps
// NameComponents there). detector cannot import personname — personname imports detector — so
// the reflective path is what covers this shape, and this is the test of that path.
type componentsLike struct {
	FullName  string
	FirstName string
	LastName  string
	Pattern   string
	Cultural  []string
	private   string //nolint:unused // deliberately unexported: reflection cannot set it
}

// buildSource returns a document and a match sliced out of it, in the shape validators
// produce: whole content split into lines, then the match and its windows sliced from a line.
func buildSource() (src string, line string) {
	src = strings.Repeat("filler line with no findings at all\n", 200) +
		"Contact alice@example.com about the invoice\n" +
		strings.Repeat("more filler that keeps the buffer large\n", 200)
	for _, l := range strings.Split(src, "\n") {
		if strings.Contains(l, "alice@example.com") {
			line = l
			break
		}
	}
	return src, line
}

func TestDetachRemovesEveryAliasIncludingEmptyOnes(t *testing.T) {
	src, line := buildSource()
	at := strings.Index(line, "alice@example.com")

	cases := []struct {
		name string
		m    Match
	}{
		{
			name: "ordinary match with both windows",
			m: Match{
				Text: line[at : at+len("alice@example.com")],
				Context: ContextInfo{
					FullLine:   line,
					BeforeText: line[:at],
					AfterText:  line[at+len("alice@example.com"):],
				},
			},
		},
		{
			// The shape that defeats a guard skipping empty strings. A match at column 0
			// has BeforeText = line[0:0]: len 0, == "", and pinning the whole document.
			name: "match at column zero, empty BeforeText",
			m: Match{
				Text: line[:7],
				Context: ContextInfo{
					FullLine:   line,
					BeforeText: line[0:0],
					AfterText:  line[7:],
				},
			},
		},
		{
			name: "match flush against end of line, empty AfterText",
			m: Match{
				Text: line[len(line)-5:],
				Context: ContextInfo{
					FullLine:   line,
					BeforeText: line[:len(line)-5],
					AfterText:  line[len(line):],
				},
			},
		},
		{
			// The metadata validator's GPS arm reports Text: line.
			name: "Text is the whole line",
			m: Match{
				Text:    line,
				Context: ContextInfo{FullLine: line},
			},
		},
		{
			name: "content in metadata strings",
			m: Match{
				Text:    line[at : at+5],
				Context: ContextInfo{FullLine: line},
				Metadata: map[string]any{
					"domain":   line[at+6 : at+17],
					"username": line[at : at+5],
					"empty":    line[at:at],
					"count":    7,
					"ok":       true,
				},
			},
		},
		{
			name: "content in a nested []Match",
			m: Match{
				Text:    line[at : at+5],
				Context: ContextInfo{FullLine: line},
				Metadata: map[string]any{
					"cluster_members": []Match{{
						Text:    line[at : at+17],
						Context: ContextInfo{FullLine: line, BeforeText: line[0:0]},
					}},
				},
			},
		},
		{
			name: "content in a struct reached only by reflection",
			m: Match{
				Text:    line[at : at+5],
				Context: ContextInfo{FullLine: line},
				Metadata: map[string]any{
					"name_components": componentsLike{
						FullName:  line[at : at+17],
						FirstName: line[at : at+5],
						LastName:  line[at+6 : at+17],
						Pattern:   "static_pattern_name",
						Cultural:  []string{"western"},
					},
				},
			},
		},
		{
			name: "content in a nested map and a string slice",
			m: Match{
				Text:    line[at : at+5],
				Context: ContextInfo{FullLine: line},
				Metadata: map[string]any{
					"nested": map[string]any{
						"field": line[at : at+9],
						"deep":  map[string]any{"deeper": line[at : at+4]},
					},
					"values": []string{line[at : at+5], line[at:at]},
					"keyed":  map[string]string{line[at : at+5]: line[at+6 : at+17]},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := deepCopyMatch(tc.m)

			// Non-vacuity: the fixture must actually alias before the call, or the test
			// proves nothing about detaching.
			if got := aliasingPaths(&tc.m, src); len(got) == 0 {
				t.Fatalf("fixture does not alias the source before detaching, so this case "+
					"cannot detect a leak: %+v", tc.m)
			}

			matches := []Match{tc.m}
			if !DetachMatches(matches, src) {
				t.Fatalf("DetachMatches declined; the budget should accept this fixture")
			}

			if got := aliasingPaths(&matches[0], src); len(got) != 0 {
				t.Errorf("still aliasing the source after detaching: %v", got)
			}
			if !reflect.DeepEqual(before, matches[0]) {
				t.Errorf("value changed by detaching\n before: %#v\n  after: %#v", before, matches[0])
			}
		})
	}
}

// TestDetachSharesOneCopyPerLine pins the sharing property. Per-match copies would multiply
// memory by the number of findings on a line, and would fragment the line identity that
// AssignLineColumns and the redaction-path overlap resolver rely on.
func TestDetachSharesOneCopyPerLine(t *testing.T) {
	src, line := buildSource()

	// Bounded by the line so the slices below stay in range; the point is many matches on
	// ONE line, not a particular count.
	n := len(line) - 4
	if n > 50 {
		n = 50
	}
	matches := make([]Match, 0, n)
	for i := 0; i < n; i++ {
		matches = append(matches, Match{
			Text:    line[i : i+3],
			Context: ContextInfo{FullLine: line, BeforeText: line[:i], AfterText: line[i+3:]},
		})
	}

	if !DetachMatches(matches, src) {
		t.Fatalf("DetachMatches declined")
	}

	ptrs := map[uintptr]int{}
	for i := range matches {
		ptrs[uintptr(unsafe.Pointer(unsafe.StringData(matches[i].Context.FullLine)))]++
	}
	if len(ptrs) != 1 {
		t.Errorf("FullLine has %d distinct backing pointers across %d matches on ONE line, "+
			"want 1: the copy is per-match instead of per-line", len(ptrs), n)
	}
}

// TestDetachSharesAcrossNonAdjacentMatchesOnALine covers the map path rather than the
// one-entry memo.
//
// The memo only spans a CONTIGUOUS run of matches on the same line, so a fixture whose matches
// are all on one line in a row is shared by the memo alone and cannot detect a per-match clone
// — found by mutating the map lookup away and watching the sibling test still pass.
// Interleaving two lines defeats the memo on every match, so sharing here can only come from
// the copies map.
func TestDetachSharesAcrossNonAdjacentMatchesOnALine(t *testing.T) {
	src, lineA := buildSource()

	var lineB string
	for _, l := range strings.Split(src, "\n") {
		if strings.HasPrefix(l, "more filler") {
			lineB = l
			break
		}
	}
	if lineB == "" || lineB == lineA {
		t.Fatalf("could not find a second distinct line in the fixture")
	}

	matches := make([]Match, 0, 40)
	for i := 0; i < 20; i++ {
		matches = append(matches,
			Match{Text: lineA[i : i+3], Context: ContextInfo{FullLine: lineA}},
			Match{Text: lineB[i : i+3], Context: ContextInfo{FullLine: lineB}},
		)
	}

	if !DetachMatches(matches, src) {
		t.Fatalf("DetachMatches declined")
	}

	ptrs := map[uintptr]bool{}
	for i := range matches {
		ptrs[uintptr(unsafe.Pointer(unsafe.StringData(matches[i].Context.FullLine)))] = true
	}
	if len(ptrs) != 2 {
		t.Errorf("two interleaved lines produced %d distinct FullLine pointers across %d "+
			"matches, want 2: the copies map is not sharing, so each match got its own copy",
			len(ptrs), len(matches))
	}
}

// TestDetachDeclinesWhenTheLineIsMostOfTheBuffer is the budget. A single-line minified
// document cannot be improved by copying — the copy is as large as what it would free — so the
// call must decline and leave everything untouched.
func TestDetachDeclinesWhenTheLineIsMostOfTheBuffer(t *testing.T) {
	line := strings.Repeat("a", 4<<20) + " alice@example.com"
	src := line + "\n"

	matches := []Match{{
		Text:    src[len(src)-19 : len(src)-1],
		Context: ContextInfo{FullLine: line, BeforeText: line[:10]},
	}}
	before := deepCopyMatch(matches[0])

	if DetachMatches(matches, src) {
		t.Errorf("DetachMatches copied a %d-byte line out of a %d-byte source; the budget "+
			"should have declined", len(line), len(src))
	}
	if !reflect.DeepEqual(before, matches[0]) {
		t.Errorf("a declined call still modified the match")
	}
	// Declining means the alias survives. That is the documented trade, and asserting it
	// keeps the decline honest rather than silently becoming a no-op everywhere.
	if got := aliasingPaths(&matches[0], src); len(got) == 0 {
		t.Errorf("expected the alias to survive a declined detach, but nothing aliases")
	}
}

// TestDetachAcceptsASparseLargeFile is the counterweight to the test above: a large file whose
// finding-bearing lines are a small fraction of it must be detached. Without this, making
// DetachMatches always decline would pass every other test here.
func TestDetachAcceptsASparseLargeFile(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < 40000; i++ {
		sb.WriteString("this line is filler and holds nothing sensitive at all\n")
	}
	sb.WriteString("Contact alice@example.com about the invoice\n")
	src := sb.String()

	var line string
	for _, l := range strings.Split(src, "\n") {
		if strings.Contains(l, "alice@example.com") {
			line = l
			break
		}
	}

	matches := []Match{{
		Text:    line[8:25],
		Context: ContextInfo{FullLine: line, BeforeText: line[:8], AfterText: line[25:]},
	}}
	if !DetachMatches(matches, src) {
		t.Fatalf("DetachMatches declined a %d-byte source whose finding line is %d bytes",
			len(src), len(line))
	}
	if got := aliasingPaths(&matches[0], src); len(got) != 0 {
		t.Errorf("still aliasing: %v", got)
	}
}

// TestDetachPreservesNilness guards the output contract. A golden locks
// "context_keywords": null, so rebuilding a nil slice as an empty one is a visible change.
func TestDetachPreservesNilness(t *testing.T) {
	src, line := buildSource()

	m := Match{
		Text:    line[:5],
		Context: ContextInfo{FullLine: line, PositiveKeywords: nil, NegativeKeywords: []string{}},
		Metadata: map[string]any{
			"nil_slice": []string(nil),
			"nil_map":   map[string]string(nil),
			"nil_any":   nil,
			"empty_str": "",
		},
	}
	matches := []Match{m}
	if !DetachMatches(matches, src) {
		t.Fatalf("DetachMatches declined")
	}

	got := matches[0]
	if got.Context.PositiveKeywords != nil {
		t.Errorf("nil PositiveKeywords became %#v", got.Context.PositiveKeywords)
	}
	if got.Context.NegativeKeywords == nil || len(got.Context.NegativeKeywords) != 0 {
		t.Errorf("empty non-nil NegativeKeywords became %#v", got.Context.NegativeKeywords)
	}
	if s, ok := got.Metadata["nil_slice"].([]string); !ok || s != nil {
		t.Errorf("nil []string in metadata became %#v", got.Metadata["nil_slice"])
	}
	if mm, ok := got.Metadata["nil_map"].(map[string]string); !ok || mm != nil {
		t.Errorf("nil map in metadata became %#v", got.Metadata["nil_map"])
	}
	if v, present := got.Metadata["nil_any"]; !present || v != nil {
		t.Errorf("nil any in metadata became %#v (present=%v)", v, present)
	}
}

// TestDetachHandlesNilAndEmptyInputs covers the trivial paths so they cannot panic on a
// cancelled scan, where flatten runs with whatever arrived.
func TestDetachHandlesNilAndEmptyInputs(t *testing.T) {
	if DetachMatches(nil, "content") {
		t.Errorf("nil matches should report no work")
	}
	if DetachMatches([]Match{}, "content") {
		t.Errorf("empty matches should report no work")
	}
	if DetachMatches([]Match{{Text: "x"}}, "") {
		t.Errorf("empty source should report no work")
	}
	// A match with no context at all, and nil metadata.
	matches := []Match{{Text: "standalone", Metadata: nil}}
	if !DetachMatches(matches, "some source content") {
		t.Fatalf("declined a trivial fixture")
	}
	if matches[0].Text != "standalone" {
		t.Errorf("Text = %q", matches[0].Text)
	}
}

// deepCopyMatch produces a value-equal Match that shares no maps or slices, so DeepEqual after
// the call compares against a genuine pre-image rather than against something the call mutated.
func deepCopyMatch(m Match) Match {
	out := m
	out.Context.PositiveKeywords = copyStrings(m.Context.PositiveKeywords)
	out.Context.NegativeKeywords = copyStrings(m.Context.NegativeKeywords)
	out.Metadata = copyMeta(m.Metadata, 0)
	return out
}

func copyStrings(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func copyMeta(in map[string]any, depth int) map[string]any {
	if in == nil || depth > 8 {
		return in
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		switch t := v.(type) {
		case map[string]any:
			out[k] = copyMeta(t, depth+1)
		case []Match:
			ms := make([]Match, len(t))
			for i := range t {
				ms[i] = deepCopyMatch(t[i])
			}
			out[k] = ms
		case []string:
			out[k] = copyStrings(t)
		case map[string]string:
			if t == nil {
				out[k] = t
				continue
			}
			mm := make(map[string]string, len(t))
			for kk, vv := range t {
				mm[kk] = vv
			}
			out[k] = mm
		default:
			out[k] = v
		}
	}
	return out
}

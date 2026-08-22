// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package detector

import (
	"reflect"
	"strings"
)

// Buffer detachment for findings.
//
// A Go substring shares the parent's backing array, so retaining it retains the WHOLE
// parent. Validators slice matches straight out of the file's entire extracted content
// (`lines := strings.Split(content, "\n")`, then `line[a:b]`), so one 16-byte finding kept
// that file's whole buffer alive for as long as the finding lived — which is until the
// process exits. Measured on 64 files of 2 MB each with one EMAIL apiece: 130 MB of live
// heap held by 64 findings.
//
// The subtle half, and the reason a careless fix does nothing: a ZERO-LENGTH substring pins
// the parent too. `big[100:100]` has len 0, compares `== ""`, and retains all 8 MB
// (measured). Every finding whose match starts at column 0 has `BeforeText = line[0:0]`, and
// every finding flush against end-of-line has the same in `AfterText` — so an implementation
// that short-circuits on `s == ""` and hands the caller's value straight back leaves the bug
// fully present, while looking like an obvious optimisation. A guard written in terms of
// VALUES cannot see it either, because the pinning view and a canonical empty string are
// indistinguishable by comparison.
//
// What prevents it here is structural rather than a special case: packStrings copies
// unconditionally, so no component it returns — empty or not — is ever a view of the source.
// The explicit canonicalisations are tidiness on top of that, and the tests are written
// against the short-circuit shape rather than against those lines, because that shape is the
// one that would actually reintroduce the defect.
//
// Value-preserving by construction: every replacement is `strings.Clone`-equal to what it
// replaced, and nil-ness is untouched. That matters beyond tidiness — the reported value is
// what the redactor replaces and what the suppression hash is computed over, so changing one
// would silently invalidate saved user rules or shrink a redaction mask.

const (
	// detachFloor is the size below which copying is always worth it, regardless of how much
	// of the buffer the copy represents. Well under any realistic extracted document, so the
	// common case never consults the ratio at all.
	detachFloor = 64 << 10

	// maxDetachDepth bounds the metadata walk. Metadata nests (a socialmedia cluster holds
	// []Match, each with its own Metadata), and a cycle through `any` is possible in
	// principle, so the walk is depth-bounded rather than trusting the shape.
	maxDetachDepth = 6
)

// DetachMatches rewrites every content-derived string reachable from matches as a copy that
// does not alias source, and reports whether it did.
//
// All-or-nothing per call. One surviving alias keeps the entire buffer reachable, so a
// partial detach would pay for copies that release nothing — it would be pure cost. When the
// finding-bearing text is most of the buffer there is nothing to win (the copy would be about
// as large as the thing it frees, and the transient peak would be worse), so the call
// declines and leaves the matches exactly as they were.
//
// Values are unchanged. Callers may ignore the return value; it exists for tests and for
// callers that want to report why nothing happened.
func DetachMatches(matches []Match, source string) bool {
	if len(matches) == 0 || source == "" {
		return false
	}

	if !detachIsWorthIt(matches, len(source)) {
		return false
	}

	// One copy per DISTINCT line, shared by every match on it. Per-match copies would be
	// both wasteful and a behaviour change: LineSpan.LineID interns {LineNumber, FullLine}
	// and the overlap resolver treats a differing FullLine as a different line, so sharing
	// keeps matches on one line at least as pointer-identical as they are today.
	copies := make(map[string]string, 16)
	var lastLine, lastCopy string
	var haveLast bool

	for i := range matches {
		m := &matches[i]

		switch line := m.Context.FullLine; {
		case line == "":
			// Defensive rather than reachable today: a finding needs a non-empty line to sit
			// on, so no validator produces this. If one ever does, the caller's value could
			// be a zero-length view of the document, and this keeps that from surviving.
			m.Context.FullLine = ""
		case haveLast && line == lastLine:
			// Matches arrive grouped by line often enough that this one-entry memo avoids
			// most of the map hashing, which is O(len(line)) per lookup.
			m.Context.FullLine = lastCopy
		default:
			c, ok := copies[line]
			if !ok {
				c = strings.Clone(line)
				copies[line] = c
			}
			m.Context.FullLine = c
			lastLine, lastCopy, haveLast = line, c, true
		}

		m.Text, m.Context.BeforeText, m.Context.AfterText =
			packStrings(m.Text, m.Context.BeforeText, m.Context.AfterText)

		detachMetadata(m.Metadata, 0)
	}

	return true
}

// detachIsWorthIt prices the copy before making it.
//
// It charges the distinct FullLine bytes plus, per match, the three short strings
// packStrings will allocate. Charging the per-match strings is not pedantry: the metadata
// validator reports `Text: line` (metadata_validator.go, the GPS arm), so Text can be a whole
// line, and a budget that priced only distinct lines would under-count that shape by a factor
// of the number of matches on the line.
func detachIsWorthIt(matches []Match, sourceLen int) bool {
	half := sourceLen / 2

	seen := make(map[string]struct{}, 16)
	total := 0
	var lastLine string
	var haveLast bool

	for i := range matches {
		m := &matches[i]

		// Per-match strings are charged whether or not the line is new.
		total += len(m.Text) + len(m.Context.BeforeText) + len(m.Context.AfterText)
		if total > detachFloor && total > half {
			return false
		}

		line := m.Context.FullLine
		if line == "" {
			continue
		}
		if len(line) > detachFloor && len(line) > half {
			// A single line already blows the budget. Return before hashing it: hashing a
			// multi-megabyte line to learn that we will not copy it is the one cost this
			// early exit exists to avoid.
			return false
		}
		if haveLast && line == lastLine {
			continue
		}
		lastLine, haveLast = line, true
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		total += len(line)
		if total > detachFloor && total > half {
			return false
		}
	}

	return true
}

// packStrings copies three short strings into ONE allocation, returning views of it.
//
// Three separate clones would be three allocations per finding; these three strings are
// always short (a match and its two context windows) and always travel together.
func packStrings(a, b, c string) (string, string, string) {
	if a == "" && b == "" && c == "" {
		return "", "", ""
	}

	var sb strings.Builder
	sb.Grow(len(a) + len(b) + len(c))
	sb.WriteString(a)
	sb.WriteString(b)
	sb.WriteString(c)
	s := sb.String()

	i, j := len(a), len(a)+len(b)
	ra, rb, rc := s[:i], s[i:j], s[j:]

	// Canonicalise empty components. This is NOT what breaks the aliasing — the copy above
	// already did that, and s[i:i] views the packed buffer rather than the document. It is
	// here so an empty window does not hold this small allocation alive on its own. The
	// load-bearing property is that there is no `if x == "" { return x }` short circuit
	// anywhere above: that is what would hand back a zero-length view of the source.
	if a == "" {
		ra = ""
	}
	if b == "" {
		rb = ""
	}
	if c == "" {
		rc = ""
	}
	return ra, rb, rc
}

// detachMetadata walks a finding's metadata, replacing content-derived strings.
//
// The fast path is a type switch over the shapes that actually carry content today. Anything
// else falls through to reflection, which is what makes this robust rather than a list to
// maintain: a validator storing a struct in Metadata is covered without opting in, and
// `detector` cannot name such a type anyway — personname imports detector, so importing
// personname here to type-switch on NameComponents would be an import cycle.
func detachMetadata(md map[string]any, depth int) {
	if md == nil || depth > maxDetachDepth {
		return
	}

	// Assigning to existing keys during a range is defined behaviour; no keys are added.
	for k, v := range md {
		switch t := v.(type) {
		case nil:
			// A nil interface value is part of the reported shape; leave it.
		case string:
			// Unconditional. strings.Clone("") returns the canonical empty string, which is
			// exactly the replacement a zero-length substring needs.
			md[k] = strings.Clone(t)
		case []Match:
			for i := range t {
				detachOneMatch(&t[i], depth+1)
			}
		case map[string]any:
			detachMetadata(t, depth+1)
		case bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64,
			float32, float64:
			// Cannot hold a reference to the buffer.
		default:
			if nv, changed := detachValue(reflect.ValueOf(v), depth+1); changed {
				md[k] = nv.Interface()
			}
		}
	}
}

// detachOneMatch detaches a Match nested inside metadata (a socialmedia cluster's
// cluster_members, for instance). The outer pass cannot reach these, and they carry the same
// content-derived strings.
func detachOneMatch(m *Match, depth int) {
	m.Context.FullLine = strings.Clone(m.Context.FullLine)
	m.Text, m.Context.BeforeText, m.Context.AfterText =
		packStrings(m.Text, m.Context.BeforeText, m.Context.AfterText)
	detachMetadata(m.Metadata, depth)
}

// detachValue returns a copy of v with every reachable string cloned, and whether it had to
// change anything. It reports changed=false for values that cannot hold a string, so the
// caller can leave the map entry untouched in the common case.
//
// Unexported fields cannot be set through reflection. A struct is copied wholesale first, so
// unexported fields keep their values; their strings stay aliased, which is a documented
// limitation rather than a silent one — the pinning guard walks exported fields only, so it
// asserts exactly what this can fix.
func detachValue(v reflect.Value, depth int) (reflect.Value, bool) {
	if depth > maxDetachDepth || !v.IsValid() {
		return v, false
	}

	switch v.Kind() {
	case reflect.String:
		if v.Len() == 0 {
			// Canonical empty, replacing a possible zero-length view of the document.
			out := reflect.New(v.Type()).Elem()
			out.SetString("")
			return out, true
		}
		out := reflect.New(v.Type()).Elem()
		out.SetString(strings.Clone(v.String()))
		return out, true

	case reflect.Struct:
		if !typeHasString(v.Type(), 0) {
			return v, false
		}
		out := reflect.New(v.Type()).Elem()
		out.Set(v) // carries unexported fields across
		changed := false
		for i := 0; i < v.NumField(); i++ {
			f := out.Field(i)
			if !f.CanSet() { // unexported
				continue
			}
			nf, fieldChanged := detachValue(v.Field(i), depth+1)
			if fieldChanged {
				f.Set(nf)
				changed = true
			}
		}
		return out, changed

	case reflect.Slice, reflect.Array:
		if !typeHasString(v.Type(), 0) {
			return v, false
		}
		if v.Kind() == reflect.Slice && v.IsNil() {
			// Nil-ness is part of the reported value: a golden locks
			// "context_keywords": null, so rebuilding a nil slice as an empty one is an
			// output change.
			return v, false
		}
		out := reflect.MakeSlice(sliceTypeOf(v.Type()), v.Len(), v.Len())
		changed := false
		for i := 0; i < v.Len(); i++ {
			ne, elemChanged := detachValue(v.Index(i), depth+1)
			if elemChanged {
				out.Index(i).Set(ne)
				changed = true
			} else {
				out.Index(i).Set(v.Index(i))
			}
		}
		if !changed {
			return v, false
		}
		return out, true

	case reflect.Map:
		if !typeHasString(v.Type(), 0) {
			return v, false
		}
		if v.IsNil() {
			return v, false
		}
		out := reflect.MakeMapWithSize(v.Type(), v.Len())
		changed := false
		for _, mk := range v.MapKeys() {
			nk, kChanged := detachValue(mk, depth+1)
			nv, vChanged := detachValue(v.MapIndex(mk), depth+1)
			if !kChanged {
				nk = mk
			}
			if !vChanged {
				nv = v.MapIndex(mk)
			}
			changed = changed || kChanged || vChanged
			out.SetMapIndex(nk, nv)
		}
		if !changed {
			return v, false
		}
		return out, true

	case reflect.Interface, reflect.Pointer:
		if v.IsNil() {
			return v, false
		}
		inner, changed := detachValue(v.Elem(), depth+1)
		if !changed {
			return v, false
		}
		if v.Kind() == reflect.Interface {
			out := reflect.New(v.Type()).Elem()
			out.Set(inner)
			return out, true
		}
		p := reflect.New(v.Type().Elem())
		p.Elem().Set(inner)
		return p, true
	}

	return v, false
}

// sliceTypeOf normalises an array type to the slice type used for its copy.
func sliceTypeOf(t reflect.Type) reflect.Type {
	if t.Kind() == reflect.Array {
		return reflect.SliceOf(t.Elem())
	}
	return t
}

// typeHasString reports whether a value of type t could contain a string at all, so whole
// branches (numeric slices, time values, plain structs of counters) are skipped without
// walking an instance.
func typeHasString(t reflect.Type, depth int) bool {
	if depth > maxDetachDepth || t == nil {
		return false
	}
	switch t.Kind() {
	case reflect.String:
		return true
	case reflect.Interface:
		// Contents unknown until runtime; assume it might.
		return true
	case reflect.Pointer, reflect.Slice, reflect.Array:
		return typeHasString(t.Elem(), depth+1)
	case reflect.Map:
		return typeHasString(t.Key(), depth+1) || typeHasString(t.Elem(), depth+1)
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			if typeHasString(t.Field(i).Type, depth+1) {
				return true
			}
		}
	}
	return false
}

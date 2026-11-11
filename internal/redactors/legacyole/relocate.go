// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package legacyole

import (
	"bytes"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// Relocating every reported value before the copy is written (#915).
//
// The overwrite loop counts what it replaced, and a value it could not find used to be logged
// (legacy_match_not_located) and skipped while the file was written and reported as redacted. Nothing
// checked the copy either: the redaction accounting had no per-finding "rewritten" bit, so a value
// that survived looked exactly like one that was masked. A numeric custom property did both: it has
// no text in any stream, so it was never found, and it was still there for the next scan to report.
//
// So, before writing, every value the loop was asked to overwrite is searched for again in what is
// about to be written, in every form the extractor can read it in: 8-bit or UTF-16LE in any stream,
// or the decoded text of a typed property. A value still present, or one that was in none of the
// original bytes to begin with, is a value this copy would keep, and the file is refused the way an
// unlocated overlap group already is: no output, the file in files_not_redacted with the cause, the
// not-redacted warning, and a failing --fail-on-incomplete.
//
// "Not located" alone is not the test. The same value reported on two lines is overwritten
// everywhere by the first unit, so the second finds nothing; a short value inside a longer one is
// gone once the longer one is written. Both were in the original and are absent from the copy, and
// that is a redaction.

// unrewrittenValue is a reported value the copy would still hold, by the types it was reported as.
type unrewrittenValue struct {
	types []string
}

// presentIn reports whether value can be read out of these stream bytes the way the extractor reads
// a value: as its 8-bit or UTF-16LE bytes in any stream, or as a typed property's decoded text.
func presentIn(logical [][]byte, typed []typedValue, value string) bool {
	if value == "" {
		return false
	}
	narrow := []byte(value)
	wide := toUTF16LE(value)
	for _, b := range logical {
		if bytes.Contains(b, narrow) || (len(wide) > 0 && bytes.Contains(b, wide)) {
			return true
		}
	}
	trimmed := strings.TrimSpace(value)
	for _, tv := range typed {
		if tv.rendering == trimmed {
			return true
		}
	}
	return false
}

// isMaskOnly reports whether a value is nothing but the mask byte. Overwriting such a value writes
// the same bytes back, so it is always "still present" and never a disclosure: it is what a copy
// this redactor already wrote holds where a value was.
func isMaskOnly(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] != maskByte {
			return false
		}
	}
	return true
}

// unitTypes is the finding types one write unit stands for: its members' for an overlap group.
func unitTypes(u legacyWriteUnit, matches []detector.Match) []string {
	if u.group.IsGroup() {
		return u.group.MemberTypes(matches)
	}
	return []string{u.match.Type}
}

// stillPresent lists the write units whose value can still be read out of the streams after every
// overwrite.
func stillPresent(units []legacyWriteUnit, matches []detector.Match, logical [][]byte, typed []typedValue) []unrewrittenValue {
	var out []unrewrittenValue
	for _, u := range units {
		v := u.match.Text
		if v == "" || isMaskOnly(v) {
			continue
		}
		if presentIn(logical, typed, v) {
			out = append(out, unrewrittenValue{types: unitTypes(u, matches)})
		}
	}
	return out
}

// refuseUnrewritten is the refusal for a copy that would still hold reported values, or nil when it
// holds none. Types and counts only: this message reaches stderr and every output format, so it never
// carries a value.
func refuseUnrewritten(outputPath string, notFound, remaining []unrewrittenValue) error {
	if len(notFound) == 0 && len(remaining) == 0 {
		return nil
	}
	var parts []string
	if len(notFound) > 0 {
		parts = append(parts, fmt.Sprintf("%d reported value(s) (types %s) were not found in any stream",
			len(notFound), typeList(notFound)))
	}
	if len(remaining) > 0 {
		parts = append(parts, fmt.Sprintf("%d reported value(s) (types %s) were still present after the overwrite",
			len(remaining), typeList(remaining)))
	}
	return fmt.Errorf("refusing to write %s: %s, so the copy would keep them",
		filepath.Base(outputPath), strings.Join(parts, ", and "))
}

// typeList is the sorted, de-duplicated types of a set of values, comma-separated.
func typeList(values []unrewrittenValue) string {
	seen := make(map[string]bool)
	var out []string
	for _, v := range values {
		for _, t := range v.types {
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"strings"
	"testing"
)

// hclHeredocOpenerByLineEnd is the opener check as it was before the linear rewrite: find the end
// of the line, then require everything after the identifier to trim to nothing. It is the oracle
// for TestHCLHeredocOpenerMatchesTheLineEndCheck, which pins that the rewrite changed only the
// cost, not a single decision.
func hclHeredocOpenerByLineEnd(s string, i int) (id string, bodyStart int, ok bool) {
	j := i + 2
	if j < len(s) && s[j] == '-' {
		j++
	}
	k := j
	for k < len(s) && (isASCIILetter(s[k]) || s[k] == '_' || (k > j && (s[k] == '-' || (s[k] >= '0' && s[k] <= '9')))) {
		k++
	}
	if k == j {
		return "", 0, false
	}
	eol := lineEnd(s, k)
	if strings.TrimSpace(s[k:eol]) != "" {
		return "", 0, false
	}
	if eol >= len(s) {
		return s[j:k], len(s), true
	}
	return s[j:k], eol + 1, true
}

// Every string of up to 5 symbols after `<<`, over an alphabet holding each class the opener
// distinguishes: identifier bytes, '-', a digit, ASCII and Unicode whitespace (\v, \f, NBSP,
// U+0085, U+2028), '\r', '\n', a non-space byte, a non-space multi-byte rune and an invalid byte.
func TestHCLHeredocOpenerMatchesTheLineEndCheck(t *testing.T) {
	alphabet := []string{"a", "Z", "_", "-", "7", " ", "\t", "\r", "\n", "\v", "\f",
		"\u00a0", "\u0085", "\u2028", "x", "=", "\u00e9", "\xff"}
	var walk func(prefix string, depth int)
	checked := 0
	walk = func(prefix string, depth int) {
		s := "<<" + prefix
		gotID, gotBody, gotOK := hclHeredocOpener(s, 0)
		wantID, wantBody, wantOK := hclHeredocOpenerByLineEnd(s, 0)
		if gotID != wantID || gotBody != wantBody || gotOK != wantOK {
			t.Fatalf("hclHeredocOpener(%q) = (%q, %d, %v), the line-end check says (%q, %d, %v)",
				s, gotID, gotBody, gotOK, wantID, wantBody, wantOK)
		}
		checked++
		if depth == 0 {
			return
		}
		for _, a := range alphabet {
			walk(prefix+a, depth-1)
		}
	}
	walk("", 5)
	walk("-", 4)
	if checked < 1000000 {
		t.Fatalf("only %d inputs checked", checked)
	}
}

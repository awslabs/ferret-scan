// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"regexp/syntax"
	"strings"
	"testing"
)

// Tests for #815: `session` is a keyword stem the assignment patterns are compiled from, but the line
// gate's admits were a hand list with no word for it, and the gate's generic fall-through admits a
// line with `=` or `:` only from 20 bytes. So `session=` with an 8- to 11-byte value on a line under
// 20 bytes was never scanned, while `token=` reported the same values at 100. The gate now admits
// every stem through lineHasKeywordStem, which is derived from the stem lists.

// stemLiteralsOf is every literal the stems match, as each stem spells it: `api_?key` gives `apikey`
// and `api_key`. Unlike keywordStemLiterals nothing is dropped for containing a shorter literal,
// since a line spelling the longer one is what its own pattern anchors on.
func stemLiteralsOf(stems []string) []string {
	var out []string
	for _, stem := range stems {
		re, err := syntax.Parse(stem, syntax.Perl)
		if err != nil {
			panic("stem " + stem + ": " + err.Error())
		}
		out = append(out, finiteLanguage(re.Simplify(), stem)...)
	}
	return out
}

// The unquoted, plural and collection patterns range over secretAssignmentKeywords, the quoted ones
// over quotedSecretKeywords, so an unquoted assignment is drawn from the first and a quoted one from
// the second.
var (
	gateAssignmentStemLiterals = stemLiteralsOf(secretAssignmentKeywords)
	gateQuotedStemLiterals     = stemLiteralsOf(quotedSecretKeywords)
)

// shortAssignmentLine is a stem literal in one of three cases assigned an 8- to 11-byte value,
// unquoted or quoted: `session=Kq7Zt9Wm`, `PWD: 'Hc4Rw9Tq2'`. Most of these lines are under 20
// bytes, below the generic fall-through, so only an admit for the stem itself lets them through.
// It is TestLineGateIsSound's third population.
func (g gateSecrets) shortAssignmentLine() string {
	caseOf := func(lit string) string {
		switch g.r.intn(3) {
		case 1:
			return strings.ToUpper(lit)
		case 2:
			return strings.ToUpper(lit[:1]) + lit[1:]
		}
		return lit
	}
	value := g.pw(8 + g.r.intn(4))
	switch g.r.intn(4) {
	case 0:
		return caseOf(g.r.pick(gateAssignmentStemLiterals)) + "=" + value
	case 1:
		return caseOf(g.r.pick(gateAssignmentStemLiterals)) + ": " + value
	case 2:
		return caseOf(g.r.pick(gateQuotedStemLiterals)) + `="` + value + `"`
	default:
		return caseOf(g.r.pick(gateQuotedStemLiterals)) + `: '` + value + `'`
	}
}

// TestLineGateAdmitsEveryStem is the guard #815 asks for: for every literal of every stem the
// keyword patterns are compiled from, the minimal assignments hold a keyword candidate and are
// admitted by containsSecretIndicators: `<stem>=<8 bytes>`, `<STEM>=<8 bytes>` and
// `<stem>: <8 bytes>` for the unquoted stems, `<stem>="<8 bytes>"` and `"<stem>": "<8 bytes>"` for the
// quoted ones. A stem added to either list is checked here with nothing to update, and an admit that
// stops covering one fails here.
func TestLineGateAdmitsEveryStem(t *testing.T) {
	v := NewValidator()
	const value = "Ab3dEf7h" // 8 bytes, mixed case and digits, accepted by plausibleUnquotedSecret
	var lines []string
	for _, lit := range gateAssignmentStemLiterals {
		lines = append(lines, lit+"="+value, strings.ToUpper(lit)+"="+value, lit+": "+value)
	}
	for _, lit := range gateQuotedStemLiterals {
		lines = append(lines, lit+`="`+value+`"`, `"`+lit+`": "`+value+`"`)
	}
	if len(lines) < 100 {
		t.Fatalf("only %d lines; the stem lists are no longer what this guard enumerates", len(lines))
	}
	for _, line := range lines {
		if len(v.keywordCandidates(line)) == 0 {
			t.Errorf("%q has no keyword candidate, so this guard tests nothing for its stem", line)
			continue
		}
		if !v.containsSecretIndicators(line) {
			t.Errorf("containsSecretIndicators rejects %q (%d bytes), which holds a keyword candidate: its stem has no admit",
				line, len(line))
		}
	}
}

// TestShortSessionAssignmentsAreScanned is the issue's reproducer through the public entry point,
// one unique value per line so that dedupe cannot hide a miss: `session=<v>` reports exactly what
// `token=<v>` reports, at every length the issue measured. On main the four lines under 20 bytes
// reported nothing and the 20- and 21-byte lines reported 100.
func TestShortSessionAssignmentsAreScanned(t *testing.T) {
	v := NewValidator()
	for _, value := range []string{"Ab3dEf7h", "Gh5jKl9mN", "Pq2sTu6wXy", "Zc8vBn4mQw1", "Rt7yUi3oPa9s", "Lk6jHg2fDs8aZ"} {
		session := secretsOn(t, v, "session="+value, "settings.txt")
		control := secretsOn(t, v, "token="+value, "settings.txt")
		if len(control) != 1 || control[0].Text != value {
			t.Fatalf("token=%s: control got %v, want one finding of the value", value, control)
		}
		if len(session) != 1 || session[0].Text != value {
			t.Errorf("session=%s (%d bytes): got %v, want one finding of the value, as token= reports",
				value, len("session="+value), session)
			continue
		}
		if session[0].Type != control[0].Type || session[0].Confidence != control[0].Confidence {
			t.Errorf("session=%s reported %s %.0f, token=%s reported %s %.0f: want the same",
				value, session[0].Type, session[0].Confidence, value, control[0].Type, control[0].Confidence)
		}
	}
}

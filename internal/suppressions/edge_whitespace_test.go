// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suppressions

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// A rule stopped matching its finding after an edit that never touched it: the identity digested the
// context windows raw, so near a line edge a CRLF `\r`, indentation or a trailing space changed it
// (#885). Measured on 39 of this repository's files: LF rules suppressed 86 of 581 findings after a
// CRLF conversion, 113 after re-indenting, 86 after adding a trailing space, and CRLF rules 86 of
// 581 on the LF copy. The current formula (v5) leaves the outer-edge whitespace out, and the two
// older formulas are also tried with the other line ending, so existing rules keep matching.
//
// Versions are written as hashVersion(n) so the v1-v4 rows also run against the parent commit,
// where they must already pass: those formulas are what existing rule files hold.

// identityFixtures are the known-answer findings. The hashes were computed by an independent model of
// the documented composite (Type | [confidence] | trimmed line | basename | line number |
// h16(before+after) | h16(value)), not by this package.
var identityFixtures = map[string]detector.Match{
	"indented CRLF line, trailing space": {
		Type: "SSN", Text: "123-45-6780", Filename: "/data/notes/customers.txt", LineNumber: 4, Confidence: 87.5, Validator: "ssn",
		Context: detector.ContextInfo{FullLine: "    social security number: 123-45-6780 \r",
			BeforeText: "    social security number: ", AfterText: " \r"},
	},
	"span with its trailing space and CR, empty windows": {
		Type: "INTELLECTUAL_PROPERTY", Text: "Copyright 2024 Example Corp \r", Filename: "LICENSE.txt", LineNumber: 1,
		Confidence: 60, Validator: "intellectual_property",
		Context: detector.ContextInfo{FullLine: "Copyright 2024 Example Corp \r"},
	},
	"no whitespace at any edge": {
		Type: "VISA", Text: "4539 0123 4567 8905", Filename: "customers.txt", LineNumber: 3, Confidence: 100, Validator: "creditcard",
		Context: detector.ContextInfo{FullLine: "payment card on file: 4539 0123 4567 8905", BeforeText: "payment card on file: "},
	},
}

func TestIdentityKnownAnswers(t *testing.T) {
	want := map[string][5]string{
		"indented CRLF line, trailing space": {
			"d3cc41110a70c7a753ad411e205d5acdd90f34a7525ecb54c0268315ad7c639d", // pragma: allowlist secret
			"49640cc018df362c75b934d9335ca272bad354b343391bdad8a8e528bbea16d2", // pragma: allowlist secret
			"e8933f9b8782ec4894c0dce13e1f17a45ca309f44364139e403e5d6538ed4aa9", // pragma: allowlist secret
			"1ff448ba5d1a02d80da3ee40bed2389ad4bf1f2cc78f8626345cdb15fcbddaff", // pragma: allowlist secret
			"a575aa0a347558e04083de43bc48e455ed42ddc1e3223054b4fe4b60b87c11c2", // pragma: allowlist secret
		},
		"span with its trailing space and CR, empty windows": {
			"4d517562e54b42c45b96f19f8d38a5ab9775f0e1f1529ca4c2290e34c1f3e1e6", // pragma: allowlist secret
			"c7fd00962e756bf149eea98c333a189f26f8dc2273dacaf566c11802ee33a1ce", // pragma: allowlist secret
			"fff938574c74a9a8cd548eda0508cc9c7923865e822cab509dfb232ac5d8357f", // pragma: allowlist secret
			"f04d018c6ffaefbe538ce247e81acdef78c715e4ead61d05c41b24ab20fa3e8e", // pragma: allowlist secret
			"1b2d2d4b66d3a7033f2f079b3e7f8cc977a02a3f5f2f2679822e79954bd53788", // pragma: allowlist secret
		},
		// With no whitespace at an edge, v5 is v2: such a v2 rule is already a v5 rule.
		"no whitespace at any edge": {
			"e415fce959b2038037044a0caf6c0d27f4cdc3b66e2bbdeb3ce57fd93817eb22", // pragma: allowlist secret
			"26acff1d3b18310d811387c1dfe3c23b51a00ed11bdefa290eb2270c2f00555a", // pragma: allowlist secret
			"7f2e82bc01b717f01beee4874a6f7d3e7198390b1f47d718b513b1bedeafbc85", // pragma: allowlist secret
			"39e1f0146ecc2bf594d28bfda208bb6bf7ba679e1f3e3edd63a9d2b2058f667e", // pragma: allowlist secret
			"26acff1d3b18310d811387c1dfe3c23b51a00ed11bdefa290eb2270c2f00555a", // pragma: allowlist secret
		},
	}
	sm := &SuppressionManager{}
	for name, f := range identityFixtures {
		for v := 1; v <= 5; v++ {
			if got := sm.findingHashVersion(f, hashVersion(v)); got != want[name][v-1] {
				t.Errorf("%s, v%d: %s, want %s", name, v, got, want[name][v-1])
			}
		}
		if got := sm.generateFindingHash(f); got != want[name][4] {
			t.Errorf("%s: a new rule is written as %s, want the v5 hash %s", name, got, want[name][4])
		}
	}
	if sm.hashSensitiveData("") != "" {
		t.Error(`hashSensitiveData("") must stay "": every hash written for an empty window depends on it`)
	}
}

// containsHash reports whether hashes holds h.
func containsHash(hashes []string, h string) bool {
	for _, c := range hashes {
		if c == h {
			return true
		}
	}
	return false
}

// onLine is the finding for value on line, its windows cut as the detector cuts them.
func onLine(line, value, typ string, lineNo int) detector.Match {
	start := strings.Index(line, value)
	return detector.Match{Type: typ, Text: value, Filename: "customers.txt", LineNumber: lineNo, Confidence: 90,
		Validator: "ssn", Context: detector.LineContext(line, start, start+len(value))}
}

// spanToLineEnd is a finding whose value runs to the end of the line, swallowing trailing whitespace
// and a `\r`, as the intellectual-property copyright pattern does.
func spanToLineEnd(line, from string, lineNo int) detector.Match {
	start := strings.Index(line, from)
	m := detector.Match{Type: "INTELLECTUAL_PROPERTY", Text: line[start:], Filename: "LICENSE.txt", LineNumber: lineNo,
		Confidence: 60, Validator: "intellectual_property", Context: detector.LineContext(line, start, len(line))}
	return m
}

// edgeEdits are the whitespace-only edits of a line the identity must not see.
var edgeEdits = map[string]func(string) string{
	"CRLF":           func(l string) string { return l + "\r" },
	"4-space indent": func(l string) string { return "    " + l },
	"tab indent":     func(l string) string { return "\t" + l },
	"trailing space": func(l string) string { return l + " " },
	"all of them":    func(l string) string { return "\t  " + l + "  \r" },
}

func TestTheCurrentIdentityIgnoresEdgeWhitespace(t *testing.T) {
	sm := &SuppressionManager{}
	findings := map[string]func(line string) detector.Match{
		"value mid-line": func(l string) detector.Match {
			return onLine(l, "123-45-6780", "SSN", 4)
		},
		"value at the line end": func(l string) detector.Match {
			return onLine(l, "4539 0123 4567 8905", "VISA", 3)
		},
		"span to the line end": func(l string) detector.Match {
			return spanToLineEnd(l, "Copyright", 1)
		},
	}
	lines := map[string]string{
		"value mid-line":        "social security number: 123-45-6780 (verified)",
		"value at the line end": "payment card on file: 4539 0123 4567 8905",
		"span to the line end":  "Copyright 2024 Example Corp",
	}
	for name, build := range findings {
		base := sm.findingHashVersion(build(lines[name]), hashVersionCurrent)
		for edit, apply := range edgeEdits {
			if got := sm.findingHashVersion(build(apply(lines[name])), hashVersionCurrent); got != base {
				t.Errorf("%s: %s changed the identity", name, edit)
			}
		}
	}

	// The decoys: every one of these is a different finding and must stay one.
	line := "social security number: 123-45-6780 (verified)"
	base := sm.findingHashVersion(onLine(line, "123-45-6780", "SSN", 4), hashVersionCurrent)
	decoys := map[string]detector.Match{
		"whitespace inside the before-window": onLine("social  security number: 123-45-6780 (verified)", "123-45-6780", "SSN", 4),
		"whitespace inside the after-window":  onLine("social security number: 123-45-6780  (verified)", "123-45-6780", "SSN", 4),
		"another value":                       onLine("social security number: 123-45-6781 (verified)", "123-45-6781", "SSN", 4),
		"another line text":                   onLine("social security no: 123-45-6780 (verified)", "123-45-6780", "SSN", 4),
		"another line number":                 onLine(line, "123-45-6780", "SSN", 5),
	}
	twice := "ssn 123-45-6780 and again 123-45-6780"
	first := onLine(twice, "123-45-6780", "SSN", 4)
	second := first
	second.Context = detector.LineContext(twice, strings.LastIndex(twice, "123-45-6780"), len(twice))
	for name, d := range decoys {
		if sm.findingHashVersion(d, hashVersionCurrent) == base {
			t.Errorf("%s: same identity as the original finding", name)
		}
	}
	if sm.findingHashVersion(first, hashVersionCurrent) == sm.findingHashVersion(second, hashVersionCurrent) {
		t.Error("two occurrences of one value on one line share an identity")
	}
}

// TestEveryOlderFormulaIsStillACandidate: v2 is skipped when it would equal the current formula, so
// every older formula must still be among the candidates of every finding shape.
func TestEveryOlderFormulaIsStillACandidate(t *testing.T) {
	sm := &SuppressionManager{}
	shapes := []detector.Match{
		onLine("social security number: 123-45-6780 (verified)", "123-45-6780", "SSN", 4),
		onLine("\tssn 123-45-6780 \t\r", "123-45-6780", "SSN", 4),
		spanToLineEnd("Copyright 2024 Example Corp \r", "Copyright", 1),
		identityFixtures["no whitespace at any edge"],
		identityFixtures["indented CRLF line, trailing space"],
	}
	for _, m := range shapes {
		candidates := sm.findingHashCandidates(m)
		if candidates[0] != sm.findingHashVersion(m, hashVersionCurrent) {
			t.Errorf("%q: the first candidate is not the current formula", m.Context.FullLine)
		}
		for _, v := range []hashVersion{hashVersionNoConfidence, hashVersionLegacyConfidence} {
			if !containsHash(candidates, sm.findingHashVersion(m, v)) {
				t.Errorf("%q: formula v%d is not a candidate", m.Context.FullLine, v)
			}
		}
	}
}

// lineEndingCase is one shape of finding near a line end, in its LF form.
type lineEndingCase struct {
	name  string
	build func(line string) detector.Match
	line  string
}

func lineEndingCases() []lineEndingCase {
	return []lineEndingCase{
		{"after-window reaches the line end", func(l string) detector.Match { return onLine(l, "123-45-6780", "SSN", 4) },
			"social security number: 123-45-6780 (verified)"},
		{"value at the line end, empty after-window", func(l string) detector.Match { return onLine(l, "123-45-6780", "SSN", 4) },
			"social security number: 123-45-6780"},
		{"trailing whitespace before the line end", func(l string) detector.Match { return onLine(l, "123-45-6780", "SSN", 4) },
			"ssn 123-45-6780 \t"},
		{"span that swallows the line end", func(l string) detector.Match { return spanToLineEnd(l, "Copyright", 1) },
			"Copyright 2024 Example Corp"},
		{"span and after-window not contiguous", func(l string) detector.Match {
			// The validator reports a sub-span as Text and keeps the window cut after the full match.
			m := onLine(l, "Example Corp", "INTELLECTUAL_PROPERTY", 1)
			m.Context.AfterText = " All rights reserved"
			return m
		}, "(c) 2024 Example Corp. All rights reserved"},
	}
}

// TestOlderRulesMatchTheOtherLineEnding: a rule an older formula wrote in an LF file suppresses the
// same finding in a CRLF copy, and the other way round.
func TestOlderRulesMatchTheOtherLineEnding(t *testing.T) {
	sm := &SuppressionManager{}
	for _, c := range lineEndingCases() {
		lf := c.build(c.line)
		crlf := c.build(c.line + "\r")
		if c.name == "span and after-window not contiguous" {
			crlf.Context.AfterText += "\r"
		}
		for _, version := range []hashVersion{hashVersionNoConfidence, hashVersionLegacyConfidence} {
			for _, dir := range []struct {
				name           string
				ruleOn, scanOn detector.Match
			}{{"LF rule, CRLF scan", lf, crlf}, {"CRLF rule, LF scan", crlf, lf}} {
				rule := sm.findingHashVersion(dir.ruleOn, version)
				if ok, _ := ruleManager(rule).IsSuppressed(dir.scanOn); !ok {
					t.Errorf("%s, v%d, %s: not suppressed", c.name, version, dir.name)
				}
			}
		}
	}
}

// TestALineEndingVariantMatchesOnlyItsOwnFinding: rules written on a CRLF copy, applied to the LF
// file, each suppress exactly the finding they were written for, and a finding with no rule stays.
func TestALineEndingVariantMatchesOnlyItsOwnFinding(t *testing.T) {
	sm := &SuppressionManager{}
	lines := []string{
		"contact 123-45-6780 or 123-45-6781",
		"ssn: 123-45-6780",
		"ssn: 123-45-6781",
		"Copyright 2024 Example Corp",
		"ssn: 123-45-6782 \t",
	}
	type entry struct{ lf, crlf detector.Match }
	var entries []entry
	for i, l := range lines {
		lineNo := i + 1
		if strings.HasPrefix(l, "Copyright") {
			entries = append(entries, entry{spanToLineEnd(l, "Copyright", lineNo), spanToLineEnd(l+"\r", "Copyright", lineNo)})
			continue
		}
		for _, v := range []string{"123-45-6780", "123-45-6781", "123-45-6782"} {
			if strings.Contains(l, v) {
				lf, crlf := onLine(l, v, "SSN", lineNo), onLine(l+"\r", v, "SSN", lineNo)
				lf.LineNumber, crlf.LineNumber = lineNo, lineNo
				entries = append(entries, entry{lf, crlf})
			}
		}
	}
	// The last entry has no rule: it is the finding that must stay reported.
	var hashes []string
	for _, e := range entries[:len(entries)-1] {
		hashes = append(hashes, sm.findingHashVersion(e.crlf, hashVersionNoConfidence))
	}
	mgr := ruleManager(hashes...)
	for i := range mgr.config.Rules {
		mgr.config.Rules[i].ID = string(rune('A' + i))
	}
	for i, e := range entries {
		ok, rule := mgr.IsSuppressed(e.lf)
		switch {
		case i == len(entries)-1 && ok:
			t.Errorf("the finding with no rule (%q) was suppressed by rule %s", e.lf.Context.FullLine, rule.ID)
		case i < len(entries)-1 && !ok:
			t.Errorf("finding %d (%q) not suppressed", i, e.lf.Context.FullLine)
		case i < len(entries)-1 && rule.ID != string(rune('A'+i)):
			t.Errorf("finding %d suppressed by rule %s, want %s", i, rule.ID, string(rune('A'+i)))
		}
	}
}

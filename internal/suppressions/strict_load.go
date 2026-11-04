// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suppressions

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

// The strict pass over a suppression file (#866).
//
// The loader used to be a plain yaml.Unmarshal into SuppressionRule, which ignores every key it does not
// know. For most files that is harmless; for a suppression file it fails open. A rule's keys are
// CONSTRAINTS on a suppressor, and ignoring one widens it: measured on two findings, an expiry spelled
// `expries_at` (or any of six other plausible spellings, or nested under `metadata:`) turned a rule that
// had lapsed — 2 findings reported, pre-commit exit 1 — into a permanent one: 0 reported, exit 0, and no
// expiry warning, because there was no expiry any more.
//
// So the pass refuses rather than warns. A rule carrying a key this version does not recognise, or a
// `metadata` key named like a rule key, is kept in the file but NOT APPLIED, and a file declaring a
// version other than "1.0" applies no rules. Warn-only — the treatment unknown CONFIG keys get — would
// leave the finding hidden while the warning scrolled past; refusing makes the finding reappear, which
// is the one outcome nobody can miss. Everything that cannot widen a suppressor (an unknown top-level
// key, a hash that can never match, an id two rules share) is named and otherwise loaded as before.

// ruleKeys is every key a rule may carry, in the order the saver writes them. It is SuppressionRule's
// yaml tags; TestRuleKeysAreTheStructsYAMLTags keeps the two from drifting apart.
var ruleKeys = []string{
	"id", "hash", "reason", "enabled", "created_by", "created_at",
	"last_seen_at", "expires_at", "reviewed_by", "reviewed_at", "metadata",
}

// supportedVersion is the only file version this loader reads. It is also the only one ever written.
const supportedVersion = "1.0"

// maxNamedProblems bounds how many entries one warning line lists before "and N more".
const maxNamedProblems = 5

type problemKind int

const (
	// Refusing: the rule (or, for a version, every rule) is kept in the file but never suppresses.
	problemUnknownRuleKey problemKind = iota
	problemShadowingMetadataKey
	problemUnsupportedVersion

	// Inert: named, and loaded exactly as before. None of these can make a rule suppress more.
	problemUnknownTopLevelKey
	problemMissingHash
	problemMalformedHash
	problemDuplicateID
)

// FileProblem is one thing the strict pass found in a suppression file.
type FileProblem struct {
	kind problemKind
	// Line is the 1-based line of the offending key or value.
	Line int
	// RuleIndex is the rule's position under rules:, or -1 for a file-level problem.
	RuleIndex int
	// RuleID is the rule's id, when it has one.
	RuleID string
	// Key is the offending key, dotted for a metadata key ("metadata.expires_at").
	Key string
	// Value is the offending value: a version, a hash, or a duplicated id.
	Value string
	// Lines lists every rule that shares a duplicated id.
	Lines []int
}

// Refuses reports whether the problem stops its rule, or for a version every rule, from being applied.
func (p FileProblem) Refuses() bool {
	switch p.kind {
	case problemUnknownRuleKey, problemShadowingMetadataKey, problemUnsupportedVersion:
		return true
	}
	return false
}

// String describes the problem in a few words, for NotApplied and for tests.
func (p FileProblem) String() string {
	switch p.kind {
	case problemUnknownRuleKey:
		return fmt.Sprintf("unknown key %q (line %d)", p.Key, p.Line)
	case problemShadowingMetadataKey:
		return fmt.Sprintf("metadata key %q is a rule key (line %d)", strings.TrimPrefix(p.Key, "metadata."), p.Line)
	case problemUnsupportedVersion:
		return fmt.Sprintf("file version %q is not %q (line %d)", p.Value, supportedVersion, p.Line)
	case problemUnknownTopLevelKey:
		return fmt.Sprintf("unknown top-level key %q (line %d)", p.Key, p.Line)
	case problemMissingHash:
		return fmt.Sprintf("no hash (line %d)", p.Line)
	case problemMalformedHash:
		return fmt.Sprintf("hash %s is not 64 lower-case hexadecimal digits (line %d)", quoteClipped(p.Value), p.Line)
	case problemDuplicateID:
		return fmt.Sprintf("id %s is used by %d rules (lines %s)", displayToken(p.Value), len(p.Lines), joinInts(p.Lines))
	}
	return "unknown problem"
}

// CheckSuppressionFile runs the strict pass over the bytes of a suppression file without loading it,
// for a caller that wants the verdict alone (a documentation guard, say). A YAML syntax error is
// returned as the error; everything else is a FileProblem.
func CheckSuppressionFile(data []byte) ([]FileProblem, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return checkDocument(&doc), nil
}

// checkDocument walks a parsed suppression file. It reads the node tree rather than decoding with
// KnownFields(true) for two reasons: the decoder stops at the FIRST unknown key, where the warning needs
// all of them with their lines; and it cannot see a metadata key that shadows a rule key, since
// metadata is a free-form map.
func checkDocument(doc *yaml.Node) []FileProblem {
	root := documentRoot(doc)
	if root == nil {
		return nil
	}
	var problems []FileProblem
	var rules *yaml.Node
	for i := 0; i+1 < len(root.Content); i += 2 {
		key, value := root.Content[i], root.Content[i+1]
		switch key.Value {
		case "version":
			if v := scalarText(value); v != "" && v != supportedVersion {
				problems = append(problems, FileProblem{kind: problemUnsupportedVersion, Line: value.Line, RuleIndex: -1, Value: v})
			}
		case "rules":
			rules = value
		default:
			problems = append(problems, FileProblem{kind: problemUnknownTopLevelKey, Line: key.Line, RuleIndex: -1, Key: key.Value})
		}
	}
	if rules == nil || rules.Kind != yaml.SequenceNode {
		return problems
	}

	idLines := map[string][]int{}
	var idOrder []string
	for idx, rule := range rules.Content {
		if rule.Kind == yaml.AliasNode && rule.Alias != nil {
			rule = rule.Alias
		}
		if rule.Kind != yaml.MappingNode {
			continue
		}
		problems = append(problems, checkRule(idx, rule)...)
		if id := scalarText(mappingValue(rule, "id")); id != "" {
			if _, seen := idLines[id]; !seen {
				idOrder = append(idOrder, id)
			}
			idLines[id] = append(idLines[id], rule.Line)
		}
	}
	for _, id := range idOrder {
		if lines := idLines[id]; len(lines) > 1 {
			problems = append(problems, FileProblem{kind: problemDuplicateID, Line: lines[0], RuleIndex: -1, RuleID: id, Value: id, Lines: lines})
		}
	}
	return problems
}

// checkRule names the problems of one rule. A rule that is refused for a key does not also get its
// hash named: fixing the key is the action, and a second entry for the same rule is noise.
func checkRule(idx int, rule *yaml.Node) []FileProblem {
	id := scalarText(mappingValue(rule, "id"))
	var refusing, inert []FileProblem
	hashSeen := false
	for _, pair := range rulePairs(rule) {
		key, value := pair[0], pair[1]
		if !isRuleKey(key.Value) {
			refusing = append(refusing, FileProblem{kind: problemUnknownRuleKey, Line: key.Line, RuleIndex: idx, RuleID: id, Key: key.Value})
			continue
		}
		switch key.Value {
		case "hash":
			hashSeen = true
			switch h := scalarText(value); {
			case h == "":
				inert = append(inert, FileProblem{kind: problemMissingHash, Line: key.Line, RuleIndex: idx, RuleID: id})
			case !isFindingHash(h):
				inert = append(inert, FileProblem{kind: problemMalformedHash, Line: value.Line, RuleIndex: idx, RuleID: id, Value: h})
			}
		case "metadata":
			if value.Kind != yaml.MappingNode {
				continue
			}
			for j := 0; j+1 < len(value.Content); j += 2 {
				if mk := value.Content[j]; isRuleKey(mk.Value) {
					refusing = append(refusing, FileProblem{kind: problemShadowingMetadataKey, Line: mk.Line, RuleIndex: idx, RuleID: id, Key: "metadata." + mk.Value})
				}
			}
		}
	}
	if !hashSeen {
		inert = append(inert, FileProblem{kind: problemMissingHash, Line: rule.Line, RuleIndex: idx, RuleID: id})
	}
	if len(refusing) > 0 {
		return refusing
	}
	return inert
}

// rulePairs returns a rule's key/value pairs, following YAML merge keys (`<<: *defaults`) into the
// mappings they merge, so a key supplied by a merge is checked like one written in place.
func rulePairs(rule *yaml.Node) [][2]*yaml.Node {
	var pairs [][2]*yaml.Node
	var walk func(m *yaml.Node, depth int)
	walk = func(m *yaml.Node, depth int) {
		if depth > 8 || m == nil {
			return
		}
		if m.Kind == yaml.AliasNode {
			walk(m.Alias, depth+1)
			return
		}
		if m.Kind != yaml.MappingNode {
			return
		}
		for i := 0; i+1 < len(m.Content); i += 2 {
			key, value := m.Content[i], m.Content[i+1]
			if key.Tag == "!!merge" {
				if value.Kind == yaml.SequenceNode {
					for _, v := range value.Content {
						walk(v, depth+1)
					}
				} else {
					walk(value, depth+1)
				}
				continue
			}
			pairs = append(pairs, [2]*yaml.Node{key, value})
		}
	}
	walk(rule, 0)
	return pairs
}

// isRuleKey reports whether key is one of the eleven rule keys.
func isRuleKey(key string) bool {
	for _, k := range ruleKeys {
		if k == key {
			return true
		}
	}
	return false
}

// isFindingHash reports whether h has the shape every hash this tool writes has: 64 lower-case hex
// digits. Matching is exact, so an upper-cased hash can never match; it is named, not lower-cased,
// because lower-casing would make a rule that suppresses nothing today start suppressing.
func isFindingHash(h string) bool {
	if len(h) != 64 {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// documentRoot returns the top-level mapping of a parsed file, or nil when there is none (an empty
// file, a comment-only file, a document that is not a mapping).
func documentRoot(doc *yaml.Node) *yaml.Node {
	if doc == nil || doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil
	}
	if root := doc.Content[0]; root.Kind == yaml.MappingNode {
		return root
	}
	return nil
}

// mappingValue returns the value of key in mapping m, or nil.
func mappingValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// scalarText is a scalar's text, "" for null, a non-scalar or a nil node.
func scalarText(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode || n.Tag == "!!null" {
		return ""
	}
	return n.Value
}

// applyRefusals marks every rule a refusing problem names, and every rule when the version is
// unsupported. The rule stays in config.Rules, so a save writes it back untouched.
func applyRefusals(config *SuppressionConfig, problems []FileProblem) {
	reasons := make(map[int][]string)
	var fileWide []string
	for _, p := range problems {
		if !p.Refuses() {
			continue
		}
		if p.kind == problemUnsupportedVersion {
			fileWide = append(fileWide, p.String())
			continue
		}
		if p.RuleIndex >= 0 && p.RuleIndex < len(config.Rules) {
			reasons[p.RuleIndex] = append(reasons[p.RuleIndex], p.String())
		}
	}
	for i := range config.Rules {
		all := append(append([]string{}, fileWide...), reasons[i]...)
		if len(all) > 0 {
			config.Rules[i].NotApplied = strings.Join(all, "; ")
		}
	}
}

// writeLoadWarnings prints the strict pass's verdict, one line per class of problem, so each line can
// be grepped for and none of them depends on another. Printed whatever --quiet or pre-commit mode say,
// like the malformed-file warning beside it: a rule that silently stopped (or never started) applying is
// exactly what those modes must not hide.
func writeLoadWarnings(w io.Writer, path string, problems []FileProblem, rulesLoaded int) {
	if w == nil || len(problems) == 0 {
		return
	}
	var version *FileProblem
	var topLevel, refusing, unmatchable, duplicates []FileProblem
	for i := range problems {
		p := problems[i]
		switch {
		case p.kind == problemUnsupportedVersion:
			version = &problems[i]
		case p.kind == problemUnknownTopLevelKey:
			topLevel = append(topLevel, p)
		case p.Refuses():
			refusing = append(refusing, p)
		case p.kind == problemDuplicateID:
			duplicates = append(duplicates, p)
		default:
			unmatchable = append(unmatchable, p)
		}
	}

	if version != nil {
		fmt.Fprintf(w, "WARNING: suppression file %s declares version %q, which this version does not read, so none "+
			"of its %d rule(s) are applied. The only version is %q; set `version: %q` once the rules are checked.\n",
			path, version.Value, rulesLoaded, supportedVersion, supportedVersion)
	}

	if len(topLevel) > 0 {
		entries := make([]string, len(topLevel))
		for i, p := range topLevel {
			entries[i] = fmt.Sprintf("%q (line %d)", p.Key, p.Line)
		}
		if rulesLoaded == 0 {
			fmt.Fprintf(w, "WARNING: 0 rules loaded from %s: unknown top-level key %s; rules belong under \"rules:\".\n",
				path, listCapped(entries))
		} else {
			fmt.Fprintf(w, "WARNING: suppression file %s has a top-level key this version does not recognise, which is "+
				"ignored: %s. Only \"version\" and \"rules\" are read.\n", path, listCapped(entries))
		}
	}

	if len(refusing) > 0 {
		rules := map[int]bool{}
		entries := make([]string, len(refusing))
		for i, p := range refusing {
			rules[p.RuleIndex] = true
			entries[i] = fmt.Sprintf("%s %q (line %d)", ruleLabel(p), p.Key, p.Line)
		}
		fmt.Fprintf(w, "WARNING: %d suppression rule(s) in %s are NOT applied because they contain keys this version "+
			"does not recognise: %s. A rule's keys are %s. Put free-form annotations under metadata:, under names "+
			"that are not rule keys.\n", len(rules), path, listCapped(entries), strings.Join(ruleKeys, ", "))
	}

	if len(unmatchable) > 0 {
		entries := make([]string, len(unmatchable))
		for i, p := range unmatchable {
			if p.kind == problemMissingHash {
				entries[i] = fmt.Sprintf("%s has no hash (line %d)", ruleLabel(p), p.Line)
			} else {
				entries[i] = fmt.Sprintf("%s hash %s (line %d) is not 64 lower-case hexadecimal digits",
					ruleLabel(p), quoteClipped(p.Value), p.Line)
			}
		}
		fmt.Fprintf(w, "WARNING: %d suppression rule(s) in %s can never match: %s. Rules match by the exact hash "+
			"--generate-suppressions writes, so regenerate the rule rather than editing its hash.\n",
			len(unmatchable), path, listCapped(entries))
	}

	for _, p := range duplicates {
		fmt.Fprintf(w, "WARNING: suppression file %s gives %d rules the same id %s (lines %s). They are applied, but an "+
			"id is how a rule is edited, disabled or removed, so give each rule its own.\n",
			path, len(p.Lines), displayToken(p.Value), joinInts(p.Lines))
	}
}

// ruleLabel names a rule in a warning: its id, or its position when it has none.
func ruleLabel(p FileProblem) string {
	if p.RuleID != "" {
		return displayToken(p.RuleID)
	}
	return fmt.Sprintf("rule %d", p.RuleIndex+1)
}

// listCapped joins up to maxNamedProblems entries and says how many it left out.
func listCapped(entries []string) string {
	if len(entries) <= maxNamedProblems {
		return strings.Join(entries, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(entries[:maxNamedProblems], ", "), len(entries)-maxNamedProblems)
}

// displayToken prints a value read from the file as is when it is plainly printable, and quoted
// otherwise, so a hostile id cannot put control characters on the operator's terminal.
func displayToken(s string) string {
	if s == "" || len(s) > 64 {
		return quoteClipped(s)
	}
	for _, r := range s {
		if !unicode.IsGraphic(r) || unicode.IsSpace(r) || r == '"' {
			return strconv.Quote(s)
		}
	}
	return s
}

// quoteClipped quotes a value read from the file, shortened so a junk value cannot flood the line.
func quoteClipped(s string) string {
	const max = 24
	if r := []rune(s); len(r) > max {
		return strconv.Quote(string(r[:max])) + "…"
	}
	return strconv.Quote(s)
}

func joinInts(ns []int) string {
	sorted := append([]int(nil), ns...)
	sort.Ints(sorted)
	parts := make([]string, len(sorted))
	for i, n := range sorted {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ", ")
}

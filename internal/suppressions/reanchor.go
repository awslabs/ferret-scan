// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suppressions

import (
	"crypto/sha256"
	"encoding"
	"fmt"
	"hash"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// Re-anchoring at --generate-suppressions (#885).
//
// A rule's identity includes its finding's line number, so a line inserted above a finding stopped the
// rule matching it. Measured on the issue's 39-file set, rules a main binary generated at v2.4.0 left
// 259 of HEAD's findings reported although their value and trimmed line were unchanged and only the
// line number had moved, and every regeneration appended a second, disabled rule for each while the
// reviewed one went on matching nothing.
//
// GenerateSuppressionRules now relocates such a rule. A rule no finding of the run identifies moves to
// the finding whose identity, recomputed at the line number the rule recorded (metadata.line_number,
// and metadata.confidence for the formula that hashed it), equals the rule's hash. Every other component
// of that identity comes from the finding (its type, trimmed line, basename, windows and value), so a
// rule can move only to the same value on the same line text, in a file of the same name: an edited
// line never relocates, which keeps a stale rule from hiding a new value. Scan-time matching stays exact.
//
// Only a one-to-one pairing is accepted. Findings are compared per basename and finding type across
// every directory of the run, because the identity names a basename, not a path. A rule that fits two
// findings (a repeated line, or same-named files whose findings sit at different lines), and a finding
// two rules fit, are refused and counted as ambiguous. Every finding of the run is a candidate,
// including those a rule already identifies, so a rule never relocates onto one copy of a repeated line
// while the other copy keeps its own rule: it is refused as ambiguous, or, when every finding it fits
// has a rule of its own, counted as matching nothing (its own copy was removed).
//
// The search compares each finding of a basename and type with each distinct (line number, confidence)
// recorded by that group's rules, which is quadratic: a file of N findings with a line inserted at the
// top has N rules to relocate and N candidates for each. MaxReanchorComparisons bounds it. Groups are
// searched cheapest first, and a group whose comparisons do not fit in what is left is not searched at
// all, because a pairing is proven one-to-one only once every comparison of its group has been made;
// its rules are counted as not evaluated and left as they are. A comparison costs a few short SHA-256
// blocks whatever the length of the finding's line: the part of the composite before the line number
// is hashed once per finding (lineOpenForm).

// MaxReanchorComparisons bounds the work one GenerateSuppressionRules call spends re-anchoring. A
// comparison is one finding against one (line number, confidence) recorded by the unmatched rules of
// its basename and finding type, and costs 1.1-1.4 µs with every candidate form computed (measured
// on an AMD EPYC 9R14, BenchmarkReanchorComparison), so the limit is under a second of hashing: a
// group of 707 findings and 707 rules, every rule to be moved. The whole of this repository from
// v2.4.0 to v2.6.0 development needed 38,260. A group that does not fit is not searched, and its rules
// are counted in GenerationReport.NotEvaluated and left as they are.
const MaxReanchorComparisons = 500_000

// reanchorMove relocates rule (an index into config.Rules) to finding (an index into the batch).
type reanchorMove struct{ rule, finding int }

// reanchorPlan is what the search decided; each list is in rule order.
type reanchorPlan struct {
	accepted     []reanchorMove
	ambiguous    []int
	unmatched    []int
	notEvaluated []int
	// comparisons is the number made, for the complexity guard.
	comparisons int
}

// anchorGroupKey is what a rule's identity names besides the line: the file's basename and the type.
type anchorGroupKey struct{ base, typ string }

// anchorKey is a line number, and the confidence a legacy rule folded into its hash: "" when the rule
// recorded none, which means the finding's own.
type anchorKey struct {
	line int
	conf string
}

// orphanRule is a rule no finding identifies, with what its identity is recomputed at.
type orphanRule struct {
	idx    int
	key    anchorKey
	digest [32]byte
}

type anchorGroup struct {
	key      anchorGroupKey
	findings []int
	rules    []orphanRule
	keys     []anchorKey // distinct, by line then confidence
	cost     int
}

// comparisonLimit is MaxReanchorComparisons unless a test lowered it.
func (sm *SuppressionManager) comparisonLimit() int {
	if sm.reanchorLimit > 0 {
		return sm.reanchorLimit
	}
	return MaxReanchorComparisons
}

// planReanchor decides, for every applied rule that no finding of the batch identifies (identified),
// whether it moves, and where. identities holds each finding's current-formula hash, and ruled says
// whether a rule identifies it. A rule is considered only when the batch has findings of its basename
// and type; the others are not counted at all, because the run may not have scanned their file or run
// the check that produces their type.
func (sm *SuppressionManager) planReanchor(matches []detector.Match, identities []string, ruled []bool, identified map[int]bool) reanchorPlan {
	var plan reanchorPlan
	findings := make(map[anchorGroupKey][]int)
	for i, m := range matches {
		k := anchorGroupKey{filepath.Base(m.Filename), m.Type}
		findings[k] = append(findings[k], i)
	}

	groups := make(map[anchorGroupKey]*anchorGroup)
	for i := range sm.config.Rules {
		rule := &sm.config.Rules[i]
		if identified[i] || rule.NotApplied != "" {
			// A rule the loader refused (#866) is neither counted nor moved.
			continue
		}
		k := anchorGroupKey{strings.TrimSpace(rule.Metadata["filename"]), strings.TrimSpace(rule.Metadata["finding_type"])}
		batch, ok := findings[k]
		if !ok {
			continue
		}
		line, err := strconv.Atoi(strings.TrimSpace(rule.Metadata["line_number"]))
		digest, valid := ruleDigest(rule.Hash)
		if err != nil || line < 0 || !valid {
			// Nothing to recompute its identity at, or a hash no identity can equal.
			plan.unmatched = append(plan.unmatched, i)
			continue
		}
		g := groups[k]
		if g == nil {
			g = &anchorGroup{key: k, findings: batch}
			groups[k] = g
		}
		g.rules = append(g.rules, orphanRule{idx: i, key: anchorKey{line: line, conf: recordedConfidence(rule)}, digest: digest})
	}

	ordered := make([]*anchorGroup, 0, len(groups))
	for _, g := range groups {
		seen := make(map[anchorKey]bool, len(g.rules))
		for _, r := range g.rules {
			if !seen[r.key] {
				seen[r.key] = true
				g.keys = append(g.keys, r.key)
			}
		}
		sort.Slice(g.keys, func(a, b int) bool {
			if g.keys[a].line != g.keys[b].line {
				return g.keys[a].line < g.keys[b].line
			}
			return g.keys[a].conf < g.keys[b].conf
		})
		g.cost = len(g.findings) * len(g.keys)
		ordered = append(ordered, g)
	}
	sort.Slice(ordered, func(a, b int) bool {
		x, y := ordered[a], ordered[b]
		if x.cost != y.cost {
			return x.cost < y.cost
		}
		if x.key.base != y.key.base {
			return x.key.base < y.key.base
		}
		return x.key.typ < y.key.typ
	})

	budget := sm.comparisonLimit()
	for _, g := range ordered {
		if g.cost > budget {
			for _, r := range g.rules {
				plan.notEvaluated = append(plan.notEvaluated, r.idx)
			}
			continue
		}
		budget -= g.cost
		plan.comparisons += g.cost
		sm.decideGroup(g, matches, identities, ruled, &plan)
	}

	sort.Ints(plan.ambiguous)
	sort.Ints(plan.unmatched)
	sort.Ints(plan.notEvaluated)
	sort.Slice(plan.accepted, func(a, b int) bool { return plan.accepted[a].rule < plan.accepted[b].rule })
	return plan
}

// decideGroup compares every finding of g with every key of g and records what each rule of g becomes.
// A node is a current-formula identity: findings that share one are the same finding as far as any rule
// can tell (a duplicate, or same-named files with the finding at the same line), so they are one
// candidate, and a rule moved to it matches all of them, as it did before they moved.
func (sm *SuppressionManager) decideGroup(g *anchorGroup, matches []detector.Match, identities []string, ruled []bool, plan *reanchorPlan) {
	byDigest := make(map[[32]byte][]int, len(g.rules)) // rule hash -> positions in g.rules
	for pos, r := range g.rules {
		byDigest[r.digest] = append(byDigest[r.digest], pos)
	}
	ruleNodes := make([][]string, len(g.rules)) // the distinct nodes each rule fits
	nodeRules := make(map[string][]int)         // the rules each node fits
	nodeRuled := make(map[string]bool)          // a finding of the node has a rule of its own
	nodeFinding := make(map[string]int)         // the node's first finding
	fit := func(pos int, node string) {
		for _, n := range ruleNodes[pos] {
			if n == node {
				return
			}
		}
		ruleNodes[pos] = append(ruleNodes[pos], node)
		nodeRules[node] = append(nodeRules[node], pos)
	}

	hasher := newAnchorHasher()
	for _, fi := range g.findings {
		node := identities[fi]
		if ruled[fi] {
			nodeRuled[node] = true
		}
		if _, ok := nodeFinding[node]; !ok {
			nodeFinding[node] = fi
		}
		open := sm.openIdentity(matches[fi])
		lastLine := -1
		for _, k := range g.keys {
			open.digestsAt(hasher, k, k.line != lastLine, func(d [32]byte) {
				for _, pos := range byDigest[d] {
					fit(pos, node)
				}
			})
			lastLine = k.line
		}
	}

	for pos, r := range g.rules {
		nodes := ruleNodes[pos]
		switch {
		case len(nodes) == 1 && !nodeRuled[nodes[0]] && len(nodeRules[nodes[0]]) == 1:
			plan.accepted = append(plan.accepted, reanchorMove{rule: r.idx, finding: nodeFinding[nodes[0]]})
		case anyUnruled(nodes, nodeRuled):
			plan.ambiguous = append(plan.ambiguous, r.idx)
		default:
			// No finding fits it, or each one that does has a rule of its own: the line was edited, or
			// the finding removed.
			plan.unmatched = append(plan.unmatched, r.idx)
		}
	}
}

func anyUnruled(nodes []string, ruled map[string]bool) bool {
	for _, n := range nodes {
		if !ruled[n] {
			return true
		}
	}
	return false
}

// ruleDigest decodes a rule hash as the matcher compares it: 64 lower-case hexadecimal digits, the
// only spelling a computed identity has. Any other spelling can never match, so it never relocates.
func ruleDigest(h string) ([32]byte, bool) {
	var d [32]byte
	if len(h) != 64 {
		return d, false
	}
	for i := 0; i < 64; i++ {
		c := h[i]
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'a' && c <= 'f':
			v = c - 'a' + 10
		default:
			return d, false
		}
		if i%2 == 0 {
			d[i/2] = v << 4
		} else {
			d[i/2] |= v
		}
	}
	return d, true
}

// recordedConfidence is the confidence a rule recorded, as the legacy formula formats it, or "" when it
// recorded none it could have hashed.
func recordedConfidence(rule *SuppressionRule) string {
	f, err := strconv.ParseFloat(strings.TrimSpace(rule.Metadata["confidence"]), 64)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%.2f", f)
}

// lineOpenForm is one candidate form of a finding with the line number left open: its identity at
// line L is SHA-256(head + L + tail). state is the SHA-256 state after head, so the identity at another
// line costs the few blocks of L and tail however long head (which holds the line) is.
type lineOpenForm struct {
	head  string
	tail  []byte
	state []byte // nil when the hash's state cannot be saved, which only costs speed
}

func (sm *SuppressionManager) newLineOpenForm(m detector.Match, version hashVersion) lineOpenForm {
	head, tail := sm.identityParts(m, version)
	f := lineOpenForm{head: head, tail: []byte(tail)}
	h := sha256.New()
	_, _ = io.WriteString(h, head)
	if saver, ok := h.(encoding.BinaryMarshaler); ok {
		if state, err := saver.MarshalBinary(); err == nil {
			f.state = state
		}
	}
	return f
}

// anchorHasher computes lineOpenForm identities with one SHA-256 hash and two buffers, reused, so a
// comparison allocates nothing. Not safe for concurrent use.
type anchorHasher struct {
	work    hash.Hash
	restore encoding.BinaryUnmarshaler // nil when the hash's state cannot be restored
	num     []byte
	sum     []byte
}

func newAnchorHasher() *anchorHasher {
	h := &anchorHasher{work: sha256.New(), num: make([]byte, 0, 20), sum: make([]byte, 0, sha256.Size)}
	h.restore, _ = h.work.(encoding.BinaryUnmarshaler)
	return h
}

// at is f's identity at line.
func (h *anchorHasher) at(f *lineOpenForm, line int) [32]byte {
	h.num = strconv.AppendInt(h.num[:0], int64(line), 10)
	var out [32]byte
	if h.restore != nil && f.state != nil && h.restore.UnmarshalBinary(f.state) == nil {
		_, _ = h.work.Write(h.num)
		_, _ = h.work.Write(f.tail)
		h.sum = h.work.Sum(h.sum[:0])
		copy(out[:], h.sum)
		return out
	}
	composite := make([]byte, 0, len(f.head)+len(h.num)+len(f.tail))
	composite = append(append(append(composite, f.head...), h.num...), f.tail...)
	return sha256.Sum256(composite)
}

// openIdentity is every candidate form of one finding (eachCandidateForm) with the line number left
// open. The legacy forms fold the confidence in before the line, so they are built per confidence, on
// first use: a group's rules record few distinct ones.
type openIdentity struct {
	sm     *SuppressionManager
	plain  []lineOpenForm
	legacy []candidateForm
	byConf map[string][]lineOpenForm
}

// candidateForm is a finding variant and the formula it is hashed under.
type candidateForm struct {
	match   detector.Match
	version hashVersion
}

func (sm *SuppressionManager) openIdentity(m detector.Match) *openIdentity {
	o := &openIdentity{sm: sm}
	eachCandidateForm(m, func(form detector.Match, version hashVersion) {
		if version.includesConfidence() {
			o.legacy = append(o.legacy, candidateForm{form, version})
			return
		}
		o.plain = append(o.plain, sm.newLineOpenForm(form, version))
	})
	return o
}

// digestsAt yields the finding's identities at k: the forms without a confidence when plain is set
// (they are the same for every confidence at one line), and the legacy forms at k's confidence.
func (o *openIdentity) digestsAt(h *anchorHasher, k anchorKey, plain bool, yield func([32]byte)) {
	if plain {
		for i := range o.plain {
			yield(h.at(&o.plain[i], k.line))
		}
	}
	forms, ok := o.byConf[k.conf]
	if !ok {
		for _, c := range o.legacy {
			m := c.match
			if k.conf != "" {
				// recordedConfidence wrote it, so it parses, and formats back to itself.
				m.Confidence, _ = strconv.ParseFloat(k.conf, 64)
			}
			forms = append(forms, o.sm.newLineOpenForm(m, c.version))
		}
		if o.byConf == nil {
			o.byConf = make(map[string][]lineOpenForm, 1)
		}
		o.byConf[k.conf] = forms
	}
	for i := range forms {
		yield(h.at(&forms[i], k.line))
	}
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suppressions

import (
	"bytes"
	"fmt"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

// Saving without losing what the saver does not own (#866).
//
// saveConfig used to yaml.Marshal the in-memory struct, which has no room for anything it does not
// model, so every save deleted every comment and every unknown key in the file. It has nine callers,
// reached from --generate-suppressions and every web UI mutation. Measured on this repository's
// committed baseline: one regeneration removed its 33-line header (and the blank line after it), the
// header that ends by warning that the regenerate command strips it.
//
// The file is now saved by patching the node tree it was loaded from: each rule keeps its own node, a
// field is rewritten only when its value changed, a rule added since the load is encoded as before and
// appended, and a removed rule's node is dropped. Comments, key order, unknown keys (top-level, in a
// rule, in metadata) and the formatting of untouched rules all survive, because nothing rewrites them.
// A file that did not exist, or could not be parsed, is still written by yaml.Marshal, so a freshly
// generated file is byte-for-byte what it was.

// marshalConfig renders sm.config for writing.
func (sm *SuppressionManager) marshalConfig() ([]byte, error) {
	if sm.doc == nil {
		return yaml.Marshal(sm.config)
	}
	if err := patchDocument(sm.doc, sm.config); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	// yaml.Marshal's indent, so a patched file and a generated one are laid out alike.
	enc.SetIndent(4)
	if err := enc.Encode(sm.doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// patchDocument brings doc in line with config, touching only what differs.
func patchDocument(doc *yaml.Node, config *SuppressionConfig) error {
	root := documentRoot(doc)
	if root == nil {
		// Nothing to patch (an empty or comment-only file, or a document that is not a mapping):
		// write the struct, keeping the document's own comments.
		fresh, err := encodeNode(config)
		if err != nil {
			return err
		}
		doc.Kind = yaml.DocumentNode
		doc.Content = []*yaml.Node{fresh}
		for i := range config.Rules {
			config.Rules[i].node = nil
		}
		return nil
	}

	if version := mappingValue(root, "version"); scalarText(version) != config.Version && config.Version != "" {
		value, err := encodeNode(config.Version)
		if err != nil {
			return err
		}
		setMappingKey(root, "version", value, 0)
	}

	seq := mappingValue(root, "rules")
	if seq == nil || seq.Kind != yaml.SequenceNode {
		if len(config.Rules) == 0 {
			return nil
		}
		fresh := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		setMappingKey(root, "rules", fresh, len(root.Content))
		seq = fresh
	}
	// `rules: []` that gains a rule would otherwise be written as one long flow sequence.
	seq.Style &^= yaml.FlowStyle

	used := make(map[*yaml.Node]bool, len(config.Rules))
	content := make([]*yaml.Node, 0, len(config.Rules))
	for i := range config.Rules {
		rule := &config.Rules[i]
		if rule.node != nil && rule.node.Kind == yaml.MappingNode && !used[rule.node] {
			if err := patchRule(rule.node, rule); err != nil {
				return fmt.Errorf("rule %s: %w", rule.ID, err)
			}
		} else {
			fresh, err := encodeNode(rule)
			if err != nil {
				return fmt.Errorf("rule %s: %w", rule.ID, err)
			}
			rule.node = fresh
		}
		used[rule.node] = true
		content = append(content, rule.node)
	}
	seq.Content = content
	return nil
}

// patchRule rewrites the fields of a rule's node whose value differs from rule, and nothing else.
//
// "Differs" is decided on DECODED values, so a timestamp the user quoted, or a reason in single quotes,
// is left exactly as written unless its value changed.
func patchRule(node *yaml.Node, rule *SuppressionRule) error {
	var was SuppressionRule
	if err := node.Decode(&was); err != nil {
		return err
	}
	want, err := encodeNode(rule)
	if err != nil {
		return err
	}
	for _, key := range ruleKeys {
		if fieldEqual(key, &was, rule) {
			continue
		}
		if key == "metadata" {
			if err := patchMetadata(node, rule.Metadata, mappingValue(want, "metadata")); err != nil {
				return err
			}
			continue
		}
		value := mappingValue(want, key)
		if value == nil {
			// The canonical form omits the field (an omitempty field that is now empty). A key written
			// in place is removed; one supplied through a YAML merge has to be overridden with null.
			if idx := keyIndex(node, key); idx >= 0 {
				node.Content = append(node.Content[:idx], node.Content[idx+2:]...)
				continue
			}
			value = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}
		}
		setMappingKey(node, key, value, insertionIndex(node, key))
	}
	return nil
}

// patchMetadata brings a rule's metadata mapping in line with want, keeping the order, comments and
// formatting of the entries that did not change. wantNode is the canonical encoding of want.
func patchMetadata(rule *yaml.Node, want map[string]string, wantNode *yaml.Node) error {
	idx := keyIndex(rule, "metadata")
	if len(want) == 0 {
		if idx >= 0 {
			rule.Content = append(rule.Content[:idx], rule.Content[idx+2:]...)
		}
		return nil
	}
	if idx < 0 || rule.Content[idx+1].Kind != yaml.MappingNode {
		setMappingKey(rule, "metadata", wantNode, insertionIndex(rule, "metadata"))
		return nil
	}
	m := rule.Content[idx+1]
	for i := 0; i+1 < len(m.Content); {
		if _, keep := want[m.Content[i].Value]; !keep {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			continue
		}
		i += 2
	}
	keys := make([]string, 0, len(want))
	for k := range want {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		existing := mappingValue(m, k)
		if existing != nil && existing.Kind == yaml.ScalarNode && existing.Value == want[k] {
			continue
		}
		value, err := encodeNode(want[k])
		if err != nil {
			return err
		}
		setMappingKey(m, k, value, len(m.Content))
	}
	return nil
}

// setMappingKey sets key to value in mapping m. An existing value is replaced, and the comments that
// were attached to it move to the new one; a missing key is inserted at pairIndex (an index into
// m.Content, always even).
func setMappingKey(m *yaml.Node, key string, value *yaml.Node, pairIndex int) {
	if idx := keyIndex(m, key); idx >= 0 {
		old := m.Content[idx+1]
		value.HeadComment, value.LineComment, value.FootComment = old.HeadComment, old.LineComment, old.FootComment
		if old.Kind == yaml.ScalarNode && value.Kind == yaml.ScalarNode && value.Tag == "!!str" &&
			(old.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle)) != 0 {
			// A string the user quoted stays quoted.
			value.Style = old.Style
		}
		m.Content[idx+1] = value
		return
	}
	if pairIndex < 0 || pairIndex > len(m.Content) {
		pairIndex = len(m.Content)
	}
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	m.Content = append(m.Content[:pairIndex], append([]*yaml.Node{keyNode, value}, m.Content[pairIndex:]...)...)
}

// keyIndex is the index in m.Content of key written in place in mapping m, or -1.
func keyIndex(m *yaml.Node, key string) int {
	if m == nil || m.Kind != yaml.MappingNode {
		return -1
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key && m.Content[i].Tag != "!!merge" {
			return i
		}
	}
	return -1
}

// insertionIndex is where a rule key that is not in node goes: after the last rule key that the saver
// writes before it, so a patched rule reads in the same order as a generated one.
func insertionIndex(node *yaml.Node, key string) int {
	rank := keyRank(key)
	pos := 0
	for i := 0; i+1 < len(node.Content); i += 2 {
		if r := keyRank(node.Content[i].Value); r >= 0 && r < rank {
			pos = i + 2
		}
	}
	return pos
}

func keyRank(key string) int {
	for i, k := range ruleKeys {
		if k == key {
			return i
		}
	}
	return -1
}

// fieldEqual reports whether the field a rule key names holds the same value in a and b.
func fieldEqual(key string, a, b *SuppressionRule) bool {
	switch key {
	case "id":
		return a.ID == b.ID
	case "hash":
		return a.Hash == b.Hash
	case "reason":
		return a.Reason == b.Reason
	case "enabled":
		return a.Enabled == b.Enabled
	case "created_by":
		return a.CreatedBy == b.CreatedBy
	case "created_at":
		return a.CreatedAt.Equal(b.CreatedAt)
	case "last_seen_at":
		return timePtrEqual(a.LastSeenAt, b.LastSeenAt)
	case "expires_at":
		return timePtrEqual(a.ExpiresAt, b.ExpiresAt)
	case "reviewed_by":
		return a.ReviewedBy == b.ReviewedBy
	case "reviewed_at":
		return timePtrEqual(a.ReviewedAt, b.ReviewedAt)
	case "metadata":
		if len(a.Metadata) != len(b.Metadata) {
			return false
		}
		for k, v := range a.Metadata {
			if w, ok := b.Metadata[k]; !ok || w != v {
				return false
			}
		}
		return true
	}
	return true
}

func timePtrEqual(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

// encodeNode is v as the node yaml.Marshal would write for it.
func encodeNode(v any) (*yaml.Node, error) {
	var n yaml.Node
	if err := n.Encode(v); err != nil {
		return nil, err
	}
	return &n, nil
}

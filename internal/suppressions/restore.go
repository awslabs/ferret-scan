// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suppressions

import (
	"fmt"
	"sort"
)

// RuleRestore is a deleted rule to put back, and the position it held.
type RuleRestore struct {
	Rule SuppressionRule
	// Position is the rule's index in the list it was deleted from. A negative or out-of-range
	// position appends.
	Position int
}

// RestoreSuppressions puts deleted rules back as they were — the same id, hash, reason, state,
// timestamps, expiry and metadata — at the positions they held. It is what the web UI's undo of a
// delete calls.
//
// Recreating a rule from the finding it suppressed cannot do that: the hash is recomputed from the
// finding's text and context, which a deleted rule does not carry, and the id, the dates and the
// expiry are new. The undo used to post the rules to an endpoint that read only findings, so it
// restored nothing and reported success (#866).
//
// A rule is refused, and named in the returned list, when it has no id or no hash, or when a rule with
// its id or its hash already exists: putting it back would then duplicate a decision rather than undo
// a deletion. The file is saved once, and only when something was restored.
func (sm *SuppressionManager) RestoreSuppressions(items []RuleRestore) (restored int, refused []string, err error) {
	if sm.config == nil {
		sm.config = &SuppressionConfig{Version: "1.0", Rules: []SuppressionRule{}}
	}
	ids := make(map[string]bool, len(sm.config.Rules))
	hashes := make(map[string]bool, len(sm.config.Rules))
	for _, rule := range sm.config.Rules {
		ids[rule.ID] = true
		hashes[rule.Hash] = true
	}

	// Ascending original position, so each insertion lands where it was: deleting rules 1 and 3 of
	// [0 1 2 3] leaves [0 2]; putting 1 back at 1 and then 3 at 3 rebuilds [0 1 2 3].
	ordered := append([]RuleRestore(nil), items...)
	rank := func(p int) int {
		if p < 0 {
			return int(^uint(0) >> 1)
		}
		return p
	}
	sort.SliceStable(ordered, func(i, j int) bool { return rank(ordered[i].Position) < rank(ordered[j].Position) })

	for _, item := range ordered {
		r := item.Rule
		switch {
		case r.ID == "":
			refused = append(refused, "a rule with no id")
			continue
		case r.Hash == "":
			refused = append(refused, fmt.Sprintf("%s: no hash", r.ID))
			continue
		case ids[r.ID]:
			refused = append(refused, fmt.Sprintf("%s: a rule with this id already exists", r.ID))
			continue
		case hashes[r.Hash]:
			refused = append(refused, fmt.Sprintf("%s: a rule for this finding already exists", r.ID))
			continue
		}

		// Only the fields the file holds, so nothing derived (and nothing else a caller sent) rides in.
		rule := SuppressionRule{
			ID:         r.ID,
			Hash:       r.Hash,
			Reason:     r.Reason,
			Enabled:    r.Enabled,
			CreatedBy:  r.CreatedBy,
			CreatedAt:  r.CreatedAt,
			LastSeenAt: r.LastSeenAt,
			ExpiresAt:  r.ExpiresAt,
			ReviewedBy: r.ReviewedBy,
			ReviewedAt: r.ReviewedAt,
		}
		if len(r.Metadata) > 0 {
			rule.Metadata = make(map[string]string, len(r.Metadata))
			for k, v := range r.Metadata {
				rule.Metadata[k] = v
			}
		}

		pos := item.Position
		if pos < 0 || pos > len(sm.config.Rules) {
			pos = len(sm.config.Rules)
		}
		sm.config.Rules = append(sm.config.Rules, SuppressionRule{})
		copy(sm.config.Rules[pos+1:], sm.config.Rules[pos:])
		sm.config.Rules[pos] = rule
		ids[rule.ID] = true
		hashes[rule.Hash] = true
		restored++
	}

	if restored > 0 {
		err = sm.saveConfig()
	}
	return restored, refused, err
}

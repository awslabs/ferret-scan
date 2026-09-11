// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package sarif

import (
	"github.com/awslabs/ferret-scan/v2/internal/core"
	"sort"
	"strings"
	"sync"
)

// RuleManager manages SARIF rule definitions for detection types
// It caches rules to avoid duplicate creation and ensures consistent
// rule definitions across the SARIF report
type RuleManager struct {
	rules map[string]*SARIFRule
	mu    sync.RWMutex
}

// NewRuleManager creates a new RuleManager instance
func NewRuleManager() *RuleManager {
	return &RuleManager{
		rules: make(map[string]*SARIFRule),
	}
}

// GetOrCreateRule retrieves an existing rule or creates a new one for the given detection type
// This method is thread-safe and caches rules to avoid duplicate creation
func (rm *RuleManager) GetOrCreateRule(detectionType string) *SARIFRule {
	// Try to get existing rule with read lock
	rm.mu.RLock()
	if rule, exists := rm.rules[detectionType]; exists {
		rm.mu.RUnlock()
		return rule
	}
	rm.mu.RUnlock()

	// Create new rule with write lock
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// Double-check in case another goroutine created it
	if rule, exists := rm.rules[detectionType]; exists {
		return rule
	}

	// Build and cache the new rule
	rule := rm.buildRuleForType(detectionType)
	rm.rules[detectionType] = rule
	return rule
}

// GetAllRules returns all cached rules for inclusion in the SARIF driver
// This should be called after all results have been processed to ensure
// all rules are included in the tool.driver.rules array
// Rules are returned in ascending rule-ID order. Ranging the cache map directly
// permuted the tool.driver.rules array between runs, so two SARIF reports of one
// unchanged scan differed — a problem for any consumer that diffs or hashes the
// report, and for reviewers reading it as an artifact.
func (rm *RuleManager) GetAllRules() []SARIFRule {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	ids := make([]string, 0, len(rm.rules))
	for id := range rm.rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	rules := make([]SARIFRule, 0, len(ids))
	for _, id := range ids {
		rules = append(rules, *rm.rules[id])
	}
	return rules
}

// buildRuleForType creates a SARIF rule for the given detection type
// using the rule descriptions from constants
func (rm *RuleManager) buildRuleForType(detectionType string) *SARIFRule {
	desc := GetRuleDescription(detectionType)

	// One page with per-type anchors, not one file per type.
	//
	// This previously built ToolInformationURI + "/blob/main/docs/checks/" +
	// detectionType + ".md", and docs/checks/ HAS NEVER EXISTED. Measured by scanning
	// this repository with every check enabled: 59 rules emitted, 59 helpUris, 0
	// resolving. Every finding in every SARIF report a consumer has opened carried a
	// dead documentation link, and nothing checked it.
	//
	// A single anchored page rather than 59 files because the content is one short
	// section per type, 35 of which have no bespoke copy at all and share the generic
	// fallback in GetRuleDescription. Fifty-nine near-identical files would be worse
	// documentation and 59 more things to drift.
	//
	// docs/checks.md is GENERATED from core.KnownTypes() and the same registry this
	// function reads, so the page and the rule cannot disagree about a type. The
	// anchor is the GitHub-flavoured Markdown slug of the heading, which for these
	// all-caps underscore names is simply the lowercased type.
	// TestEveryHelpURIResolves asserts every emitted rule's target exists.
	// Anchor only when the type is documented; otherwise link the PAGE.
	//
	// This is the part that makes the hand-maintained core.KnownTypes() list safe. A
	// list of type names cannot be complete by construction -- sub-types are minted by
	// validators, and this one was already missing five METADATA sub-types
	// (AUTHOR_INFO, COMPANY_INFO, TEMPLATE_INFO, LAST_MODIFIED_BY, APPLICATION_INFO)
	// on the day it was written, because it was seeded by scanning a repository that
	// contains no office documents.
	//
	// So completeness of the list decides whether a reviewer lands on the RIGHT
	// SECTION, never whether the link works at all: an unlisted type links to
	// docs/checks.md, which is committed. The failure mode of drift is a slightly less
	// useful link, not the 404 this whole change exists to remove.
	helpURI := ToolInformationURI + "/blob/main/docs/checks.md"
	if core.IsKnownType(detectionType) {
		helpURI += "#" + strings.ToLower(detectionType)
	}

	return &SARIFRule{
		ID:               detectionType,
		ShortDescription: SARIFMessage{Text: desc.Short},
		FullDescription:  SARIFMessage{Text: desc.Full},
		Help:             SARIFMessage{Text: desc.Help},
		HelpURI:          helpURI,
	}
}

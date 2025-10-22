// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package sarif

import "sync"

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
func (rm *RuleManager) GetAllRules() []SARIFRule {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	rules := make([]SARIFRule, 0, len(rm.rules))
	for _, rule := range rm.rules {
		rules = append(rules, *rule)
	}
	return rules
}

// buildRuleForType creates a SARIF rule for the given detection type
// using the rule descriptions from constants
func (rm *RuleManager) buildRuleForType(detectionType string) *SARIFRule {
	desc := GetRuleDescription(detectionType)

	// Generate help URI pointing to the GitHub repository documentation
	helpURI := ToolInformationURI + "/blob/main/docs/checks/" + detectionType + ".md"

	return &SARIFRule{
		ID:               detectionType,
		ShortDescription: SARIFMessage{Text: desc.Short},
		FullDescription:  SARIFMessage{Text: desc.Full},
		Help:             SARIFMessage{Text: desc.Help},
		HelpURI:          helpURI,
	}
}

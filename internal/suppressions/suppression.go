// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suppressions

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"ferret-scan/internal/detector"
	"ferret-scan/internal/paths"

	"gopkg.in/yaml.v3"
)

// hashLineWithoutComment matches `hash:` lines that don't already carry a
// trailing comment. Used to append `# pragma: allowlist secret` so secret
// scanners (including ferret-scan itself) skip the high-entropy hash values.
var hashLineWithoutComment = regexp.MustCompile(`(?m)^(\s*hash:\s*\S+)[ \t]*$`)

// annotateHashesWithAllowlistPragma appends `# pragma: allowlist secret` to
// every `hash:` line in the marshaled YAML that doesn't already have a
// trailing comment. The hash field is a SHA-256 of the finding identity, not
// the secret itself, but it has enough entropy to trip secret scanners — this
// keeps the suppression file from generating false-positive findings.
func annotateHashesWithAllowlistPragma(data []byte) []byte {
	return hashLineWithoutComment.ReplaceAll(data, []byte("$1 # pragma: allowlist secret"))
}

// SuppressionRule represents a single suppression rule
type SuppressionRule struct {
	ID         string            `yaml:"id"`
	Hash       string            `yaml:"hash"`
	Reason     string            `yaml:"reason"`
	Enabled    bool              `yaml:"enabled"`
	CreatedBy  string            `yaml:"created_by,omitempty"`
	CreatedAt  time.Time         `yaml:"created_at"`
	LastSeenAt *time.Time        `yaml:"last_seen_at,omitempty"`
	ExpiresAt  *time.Time        `yaml:"expires_at,omitempty"`
	ReviewedBy string            `yaml:"reviewed_by,omitempty"`
	ReviewedAt *time.Time        `yaml:"reviewed_at,omitempty"`
	Metadata   map[string]string `yaml:"metadata,omitempty"`
}

// SuppressionConfig represents the suppression configuration file
type SuppressionConfig struct {
	Version string            `yaml:"version"`
	Rules   []SuppressionRule `yaml:"rules"`
}

// SuppressionManager handles finding suppressions.
//
// Mutating methods (AddSuppression, RemoveSuppression, EditSuppression,
// CreateSuppressionFromFinding*, CleanupExpired, etc.) are NOT safe for
// concurrent use — callers must ensure they happen serially or behind their
// own lock. The read path (IsSuppressed and the rulesByHash index it
// consults) is guarded by indexMu so concurrent reads are safe and so a lazy
// index rebuild can't race itself.
type SuppressionManager struct {
	configPath string
	config     *SuppressionConfig
	enabled    bool
	// rulesByHash indexes config.Rules by Hash so IsSuppressed runs in O(1)
	// instead of O(N). Multiple rules can theoretically share a hash, so the
	// value is a slice; the original linear scan returned the first match,
	// which we preserve here. Rebuilt on every load/save under indexMu.
	rulesByHash map[string][]int
	indexMu     sync.RWMutex
}

// NewSuppressionManager creates a new suppression manager
func NewSuppressionManager(configPath string) *SuppressionManager {
	if configPath == "" {
		configPath = findDefaultSuppressionFile()
	}

	manager := &SuppressionManager{
		configPath: configPath,
		enabled:    true,
	}

	manager.loadConfig()
	return manager
}

// findDefaultSuppressionFile looks for default suppression files
func findDefaultSuppressionFile() string {
	return paths.GetSuppressionsFile()
}

// loadConfig loads the suppression configuration. A missing file is treated
// as "no rules yet" silently — that's the legitimate first-run case. A file
// that exists but fails to parse is logged loudly to stderr so the user
// notices their rules aren't being applied; previously parse errors silently
// produced an empty rule set, which made suppressions look configured but
// silently inactive.
func (sm *SuppressionManager) loadConfig() {
	if sm.configPath == "" {
		sm.config = &SuppressionConfig{
			Version: "1.0",
			Rules:   []SuppressionRule{},
		}
		return
	}

	cleanPath := filepath.Clean(sm.configPath)
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		// Distinguish "file does not exist" (silent) from any other error
		// (which is real and worth surfacing).
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr,
				"warning: cannot read suppression file %q: %v — treating as empty\n",
				sm.configPath, err)
		}
		sm.config = &SuppressionConfig{
			Version: "1.0",
			Rules:   []SuppressionRule{},
		}
		return
	}

	var config SuppressionConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		fmt.Fprintf(os.Stderr,
			"warning: suppression file %q is malformed (%v) — treating as empty; existing rules will NOT be applied\n",
			sm.configPath, err)
		sm.config = &SuppressionConfig{
			Version: "1.0",
			Rules:   []SuppressionRule{},
		}
		return
	}

	sm.config = &config
	sm.rebuildHashIndex()
}

// rebuildHashIndex constructs the hash → rule-indices lookup. Call after any
// mutation of sm.config.Rules. Cheap (single pass over rules) so we just
// rebuild rather than maintain incremental updates across the many
// add/edit/remove paths. Acquires the index write lock.
func (sm *SuppressionManager) rebuildHashIndex() {
	sm.indexMu.Lock()
	defer sm.indexMu.Unlock()
	sm.rebuildHashIndexLocked()
}

// rebuildHashIndexLocked rebuilds the index assuming the caller already holds
// indexMu for writing.
func (sm *SuppressionManager) rebuildHashIndexLocked() {
	if sm.config == nil {
		sm.rulesByHash = nil
		return
	}
	idx := make(map[string][]int, len(sm.config.Rules))
	for i, rule := range sm.config.Rules {
		idx[rule.Hash] = append(idx[rule.Hash], i)
	}
	sm.rulesByHash = idx
}

// generateFindingHash creates a unique hash for a finding
func (sm *SuppressionManager) generateFindingHash(match detector.Match) string {
	// Create a composite string with all relevant identifying information
	components := []string{
		match.Type,
		fmt.Sprintf("%.2f", match.Confidence),
		strings.TrimSpace(match.Context.FullLine),
		filepath.Base(match.Filename), // Use basename to avoid path sensitivity
		fmt.Sprintf("%d", match.LineNumber),
	}

	// Add context for uniqueness but hash it for privacy
	contextHash := sm.hashSensitiveData(match.Context.BeforeText + match.Context.AfterText)
	components = append(components, contextHash)

	// Hash the match text separately for privacy
	matchHash := sm.hashSensitiveData(match.Text)
	components = append(components, matchHash)

	// Create final hash
	composite := strings.Join(components, "|")
	hash := sha256.Sum256([]byte(composite))
	return fmt.Sprintf("%x", hash)
}

// hashSensitiveData creates a hash of sensitive data
func (sm *SuppressionManager) hashSensitiveData(data string) string {
	if data == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash)[:16] // Use first 16 chars for brevity
}

// IsSuppressed checks if a finding should be suppressed.
// Safe for concurrent use across goroutines.
func (sm *SuppressionManager) IsSuppressed(match detector.Match) (bool, *SuppressionRule) {
	if !sm.enabled || sm.config == nil {
		return false, nil
	}

	findingHash := sm.generateFindingHash(match)

	// Fast read-locked path: index is already built.
	sm.indexMu.RLock()
	if sm.rulesByHash != nil {
		for _, ruleIdx := range sm.rulesByHash[findingHash] {
			rule := &sm.config.Rules[ruleIdx]
			if !rule.Enabled {
				continue
			}
			if rule.ExpiresAt != nil && time.Now().After(*rule.ExpiresAt) {
				continue
			}
			sm.indexMu.RUnlock()
			return true, rule
		}
		sm.indexMu.RUnlock()
		return false, nil
	}
	sm.indexMu.RUnlock()

	// Lazy build for tests/callers that mutate sm.config.Rules without
	// going through saveConfig. Take the write lock and re-check (another
	// caller may have built it in between).
	sm.indexMu.Lock()
	if sm.rulesByHash == nil {
		sm.rebuildHashIndexLocked()
	}
	for _, ruleIdx := range sm.rulesByHash[findingHash] {
		rule := &sm.config.Rules[ruleIdx]
		if !rule.Enabled {
			continue
		}
		if rule.ExpiresAt != nil && time.Now().After(*rule.ExpiresAt) {
			continue
		}
		sm.indexMu.Unlock()
		return true, rule
	}
	sm.indexMu.Unlock()
	return false, nil
}

// AddSuppression adds a new suppression rule
func (sm *SuppressionManager) AddSuppression(match detector.Match, reason, createdBy string, expiresAt *time.Time) error {
	if sm.config == nil {
		sm.config = &SuppressionConfig{
			Version: "1.0",
			Rules:   []SuppressionRule{},
		}
	}

	findingHash := sm.generateFindingHash(match)

	// Check if already exists
	for _, rule := range sm.config.Rules {
		if rule.Hash == findingHash {
			return fmt.Errorf("suppression rule already exists for this finding")
		}
	}

	// Generate unique ID with sequential number
	maxID := 0
	for _, existingRule := range sm.config.Rules {
		if existingRule.ID != "" {
			var num int
			if _, err := fmt.Sscanf(existingRule.ID, "SUP-%08d", &num); err == nil && num > maxID {
				maxID = num
			}
		}
	}
	id := fmt.Sprintf("SUP-%08d", maxID+1)

	// Set default expiration to 1 week if not provided
	if expiresAt == nil {
		defaultExpiry := time.Now().AddDate(0, 0, 7) // 1 week from now
		expiresAt = &defaultExpiry
	}

	rule := SuppressionRule{
		ID:        id,
		Hash:      findingHash,
		Reason:    reason,
		Enabled:   true,
		CreatedBy: createdBy,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
		Metadata: map[string]string{
			"finding_type":    match.Type,
			"filename":        filepath.Base(match.Filename),
			"line_number":     fmt.Sprintf("%d", match.LineNumber),
			"confidence":      fmt.Sprintf("%.0f", match.Confidence),
			"context_hash":    sm.hashSensitiveData(match.Context.BeforeText + match.Context.AfterText),
			"match_text_hash": sm.hashSensitiveData(match.Text),
		},
	}

	sm.config.Rules = append(sm.config.Rules, rule)
	return sm.saveConfig()
}

// RemoveSuppression removes a suppression rule by ID
func (sm *SuppressionManager) RemoveSuppression(id string) error {
	if sm.config == nil {
		return fmt.Errorf("no suppression config loaded")
	}

	for i, rule := range sm.config.Rules {
		if rule.ID == id {
			sm.config.Rules = append(sm.config.Rules[:i], sm.config.Rules[i+1:]...)
			return sm.saveConfig()
		}
	}

	return fmt.Errorf("suppression rule with ID %s not found", id)
}

// ListSuppressions returns all suppression rules
func (sm *SuppressionManager) ListSuppressions() []SuppressionRule {
	if sm.config == nil {
		return []SuppressionRule{}
	}
	return sm.config.Rules
}

// saveConfig saves the suppression configuration to file
func (sm *SuppressionManager) saveConfig() error {
	if sm.configPath == "" {
		sm.configPath = paths.GetSuppressionsFile()
	}

	data, err := yaml.Marshal(sm.config)
	if err != nil {
		return fmt.Errorf("failed to marshal suppression config: %w", err)
	}
	data = annotateHashesWithAllowlistPragma(data)
	// Rules just changed — invalidate the IsSuppressed lookup index.
	sm.rebuildHashIndex()

	// Create directory if it doesn't exist
	dir := filepath.Dir(sm.configPath)
	if dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
	}

	// Write with restrictive permissions
	if err := os.WriteFile(sm.configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write suppression config: %w", err)
	}

	return nil
}

// CleanupExpired removes expired suppression rules
func (sm *SuppressionManager) CleanupExpired() int {
	if sm.config == nil {
		return 0
	}

	now := time.Now()
	originalCount := len(sm.config.Rules)

	var activeRules []SuppressionRule
	for _, rule := range sm.config.Rules {
		if rule.ExpiresAt == nil || now.Before(*rule.ExpiresAt) {
			activeRules = append(activeRules, rule)
		}
	}

	sm.config.Rules = activeRules
	removed := originalCount - len(activeRules)

	if removed > 0 {
		sm.saveConfig()
	}

	return removed
}

// GetSuppressionInfo returns information about a specific finding's suppression status
func (sm *SuppressionManager) GetSuppressionInfo(match detector.Match) map[string]interface{} {
	info := map[string]interface{}{
		"hash":       sm.generateFindingHash(match),
		"suppressed": false,
		"enabled":    nil,
		"rule_id":    nil,
		"reason":     nil,
		"created_by": nil,
		"created_at": nil,
		"expires_at": nil,
	}

	if suppressed, rule := sm.IsSuppressed(match); suppressed && rule != nil {
		info["suppressed"] = true
		info["enabled"] = rule.Enabled
		info["rule_id"] = rule.ID
		info["reason"] = rule.Reason
		info["created_by"] = rule.CreatedBy
		info["created_at"] = rule.CreatedAt
		info["expires_at"] = rule.ExpiresAt
	}

	return info
}

// GetExpiredRule checks if there's an expired suppression rule for a finding
func (sm *SuppressionManager) GetExpiredRule(match detector.Match) *SuppressionRule {
	if !sm.enabled || sm.config == nil {
		return nil
	}

	findingHash := sm.generateFindingHash(match)

	for _, rule := range sm.config.Rules {
		if rule.Hash == findingHash && rule.Enabled {
			// Check if rule has expired
			if rule.ExpiresAt != nil && time.Now().After(*rule.ExpiresAt) {
				return &rule
			}
		}
	}

	return nil
}

// SetEnabled enables or disables the suppression manager
func (sm *SuppressionManager) SetEnabled(enabled bool) {
	sm.enabled = enabled
}

// IsEnabled returns whether the suppression manager is enabled
func (sm *SuppressionManager) IsEnabled() bool {
	return sm.enabled
}

// GetConfigPath returns the path to the suppression config file
func (sm *SuppressionManager) GetConfigPath() string {
	return sm.configPath
}

// GenerateSuppressionRules creates suppression rules for all findings with enabled=false
func (sm *SuppressionManager) GenerateSuppressionRules(matches []detector.Match, reason string, enabled bool) error {
	if sm.config == nil {
		sm.config = &SuppressionConfig{
			Version: "1.0",
			Rules:   []SuppressionRule{},
		}
	}

	// Create a map of existing hashes for quick lookup
	existingHashes := make(map[string]*SuppressionRule)
	for i := range sm.config.Rules {
		existingHashes[sm.config.Rules[i].Hash] = &sm.config.Rules[i]
	}

	addedCount := 0
	updatedCount := 0
	now := time.Now()

	// Find max ID once
	maxID := 0
	for _, existingRule := range sm.config.Rules {
		if existingRule.ID != "" {
			var num int
			if _, err := fmt.Sscanf(existingRule.ID, "SUP-%08d", &num); err == nil && num > maxID {
				maxID = num
			}
		}
	}

	for _, match := range matches {
		findingHash := sm.generateFindingHash(match)

		// Check if already exists
		if existingRule, exists := existingHashes[findingHash]; exists {
			// Update last_seen_at for existing rule
			existingRule.LastSeenAt = &now
			updatedCount++
			continue
		}

		// Generate unique ID with sequential number
		id := fmt.Sprintf("SUP-%08d", maxID+addedCount+1)

		// Set default expiration to 1 week
		defaultExpiry := now.AddDate(0, 0, 7)

		rule := SuppressionRule{
			ID:         id,
			Hash:       findingHash,
			Reason:     reason,
			Enabled:    enabled,
			CreatedAt:  now,
			LastSeenAt: &now,
			ExpiresAt:  &defaultExpiry,
			Metadata: map[string]string{
				"finding_type":    match.Type,
				"filename":        filepath.Base(match.Filename),
				"line_number":     fmt.Sprintf("%d", match.LineNumber),
				"confidence":      fmt.Sprintf("%.0f", match.Confidence),
				"context_hash":    sm.hashSensitiveData(match.Context.BeforeText + match.Context.AfterText),
				"match_text_hash": sm.hashSensitiveData(match.Text),
			},
		}

		sm.config.Rules = append(sm.config.Rules, rule)
		addedCount++
	}

	if addedCount > 0 || updatedCount > 0 {
		return sm.saveConfig()
	}
	return nil
}

// EnableSuppressionByHash enables a suppression rule by hash
func (sm *SuppressionManager) EnableSuppressionByHash(hash, reason string) error {
	if sm.config == nil {
		return fmt.Errorf("no suppression config loaded")
	}

	for i := range sm.config.Rules {
		if sm.config.Rules[i].Hash == hash {
			sm.config.Rules[i].Enabled = true
			if reason != "" {
				sm.config.Rules[i].Reason = reason
			}
			now := time.Now()
			sm.config.Rules[i].LastSeenAt = &now
			return sm.saveConfig()
		}
	}

	return fmt.Errorf("suppression rule with hash %s not found", hash)
}

// DisableSuppressionByID disables a suppression rule by ID
func (sm *SuppressionManager) DisableSuppressionByID(id string) error {
	if sm.config == nil {
		return fmt.Errorf("no suppression config loaded")
	}

	for i := range sm.config.Rules {
		if sm.config.Rules[i].ID == id {
			sm.config.Rules[i].Enabled = false
			return sm.saveConfig()
		}
	}

	return fmt.Errorf("suppression rule with ID %s not found", id)
}

// EditSuppression edits a suppression rule by ID
func (sm *SuppressionManager) EditSuppression(id, reason, createdBy string, enabled bool, expiresAt *time.Time) error {
	if sm.config == nil {
		return fmt.Errorf("no suppression config loaded")
	}

	for i := range sm.config.Rules {
		if sm.config.Rules[i].ID == id {
			sm.config.Rules[i].Reason = reason
			sm.config.Rules[i].CreatedBy = createdBy
			sm.config.Rules[i].Enabled = enabled
			sm.config.Rules[i].ExpiresAt = expiresAt
			return sm.saveConfig()
		}
	}

	return fmt.Errorf("suppression rule with ID %s not found", id)
}

// CreateSuppressionFromFinding creates a suppression rule from finding data
func (sm *SuppressionManager) CreateSuppressionFromFinding(hash, reason string, findingData map[string]interface{}) error {
	return sm.CreateSuppressionFromFindingWithExpiration(hash, reason, findingData, nil)
}

func (sm *SuppressionManager) CreateSuppressionFromFindingWithExpiration(hash, reason string, findingData map[string]interface{}, expiresAt *time.Time) error {
	if sm.config == nil {
		sm.config = &SuppressionConfig{
			Version: "1.0",
			Rules:   []SuppressionRule{},
		}
	}

	// Create a mock detector.Match to generate proper hash
	mockMatch := detector.Match{
		Type:       getString(findingData, "type"),
		Text:       getString(findingData, "text"),
		Filename:   getString(findingData, "filename"),
		LineNumber: int(getFloat(findingData, "line_number")),
		Confidence: getFloat(findingData, "confidence"),
		Context: detector.ContextInfo{
			FullLine:   getString(findingData, "full_line"),   // Use full_line if provided
			BeforeText: getString(findingData, "before_text"), // Use before_text if provided
			AfterText:  getString(findingData, "after_text"),  // Use after_text if provided
		},
	}

	// Generate proper hash using the same method as CLI
	properHash := sm.generateFindingHash(mockMatch)

	// Check if already exists using proper hash
	for _, rule := range sm.config.Rules {
		if rule.Hash == properHash {
			return fmt.Errorf("suppression rule already exists for this finding")
		}
	}

	// Generate unique ID with sequential number
	maxID := 0
	for _, existingRule := range sm.config.Rules {
		if existingRule.ID != "" {
			var num int
			if _, err := fmt.Sscanf(existingRule.ID, "SUP-%08d", &num); err == nil && num > maxID {
				maxID = num
			}
		}
	}
	id := fmt.Sprintf("SUP-%08d", maxID+1)

	// Extract metadata from finding data with proper hashes
	metadata := map[string]string{
		"finding_type":    getString(findingData, "type"),
		"filename":        filepath.Base(getString(findingData, "filename")),
		"line_number":     fmt.Sprintf("%.0f", getFloat(findingData, "line_number")),
		"confidence":      fmt.Sprintf("%.0f", getFloat(findingData, "confidence")),
		"context_hash":    sm.hashSensitiveData(""), // Empty context for web UI
		"match_text_hash": sm.hashSensitiveData(getString(findingData, "text")),
	}

	rule := SuppressionRule{
		ID:        id,
		Hash:      properHash, // Use properly generated hash
		Reason:    reason,
		Enabled:   true,
		CreatedBy: "web-ui",
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
		Metadata:  metadata,
	}

	sm.config.Rules = append(sm.config.Rules, rule)
	return sm.saveConfig()
}

func getString(data map[string]interface{}, key string) string {
	if val, ok := data[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func getFloat(data map[string]interface{}, key string) float64 {
	if val, ok := data[key]; ok {
		if f, ok := val.(float64); ok {
			return f
		}
	}
	return 0
}

// GenerateFindingHashFromData generates a hash from finding data (for web UI)
func (sm *SuppressionManager) GenerateFindingHashFromData(findingData map[string]interface{}) (string, error) {
	// Create a mock detector.Match to generate proper hash
	mockMatch := detector.Match{
		Type:       getString(findingData, "type"),
		Text:       getString(findingData, "text"),
		Filename:   getString(findingData, "filename"),
		LineNumber: int(getFloat(findingData, "line_number")),
		Confidence: getFloat(findingData, "confidence"),
		Context: detector.ContextInfo{
			FullLine:   getString(findingData, "full_line"),
			BeforeText: getString(findingData, "before_text"),
			AfterText:  getString(findingData, "after_text"),
		},
	}

	return sm.generateFindingHash(mockMatch), nil
}

// CreateSuppressionFromFindingWithState creates a suppression rule with specific enabled state
func (sm *SuppressionManager) CreateSuppressionFromFindingWithState(hash, reason string, findingData map[string]interface{}, enabled bool) error {
	if sm.config == nil {
		sm.config = &SuppressionConfig{
			Version: "1.0",
			Rules:   []SuppressionRule{},
		}
	}

	// Check if already exists
	for _, rule := range sm.config.Rules {
		if rule.Hash == hash {
			return fmt.Errorf("suppression rule already exists for this finding")
		}
	}

	// Generate unique ID with sequential number
	maxID := 0
	for _, existingRule := range sm.config.Rules {
		if existingRule.ID != "" {
			var num int
			if _, err := fmt.Sscanf(existingRule.ID, "SUP-%08d", &num); err == nil && num > maxID {
				maxID = num
			}
		}
	}
	id := fmt.Sprintf("SUP-%08d", maxID+1)

	// Extract metadata from finding data
	metadata := map[string]string{
		"finding_type":    getString(findingData, "type"),
		"filename":        filepath.Base(getString(findingData, "filename")),
		"line_number":     fmt.Sprintf("%.0f", getFloat(findingData, "line_number")),
		"confidence":      fmt.Sprintf("%.0f", getFloat(findingData, "confidence")),
		"context_hash":    "",
		"match_text_hash": sm.hashSensitiveData(getString(findingData, "text")),
	}

	// Set default expiration to 1 week
	defaultExpiry := time.Now().AddDate(0, 0, 7)

	rule := SuppressionRule{
		ID:        id,
		Hash:      hash,
		Reason:    reason,
		Enabled:   enabled, // Use provided enabled state
		CreatedBy: "web-ui-undo",
		CreatedAt: time.Now(),
		ExpiresAt: &defaultExpiry,
		Metadata:  metadata,
	}

	sm.config.Rules = append(sm.config.Rules, rule)
	return sm.saveConfig()
}

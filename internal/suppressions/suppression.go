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

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/explain"
	"github.com/awslabs/ferret-scan/v2/internal/paths"

	"gopkg.in/yaml.v3"
)

// draftedSuppressReason returns the per-finding suppression reason drafted by
// the --explain pass, if one is attached to the match; otherwise "". Used to
// give generated suppression rules a specific, human-reviewable justification
// instead of a generic boilerplate string.
func draftedSuppressReason(match detector.Match) string {
	if ex, ok := explain.FromMatch(match); ok {
		return ex.DraftSuppressReason
	}
	return ""
}

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
// maxHashLineLen bounds how much of Context.FullLine is folded into a finding
// hash. The hash is computed once per match, so embedding the raw FullLine makes
// IsSuppressed O(matches × lineLen) — catastrophic when the input is a single
// very long line (minified JS/JSON, a one-line CSV, a packed log line) where
// FullLine is the entire file: 60k matches × a 1 MB line took ~24s in the
// suppression layer alone, independent of any validator. Capping the
// FullLine contribution makes it O(matches × cap). The cap is far larger than
// any real source line, so the composite — and therefore the hash — is
// byte-identical for every realistic finding, preserving existing suppression
// files; only pathological multi-KB single lines (which no one has hand-written
// a suppression rule against) are truncated.
const maxHashLineLen = 8192

// generateFindingHash returns the current-version identity of a finding, used when
// WRITING a new rule.
//
// Confidence is deliberately NOT an input. It used to be, and that made a saved rule
// stop matching whenever a finding's score moved — including for reasons that have
// nothing to do with the finding. Measured on two .docx files with identical content
// and identical basenames, differing only by an unrelated author name in the metadata:
// the same API_KEY_OR_SECRET scored 55 in one and 60 in the other (the bridge adds a
// cross-path correlation boost when both validation paths report), so a rule written
// against the first file left the finding unsuppressed in the second. The same
// mechanism broke 1 of 78 rules when a single EXIF finding was demoted from 80 to 55.
//
// Confidence is a SCORE, not an identity: it is exactly the field the tool is expected
// to keep tuning. Hashing it meant every scoring improvement silently invalidated
// operators' suppression files, which is both surprising and unsafe — a rule that stops
// matching turns a finding an operator had reviewed and accepted back into noise, and
// in a pre-commit gate back into a block.
//
// What identifies a finding is what it is and where it is: type, the line it sits on,
// the file's basename, the line number, its surrounding context and the matched value.
// All of those still participate.
func (sm *SuppressionManager) generateFindingHash(match detector.Match) string {
	return sm.findingHashVersion(match, hashVersionCurrent)
}

// hashVersion identifies a finding-hash formula. Old rule files carry hashes computed
// by an older formula, and they have to keep working: an operator's suppression file is
// a record of decisions they already made, not a cache we may invalidate.
type hashVersion int

const (
	// hashVersionLegacyConfidence is the original formula, which included
	// fmt.Sprintf("%.2f", Confidence) as the second component. Still computed when
	// MATCHING so pre-existing rule files keep suppressing, never when writing.
	hashVersionLegacyConfidence hashVersion = 1

	// hashVersionNoConfidence drops confidence from the identity.
	hashVersionNoConfidence hashVersion = 2

	// hashVersionNoConfidenceContextless and hashVersionLegacyConfidenceContextless
	// reproduce the two formulas above as they were computed for a finding whose
	// Context was empty.
	//
	// They exist for the validators that used to emit no context at all (see
	// contextlessHashValidators). A rule an operator wrote against one of those
	// findings recorded a hash over an empty FullLine and an empty before/after
	// pair; once the validator starts attaching context, the current formula
	// produces a different hash and that rule would stop matching. Computing the
	// empty-context variant as an additional MATCHING candidate keeps the rule
	// working. Never written.
	hashVersionNoConfidenceContextless     hashVersion = 3
	hashVersionLegacyConfidenceContextless hashVersion = 4

	// hashVersionCurrent is what new rules are written with.
	hashVersionCurrent = hashVersionNoConfidence
)

// includesConfidence reports whether this formula folds Confidence into the
// identity. Only the two legacy formulas do.
func (v hashVersion) includesConfidence() bool {
	return v == hashVersionLegacyConfidence || v == hashVersionLegacyConfidenceContextless
}

// contextless reports whether this formula computes the identity as though the
// finding carried no Context.
func (v hashVersion) contextless() bool {
	return v == hashVersionNoConfidenceContextless || v == hashVersionLegacyConfidenceContextless
}

// contextlessHashValidators names the validators that emitted findings with an
// empty ContextInfo before context recording was added to them, keyed by
// Match.Validator.
//
// The empty-context hash variants are offered as matching candidates for these
// validators ONLY. Offering them for every validator would weaken suppression
// identity across the board: with context excluded, two findings that agree on
// type, basename, line number and value but sit on different line content become
// indistinguishable, so a rule could keep suppressing after the line around the
// value changed -- which is how a stale suppression hides a newly introduced
// secret. Scoping the compatibility to the validators that actually need it keeps
// the identity of the other sixteen exactly as it was.
//
// This list is closed. A validator added later starts out recording context, so it
// has no pre-existing contextless rules to be compatible with, and adding it here
// would weaken its identity for nothing.
var contextlessHashValidators = map[string]bool{
	"secrets":         true,
	"PERSON_NAME":     true,
	"cloud_resources": true,
}

// findingHashVersion computes a finding's hash under a specific formula version.
func (sm *SuppressionManager) findingHashVersion(match detector.Match, version hashVersion) string {
	// A contextless formula reads the context components as though the finding
	// carried none, reproducing the hash this finding had before its validator
	// began recording context.
	ctx := match.Context
	if version.contextless() {
		ctx = detector.ContextInfo{}
	}

	// Bound the FullLine contribution (see maxHashLineLen). TrimSpace first so a
	// short line padded with whitespace still hashes identically; the cap only
	// engages for genuinely long lines.
	fullLine := strings.TrimSpace(ctx.FullLine)
	if len(fullLine) > maxHashLineLen {
		fullLine = fullLine[:maxHashLineLen]
	}

	// Create a composite string with all relevant identifying information. The v1
	// ordering is preserved exactly — confidence second — because any change to the
	// component order or separator would alter every v1 hash and defeat the
	// compatibility this version switch exists to provide.
	components := []string{match.Type}
	if version.includesConfidence() {
		components = append(components, fmt.Sprintf("%.2f", match.Confidence))
	}
	components = append(components,
		fullLine,
		filepath.Base(match.Filename), // Use basename to avoid path sensitivity
		fmt.Sprintf("%d", match.LineNumber),
	)

	// Add context for uniqueness but hash it for privacy
	contextHash := sm.hashSensitiveData(ctx.BeforeText + ctx.AfterText)
	components = append(components, contextHash)

	// Hash the match text separately for privacy
	matchHash := sm.hashSensitiveData(match.Text)
	components = append(components, matchHash)

	// Create final hash
	composite := strings.Join(components, "|")
	hash := sha256.Sum256([]byte(composite))
	return fmt.Sprintf("%x", hash)
}

// findingHashCandidates returns every hash a finding could legitimately be recorded
// under, current formula first.
//
// Matching accepts any of them so an existing rule file keeps working untouched, while
// newly written rules use only the current formula and stop being confidence-sensitive.
// A rule file therefore migrates as it is regenerated rather than needing a conversion
// step, and an operator who never regenerates loses nothing.
//
// For the validators in contextlessHashValidators the empty-context variants of both
// formulas are candidates too, because those validators used to emit findings with no
// context and rules were written against those hashes.
func (sm *SuppressionManager) findingHashCandidates(match detector.Match) []string {
	candidates := []string{
		sm.findingHashVersion(match, hashVersionNoConfidence),
		sm.findingHashVersion(match, hashVersionLegacyConfidence),
	}
	if contextlessHashValidators[match.Validator] {
		candidates = append(candidates,
			sm.findingHashVersion(match, hashVersionNoConfidenceContextless),
			sm.findingHashVersion(match, hashVersionLegacyConfidenceContextless),
		)
	}
	return candidates
}

// hashMatchesFinding reports whether a stored rule hash identifies this finding under
// any supported formula version.
func (sm *SuppressionManager) hashMatchesFinding(ruleHash string, match detector.Match) bool {
	if ruleHash == "" {
		return false
	}
	for _, candidate := range sm.findingHashCandidates(match) {
		if ruleHash == candidate {
			return true
		}
	}
	return false
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

	// Every hash this finding could be recorded under: the current formula, plus the
	// legacy confidence-sensitive one so an existing rule file keeps suppressing
	// without being regenerated.
	candidates := sm.findingHashCandidates(match)

	// Fast read-locked path: index is already built.
	sm.indexMu.RLock()
	if sm.rulesByHash != nil {
		for _, findingHash := range candidates {
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
	for _, findingHash := range candidates {
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

	// Check if already exists, under EITHER formula: a rule recorded with the legacy
	// confidence-sensitive hash already covers this finding, so adding a second one
	// would leave the operator with two rules for one decision.
	for _, rule := range sm.config.Rules {
		if sm.hashMatchesFinding(rule.Hash, match) {
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
			"confidence":      fmt.Sprintf("%.2f", match.Confidence),
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

	for _, rule := range sm.config.Rules {
		if sm.hashMatchesFinding(rule.Hash, match) && rule.Enabled {
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

	// Index existing hashes by their POSITION in sm.config.Rules, not by
	// pointer. The loop below appends to sm.config.Rules, which reallocates the
	// backing array once capacity is exceeded; a *SuppressionRule captured here
	// would then point into the abandoned array and every LastSeenAt write
	// through it would be silently lost. IsSuppressed already indexes by
	// position for the same reason.
	existingHashes := make(map[string]int, len(sm.config.Rules))
	for i := range sm.config.Rules {
		existingHashes[sm.config.Rules[i].Hash] = i
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

		// Check if already exists under EITHER formula. A rule file written before
		// confidence left the hash records the legacy hash, and treating that as
		// absent would append a duplicate rule for a finding the operator has already
		// ruled on — the file would grow a second entry per finding on every
		// regeneration. Refreshing last_seen_at on the legacy rule instead lets the
		// file carry forward untouched; it migrates only when a rule is genuinely new.
		matchedIdx := -1
		for _, candidate := range sm.findingHashCandidates(match) {
			if idx, exists := existingHashes[candidate]; exists {
				matchedIdx = idx
				break
			}
		}
		if idx := matchedIdx; idx >= 0 {
			// Update last_seen_at for existing rule. Written through the live
			// slice so it survives any reallocation caused by the appends below.
			sm.config.Rules[idx].LastSeenAt = &now
			updatedCount++
			continue
		}

		// Generate unique ID with sequential number
		id := fmt.Sprintf("SUP-%08d", maxID+addedCount+1)

		// Set default expiration to 1 week
		defaultExpiry := now.AddDate(0, 0, 7)

		// Prefer the per-finding drafted reason from --explain when present;
		// it states WHY this specific finding looks suppressible (e.g. "Test
		// fixture ... not a real VISA"). Fall back to the caller's generic
		// reason for unannotated findings, so behaviour is unchanged without
		// --explain.
		ruleReason := reason
		if drafted := draftedSuppressReason(match); drafted != "" {
			ruleReason = drafted
		}

		rule := SuppressionRule{
			ID:         id,
			Hash:       findingHash,
			Reason:     ruleReason,
			Enabled:    enabled,
			CreatedAt:  now,
			LastSeenAt: &now,
			ExpiresAt:  &defaultExpiry,
			Metadata: map[string]string{
				"finding_type":    match.Type,
				"filename":        filepath.Base(match.Filename),
				"line_number":     fmt.Sprintf("%d", match.LineNumber),
				"confidence":      fmt.Sprintf("%.2f", match.Confidence),
				"context_hash":    sm.hashSensitiveData(match.Context.BeforeText + match.Context.AfterText),
				"match_text_hash": sm.hashSensitiveData(match.Text),
			},
		}

		sm.config.Rules = append(sm.config.Rules, rule)
		// Record the new hash so a second occurrence of the SAME finding in this
		// batch is treated as existing (last_seen_at touch) rather than emitting
		// a second identical rule. Without this, a value repeated N times in a
		// scan produced N byte-identical rules differing only in ID.
		existingHashes[findingHash] = len(sm.config.Rules) - 1
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
		"confidence":      fmt.Sprintf("%.2f", getFloat(findingData, "confidence")),
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
		"confidence":      fmt.Sprintf("%.2f", getFloat(findingData, "confidence")),
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

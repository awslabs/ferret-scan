// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suppressions

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

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

	// NotApplied says why the loader refused this rule: it carries a key this version does not
	// recognise, a metadata key named like a rule key, or sits in a file of another version. Such a
	// rule is listed and saved back untouched, but never suppresses (#866). Derived on every load and
	// never written to the file.
	NotApplied string `yaml:"-" json:"NotApplied,omitempty"`

	// node is this rule's place in the parsed file, so a save rewrites only the fields that changed and
	// keeps the comments and keys it does not own. Nil for a rule created since the load.
	node *yaml.Node
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
	// expiryMu guards generatedExpirySpec.
	expiryMu sync.RWMutex
	// generatedExpirySpec is the lifetime given to newly generated rules; the zero value means none.
	// A spec rather than a duration so an absolute date is expressible (#696).
	generatedExpirySpec ExpirySpec
	// lastGeneration counts what the last GenerateSuppressionRules call did (#885).
	lastGeneration GenerationReport

	// lapsed records the findings a lapsed rule left in the report. It has its own lock, deliberately
	// not indexMu, because IsSuppressed runs on worker goroutines as well as the report path.
	lapsed lapsedLedger
	// ledger records which rules matched a finding and which finding types this run reported, for
	// UnmatchedRules (#885). Its own lock too, for the same reason.
	ledger runLedger
	// deferred holds the hashes GenerateSuppressionRules re-anchored rules to. IsSuppressed skips
	// them, so a re-anchored rule takes effect from the next load and never in the run that moved it.
	// Guarded by indexMu.
	deferred map[string]bool
	// reanchorLimit replaces MaxReanchorComparisons when positive; set only by tests.
	reanchorLimit int

	// doc is the file as parsed, which saveConfig patches instead of re-marshalling the struct; nil
	// when the file did not exist or could not be parsed.
	doc *yaml.Node
	// loadErr is why a file that exists could not be read or parsed; nil when it loaded or does not
	// exist. While it is set every save refuses, so the empty fallback never replaces the file (#880).
	loadErr error
	// warnings receives the loader's diagnostics.
	warnings io.Writer
}

// lapsedLedger records, once per finding, that a rule which would have suppressed it had expired.
//
// It is keyed by finding rather than counted per call because IsSuppressed is called more than once
// for the same finding: under --enable-redaction the worker pool asks before redacting and the report
// path asks again, so a per-call count printed "4 finding(s)" for 2 (#866). A finding that another,
// live rule still suppresses is not recorded at all: the disclosure says the findings "are reported".
type lapsedLedger struct {
	mu       sync.Mutex
	findings map[string]struct{}
	oldest   *time.Time
}

// ManagerOptions adjusts NewSuppressionManagerWithOptions.
type ManagerOptions struct {
	// Warnings receives the loader's diagnostics: a file that cannot be read or parsed, and what the
	// strict pass names. nil means os.Stderr. io.Discard withholds them, for a caller whose stderr is
	// a findings document rather than prose.
	Warnings io.Writer
}

// NewSuppressionManager creates a new suppression manager
func NewSuppressionManager(configPath string) *SuppressionManager {
	return NewSuppressionManagerWithOptions(configPath, ManagerOptions{})
}

// NewSuppressionManagerWithOptions is NewSuppressionManager with its diagnostics routed by opts.
func NewSuppressionManagerWithOptions(configPath string, opts ManagerOptions) *SuppressionManager {
	if configPath == "" {
		configPath = findDefaultSuppressionFile()
	}

	manager := &SuppressionManager{
		configPath: configPath,
		enabled:    true,
		warnings:   opts.Warnings,
	}
	if manager.warnings == nil {
		manager.warnings = os.Stderr
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
// silently inactive. Such a file, and one that cannot be read, is also
// recorded in loadErr, so no save writes the empty fallback over it (#880).
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
			fmt.Fprintf(sm.warnings,
				"warning: cannot read suppression file %q: %v — treating as empty\n",
				sm.configPath, err)
			// The file is there but its rules are unknown, so it is not ours to replace.
			sm.loadErr = &loadFailure{path: sm.configPath, verb: "read", err: err}
		}
		sm.config = &SuppressionConfig{
			Version: "1.0",
			Rules:   []SuppressionRule{},
		}
		return
	}

	// Parsed once into a node tree: the strict pass reads it, and saveConfig patches it so a save
	// keeps what the struct cannot hold (#866). Decoding the struct from the tree is the same decoder
	// yaml.Unmarshal runs, so a file loads into exactly the rules it always did.
	var doc yaml.Node
	var config SuppressionConfig
	err = yaml.Unmarshal(data, &doc)
	if err == nil && doc.Kind != 0 {
		err = doc.Decode(&config)
	}
	if err != nil {
		fmt.Fprintf(sm.warnings,
			"warning: suppression file %q is malformed (%v) — treating as empty; existing rules will NOT be applied\n",
			sm.configPath, err)
		sm.loadErr = &loadFailure{path: sm.configPath, verb: "parsed", err: err}
		sm.config = &SuppressionConfig{
			Version: "1.0",
			Rules:   []SuppressionRule{},
		}
		return
	}

	if doc.Kind != 0 {
		sm.doc = &doc
		if seq := mappingValue(documentRoot(&doc), "rules"); seq != nil && seq.Kind == yaml.SequenceNode &&
			len(seq.Content) == len(config.Rules) {
			for i := range config.Rules {
				config.Rules[i].node = seq.Content[i]
			}
		}
	}
	problems := checkDocument(&doc)
	applyRefusals(&config, problems)
	writeLoadWarnings(sm.warnings, sm.configPath, problems, len(config.Rules))

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

	// hashVersionTrimmedEdges is hashVersionNoConfidence with the whitespace at the outer edges
	// left out: BeforeText's leading whitespace, AfterText's trailing whitespace and Text's
	// whitespace at both ends.
	//
	// The windows are cut from the raw line, so near a line edge they held the indentation, a
	// trailing space or a CRLF file's `\r`, and the intellectual-property span swallows trailing
	// whitespace and `\r` into Text. An edit that touched none of the finding, converting a file to
	// CRLF, re-indenting it or adding a trailing space, changed its identity and un-suppressed it:
	// measured on 39 of this repository's files, LF rules suppressed 86 of 581 findings after a
	// CRLF conversion and 113 of 581 after re-indenting (#885). The windows stay, trimmed only at
	// their outer edges, because they are what tells two occurrences on one line apart. For a
	// finding with no whitespace at those edges this formula equals hashVersionNoConfidence, so
	// most rules written by the older formula are already rules of this one.
	hashVersionTrimmedEdges hashVersion = 5

	// hashVersionCurrent is what new rules are written with.
	hashVersionCurrent = hashVersionTrimmedEdges
)

// trimsEdges reports whether this formula leaves out the whitespace at the outer edges of the
// context windows and of the value.
func (v hashVersion) trimsEdges() bool {
	return v == hashVersionTrimmedEdges
}

// hasEdgeWhitespace reports whether hashVersionTrimmedEdges trims anything from match, that is,
// whether its hash can differ from hashVersionNoConfidence's.
func hasEdgeWhitespace(match detector.Match) bool {
	before, after := match.Context.BeforeText, match.Context.AfterText
	return strings.TrimLeftFunc(before, unicode.IsSpace) != before ||
		strings.TrimRightFunc(after, unicode.IsSpace) != after ||
		strings.TrimSpace(match.Text) != match.Text
}

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
	// Create final hash. hex.EncodeToString writes what fmt's %x does for a [32]byte, without the
	// reflection: this runs several times per finding.
	head, tail := sm.identityParts(match, version)
	hash := sha256.Sum256([]byte(head + strconv.Itoa(match.LineNumber) + tail))
	return hex.EncodeToString(hash[:])
}

// identityParts is the composite a finding's hash digests under version, split around its line
// number: the composite is head + strconv.Itoa(match.LineNumber) + tail. Re-anchoring needs the
// identity a finding would have had at another line (reanchor.go), and computing it from the same two
// parts is what keeps that search and scan-time matching from ever disagreeing about the formula.
func (sm *SuppressionManager) identityParts(match detector.Match, version hashVersion) (head, tail string) {
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

	// The composite holds all the identifying information, joined by "|". The v1
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
		"",                            // the line number goes here, between head and tail
	)
	head = strings.Join(components, "|")

	// Context contributes to IDENTITY, digested so the composite stays a bounded length and the
	// raw surrounding text is not embedded. Not a privacy measure, and the comment used to say it
	// was: this digest is a component of the identity hash below, which is what makes a rule match
	// the same finding on a teammate's machine. It cannot be dropped or salted — the file is
	// committed, so any salt travels with it — which is precisely why the two INFORMATIONAL copies
	// of these digests were removed from rule metadata instead (#673).
	before, after, text := ctx.BeforeText, ctx.AfterText, match.Text
	if version.trimsEdges() {
		// Only the OUTER edges: whitespace inside a window or inside the value is still identity.
		before = strings.TrimLeftFunc(before, unicode.IsSpace)
		after = strings.TrimRightFunc(after, unicode.IsSpace)
		text = strings.TrimSpace(text)
	}
	contextHash := sm.hashSensitiveData(before + after)

	// Likewise a component of identity, not a privacy measure.
	matchHash := sm.hashSensitiveData(text)
	return head, "|" + contextHash + "|" + matchHash
}

// findingHashCandidates returns every hash a finding could legitimately be recorded
// under, current formula first, each once.
//
// Matching accepts any of them so an existing rule file keeps working untouched, while
// newly written rules use only the current formula. A rule file therefore migrates as it
// is regenerated rather than needing a conversion step, and an operator who never
// regenerates loses nothing.
//
// For the validators in contextlessHashValidators the empty-context variants of both
// older formulas are candidates too, because those validators used to emit findings
// with no context and rules were written against those hashes.
//
// The two older formulas digest the windows raw, so a rule they wrote in an LF file did
// not match the same finding in a CRLF copy, nor the other way round. They are also
// computed for the finding as it reads with the other line ending (otherLineEnding),
// which covers both directions; the current formula needs no such variant.
func (sm *SuppressionManager) findingHashCandidates(match detector.Match) []string {
	candidates := make([]string, 0, 8)
	eachCandidateForm(match, func(form detector.Match, version hashVersion) {
		h := sm.findingHashVersion(form, version)
		for _, c := range candidates {
			if c == h {
				return
			}
		}
		candidates = append(candidates, h)
	})
	return candidates
}

// eachCandidateForm calls yield with every (finding, formula) pair whose hash is one of the finding's
// candidates, current formula first: findingHashCandidates hashes them at the finding's own line, and
// re-anchoring at the line a rule recorded, so the two read one list.
func eachCandidateForm(match detector.Match, yield func(detector.Match, hashVersion)) {
	yield(match, hashVersionCurrent)
	if hasEdgeWhitespace(match) {
		// Otherwise v2 digests exactly what the current formula does, and is the same hash.
		yield(match, hashVersionNoConfidence)
	}
	yield(match, hashVersionLegacyConfidence)
	if contextlessHashValidators[match.Validator] {
		yield(match, hashVersionNoConfidenceContextless)
		yield(match, hashVersionLegacyConfidenceContextless)
	}
	for _, variant := range otherLineEnding(match) {
		yield(variant, hashVersionNoConfidence)
		yield(variant, hashVersionLegacyConfidence)
	}
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

// hashSensitiveData returns the first 16 hex characters of the SHA-256 of data.
//
// SIXTY-FOUR BITS, UNSALTED, and that is not a privacy control — it is an identity component. The
// search space that matters is the space of VALUES, not the space of digests: measured, the full
// 10^9 US SSN space falls in 367 seconds single-threaded, a date of birth (10^4) is instant, and a
// search bounded to one area and group number (10^4 serials) recovered a planted SSN in 5 ms.
//
// So a digest of a value is as sensitive as the value for any low-entropy value, and the only
// legitimate reason to write one into a file a team COMMITS is that the rule cannot be matched
// without it. That is true of findingHashVersion's composite and was NOT true of the
// `context_hash` and `match_text_hash` entries this used to put in every rule's metadata: nothing
// in the tree ever read them (#673).
func (sm *SuppressionManager) hashSensitiveData(data string) string {
	if data == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8]) // the first 16 hex chars, for brevity
}

// IsSuppressed checks if a finding should be suppressed.
// Safe for concurrent use across goroutines.
func (sm *SuppressionManager) IsSuppressed(match detector.Match) (bool, *SuppressionRule) {
	if !sm.enabled || sm.config == nil {
		return false, nil
	}

	// Lazy build for tests/callers that mutate sm.config.Rules without going through saveConfig.
	// Built under the write lock and re-checked, since another caller may have built it in between;
	// matching then runs on ONE path whether or not the index had to be built. It used to run on two,
	// and the lazy one never counted a lapsed rule (#866).
	sm.indexMu.RLock()
	if sm.rulesByHash == nil {
		sm.indexMu.RUnlock()
		sm.indexMu.Lock()
		if sm.rulesByHash == nil {
			sm.rebuildHashIndexLocked()
		}
		sm.indexMu.Unlock()
		sm.indexMu.RLock()
	}
	if len(sm.rulesByHash) == 0 {
		// No rule can match, so skip hashing the finding, which is nearly all of this call's cost
		// and is paid for every finding of every scan, with or without a suppression file.
		sm.indexMu.RUnlock()
		return false, nil
	}
	// Every hash this finding could be recorded under: the current formula, plus every older one
	// (#247, #885) so an existing rule file keeps suppressing without being regenerated.
	candidates := sm.findingHashCandidates(match)
	var hitBuf [4]string
	rule, lapsedAt, hits := sm.matchLocked(candidates, hitBuf[:0])
	sm.indexMu.RUnlock()

	// Recorded whichever way the finding went, so UnmatchedRules can tell a rule that matched
	// nothing from one whose finding this run never reported.
	sm.ledger.record(match.Type, hits)
	if rule != nil {
		return true, rule
	}
	if lapsedAt != nil {
		// A rule matched by hash and would have suppressed this finding, but had expired.
		sm.noteExpiredSkip(lapsedFindingKey(match, candidates[0]), *lapsedAt)
	}
	return false, nil
}

// matchLocked returns the first enabled, applied, unexpired rule matching any candidate hash. When
// there is none, it returns the earliest expiry among matching rules that had lapsed, or nil. It also
// appends to hits every candidate that some enabled, applied, unexpired rule holds, so a rule that
// matched behind another one (two rules for one finding) is not reported as matching nothing. A rule
// re-anchored by this manager is skipped (see GenerateSuppressionRules). The caller holds indexMu for
// reading.
func (sm *SuppressionManager) matchLocked(candidates, hits []string) (*SuppressionRule, *time.Time, []string) {
	now := time.Now()
	var lapsedAt *time.Time
	var found *SuppressionRule
	for _, findingHash := range candidates {
		if sm.deferred[findingHash] {
			continue
		}
		for _, ruleIdx := range sm.rulesByHash[findingHash] {
			rule := &sm.config.Rules[ruleIdx]
			if !rule.Enabled || rule.NotApplied != "" {
				continue
			}
			if rule.ExpiresAt != nil && now.After(*rule.ExpiresAt) {
				if lapsedAt == nil || rule.ExpiresAt.Before(*lapsedAt) {
					at := *rule.ExpiresAt
					lapsedAt = &at
				}
				continue
			}
			if found == nil {
				found = rule
			}
			// The ledger is keyed by hash, so one live rule per candidate records every rule holding it.
			hits = append(hits, findingHash)
			break
		}
	}
	if found != nil {
		return found, nil, hits
	}
	return nil, lapsedAt, hits
}

// lapsedFindingKey identifies one finding for the lapsed-rule ledger: its full path, which tells two
// files with the same basename apart, and its current-formula identity hash.
func lapsedFindingKey(match detector.Match, identity string) string {
	return match.Filename + "\x00" + identity
}

// AddSuppression adds a new suppression rule
func (sm *SuppressionManager) AddSuppression(match detector.Match, reason, createdBy string, expiresAt *time.Time) error {
	if sm.loadErr != nil {
		return sm.loadErr
	}
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

	// NO DEFAULT EXPIRY. A nil expiresAt means the rule does not expire.
	//
	// This used to default to one week, which made a committed, hand-reviewed baseline inert seven
	// days after it was generated — silently, because IsSuppressed skips an expired rule with a bare
	// continue. Measured on this repository's own .ferret-scan-suppressions.yaml: all 245 rules
	// (92 of them enabled: true and hand-reviewed) carried expires_at 2026-05-28, and had therefore
	// been doing nothing for about four months. The file's own header says it exists "so all
	// contributors and CI share the same baseline" (#696).
	//
	// A suppression is a decision someone made deliberately; it should last until someone changes it.
	// Expiry is still available — pass a non-nil expiresAt, or --suppression-expires on the CLI — but
	// it is now something you ask for rather than something you get without knowing.
	//
	// An explicit expiresAt from the caller always wins; SetGeneratedExpiry only fills a nil.
	if expiresAt == nil {
		expiresAt = sm.generatedExpiry(time.Now())
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
			"finding_type": match.Type,
			"filename":     filepath.Base(match.Filename),
			"line_number":  fmt.Sprintf("%d", match.LineNumber),
			"confidence":   fmt.Sprintf("%.2f", match.Confidence),
		},
	}

	sm.config.Rules = append(sm.config.Rules, rule)
	return sm.saveConfig()
}

// RemoveSuppression removes a suppression rule by ID
func (sm *SuppressionManager) RemoveSuppression(id string) error {
	if sm.loadErr != nil {
		return sm.loadErr
	}
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
	if sm.loadErr != nil {
		// What the manager holds is the empty fallback for a file it could not load, never the file, so
		// writing it would replace the operator's rules (#880). The public mutators refuse before they
		// change anything; this catches any path that reaches the write anyway, and drops what that path
		// added in memory, so a refused save changes nothing on disk or in memory.
		sm.config = &SuppressionConfig{Version: "1.0", Rules: []SuppressionRule{}}
		sm.rebuildHashIndex()
		return sm.loadErr
	}
	if sm.configPath == "" {
		sm.configPath = paths.GetSuppressionsFile()
	}

	data, err := sm.marshalConfig()
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

// CleanupExpired removes expired suppression rules. It removes none, and writes nothing, while
// LoadError is set.
func (sm *SuppressionManager) CleanupExpired() int {
	if sm.loadErr != nil || sm.config == nil {
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
		if sm.hashMatchesFinding(rule.Hash, match) && rule.Enabled && rule.NotApplied == "" {
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

// GenerateSuppressionRules brings the rule file in line with matches, the findings of one run, and
// saves it. A new rule is created with the given enabled state (the CLI passes false). An existing rule
// is never removed, and its id, reason, enabled, dates, expiry and other metadata are never changed:
//
//   - a rule that identifies a finding has last_seen_at refreshed, and is rewritten to the current
//     hash formula when it matched through an older one (migration);
//   - a rule that identifies none of them, but would identify one at the line number the rule recorded,
//     is re-anchored to that finding: its hash, metadata.line_number and last_seen_at are rewritten.
//     Only a one-to-one pairing is accepted, and the search is bounded by MaxReanchorComparisons
//     (reanchor.go);
//   - a finding no rule identifies gets a new rule.
//
// LastGeneration counts each (#885). A re-anchored rule takes effect when the file is next loaded: this
// manager's IsSuppressed goes on matching as it did before the call, so a run that generates before
// it reports (--stdin) reports what a run that reports first (--file) does, and no rule ever moves at
// scan time.
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

	var report GenerationReport
	migrated := make(map[int]bool)
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

	// refresh records that rule idx identifies a finding whose current-formula hash is findingHash.
	refresh := func(idx int, findingHash string) {
		// Update last_seen_at for existing rule. Written through the live
		// slice so it survives any reallocation caused by the appends below.
		rule := &sm.config.Rules[idx]
		rule.LastSeenAt = &now
		report.Refreshed++
		// A rule matched by an older formula is rewritten to the current one, here and only
		// here: an explicit write, by the run that just saw its finding. Its other fields stay.
		// The current formula is tried first, so a rule that differs from findingHash matched
		// through an older one. A rule the loader refused (#866) is left as it is (#885).
		if rule.Hash != findingHash && rule.NotApplied == "" && !migrated[idx] {
			rule.Hash = findingHash
			existingHashes[findingHash] = idx
			migrated[idx] = true
		}
	}
	// carried holds every rule hash some finding of this run carries among its candidates, so a second
	// rule for one finding is not mistaken for a rule whose finding moved.
	carried := make(map[string]bool)
	lookup := func(candidates []string) int {
		matched := -1
		for _, candidate := range candidates {
			if idx, exists := existingHashes[candidate]; exists {
				carried[candidate] = true
				if matched < 0 {
					matched = idx
				}
			}
		}
		return matched
	}
	loadedHashes := make([]string, len(sm.config.Rules))
	for i := range sm.config.Rules {
		loadedHashes[i] = sm.config.Rules[i].Hash
	}

	// Pass 1: the findings a rule already identifies. Checked under ANY formula. A rule file written
	// by an older formula records an older hash, and treating that as absent would append a duplicate
	// rule for a finding the operator has already ruled on — the file would grow a second entry per
	// finding on every regeneration. The matched rule is refreshed instead, and rewritten to the
	// current formula.
	identities := make([]string, len(matches)) // each finding's current-formula hash
	ruled := make([]bool, len(matches))        // a rule identifies the finding
	var unruled []int
	var unruledCandidates [][]string
	for i, match := range matches {
		candidates := sm.findingHashCandidates(match)
		identities[i] = candidates[0]
		if idx := lookup(candidates); idx >= 0 {
			refresh(idx, identities[i])
			ruled[i] = true
			continue
		}
		unruled = append(unruled, i)
		unruledCandidates = append(unruledCandidates, candidates)
	}

	// Pass 2: the rules no finding identifies, re-anchored to the finding they moved with.
	identified := make(map[int]bool, len(carried))
	for i, h := range loadedHashes {
		if carried[h] || carried[sm.config.Rules[i].Hash] {
			identified[i] = true
		}
	}
	plan := sm.planReanchor(matches, identities, ruled, identified)
	reanchored := make(map[int]bool, len(plan.accepted))
	for _, move := range plan.accepted {
		rule := &sm.config.Rules[move.rule]
		rule.Hash = identities[move.finding]
		rule.Metadata["line_number"] = strconv.Itoa(matches[move.finding].LineNumber)
		rule.LastSeenAt = &now
		existingHashes[rule.Hash] = move.rule
		reanchored[move.rule] = true
	}
	report.ReAnchored = len(plan.accepted)
	report.Ambiguous = len(plan.ambiguous)
	report.Unmatched = len(plan.unmatched)
	report.NotEvaluated = len(plan.notEvaluated)
	if len(reanchored) > 0 {
		sm.indexMu.Lock()
		if sm.deferred == nil {
			sm.deferred = make(map[string]bool, len(reanchored))
		}
		for idx := range reanchored {
			sm.deferred[sm.config.Rules[idx].Hash] = true
		}
		sm.indexMu.Unlock()
	}

	// Pass 3: the findings still without a rule get one, in the order they were found.
	for k, i := range unruled {
		match := matches[i]
		findingHash := identities[i]
		if idx := lookup(unruledCandidates[k]); idx >= 0 {
			// A rule added for an earlier occurrence of this finding, or the rule just re-anchored to
			// it, which pass 2 has already counted.
			if !reanchored[idx] {
				refresh(idx, findingHash)
			}
			continue
		}

		// Generate unique ID with sequential number
		id := fmt.Sprintf("SUP-%08d", maxID+report.Added+1)

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
			ExpiresAt:  sm.generatedExpiry(now),
			Metadata: map[string]string{
				"finding_type": match.Type,
				"filename":     filepath.Base(match.Filename),
				"line_number":  fmt.Sprintf("%d", match.LineNumber),
				"confidence":   fmt.Sprintf("%.2f", match.Confidence),
			},
		}

		sm.config.Rules = append(sm.config.Rules, rule)
		// Record the new hash so a second occurrence of the SAME finding in this
		// batch is treated as existing (last_seen_at touch) rather than emitting
		// a second identical rule. Without this, a value repeated N times in a
		// scan produced N byte-identical rules differing only in ID.
		existingHashes[findingHash] = len(sm.config.Rules) - 1
		report.Added++
	}
	report.Migrated = len(migrated)

	// Recorded only once the file holds it: a save that fails leaves the zero report.
	sm.lastGeneration = GenerationReport{}
	if report.Added > 0 || report.Refreshed > 0 || report.ReAnchored > 0 {
		if err := sm.saveConfig(); err != nil {
			return err
		}
	}
	// A re-anchored rule has its finding in this run; once it is on disk, UnmatchedRules says so.
	for idx := range reanchored {
		sm.ledger.markHit(sm.config.Rules[idx].Hash)
	}
	sm.lastGeneration = report
	return nil
}

// EnableSuppressionByHash enables a suppression rule by hash
func (sm *SuppressionManager) EnableSuppressionByHash(hash, reason string) error {
	if sm.loadErr != nil {
		return sm.loadErr
	}
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
	if sm.loadErr != nil {
		return sm.loadErr
	}
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
	if sm.loadErr != nil {
		return sm.loadErr
	}
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
	if sm.loadErr != nil {
		return sm.loadErr
	}
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
		"finding_type": getString(findingData, "type"),
		"filename":     filepath.Base(getString(findingData, "filename")),
		"line_number":  fmt.Sprintf("%.0f", getFloat(findingData, "line_number")),
		"confidence":   fmt.Sprintf("%.2f", getFloat(findingData, "confidence")),
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
	if sm.loadErr != nil {
		return sm.loadErr
	}
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
		"finding_type": getString(findingData, "type"),
		"filename":     filepath.Base(getString(findingData, "filename")),
		"line_number":  fmt.Sprintf("%.0f", getFloat(findingData, "line_number")),
		"confidence":   fmt.Sprintf("%.2f", getFloat(findingData, "confidence")),
	}

	rule := SuppressionRule{
		ID:        id,
		Hash:      hash,
		Reason:    reason,
		Enabled:   enabled, // Use provided enabled state
		CreatedBy: "web-ui-undo",
		CreatedAt: time.Now(),
		ExpiresAt: sm.generatedExpiry(time.Now()),
		Metadata:  metadata,
	}

	sm.config.Rules = append(sm.config.Rules, rule)
	return sm.saveConfig()
}

// SetGeneratedExpiry makes rules created from now on expire after d.
//
// Opt-in, and the reason it exists is that removing the one-week default removed a capability along
// with the defect. A team that wants suppressions to lapse so they get revisited can still have that;
// what they can no longer have is a baseline that lapses without anyone asking for it (#696).
//
// A zero or negative d means no expiry, which is the default.
func (sm *SuppressionManager) SetGeneratedExpiry(d time.Duration) {
	sm.SetGeneratedExpirySpec(ExpirySpec{relative: d, source: d.String()})
}

// SetGeneratedExpirySpec is the form the CLI and the config file both use, because both carry the
// user's own spelling — "30d", "4w", "2026-12-31" — and ParseExpirySpec is the single place that reads
// it. A duration-only setter could not express an absolute date, and an absolute date is the only way
// to say "expire every rule from this run on the same day".
func (sm *SuppressionManager) SetGeneratedExpirySpec(spec ExpirySpec) {
	sm.expiryMu.Lock()
	defer sm.expiryMu.Unlock()
	sm.generatedExpirySpec = spec
}

// generatedExpiry returns the ExpiresAt a newly generated rule should carry, or nil for none.
func (sm *SuppressionManager) generatedExpiry(now time.Time) *time.Time {
	sm.expiryMu.RLock()
	defer sm.expiryMu.RUnlock()
	return sm.generatedExpirySpec.Resolve(now)
}

// ExpiredSkips reports how many findings are in the report because a rule that WOULD have suppressed
// them had expired, and the oldest such expiry seen.
//
// Counted at the moment of matching rather than by walking the file, because that is the number an
// operator can act on: "3 findings are in your report that your own rules were meant to suppress" is
// actionable, while "the file contains 245 expired rules" does not say whether any of them mattered.
//
// This is what was missing when the whole committed baseline lapsed: IsSuppressed skips an expired
// rule with a bare `continue`, so a baseline could stop working entirely and every run looked normal.
//
// Each finding counts once however often it is matched (see lapsedLedger), and only when no live rule
// suppresses it after all. Safe for concurrent use: the redaction filter matches on worker goroutines.
func (sm *SuppressionManager) ExpiredSkips() (count int, oldest *time.Time) {
	sm.lapsed.mu.Lock()
	defer sm.lapsed.mu.Unlock()
	if sm.lapsed.oldest != nil {
		t := *sm.lapsed.oldest
		oldest = &t
	}
	return len(sm.lapsed.findings), oldest
}

// noteExpiredSkip records that the finding identified by findingKey was left unsuppressed because the
// rule that matched it expired at expiredAt.
func (sm *SuppressionManager) noteExpiredSkip(findingKey string, expiredAt time.Time) {
	sm.lapsed.mu.Lock()
	defer sm.lapsed.mu.Unlock()
	if sm.lapsed.findings == nil {
		sm.lapsed.findings = make(map[string]struct{})
	}
	sm.lapsed.findings[findingKey] = struct{}{}
	if sm.lapsed.oldest == nil || expiredAt.Before(*sm.lapsed.oldest) {
		t := expiredAt
		sm.lapsed.oldest = &t
	}
}

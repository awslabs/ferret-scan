// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package cloudresources detects cloud provider resource identifiers (AWS ARNs,
// Azure resource IDs, GCP resource names, OCI OCIDs, IBM CRNs, Alibaba ARNs).
//
// These identifiers are references, not credentials — they are non-secret by
// design (AWS treats account IDs as shareable; ARNs appear in trust policies
// and IaC). The value here is reconnaissance/IaC-hygiene: catching an account
// ID, subscription UUID, or internal resource name in an artifact that crosses
// a trust boundary (a doc, ticket, or chat message). Sensitivity therefore
// tracks whether the identifier embeds a tenant-owner identity, which drives
// the per-type confidence tiering below.
package cloudresources

import (
	stdctx "context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/awslabs/ferret-scan/internal/config"
	"github.com/awslabs/ferret-scan/internal/detector"
	"github.com/awslabs/ferret-scan/internal/execguard"
	"github.com/awslabs/ferret-scan/internal/observability"
)

// maxContentBytes bounds the input this validator will scan. Beyond this size
// the scan is skipped with a logged warning rather than risking a slow scan on
// a hostile or pathological input. Cloud resource IDs in real documents appear
// well within this budget; huge inputs are almost always binary/generated.
const maxContentBytes = 5 << 20 // 5 MB

// maxMatchesPerPattern caps how many matches a single pattern may contribute,
// so a degenerate input (e.g. a file that is nothing but ARNs) cannot produce
// an unbounded result set. Excess matches are dropped with a logged warning.
const maxMatchesPerPattern = 5000

// acceptThreshold is a sanity floor: matches scoring below it are too weak to be
// worth surfacing at any confidence level and are dropped. It is intentionally
// well below the LOW/MEDIUM/HIGH band boundaries (60/90) so the per-type tiering
// — not this floor — decides visibility. Account-less, low-signal forms (S3
// buckets, OCIDs, management groups) score into the LOW band (<60) so they are
// hidden by `--confidence high,medium` but still available under the default,
// while identity-bearing resources land in MEDIUM/HIGH. This keeps the
// default-on validator from burying PII/secret findings without silently making
// whole resource classes undetectable.
const acceptThreshold = 45.0

// Validator implements the detector.Validator interface for detecting
// cloud provider resource identifiers using regex patterns and contextual analysis.
type Validator struct {
	// Pre-compiled regex patterns for all cloud providers.
	patterns []*regexp.Regexp

	// Keywords that suggest a cloud resource context (used by AnalyzeContext).
	positiveKeywords []string

	// Keywords that suggest test/example context. Matched as whole tokens on the
	// match's own line, never as a substring against the whole document.
	negativeKeywords []string

	// Provider configuration (enabled/disabled providers).
	enabledProviders map[string]bool

	// Custom patterns from configuration.
	customPatterns []*regexp.Regexp

	// Observability (following standard pattern).
	observer *observability.StandardObserver
}

// NewValidator creates and returns a new Validator instance
// with predefined patterns and keywords for detecting cloud resource identifiers.
func NewValidator() *Validator {
	return &Validator{
		patterns: compileCloudResourcePatterns(),
		positiveKeywords: []string{
			"arn", "aws", "azure", "gcp", "google", "cloud", "resource",
			"subscription", "project", "account", "ocid", "crn", "acs",
		},
		negativeKeywords: []string{
			"example", "test", "demo", "sample", "fake", "mock", "dummy",
			"placeholder", "template", "tutorial", "documentation",
		},
		enabledProviders: map[string]bool{
			"aws":     true,
			"azure":   true,
			"gcp":     true,
			"oci":     true,
			"ibm":     true,
			"alibaba": true,
		},
		customPatterns: []*regexp.Regexp{},
		observer:       nil,
	}
}

// SetObserver sets the observability component.
func (v *Validator) SetObserver(observer *observability.StandardObserver) {
	v.observer = observer
}

// ValidateContent validates preprocessed content for cloud resource identifiers.
//
// Performance: all per-document analysis (lowercasing, keyword/config detection,
// line-offset indexing) is computed ONCE here, not per match. Matches are located
// via FindAllStringIndex so the byte offset gives an exact line number without a
// full-content rescan, and identical (text, offset) hits from overlapping patterns
// are de-duplicated. This keeps the scan linear in content size; the previous
// per-match full-content ToLower + strings.Index made it O(matches × content),
// which took ~84s on an 800 KB file.
func (v *Validator) ValidateContent(content string, originalPath string) ([]detector.Match, error) {
	// Backward-compatible shim: run with a background context (never cancels).
	return v.ValidateContentCtx(stdctx.Background(), content, originalPath)
}

// ValidateContentCtx implements execguard.ContextAwareValidator: the context-aware
// form of ValidateContent, polling ctx once per candidate span in the scoring loop
// so a runaway scan over tens of thousands of matches is reclaimed promptly (v2
// Phase 3). On cancellation it returns the matches gathered so far plus ctx.Err().
func (v *Validator) ValidateContentCtx(ctx stdctx.Context, content string, originalPath string) ([]detector.Match, error) {
	var finishTiming func(bool, map[string]interface{})
	if v.observer != nil {
		finishTiming = v.observer.StartTiming("cloud_resources", "validate_content", originalPath)
	}

	// Guard against pathological inputs.
	if len(content) > maxContentBytes {
		v.logDetail(fmt.Sprintf("Content %d bytes exceeds %d-byte cap; skipping cloud-resource scan for %q", len(content), maxContentBytes, originalPath))
		if finishTiming != nil {
			finishTiming(true, map[string]interface{}{"match_count": 0, "skipped_oversize": true})
		}
		return nil, nil
	}

	// Entry-level cancellation check (v2 Phase 3): the whole-content regex pass and
	// containment dedup below run before the polled scoring loop, so an
	// already-cancelled/expired scan bails here rather than paying for them.
	if execguard.LineLoopCancelled(ctx, 0) {
		if finishTiming != nil {
			finishTiming(false, map[string]interface{}{"cancelled": true, "match_count": 0})
		}
		return nil, ctx.Err()
	}

	// Precompute document-level signals once.
	lineIndex := newLineIndex(content)
	customStart := len(v.patterns)
	allPatterns := append(append([]*regexp.Regexp{}, v.patterns...), v.customPatterns...)

	// Collect every raw span first, then dedup by containment. Overlapping
	// patterns (the generic AWS ARN vs the S3-specific one, or the Azure full
	// resource path vs its /resourceGroups prefix) produce nested spans for the
	// same logical resource; keeping only the maximal (non-contained) span emits
	// each resource once, at its fullest extent.
	type rawMatch struct {
		start, end int
		isCustom   bool
	}
	var raws []rawMatch
	var truncated int
	seenSpan := make(map[[2]int]bool)

	for pi, pattern := range allPatterns {
		isCustom := pi >= customStart
		locs := pattern.FindAllStringIndex(content, -1)
		if len(locs) > maxMatchesPerPattern {
			truncated += len(locs) - maxMatchesPerPattern
			locs = locs[:maxMatchesPerPattern]
		}
		for _, loc := range locs {
			span := [2]int{loc[0], loc[1]}
			if seenSpan[span] {
				continue
			}
			seenSpan[span] = true
			raws = append(raws, rawMatch{start: loc[0], end: loc[1], isCustom: isCustom})
		}
	}

	// Drop any span fully contained within a longer span (the longer one wins),
	// via an O(n log n) sort-and-sweep instead of an O(n^2) all-pairs scan. The
	// previous all-pairs comparison was itself a DoS vector: on single-line input
	// n = total matches across all patterns (tens of thousands), so n^2 reached
	// ~10^9. Sort by (start asc, end desc); processing in that order, a span is
	// contained in an earlier, longer span iff its end <= the maximal end seen so
	// far from a strictly-longer span. Equal spans are kept (handled by the
	// length check) so identical matches from different patterns still dedupe via
	// the earlier seenSpan map.
	sort.Slice(raws, func(i, j int) bool {
		if raws[i].start != raws[j].start {
			return raws[i].start < raws[j].start
		}
		return raws[i].end > raws[j].end // longer first at the same start
	})
	containedFlag := make([]bool, len(raws))
	maxEnd := -1
	maxLen := 0
	for i := range raws {
		span := raws[i]
		spanLen := span.end - span.start
		// Contained iff a previously-seen span starts at/before this one (true by
		// sort order) and ends at/after it while being strictly longer.
		if span.end <= maxEnd && spanLen < maxLen {
			containedFlag[i] = true
			continue
		}
		if span.end > maxEnd {
			maxEnd = span.end
			maxLen = spanLen
		}
	}

	var matches []detector.Match
	providerCounts := make(map[string]int)
	var suppressedKeyword, suppressedLowConf int

	// Per-line cache: matches on the same line share the same line text, its
	// lowercase, AND whether that line carries a negative (test-context) keyword,
	// so compute each once per distinct line-start offset rather than per match.
	// The negative-keyword scan in particular is O(lineLen × keywords); hoisting
	// it here turns the per-match O(content) work into O(content) total. On
	// single-line input every match shares one line, so all of this is computed
	// exactly once instead of once per (potentially tens of thousands of) matches.
	cachedLineStart := -1
	var cachedLine, cachedLineLower string
	var cachedLineHasNegKw bool

	for i := range raws {
		// Cooperative cancellation (v2 Phase 3): bail promptly on deadline/cancel,
		// returning the matches gathered so far plus the reason.
		if execguard.LineLoopCancelled(ctx, i) {
			if finishTiming != nil {
				finishTiming(false, map[string]interface{}{"cancelled": true, "match_count": len(matches)})
			}
			return matches, ctx.Err()
		}
		if containedFlag[i] {
			continue
		}
		start, end, isCustom := raws[i].start, raws[i].end, raws[i].isCustom
		text := content[start:end]

		resourceType := getCloudResourceType(text)

		// Filter by enabled provider (only for recognized providers).
		provider := getProviderFromType(resourceType)
		if provider != "" && !v.isProviderEnabled(provider) {
			continue
		}

		// Public-by-design resources are not sensitive; drop them outright.
		if isPublicResource(text) {
			v.logDetail(fmt.Sprintf("Match filtered (public-by-design resource): %q", text))
			continue
		}

		lineStart, lineEnd := lineIndex.lineBounds(content, start)
		if lineStart != cachedLineStart {
			cachedLineStart = lineStart
			cachedLine = content[lineStart:lineEnd]
			cachedLineLower = strings.ToLower(cachedLine)
			cachedLineHasNegKw = hasKeywordToken(cachedLineLower, v.negativeKeywords)
		}
		lineNo := lineIndex.lineAt(start)

		confidence, factors := v.scoreMatch(text, resourceType, cachedLineHasNegKw, isCustom)

		// Below the sanity floor: too weak to surface at any confidence level.
		if confidence < acceptThreshold {
			if cachedLineHasNegKw {
				suppressedKeyword++
			} else {
				suppressedLowConf++
			}
			v.logDetail(fmt.Sprintf("Match filtered (confidence %.1f%% < %.0f): %q", confidence, acceptThreshold, text))
			continue
		}

		matches = append(matches, detector.Match{
			Text:       text,
			LineNumber: lineNo,
			Type:       resourceType,
			Confidence: confidence,
			Filename:   originalPath,
			Validator:  "cloud_resources",
			Metadata:   v.buildMetadata(text, resourceType, factors),
		})
		if provider != "" {
			providerCounts[provider]++
		}
	}

	if truncated > 0 {
		v.logDetail(fmt.Sprintf("Match cap reached; %d additional matches not processed for %q", truncated, originalPath))
	}
	if suppressedKeyword+suppressedLowConf > 0 {
		v.logDetail(fmt.Sprintf("Suppressed %d candidate(s): %d below confidence threshold, %d with same-line test keyword",
			suppressedKeyword+suppressedLowConf, suppressedLowConf, suppressedKeyword))
	}

	if finishTiming != nil {
		finishTiming(true, map[string]interface{}{
			"match_count":        len(matches),
			"content_length":     len(content),
			"provider_counts":    providerCounts,
			"suppressed_keyword": suppressedKeyword,
			"suppressed_lowconf": suppressedLowConf,
			"truncated_overcap":  truncated,
		})
	}

	return matches, nil
}

// Validate implements the detector.Validator interface for direct file
// processing. The cloud resources validator only processes preprocessed content
// via ValidateContent, so this returns no results.
func (v *Validator) Validate(filePath string) ([]detector.Match, error) {
	if v.observer != nil {
		finish := v.observer.StartTiming("cloud_resources", "validate_file", filePath)
		finish(true, map[string]interface{}{"match_count": 0, "direct_file_processing": false})
	}
	return []detector.Match{}, nil
}

// logDetail is a nil-safe debug logging helper.
func (v *Validator) logDetail(msg string) {
	if v.observer != nil && v.observer.DebugObserver != nil {
		v.observer.DebugObserver.LogDetail("cloud_resources", msg)
	}
}

// ---------------------------------------------------------------------------
// Line indexing (offset -> line number / line text) computed once per scan.
// ---------------------------------------------------------------------------

// lineIndex maps byte offsets to 1-based line numbers using the precomputed
// positions of newline characters, so a match's line is an O(log n) lookup
// rather than an O(content) strings.Index scan per match.
type lineIndex struct {
	newlineOffsets []int // byte offset of each '\n'
}

func newLineIndex(content string) *lineIndex {
	var offs []int
	for i := 0; i < len(content); i++ {
		if content[i] == '\n' {
			offs = append(offs, i)
		}
	}
	return &lineIndex{newlineOffsets: offs}
}

// lineAt returns the 1-based line number containing byte offset pos.
func (li *lineIndex) lineAt(pos int) int {
	// Number of newlines strictly before pos == count of offsets < pos.
	lo, hi := 0, len(li.newlineOffsets)
	for lo < hi {
		mid := (lo + hi) / 2
		if li.newlineOffsets[mid] < pos {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo + 1
}

// lineBounds returns the [start,end) byte range of the line containing offset
// pos, via binary search over the precomputed newline offsets — O(log n) with no
// content rescan. The previous lineText scanned backward/forward to the nearest
// newline with LastIndexByte/IndexByte, which is O(content) per call and, on a
// single-line input (no newlines), made the per-match loop O(matches × content).
func (li *lineIndex) lineBounds(content string, pos int) (int, int) {
	offs := li.newlineOffsets
	// Find the first newline at or after pos (line end), and the newline just
	// before pos (line start). Binary search the sorted offsets once.
	lo, hi := 0, len(offs)
	for lo < hi {
		mid := (lo + hi) / 2
		if offs[mid] < pos {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	// offs[lo] is the first newline >= pos (line end); offs[lo-1] is the newline
	// before pos (so the line starts after it).
	start := 0
	if lo > 0 {
		start = offs[lo-1] + 1
	}
	end := len(content)
	if lo < len(offs) {
		end = offs[lo]
	}
	return start, end
}

// ---------------------------------------------------------------------------
// Confidence scoring (account-gated tiering).
// ---------------------------------------------------------------------------

// typeBaseConfidence assigns a per-type base score reflecting real sensitivity.
// Identity-bearing resources (those whose patterns require an account/subscription/
// project anchor) start high; account-less, low-signal forms start at or below
// the accept threshold so they only surface when same-line context corroborates.
func typeBaseConfidence(resourceType, match string) float64 {
	// Band targets (filtered by --confidence): HIGH >=90, MEDIUM 60-89, LOW <60.
	switch resourceType {
	case "AWS_ARN":
		// S3 ARNs carry no account/region by design — low-signal bucket names
		// sit in the LOW band so --confidence high,medium hides them.
		if strings.HasPrefix(match, "arn:aws") && strings.Contains(match, ":s3:::") {
			return 55.0
		}
		return 85.0 // generic/IAM/lambda/ec2 patterns all require a 12-digit account
	case "AZURE_RESOURCE_ID":
		// Management-group form has no subscription GUID — LOW band.
		if strings.HasPrefix(match, "/providers/") {
			return 55.0
		}
		return 90.0 // subscription form: validated GUID + topology
	case "GCP_RESOURCE_NAME":
		// folders/ and organizations/ are bare numeric hierarchy IDs (no project
		// anchor) — keep them in the MEDIUM band but below project resources.
		if strings.HasPrefix(match, "folders/") || strings.HasPrefix(match, "organizations/") {
			return 65.0
		}
		return 85.0 // project ID is the account-equivalent anchor
	case "IBM_CRN":
		return 80.0 // account present only when scope is a/{account}; boosted below
	case "ALIBABA_ARN":
		return 80.0
	case "OCI_OCID":
		return 55.0 // no tenancy surfaced; opaque id — LOW band
	default:
		return 75.0 // custom / unknown
	}
}

// scoreMatch computes the confidence and the list of contributing factors for a
// match, using only the match text and its OWN line (never the whole document).
// lineHasNegKeyword reports whether the match's line carries a negative
// (test-context) keyword; the caller computes it once per line (cached) so the
// scan is not repeated per match. The public CalculateConfidence path, which has
// no line context, passes false.
func (v *Validator) scoreMatch(match, resourceType string, lineHasNegKeyword, isCustom bool) (float64, []string) {
	base := typeBaseConfidence(resourceType, match)
	if isCustom {
		base = 75.0
	}
	confidence := base
	factors := []string{fmt.Sprintf("base_match:+%.0f", base)}

	// Boost: a genuine account/subscription/project anchor is the strongest
	// sensitivity signal. This is what separates an identity-bearing reference
	// from a low-signal bucket/OCID.
	if accountID := extractAccountID(match); accountID != "" {
		confidence += 10.0
		factors = append(factors, "valid_account_id:+10")
	}

	// Penalty: implausibly short match.
	if len(match) < 20 {
		confidence -= 10.0
		factors = append(factors, "short_match:-10")
	}
	// Penalty: implausibly long match (likely greedy over-capture).
	if len(match) > 500 {
		confidence -= 15.0
		factors = append(factors, "long_match:-15")
	}

	// LOCAL test-context penalty: only the match's own line is considered, so a
	// stray "example" elsewhere in the document cannot suppress a real finding.
	// Whole-token match avoids dropping names like "company-templates". The scan
	// is hoisted to the caller (computed once per line) so this stays O(1) even
	// when thousands of matches share one line — see ValidateContent's per-line
	// cache. The public CalculateConfidence path passes false (no line context).
	if lineHasNegKeyword {
		confidence -= 20.0
		factors = append(factors, "test_context:-20")
	}

	if confidence < 0 {
		confidence = 0
	} else if confidence > 100 {
		confidence = 100
	}
	return confidence, factors
}

// hasKeywordToken reports whether lowerLine contains any keyword as a whole
// token (delimited by non-alphanumeric boundaries), so "company-templates" does
// NOT match "template" but "see example below" does match "example".
func hasKeywordToken(lowerLine string, keywords []string) bool {
	for _, kw := range keywords {
		idx := 0
		for {
			i := strings.Index(lowerLine[idx:], kw)
			if i < 0 {
				break
			}
			at := idx + i
			before := at - 1
			after := at + len(kw)
			okBefore := before < 0 || !isWordByte(lowerLine[before])
			okAfter := after >= len(lowerLine) || !isWordByte(lowerLine[after])
			if okBefore && okAfter {
				return true
			}
			idx = at + 1
			if idx >= len(lowerLine) {
				break
			}
		}
	}
	return false
}

func isWordByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// CalculateConfidence implements the detector.Validator interface. It mirrors
// the scoring used in ValidateContent (minus the line-local context penalty,
// which requires surrounding text) so the two paths do not diverge.
func (v *Validator) CalculateConfidence(match string) (float64, map[string]bool) {
	resourceType := getCloudResourceType(match)
	confidence, _ := v.scoreMatch(match, resourceType, false, false)
	checks := map[string]bool{
		"valid_format":      true,
		"valid_account_id":  extractAccountID(match) != "",
		"sufficient_length": len(match) >= 20,
		"reasonable_length": len(match) <= 500,
	}
	return confidence, checks
}

// AnalyzeContext implements the detector.Validator interface. It analyzes the
// context around a match and returns a confidence adjustment.
func (v *Validator) AnalyzeContext(match string, context detector.ContextInfo) float64 {
	fullContext := strings.ToLower(context.BeforeText + " " + context.FullLine + " " + context.AfterText)
	lineLower := strings.ToLower(context.FullLine)

	var impact float64
	for _, keyword := range v.positiveKeywords {
		if strings.Contains(fullContext, keyword) {
			if strings.Contains(lineLower, keyword) {
				impact += 10
			} else {
				impact += 5
			}
		}
	}
	for _, keyword := range v.negativeKeywords {
		if hasKeywordToken(fullContext, []string{keyword}) {
			if hasKeywordToken(lineLower, []string{keyword}) {
				impact -= 25
			} else {
				impact -= 12
			}
		}
	}
	if impact > 40 {
		impact = 40
	} else if impact < -80 {
		impact = -80
	}
	return impact
}

// ---------------------------------------------------------------------------
// Public-resource allowlist (public-by-design => not sensitive).
// ---------------------------------------------------------------------------

// publicProjectPrefixes are GCP project IDs published by Google (public datasets
// / public artifact projects); a resource scoped to one of these is not a leak.
var publicProjectPrefixes = []string{
	"bigquery-public-data", "gcp-public-data", "google.com:", "public-data",
}

// isPublicResource reports whether a matched identifier is public-by-design and
// therefore not sensitive: AWS-managed policies/service-linked roles, public GCP
// datasets, etc. These are ubiquitous in IaC and would otherwise be pure noise.
func isPublicResource(match string) bool {
	// AWS-managed policy ARNs use the literal account "aws".
	if strings.HasPrefix(match, "arn:aws:iam::aws:") {
		return true
	}
	// GovCloud/China managed policies use the same literal-aws account slot.
	if strings.HasPrefix(match, "arn:aws") {
		if i := strings.Index(match, ":iam::aws:"); i >= 0 {
			return true
		}
	}
	// Public GCP datasets / projects.
	for _, p := range publicProjectPrefixes {
		if strings.Contains(match, "projects/"+p) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Metadata.
// ---------------------------------------------------------------------------

// buildMetadata constructs metadata for a cloud resource finding.
func (v *Validator) buildMetadata(match, resourceType string, factors []string) map[string]any {
	metadata := map[string]any{
		"provider":      getProviderFromType(resourceType),
		"resource_type": resourceType,
	}

	if accountID := extractAccountID(match); accountID != "" {
		metadata["account_id"] = accountID
	}
	if region := extractRegion(match, resourceType); region != "" {
		metadata["region"] = region
	}
	if len(factors) > 0 {
		metadata["confidence_factors"] = factors
	}

	switch resourceType {
	case "AWS_ARN":
		if service := extractAWSServiceType(match); service != "" {
			metadata["service"] = service
		}
	case "AZURE_RESOURCE_ID":
		if rg := extractAzureResourceGroup(match); rg != "" {
			metadata["resource_group"] = rg
		}
		if azureType := extractAzureResourceType(match); azureType != "" {
			metadata["azure_resource_type"] = azureType
		}
	case "GCP_RESOURCE_NAME":
		if projectID := extractGCPProjectID(match); projectID != "" {
			metadata["project_id"] = projectID
		}
		if gcpType := extractGCPResourceType(match); gcpType != "" {
			metadata["gcp_resource_type"] = gcpType
		}
	case "OCI_OCID":
		if ociType := extractOCIResourceType(match); ociType != "" {
			metadata["oci_resource_type"] = ociType
		}
	case "IBM_CRN":
		if service := extractIBMServiceType(match); service != "" {
			metadata["service"] = service
		}
	case "ALIBABA_ARN":
		if service := extractAlibabaServiceType(match); service != "" {
			metadata["service"] = service
		}
	}
	return metadata
}

// ---------------------------------------------------------------------------
// Configuration.
// ---------------------------------------------------------------------------

var validProviderNames = map[string]bool{
	"aws": true, "azure": true, "gcp": true, "oci": true, "ibm": true, "alibaba": true,
}

// Configure loads enabled_providers and custom_patterns from the
// "cloud_resources" section of the validators configuration.
func (v *Validator) Configure(cfg *config.Config) {
	if cfg == nil || cfg.Validators == nil {
		return
	}
	cloudConfig, ok := cfg.Validators["cloud_resources"]
	if !ok {
		return
	}

	if providers, ok := cloudConfig["enabled_providers"].(map[string]interface{}); ok {
		for provider, enabled := range providers {
			if !validProviderNames[provider] {
				v.logDetail(fmt.Sprintf("Warning: unknown provider name %q in enabled_providers, skipping", provider))
				continue
			}
			if enabledBool, ok := enabled.(bool); ok {
				v.enabledProviders[provider] = enabledBool
			}
		}
	} else if _, exists := cloudConfig["enabled_providers"]; exists {
		v.logDetail("Warning: enabled_providers has unexpected type, expected map[string]interface{}")
	}

	if patterns, ok := cloudConfig["custom_patterns"].([]interface{}); ok {
		for _, pattern := range patterns {
			if patternStr, ok := pattern.(string); ok {
				if regex, err := regexp.Compile(patternStr); err == nil {
					v.customPatterns = append(v.customPatterns, regex)
				} else {
					v.logDetail(fmt.Sprintf("Invalid custom pattern %q: %v", patternStr, err))
				}
			}
		}
	}

	v.logStartup()
}

func (v *Validator) logStartup() {
	if v.observer == nil || v.observer.DebugObserver == nil {
		return
	}
	v.observer.DebugObserver.LogDetail("cloud_resources",
		fmt.Sprintf("Cloud Resource Validator initialized: %d built-in patterns, %d custom patterns",
			len(v.patterns), len(v.customPatterns)))
	enabledCount := 0
	for _, enabled := range v.enabledProviders {
		if enabled {
			enabledCount++
		}
	}
	v.observer.DebugObserver.LogDetail("cloud_resources",
		fmt.Sprintf("Providers: %d enabled, %d disabled", enabledCount, len(v.enabledProviders)-enabledCount))
}

func (v *Validator) isProviderEnabled(provider string) bool {
	enabled, exists := v.enabledProviders[provider]
	return exists && enabled
}

// ---------------------------------------------------------------------------
// Type classification + provider mapping.
// ---------------------------------------------------------------------------

// getCloudResourceType determines the resource type by prefix. AWS detection
// tolerates non-standard partitions (aws-us-gov, aws-cn, aws-iso...).
func getCloudResourceType(match string) string {
	if isAWSARNPrefix(match) {
		return "AWS_ARN"
	}
	if strings.HasPrefix(match, "/subscriptions/") {
		return "AZURE_RESOURCE_ID"
	}
	if strings.HasPrefix(match, "/providers/Microsoft.Management/managementGroups/") {
		return "AZURE_RESOURCE_ID"
	}
	if strings.HasPrefix(match, "projects/") {
		return "GCP_RESOURCE_NAME"
	}
	if strings.HasPrefix(match, "folders/") || strings.HasPrefix(match, "organizations/") {
		return "GCP_RESOURCE_NAME"
	}
	if strings.HasPrefix(match, "//") && strings.Contains(match, "/projects/") {
		return "GCP_RESOURCE_NAME"
	}
	if strings.HasPrefix(match, "ocid1.") {
		return "OCI_OCID"
	}
	if strings.HasPrefix(match, "crn:v1:") {
		return "IBM_CRN"
	}
	if strings.HasPrefix(match, "acs:") {
		return "ALIBABA_ARN"
	}
	return "CLOUD_RESOURCE_ID"
}

// isAWSARNPrefix reports whether s begins with an AWS ARN prefix in any
// partition: arn:aws:, arn:aws-us-gov:, arn:aws-cn:, arn:aws-iso:, etc.
func isAWSARNPrefix(s string) bool {
	if !strings.HasPrefix(s, "arn:aws") {
		return false
	}
	rest := s[len("arn:aws"):]
	// Next char must be ':' (standard) or '-' (partition suffix like -us-gov).
	if strings.HasPrefix(rest, ":") {
		return true
	}
	if strings.HasPrefix(rest, "-") {
		if i := strings.IndexByte(rest, ':'); i > 0 {
			return true
		}
	}
	return false
}

func getProviderFromType(resourceType string) string {
	switch resourceType {
	case "AWS_ARN":
		return "aws"
	case "AZURE_RESOURCE_ID":
		return "azure"
	case "GCP_RESOURCE_NAME":
		return "gcp"
	case "OCI_OCID":
		return "oci"
	case "IBM_CRN":
		return "ibm"
	case "ALIBABA_ARN":
		return "alibaba"
	default:
		return ""
	}
}

// ---------------------------------------------------------------------------
// Account/region/service extraction.
// ---------------------------------------------------------------------------

var awsAccountIDPattern = regexp.MustCompile(`^\d{12}$`)
var azureUUIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var azureSubscriptionPattern = regexp.MustCompile(`/subscriptions/([^/]+)`)
var azureResourceGroupPattern = regexp.MustCompile(`/resourceGroups/([^/]+)`)
var alibabaAccountIDPattern = regexp.MustCompile(`^\d{6,}$`)

// extractAccountID extracts the account/subscription/project anchor from a match.
func extractAccountID(match string) string {
	switch {
	case isAWSARNPrefix(match):
		return extractAWSAccountID(match)
	case strings.HasPrefix(match, "/subscriptions/"):
		return extractAzureSubscriptionID(match)
	case strings.HasPrefix(match, "projects/") || strings.HasPrefix(match, "//"):
		return extractGCPProjectID(match)
	case strings.HasPrefix(match, "ocid1."):
		return "" // OCIDs surface no tenancy
	case strings.HasPrefix(match, "crn:v1:"):
		return extractIBMAccountID(match)
	case strings.HasPrefix(match, "acs:"):
		return extractAlibabaAccountID(match)
	}
	return ""
}

// extractAWSAccountID returns the 12-digit account ID (field index 4) of an ARN
// in any partition. Returns "" for the literal-aws managed-policy form.
func extractAWSAccountID(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) < 5 {
		return ""
	}
	accountID := parts[4]
	if !awsAccountIDPattern.MatchString(accountID) {
		return ""
	}
	return accountID
}

func extractAzureSubscriptionID(resourcePath string) string {
	m := azureSubscriptionPattern.FindStringSubmatch(resourcePath)
	if len(m) < 2 {
		return ""
	}
	if !azureUUIDPattern.MatchString(m[1]) {
		return ""
	}
	return m[1]
}

func extractAzureResourceGroup(resourcePath string) string {
	m := azureResourceGroupPattern.FindStringSubmatch(resourcePath)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// extractAzureResourceType returns "namespace/type" after "/providers/".
func extractAzureResourceType(resourcePath string) string {
	const seg = "/providers/"
	idx := strings.Index(strings.ToLower(resourcePath), strings.ToLower(seg))
	if idx == -1 {
		return ""
	}
	after := resourcePath[idx+len(seg):]
	if after == "" {
		return ""
	}
	parts := strings.SplitN(after, "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	return parts[0] + "/" + parts[1]
}

var gcpProjectIDPattern = regexp.MustCompile(`^[a-z][-a-z0-9]{4,28}[a-z0-9]$`)
var gcpDomainProjectPattern = regexp.MustCompile(`^[a-z0-9.-]+:[a-z][-a-z0-9]{4,28}[a-z0-9]$`)
var gcpProjectsPattern = regexp.MustCompile(`projects/([^/\s]+)`)

// extractGCPProjectID extracts and validates the project ID. Accepts the
// domain-scoped form (e.g. google.com:my-project) as well as the plain form.
func extractGCPProjectID(resourcePath string) string {
	m := gcpProjectsPattern.FindStringSubmatch(resourcePath)
	if len(m) < 2 {
		return ""
	}
	pid := m[1]
	if gcpProjectIDPattern.MatchString(pid) || gcpDomainProjectPattern.MatchString(pid) {
		return pid
	}
	return ""
}

func extractGCPZoneOrRegion(resourcePath string) string {
	for _, scope := range []string{"/zones/", "/regions/", "/locations/"} {
		if idx := strings.Index(resourcePath, scope); idx != -1 {
			after := resourcePath[idx+len(scope):]
			if s := strings.IndexByte(after, '/'); s != -1 {
				return after[:s]
			}
			return after
		}
	}
	return ""
}

// extractGCPResourceType returns the resource-type segment (second-to-last).
func extractGCPResourceType(resourcePath string) string {
	path := resourcePath
	if strings.HasPrefix(path, "//") {
		idx := strings.Index(path, "/projects/")
		if idx == -1 {
			return ""
		}
		path = path[idx+1:]
	}
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-2]
}

func extractOCIResourceType(ocid string) string {
	if !strings.HasPrefix(ocid, "ocid1.") {
		return ""
	}
	parts := strings.SplitN(ocid, ".", 5)
	if len(parts) < 5 {
		return ""
	}
	return parts[1]
}

func extractOCIRegion(ocid string) string {
	if !strings.HasPrefix(ocid, "ocid1.") {
		return ""
	}
	parts := strings.SplitN(ocid, ".", 5)
	if len(parts) < 5 {
		return ""
	}
	return parts[3]
}

func extractIBMAccountID(crn string) string {
	parts := strings.Split(crn, ":")
	if len(parts) < 7 {
		return ""
	}
	scope := parts[6]
	if strings.HasPrefix(scope, "a/") {
		return scope[2:]
	}
	return ""
}

func extractIBMServiceType(crn string) string {
	parts := strings.Split(crn, ":")
	if len(parts) < 5 {
		return ""
	}
	return parts[4]
}

func extractIBMRegion(crn string) string {
	parts := strings.Split(crn, ":")
	if len(parts) < 6 {
		return ""
	}
	return parts[5]
}

func extractAWSServiceType(arn string) string {
	if !isAWSARNPrefix(arn) {
		return ""
	}
	parts := strings.Split(arn, ":")
	if len(parts) < 3 {
		return ""
	}
	return parts[2]
}

func extractAWSRegion(arn string) string {
	if !isAWSARNPrefix(arn) {
		return ""
	}
	parts := strings.Split(arn, ":")
	if len(parts) < 5 {
		return ""
	}
	return parts[3]
}

func extractAlibabaAccountID(arn string) string {
	if !strings.HasPrefix(arn, "acs:") {
		return ""
	}
	parts := strings.Split(arn, ":")
	if len(parts) < 5 {
		return ""
	}
	accountID := parts[3]
	if !alibabaAccountIDPattern.MatchString(accountID) {
		return ""
	}
	return accountID
}

func extractAlibabaServiceType(arn string) string {
	if !strings.HasPrefix(arn, "acs:") {
		return ""
	}
	parts := strings.Split(arn, ":")
	if len(parts) < 5 {
		return ""
	}
	return parts[1]
}

func extractAlibabaRegion(arn string) string {
	if !strings.HasPrefix(arn, "acs:") {
		return ""
	}
	parts := strings.Split(arn, ":")
	if len(parts) < 5 {
		return ""
	}
	return parts[2]
}

func extractRegion(match, resourceType string) string {
	switch resourceType {
	case "AWS_ARN":
		return extractAWSRegion(match)
	case "GCP_RESOURCE_NAME":
		return extractGCPZoneOrRegion(match)
	case "OCI_OCID":
		return extractOCIRegion(match)
	case "IBM_CRN":
		return extractIBMRegion(match)
	case "ALIBABA_ARN":
		return extractAlibabaRegion(match)
	default:
		return ""
	}
}

// ---------------------------------------------------------------------------
// Patterns.
// ---------------------------------------------------------------------------

// compileCloudResourcePatterns compiles the built-in patterns. Segment classes
// exclude whitespace/newlines so a match cannot bleed across lines, and the AWS
// partition segment tolerates GovCloud/China/ISO partitions. There is a single
// AWS pattern (no service-specific duplicates) to avoid double-emission.
func compileCloudResourcePatterns() []*regexp.Regexp {
	patternStrings := []string{
		// AWS ARN — any partition (aws, aws-us-gov, aws-cn, aws-iso...).
		// Two forms: with a 12-digit account, and account-less S3. The resource
		// tail excludes whitespace, quotes, and common list/sentence punctuation
		// (, ; ) ] } < >) so the match stops at a natural boundary instead of
		// running into surrounding prose — but it does NOT use an ASCII allowlist,
		// so Unicode resource names are captured whole rather than truncated at
		// the first non-ASCII byte.
		"arn:aws(?:-[a-z0-9-]+)?:[a-zA-Z0-9-]+:[a-zA-Z0-9-]*:[0-9]{12}:[^\\s\"',;)\\]}<>]+",
		"arn:aws(?:-[a-z0-9-]+)?:s3:::[^\\s\"',;)\\]}<>]+",

		// Azure Resource IDs (case-insensitive subscription GUID; no newline bleed).
		`/subscriptions/(?i:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/resourceGroups/[^/\s]+/providers/[^/\s]+/[^/\s]+/[^/\s]+`,
		`/subscriptions/(?i:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/resourceGroups/[^/\s]+`,
		`/providers/Microsoft\.Management/managementGroups/[a-zA-Z0-9_.-]+`,

		// GCP resource names — zones/regions/locations, global, and hierarchy.
		`projects/[a-zA-Z0-9.:-]+/(?:zones|regions|locations)/[a-zA-Z0-9-]+/[a-zA-Z0-9]+/[a-zA-Z0-9-]+(?:/[a-zA-Z0-9-]+)*`,
		`projects/[a-zA-Z0-9.:-]+/global/[a-zA-Z0-9]+/[a-zA-Z0-9-]+`,
		`projects/[a-zA-Z0-9.:-]+/serviceAccounts/[^\s/]+`,
		`(?:folders|organizations)/[0-9]+(?:/[a-zA-Z0-9-]+)*`,
		`//[a-zA-Z0-9.-]+/projects/[a-zA-Z0-9.:-]+`,

		// OCI OCID — realistic type/id lengths to reduce false positives.
		`ocid1\.[a-z]{3,}\.oc[0-9]+\.[a-zA-Z0-9-]*\.[a-zA-Z0-9]{8,}`,

		// IBM CRN — 6 mandatory fields then up to 4 optional tail segments, so
		// both 9- and 10-segment real-world CRNs match.
		`crn:v1:[a-zA-Z0-9-]+:[a-zA-Z0-9-]+:[a-zA-Z0-9-]+:[a-zA-Z0-9-]*(?::[a-zA-Z0-9/_.-]*){1,4}`,

		// Alibaba Cloud ARN.
		`acs:[a-zA-Z0-9-]+:[a-zA-Z0-9-]*:[0-9]*:[a-zA-Z0-9:/_.-]+`,
	}

	var compiled []*regexp.Regexp
	for _, p := range patternStrings {
		if rx, err := regexp.Compile(p); err == nil {
			compiled = append(compiled, rx)
		}
	}
	return compiled
}

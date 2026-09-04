// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package email

import (
	stdctx "context"
	"regexp"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/execguard"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/validators/kwmatch"
)

// containsKeywordLower is containsKeyword for callers that have already
// lowercased both arguments. The whole-word scan is identical; only the
// redundant strings.ToLower allocations are skipped. Hoisting the lowercasing
// out of the hot path matters because the previous code re-lowercased the
// (potentially huge) line text once per keyword per match.
func containsKeywordLower(lt, lk string) bool {
	return kwmatch.ContainsLower(lt, lk)
}

// maxKeywordLen bounds how far past a context-window/full-line junction a
// keyword could reach. Any positive/negative keyword that spans the single
// space inserted between BeforeText and the line (or the line and AfterText)
// occupies at most len(keyword)-1 bytes on the line side of that space. This
// must be >= the longest keyword (currently "documentation", 13); 32 leaves
// headroom. It lets the per-match keyword scan touch only a bounded slice of
// the line instead of the whole line.
const maxKeywordLen = 32

// lineKeywordCache holds the per-LINE-global state that the previous code
// recomputed for every match on the line. For a single very long line packed
// with N email matches the old path was O(N * lineLen * keywordCount): each
// match re-lowercased the whole line, re-scanned every positive and negative
// keyword across it (twice — once for analyzeContextAt, once for findKeywords),
// and re-ran isTabularData over the whole line. None of that depends on the
// match's byte offset, so it is computed exactly once per line here and reused,
// dropping the per-line cost to O(lineLen * keywordCount).
type lineKeywordCache struct {
	lowerLine string
	posInLine []bool // containsKeyword(line, positiveKeywords[i])
	negInLine []bool // containsKeyword(line, negativeKeywords[i])
	tabular   bool   // isTabularData(line, ...) — the match arg is unused
	posFound  []string
	negFound  []string
}

// buildLineCache computes the per-line-global keyword/tabular state once.
func (v *Validator) buildLineCache(line string) *lineKeywordCache {
	lc := &lineKeywordCache{
		lowerLine: strings.ToLower(line),
		posInLine: make([]bool, len(v.positiveKeywords)),
		negInLine: make([]bool, len(v.negativeKeywords)),
	}
	for i, kw := range v.positiveKeywords {
		if containsKeywordLower(lc.lowerLine, strings.ToLower(kw)) {
			lc.posInLine[i] = true
			lc.posFound = append(lc.posFound, kw)
		}
	}
	for i, kw := range v.negativeKeywords {
		if containsKeywordLower(lc.lowerLine, strings.ToLower(kw)) {
			lc.negInLine[i] = true
			lc.negFound = append(lc.negFound, kw)
		}
	}
	// isTabularData ignores its match argument; it is purely line-dependent.
	lc.tabular = v.isTabularData(line, "")
	return lc
}

// Pre-compiled regex patterns to avoid repeated compilation in hot paths.
var (
	validCharsPattern      = regexp.MustCompile(`^[A-Za-z0-9._%+-]+$`)
	validDomainPattern     = regexp.MustCompile(`^[A-Za-z0-9.-]+$`)
	emailMultiSpacePattern = regexp.MustCompile(`\s{2,}`)
	nameEmailPattern       = regexp.MustCompile(`[A-Z][a-z]+\s+[A-Z][a-z]+\s+[A-Za-z0-9._%+-]+@`)
)

// machineEmailCap is the maximum final confidence for machine-identifier
// addresses (noreply@, mailer-daemon@, service accounts). They are real,
// deliverable addresses — worth detecting and redacting — but they are not a
// person's contact information, so they must not reach the HIGH band that
// drives blocking decisions. 85 keeps them prominent MEDIUM findings.
const machineEmailCap = 85.0

// machineLocalParts are local-part prefixes (or exact local parts) that
// identify automated senders rather than people. Sourced from the reranker
// benchmark corpus, where these fired at 100 HIGH across logs, mail headers,
// git trailers, cron configs, and monitoring identities.
var machineLocalParts = []string{
	"noreply", "no-reply", "no_reply", "donotreply", "do-not-reply",
	"mailer-daemon", "postmaster", "bounce", "bounces",
	"alerts", "alert", "notifications", "notification", "notify",
	"automated", "auto-confirm", "auto-reply", "autoreply",
	"svc-", "service-account", "system", "daemon", "cron", "robot", "bot@",
}

// isMachineLocalPart reports whether the email's local part identifies an
// automated sender. An entry matches when the local part equals it exactly,
// or continues with a machine-style separator (+ - _ or a digit: noreply2@,
// alerts+prod@, svc-deploy@). A "." continuation does NOT match: dot-joined
// continuations are the firstname.lastname convention, so system.smith@ is a
// person, not a daemon.
func isMachineLocalPart(email string) bool {
	at := strings.IndexByte(email, '@')
	if at <= 0 {
		return false
	}
	local := strings.ToLower(email[:at])
	for _, p := range machineLocalParts {
		p = strings.TrimSuffix(p, "@")
		if !strings.HasPrefix(local, p) {
			continue
		}
		if len(local) == len(p) {
			return true // exact match
		}
		// Entries that end in a separator (svc-) carry their boundary with
		// them; any continuation matches.
		if last := p[len(p)-1]; last == '-' || last == '_' {
			return true
		}
		next := local[len(p)]
		if next == '+' || next == '-' || next == '_' || (next >= '0' && next <= '9') {
			return true
		}
	}
	return false
}

// Validator implements the detector.Validator interface for detecting
// email addresses using regex patterns and contextual analysis.
type Validator struct {
	pattern string
	regex   *regexp.Regexp

	// Keywords that suggest an email context
	positiveKeywords []string

	// Keywords that suggest this is not a real email
	negativeKeywords []string

	// Known test patterns that indicate test data
	knownTestPatterns []string

	// Common test domains and usernames
	testDomains   []string
	testUsernames []string

	// Common business email patterns
	businessPatterns []string

	// Observability
	observer observability.Observer
}

// NewValidator creates and returns a new Validator instance
// with predefined patterns, keywords, and validation rules for detecting email addresses.
func NewValidator() *Validator {
	v := &Validator{
		pattern: `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`,
		positiveKeywords: []string{
			"email", "e-mail", "contact", "mailto", "address", "recipient", "sender",
			"from", "to", "cc", "bcc", "reply", "subscribe", "unsubscribe",
			"notification", "alert", "newsletter", "support", "info", "admin",
			"sales", "marketing", "customer", "service", "help", "noreply",
			"donotreply", "bounce", "postmaster", "webmaster",
		},
		negativeKeywords: []string{
			"test", "example", "fake", "mock", "sample", "dummy", "placeholder",
			"demo", "template", "tutorial", "documentation", "readme",
			"lorem", "ipsum", "foo", "bar", "baz", "temp", "temporary",
			"invalid", "nonexistent", "blackhole", "devnull",
			// Git and version control keywords
			"git clone", "git@", "ssh://", "https://", "http://",
			"repository", "repo", "clone", "checkout", "fetch", "pull", "push",
		},
		knownTestPatterns: []string{
			"test@", "example@", "user@", "admin@", "noreply@",
			"@test", "@example", "@localhost", "@domain", "@company",
		},
		testDomains: []string{
			"example.com", "example.org", "example.net", "test.com", "test.org",
			"localhost", "domain.com", "company.com", "email.com", "mail.com",
			"foo.com", "bar.com", "baz.com", "temp.com", "dummy.com",
			"sample.com", "demo.com", "placeholder.com", "invalid.com",
		},
		testUsernames: []string{
			"test", "example", "user", "admin", "root", "demo", "sample",
			"dummy", "placeholder", "foo", "bar", "baz", "temp", "invalid",
			"john.doe", "jane.smith", "user123", "testuser", "demouser",
		},
		businessPatterns: []string{
			"firstname.lastname@", "first.last@", "f.lastname@", "flastname@",
			"lastname.firstname@", "last.first@", "l.firstname@", "lfirstname@",
		},
	}

	// Compile the regex pattern once at initialization
	v.regex = regexp.MustCompile(v.pattern)
	return v
}

// SetObserver sets the observability component
func (v *Validator) SetObserver(observer observability.Observer) {
	v.observer = observer
}

// ValidateContent validates preprocessed content for email addresses
func (v *Validator) ValidateContent(content string, originalPath string) ([]detector.Match, error) {
	// Backward-compatible shim: run with a background context (never cancels).
	return v.ValidateContentCtx(stdctx.Background(), content, originalPath)
}

// ValidateContentCtx implements execguard.ContextAwareValidator: the context-aware
// form of ValidateContent, polling ctx once per line so a runaway multi-line scan
// is reclaimed promptly (v2 Phase 3). Returns partial matches + ctx.Err() on
// cancellation.
func (v *Validator) ValidateContentCtx(ctx stdctx.Context, content string, originalPath string) ([]detector.Match, error) {
	var finishTiming func(bool, map[string]interface{})
	if v.observer != nil {
		finishTiming = v.observer.StartTiming("email_validator", "validate_content", originalPath)
	}

	var matches []detector.Match

	// Split content into lines for processing
	lines := strings.Split(content, "\n")

	// Use the pre-compiled regex
	re := v.regex

	for lineNum, line := range lines {
		// Cooperative cancellation (v2 Phase 3): bail promptly on deadline/cancel.
		if execguard.LineLoopCancelled(ctx, lineNum) {
			if finishTiming != nil {
				finishTiming(false, map[string]interface{}{"cancelled": true, "match_count": len(matches)})
			}
			return matches, ctx.Err()
		}
		// Use match offsets (not just the strings) so that when the same email
		// text appears more than once on a line, each occurrence is analyzed with
		// ITS OWN surrounding context. The previous code re-ran strings.Index,
		// which always returned the first occurrence and mis-scored duplicates.
		matchLocs := re.FindAllStringIndex(line, -1)
		if len(matchLocs) == 0 {
			continue
		}

		// Compute the per-line-global keyword/tabular state exactly once, then
		// reuse it for every match on this line. Previously each match
		// re-lowercased the whole line and re-scanned every keyword across it,
		// which made a single very long line packed with matches quadratic.
		lc := v.buildLineCache(line)

		for _, loc := range matchLocs {
			matchIndex, matchEnd := loc[0], loc[1]
			match := line[matchIndex:matchEnd]

			// Calculate confidence
			confidence, checks := v.CalculateConfidence(match)

			// Analyze email structure
			emailParts := v.AnalyzeEmailStructure(match)

			// For preprocessed content, create a context info
			contextInfo := detector.ContextInfo{
				FullLine: line,
			}

			// Extract context around THIS occurrence of the match.
			start := matchIndex - 50
			if start < 0 {
				start = 0
			}
			end := matchEnd + 50
			if end > len(line) {
				end = len(line)
			}
			contextInfo.BeforeText = line[start:matchIndex]
			contextInfo.AfterText = line[matchEnd:end]

			// Analyze context and adjust confidence. The true after-match text is
			// passed so the URL-structure check inspects this occurrence.
			contextImpact := v.analyzeContextAt(match, contextInfo, line[matchEnd:], lc)

			// Check for tabular data and boost confidence. Tabular detection is
			// line-global (its match argument is unused) so it is taken from the
			// per-line cache instead of recomputed for every match.
			if lc.tabular {
				contextImpact += 15 // Boost for tabular data
			}

			confidence += contextImpact

			// HARD CAP for machine-identifier local parts (noreply@,
			// mailer-daemon@, svc-*@, ...): these are the single most common
			// email FP in real logs and configs — they are addresses, but not
			// a person's contact. The -15 test-pattern penalty alone is
			// clawed back by positive context ("alert", "notification",
			// "noreply" are themselves positive keywords) and re-clamped to
			// 100 HIGH. Mirror the phone fictional-range cap: applied AFTER
			// context adjustment so keyword stacking cannot raise a machine
			// address back into HIGH. Capped at 85 (solid MEDIUM) — still
			// detected, displayed, and redactable, never HIGH.
			if isMachineLocalPart(match) && confidence > machineEmailCap {
				confidence = machineEmailCap
			}

			// Ensure confidence stays within bounds
			if confidence > 100 {
				confidence = 100
			} else if confidence < 0 {
				confidence = 0
			}

			// Skip matches with 0% confidence - they are false positives
			if confidence <= 0 {
				continue
			}

			// Store keywords found in context
			contextInfo.PositiveKeywords = v.findKeywordsCached(contextInfo, v.positiveKeywords, lc.posInLine, lc)
			contextInfo.NegativeKeywords = v.findKeywordsCached(contextInfo, v.negativeKeywords, lc.negInLine, lc)
			contextInfo.ConfidenceImpact = contextImpact

			emailType := v.getEmailProviderType(match)
			matches = append(matches, detector.Match{
				Text:       match,
				LineNumber: lineNum + 1, // 1-based line numbering
				Type:       emailType,
				Confidence: confidence,
				Filename:   originalPath,
				Validator:  "email",
				Context:    contextInfo,
				Metadata: map[string]any{
					"domain":            emailParts["domain"],
					"username":          emailParts["username"],
					"tld":               emailParts["tld"],
					"email_provider":    emailType,
					"validation_checks": checks,
					"context_impact":    contextInfo.ConfidenceImpact,
					"source":            "preprocessed_content",
					"original_file":     originalPath,
				},
			})
			// An address whose last label is not in the IANA root zone may not reach the HIGH
			// band. Declared as a ceiling on the match just appended; see unrecognisedTLDCeiling.
			applyUnrecognisedTLDCeiling(&matches[len(matches)-1], checks)
		}
	}

	if finishTiming != nil {
		finishTiming(true, map[string]interface{}{
			"match_count":     len(matches),
			"lines_processed": len(lines),
			"content_length":  len(content),
		})
	}

	return matches, nil
}

// AnalyzeContext analyzes the context around a match and returns a confidence
// adjustment. It satisfies the detector.Validator interface; it derives the
// after-match text from the first occurrence on the line (back-compat for
// external callers). The scan loop calls analyzeContextAt directly with the
// exact occurrence offset so duplicate matches are scored correctly.
func (v *Validator) AnalyzeContext(match string, context detector.ContextInfo) float64 {
	afterMatch := ""
	if idx := strings.Index(context.FullLine, match); idx >= 0 {
		afterMatch = context.FullLine[idx+len(match):]
	}
	// Back-compat path for external callers: build the per-line cache on demand.
	return v.analyzeContextAt(match, context, afterMatch, v.buildLineCache(context.FullLine))
}

// junctionWindows holds the two bounded strings used to detect keyword matches
// that the precomputed whole-line flags (lc.*InLine) cannot account for: matches
// lying inside the BeforeText/AfterText context windows, and matches that cross
// the single space the original code inserted between BeforeText and the full
// line (and between the full line and AfterText). Matches that lie entirely
// inside the line interior are reported by the *InLine flags instead.
//
// Each window includes a bounded slice of the adjacent line (length boundedLine)
// so any junction-crossing match has its full body and word-boundary neighbours
// present, while leaving the line's real neighbour bytes at the cut so the cut
// itself never fabricates a false word boundary for an accepted match. junctPos
// records the index of the junction space within the window; only occurrences
// that touch the window/junction region are accepted (interior-line occurrences,
// reachable only past the cut, are rejected — they are handled by *InLine).
type junctionWindows struct {
	before    string // lower(BeforeText) + " " + line head
	beforePos int    // index of the space separating BeforeText from the line head
	after     string // line tail + " " + lower(AfterText)
	afterPos  int    // index of the space separating the line tail from AfterText
}

// boundedLine is how much of the line is included on the line side of each
// junction. It must exceed maxKeywordLen so that an accepted (window or
// junction-crossing) occurrence's word-boundary neighbour byte at the far end is
// always a real line byte, never the artificial slice cut. 2*maxKeywordLen is
// comfortably sufficient since an accepted occurrence reaches at most
// maxKeywordLen bytes past the junction space.
const boundedLine = 2 * maxKeywordLen

func buildJunctionWindows(beforeText, lowerLine, afterText string) junctionWindows {
	head := lowerLine
	if len(head) > boundedLine {
		head = head[:boundedLine]
	}
	tail := lowerLine
	if len(tail) > boundedLine {
		tail = tail[len(tail)-boundedLine:]
	}
	lb := strings.ToLower(beforeText)
	la := strings.ToLower(afterText)
	return junctionWindows{
		before:    lb + " " + head,
		beforePos: len(lb),
		after:     tail + " " + la,
		afterPos:  len(tail),
	}
}

// containsKeywordCrossing reports whether lk occurs as a whole word in s such
// that the occurrence touches the junction region. accept reports, given a
// match's [start,end) range, whether that match is one the caller wants:
//   - before window: start <= junctPos (match begins in BeforeText or at the
//     junction space) — i.e. window-interior or junction-crossing matches.
//   - after window:  end > junctPos (match ends in AfterText or crosses into it).
//
// Matches that fall entirely on the line side past the junction are interior
// line matches and are intentionally skipped (covered by the *InLine flag), so
// the bounded-line slice cut cannot fabricate them.
//
// ModeAlnum matches the boundary semantics of the other keyword scans in this
// package; accept is only consulted for whole-word occurrences.
func containsKeywordCrossing(s, lk string, accept func(start, end int) bool) bool {
	return kwmatch.ContainsFunc(s, lk, accept)
}

// keywordInContext reports whether keyword (lowercased as lowerKw) appears
// whole-word in the original
// fullContext = lower(BeforeText)+" "+lowerLine+" "+lower(AfterText),
// using the precomputed in-line flag plus the bounded junction windows.
func keywordInContext(inLine bool, lowerKw string, jw junctionWindows) bool {
	if inLine {
		return true
	}
	if containsKeywordCrossing(jw.before, lowerKw, func(start, end int) bool {
		return start <= jw.beforePos
	}) {
		return true
	}
	return containsKeywordCrossing(jw.after, lowerKw, func(start, end int) bool {
		return end > jw.afterPos
	})
}

// analyzeContextAt is AnalyzeContext with the exact post-match text supplied by
// the caller, so the URL-structure check inspects the correct occurrence. The
// per-line keyword cache supplies the line-global keyword presence so this is
// O(keywordCount * windowLen) per match rather than O(keywordCount * lineLen).
func (v *Validator) analyzeContextAt(match string, context detector.ContextInfo, afterMatch string, lc *lineKeywordCache) float64 {
	var confidenceImpact float64 = 0

	// CRITICAL: Check for URL/URI structure first (highest priority)
	// Any user@host pattern followed by :, /, or :// is a URL/URI, not an email
	if hasURLStructureAfter(afterMatch) {
		// This is a URL/URI (git@host:path, user@host/path, etc.), not an email
		return -100 // Zero out confidence completely
	}

	jw := buildJunctionWindows(context.BeforeText, lc.lowerLine, context.AfterText)

	// Check for positive keywords (increase confidence). Whole-word matching only.
	for i, keyword := range v.positiveKeywords {
		lowerKw := strings.ToLower(keyword)
		if keywordInContext(lc.posInLine[i], lowerKw, jw) {
			// Give more weight to keywords that are closer to the match.
			// lc.posInLine[i] == containsKeyword(context.FullLine, keyword).
			if lc.posInLine[i] {
				confidenceImpact += 8 // +8% for keywords in the same line
			} else {
				confidenceImpact += 4 // +4% for keywords in surrounding context
			}
		}
	}

	// Check for negative keywords (decrease confidence). Whole-word matching only,
	// so "bar"/"baz"/"foo"/"temp" no longer fire inside barack/bazaar/temptation.
	for i, keyword := range v.negativeKeywords {
		lowerKw := strings.ToLower(keyword)
		if keywordInContext(lc.negInLine[i], lowerKw, jw) {
			// Give more weight to keywords that are closer to the match.
			if lc.negInLine[i] {
				confidenceImpact -= 20 // -20% for negative keywords in the same line
			} else {
				confidenceImpact -= 10 // -10% for negative keywords in surrounding context
			}
		}
	}

	// Cap the impact to reasonable bounds
	if confidenceImpact > 30 {
		confidenceImpact = 30 // Maximum +30% boost
	} else if confidenceImpact < -60 {
		confidenceImpact = -60 // Maximum -60% reduction
	}

	return confidenceImpact
}

// findKeywordsCached returns the keywords found in the per-match context, in the
// same order as the keywords slice. It is the cached equivalent of the previous
// findKeywords: inLine[i] is the precomputed whole-line presence of keywords[i],
// and the two bounded junction strings cover the BeforeText/AfterText windows.
// This reproduces containsKeyword(fullContext, keyword) exactly without
// re-scanning the whole line per match.
func (v *Validator) findKeywordsCached(context detector.ContextInfo, keywords []string, inLine []bool, lc *lineKeywordCache) []string {
	jw := buildJunctionWindows(context.BeforeText, lc.lowerLine, context.AfterText)

	var found []string
	for i, keyword := range keywords {
		if keywordInContext(inLine[i], strings.ToLower(keyword), jw) {
			found = append(found, keyword)
		}
	}

	return found
}

// CalculateConfidence calculates the confidence score for a potential email address
func (v *Validator) CalculateConfidence(match string) (float64, map[string]bool) {
	checks := map[string]bool{
		"valid_format":        true,
		"valid_domain":        true,
		"valid_tld":           true,
		"not_test_email":      true,
		"business_pattern":    false,
		"reasonable_length":   true,
		"no_consecutive_dots": true,
		"valid_username":      true,
	}

	confidence := 100.0
	lowerMatch := strings.ToLower(match)

	// Basic format validation (already passed regex, but check edge cases)
	if !v.isValidEmailFormat(match) {
		confidence -= 30
		checks["valid_format"] = false
	}

	// RFC compliance: Domain must start with alphanumeric character (not hyphen)
	if !v.hasValidDomainStart(match) {
		confidence -= 100 // Zero out confidence for RFC violations
		checks["valid_domain"] = false
	}

	// Check domain validity (20%)
	parts := strings.Split(match, "@")
	if len(parts) != 2 {
		confidence -= 20
		checks["valid_domain"] = false
	} else {
		domain := strings.ToLower(parts[1])

		// Check for test domains
		if v.isTestDomain(domain) {
			confidence -= 25
			checks["not_test_email"] = false
		}

		// TLD recognition. The hardcoded list is incomplete (it omits many
		// delegated gTLDs such as .amazon/.google/.aws/.phd), so a -100
		// "zero it out" penalty silently dropped real emails on those TLDs.
		// The regex already requires a 2+ alphabetic TLD, so an unrecognized
		// TLD is only weak evidence of a fake address: apply a small penalty
		// instead of suppressing the finding entirely.
		if !v.hasValidTLD(domain) {
			confidence -= 10
			checks["valid_tld"] = false
		}
	}

	// Check username validity (15%)
	if len(parts) == 2 {
		username := strings.ToLower(parts[0])

		// Check for test usernames
		if v.isTestUsername(username) {
			confidence -= 20
			checks["not_test_email"] = false
		}

		// Check for business patterns
		if v.matchesBusinessPattern(lowerMatch) {
			checks["business_pattern"] = true
			confidence += 5 // Small boost for business-like emails
		}
	}

	// Check reasonable length (10%)
	if len(match) > 254 || len(match) < 6 {
		confidence -= 10
		checks["reasonable_length"] = false
	}

	// Check for consecutive dots (10%)
	if strings.Contains(match, "..") {
		confidence -= 10
		checks["no_consecutive_dots"] = false
	}

	// Check for known test patterns (15%)
	for _, pattern := range v.knownTestPatterns {
		if strings.Contains(lowerMatch, pattern) {
			confidence -= 15
			checks["not_test_email"] = false
			break
		}
	}

	if confidence < 0 {
		confidence = 0
	}
	return confidence, checks
}

// AnalyzeEmailStructure breaks down the email into components
func (v *Validator) AnalyzeEmailStructure(email string) map[string]string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return map[string]string{
			"username": email,
			"domain":   "",
			"tld":      "",
		}
	}

	username := parts[0]
	domain := parts[1]

	// Extract TLD
	domainParts := strings.Split(domain, ".")
	tld := ""
	if len(domainParts) > 0 {
		tld = domainParts[len(domainParts)-1]
	}

	return map[string]string{
		"username": username,
		"domain":   domain,
		"tld":      tld,
	}
}

// getEmailProviderType determines the specific email provider type based on domain analysis
func (v *Validator) getEmailProviderType(email string) string {
	parts := strings.Split(strings.ToLower(email), "@")
	if len(parts) != 2 {
		return "EMAIL"
	}

	domain := parts[1]

	// Major email providers
	switch domain {
	// Google services
	case "gmail.com", "googlemail.com":
		return "GMAIL"
	case "google.com":
		return "GOOGLE_WORKSPACE"

	// Microsoft services
	case "outlook.com", "hotmail.com", "live.com", "msn.com":
		return "OUTLOOK"
	case "microsoft.com":
		return "MICROSOFT_365"

	// Yahoo services
	case "yahoo.com", "yahoo.co.uk", "yahoo.ca", "yahoo.au", "yahoo.de", "yahoo.fr", "yahoo.it", "yahoo.es", "yahoo.co.jp", "yahoo.co.in":
		return "YAHOO"

	// Apple services
	case "icloud.com", "me.com", "mac.com":
		return "ICLOUD"
	case "apple.com":
		return "APPLE_CORPORATE"

	// Other major providers
	case "aol.com":
		return "AOL"
	case "protonmail.com", "proton.me", "pm.me":
		return "PROTONMAIL"
	case "tutanota.com", "tutanota.de", "tutamail.com", "tuta.io":
		return "TUTANOTA"
	case "fastmail.com", "fastmail.fm":
		return "FASTMAIL"
	case "zoho.com", "zohomail.com":
		return "ZOHO"
	case "yandex.com", "yandex.ru":
		return "YANDEX"
	case "mail.ru", "inbox.ru", "list.ru", "bk.ru":
		return "MAIL_RU"

	// Business/Enterprise providers
	case "salesforce.com":
		return "SALESFORCE"
	case "slack.com":
		return "SLACK"
	case "atlassian.com":
		return "ATLASSIAN"
	case "github.com":
		return "GITHUB"
	case "gitlab.com":
		return "GITLAB"

	// Educational domains
	case "edu", "ac.uk", "edu.au", "edu.ca":
		return "EDUCATIONAL"
	}

	// Check for common educational patterns
	if strings.HasSuffix(domain, ".edu") || strings.HasSuffix(domain, ".ac.uk") ||
		strings.HasSuffix(domain, ".edu.au") || strings.HasSuffix(domain, ".edu.ca") ||
		strings.HasSuffix(domain, ".ac.in") || strings.HasSuffix(domain, ".edu.sg") {
		return "EDUCATIONAL"
	}

	// Check for government domains
	if strings.HasSuffix(domain, ".gov") || strings.HasSuffix(domain, ".gov.uk") ||
		strings.HasSuffix(domain, ".gov.au") || strings.HasSuffix(domain, ".gov.ca") ||
		strings.HasSuffix(domain, ".mil") {
		return "GOVERNMENT"
	}

	// Check for temporary/disposable email services (check this before business check)
	if v.isDisposableEmail(domain) {
		return "DISPOSABLE"
	}

	// Check for common business patterns
	if v.isBusinessDomain(domain) {
		return "BUSINESS"
	}

	// Default to generic email type
	return "EMAIL"
}

// isBusinessDomain checks if the domain appears to be a business domain
func (v *Validator) isBusinessDomain(domain string) bool {
	// Common business indicators
	businessIndicators := []string{
		"corp", "company", "inc", "ltd", "llc", "group", "enterprise",
		"solutions", "services", "consulting", "tech", "software",
		"systems", "digital", "online", "web", "net", "org",
	}

	domainLower := strings.ToLower(domain)

	// Check if domain contains business indicators
	for _, indicator := range businessIndicators {
		if strings.Contains(domainLower, indicator) {
			return true
		}
	}

	// Check for common business TLDs
	businessTLDs := []string{".biz", ".co", ".inc", ".corp", ".company"}
	for _, tld := range businessTLDs {
		if strings.HasSuffix(domainLower, tld) {
			return true
		}
	}

	// If it's not a well-known consumer provider and has a reasonable structure, likely business
	parts := strings.Split(domain, ".")
	if len(parts) >= 2 && len(parts[0]) > 3 && !v.isConsumerProvider(domain) {
		return true
	}

	return false
}

// isConsumerProvider checks if the domain is a known consumer email provider
func (v *Validator) isConsumerProvider(domain string) bool {
	consumerProviders := []string{
		"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
		"icloud.com", "protonmail.com", "tutanota.com", "fastmail.com",
		"zoho.com", "yandex.com", "mail.ru", "live.com", "msn.com",
	}

	domainLower := strings.ToLower(domain)
	for _, provider := range consumerProviders {
		if domainLower == provider {
			return true
		}
	}
	return false
}

// isDisposableEmail checks if the domain is a known disposable/temporary email service
func (v *Validator) isDisposableEmail(domain string) bool {
	disposableProviders := []string{
		"10minutemail.com", "guerrillamail.com", "mailinator.com", "tempmail.org",
		"temp-mail.org", "throwaway.email", "maildrop.cc", "sharklasers.com",
		"guerrillamailblock.com", "pokemail.net", "spam4.me", "tempail.com",
		"20minutemail.it", "emailondeck.com", "fakeinbox.com", "getnada.com",
		"harakirimail.com", "incognitomail.org", "jetable.org", "mailcatch.com",
		"mailnesia.com", "mytrashmail.com", "no-spam.ws", "nowmymail.com",
		"objectmail.com", "oneoffmail.com", "pookmail.com", "quickinbox.com",
		"rcpt.at", "rtrtr.com", "sendspamhere.com", "tempemail.com",
		"tempinbox.com", "tempmailo.com", "tempmailaddress.com", "trashmail.at",
		"trashmail.com", "trashmail.de", "trashmail.me", "trashmail.net",
		"wegwerfmail.de", "wegwerfmail.net", "wegwerfmail.org", "yopmail.com",
	}

	domainLower := strings.ToLower(domain)
	for _, provider := range disposableProviders {
		if domainLower == provider {
			return true
		}
	}
	return false
}

// Helper methods

// hasValidDomainStart checks if the domain starts with an alphanumeric character (RFC compliant)
// This prevents domains starting with hyphens like "-.hF" which are invalid
func (v *Validator) hasValidDomainStart(email string) bool {
	atIndex := strings.Index(email, "@")
	if atIndex == -1 || atIndex+1 >= len(email) {
		return false
	}

	// Check if character after @ is alphanumeric (not hyphen or other invalid chars)
	char := email[atIndex+1]
	return (char >= 'A' && char <= 'Z') ||
		(char >= 'a' && char <= 'z') ||
		(char >= '0' && char <= '9')
}

func (v *Validator) isValidEmailFormat(email string) bool {
	// More strict validation than the initial regex
	if len(email) == 0 || len(email) > 254 {
		return false
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}

	username := parts[0]
	domain := parts[1]

	// Username checks
	if len(username) == 0 || len(username) > 64 {
		return false
	}

	// Domain checks
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}

	// Check for valid characters
	if !validCharsPattern.MatchString(username) {
		return false
	}

	if !validDomainPattern.MatchString(domain) {
		return false
	}

	return true
}

func (v *Validator) isTestDomain(domain string) bool {
	for _, testDomain := range v.testDomains {
		if domain == testDomain {
			return true
		}
	}
	// Non-routable / reserved pseudo-TLD suffixes (RFC 2606/6761) are dev-only
	// and not real deliverable addresses (L8): treat them as test domains so
	// user@host.local / .localhost / .test / .invalid don't surface at HIGH.
	for _, suffix := range []string{".local", ".localhost", ".test", ".invalid", ".example"} {
		if strings.HasSuffix(domain, suffix) {
			return true
		}
	}
	return false
}

func (v *Validator) isTestUsername(username string) bool {
	for _, testUsername := range v.testUsernames {
		if username == testUsername {
			return true
		}
	}
	return false
}

func (v *Validator) hasValidTLD(domain string) bool {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}
	tld := strings.ToLower(parts[len(parts)-1])
	_, ok := ianaTLDs[tld]
	return ok
}

func (v *Validator) matchesBusinessPattern(email string) bool {
	lowerEmail := strings.ToLower(email)

	for _, pattern := range v.businessPatterns {
		if strings.Contains(lowerEmail, pattern) {
			return true
		}
	}

	// Check for firstname.lastname pattern
	parts := strings.Split(email, "@")
	if len(parts) == 2 {
		username := parts[0]
		if strings.Contains(username, ".") && !strings.HasPrefix(username, ".") && !strings.HasSuffix(username, ".") {
			return true
		}
	}

	return false
}

// isTabularData checks if the email appears to be in a tabular format
func (v *Validator) isTabularData(line, match string) bool {
	// Check for common tabular delimiters
	tabCount := strings.Count(line, "\t")
	commaCount := strings.Count(line, ",")
	semicolonCount := strings.Count(line, ";")
	pipeCount := strings.Count(line, "|")

	// If line has common delimiters, likely tabular
	if tabCount > 0 || commaCount >= 2 || semicolonCount >= 2 || pipeCount >= 2 {
		return true
	}

	// Check for multiple consecutive spaces (common in fixed-width tabular data)
	if len(emailMultiSpacePattern.FindAllString(line, -1)) >= 2 {
		return true
	}

	// Check for common email list patterns (names followed by emails)
	if nameEmailPattern.MatchString(line) {
		return true
	}

	return false
}

// hasURLStructureAfter checks if the match is actually a URL/URI, not an email,
// from the text that immediately follows the match. Taking afterMatch directly
// (rather than re-running strings.Index on the line) ensures the correct
// occurrence is analyzed when the same email text appears more than once.
func hasURLStructureAfter(afterMatch string) bool {
	if len(afterMatch) == 0 {
		return false
	}

	// URL/URI structural indicators (protocol-agnostic)
	// These patterns indicate a URL/URI, not an email:

	// 2. Protocol separator: user@host://
	//    Examples: sftp://user@host://path
	if strings.HasPrefix(afterMatch, "://") {
		return true
	}

	// 1 & 3. A ':' or '/' after the domain is URL/URI structure ONLY when
	// something non-blank follows it, because that something is the port, path or
	// ref the separator introduces: git@github.com:user/repo, user@host:22,
	// postgres://user@host:5432/db, user@server/share.
	//
	// The separator ALONE is not enough. A colon that ends a clause is ordinary
	// prose -- "Escalation owner schen@acmehealth.com: paged at 02:14 UTC" -- and
	// treating it as a URL returned -100, zeroing the confidence and deleting a
	// real business email. That is a leak rather than a scoring nit: only reported
	// findings are handed to the redactor, and a file with no findings has no
	// redacted output written at all, so the address survived in cleartext.
	//
	// The distinction is structural, not a word list: a URI never puts whitespace
	// between the separator and what it introduces, and prose always does (or ends
	// the line). Verified on 15 URI/SCM/registry forms and 15 prose forms, half of
	// each written as a held-out set after the rule: 15/15 and 15/15.
	//
	// An immediately-adjacent separator with no space stays URL structure, which
	// keeps the conservative reading for genuinely ambiguous input like
	// "owner@host:paged".
	if afterMatch[0] == ':' || afterMatch[0] == '/' || afterMatch[0] == '\\' {
		rest := afterMatch[1:]
		if rest == "" {
			return false // separator at end of line: prose, not a URI
		}
		switch rest[0] {
		case ' ', '\t', '\r', '\n':
			return false // separator then whitespace: prose punctuation
		}
		return true
	}

	// 4. Double-at pattern: user@@host (some protocols)
	if afterMatch[0] == '@' {
		return true
	}

	// Email structural indicators (what we expect for real emails)
	// If none of the URL patterns match, check for email-like structure

	// Emails typically followed by: whitespace, punctuation, or end of line
	emailTerminators := []byte{' ', '\t', '\n', '\r', ',', ';', ')', ']', '}', '>', '.', '!', '?'}
	for _, terminator := range emailTerminators {
		if afterMatch[0] == terminator {
			return false // Looks like an email
		}
	}

	// If we get here, the structure is ambiguous
	// Default to false (assume email) to avoid false negatives
	return false
}

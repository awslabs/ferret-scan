// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package email

import (
	stdctx "context"
	"os"
	"regexp"
	"strings"

	"github.com/awslabs/ferret-scan/internal/detector"
	"github.com/awslabs/ferret-scan/internal/execguard"
	"github.com/awslabs/ferret-scan/internal/observability"
)

// containsKeyword reports whether text contains keyword as a whole word/phrase,
// case-insensitively. The previous code used strings.Contains, so short negative
// keywords matched inside ordinary words — "bar" in "barack", "baz" in "bazaar",
// "temp" in "temptation" — suppressing real emails (and short positives like
// "to"/"info" spuriously boosting). Implemented as a plain string scan (a word
// byte is [a-z0-9]) rather than a per-keyword regex to keep context analysis
// cheap in the hot path.
func containsKeyword(text, keyword string) bool {
	return containsKeywordLower(strings.ToLower(text), strings.ToLower(keyword))
}

// containsKeywordLower is containsKeyword for callers that have already
// lowercased both arguments. The whole-word scan is identical; only the
// redundant strings.ToLower allocations are skipped. Hoisting the lowercasing
// out of the hot path matters because the previous code re-lowercased the
// (potentially huge) line text once per keyword per match.
func containsKeywordLower(lt, lk string) bool {
	if lk == "" {
		return false
	}
	for from := 0; from+len(lk) <= len(lt); {
		i := strings.Index(lt[from:], lk)
		if i < 0 {
			return false
		}
		i += from
		leftOK := i == 0 || !isEmailWordByte(lt[i-1])
		right := i + len(lk)
		rightOK := right >= len(lt) || !isEmailWordByte(lt[right])
		if leftOK && rightOK {
			return true
		}
		from = i + 1
	}
	return false
}

// isEmailWordByte reports whether b is a word character ([a-z0-9]) for keyword
// boundary detection. text is already lowercased by the caller.
func isEmailWordByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
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
	observer *observability.StandardObserver
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
func (v *Validator) SetObserver(observer *observability.StandardObserver) {
	v.observer = observer
}

// Validate implements the detector.Validator interface
func (v *Validator) Validate(filePath string) ([]detector.Match, error) {
	var finishTiming func(bool, map[string]interface{})
	var finishStep func(bool, string)
	if v.observer != nil {
		finishTiming = v.observer.StartTiming("email_validator", "validate_file", filePath)
		if v.observer.DebugObserver != nil {
			finishStep = v.observer.DebugObserver.StartStep("email_validator", "validate_file", filePath)
		}
	}

	// Email validator should not process files directly - only preprocessed content
	// Return empty results to avoid processing file system data
	if finishTiming != nil {
		finishTiming(true, map[string]interface{}{"match_count": 0, "direct_file_processing": false})
	}
	if finishStep != nil {
		finishStep(true, "Email validator only processes preprocessed content")
	}
	return []detector.Match{}, nil
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
func containsKeywordCrossing(s, lk string, accept func(start, end int) bool) bool {
	if lk == "" {
		return false
	}
	for from := 0; from+len(lk) <= len(s); {
		i := strings.Index(s[from:], lk)
		if i < 0 {
			return false
		}
		i += from
		leftOK := i == 0 || !isEmailWordByte(s[i-1])
		right := i + len(lk)
		rightOK := right >= len(s) || !isEmailWordByte(s[right])
		if leftOK && rightOK && accept(i, right) {
			return true
		}
		from = i + 1
	}
	return false
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
	// Complete IANA TLD list - updated December 2024
	// Source: https://www.iana.org/domains/root/db
	validTLDs := map[string]bool{
		// Generic TLDs (gTLDs) - Original
		"com": true, "org": true, "net": true, "edu": true, "gov": true,
		"mil": true, "int": true, "arpa": true,

		// Sponsored TLDs
		"aero": true, "asia": true, "biz": true, "cat": true, "coop": true,
		"info": true, "jobs": true, "mobi": true, "museum": true, "name": true,
		"post": true, "tel": true, "travel": true, "xxx": true,

		// New Generic TLDs (nTLDs) - Major ones
		"academy": true, "accountant": true, "accountants": true, "actor": true, "adult": true,
		"africa": true, "agency": true, "airforce": true, "amsterdam": true, "app": true,
		"art": true, "attorney": true, "auction": true, "audio": true, "auto": true,
		"baby": true, "band": true, "bank": true, "bar": true, "bargains": true,
		"beauty": true, "beer": true, "best": true, "bet": true, "bible": true,
		"bike": true, "bingo": true, "bio": true, "black": true, "blog": true,
		"blue": true, "boat": true, "book": true, "boutique": true, "box": true,
		"broker": true, "build": true, "business": true, "buy": true, "buzz": true,
		"cafe": true, "cam": true, "camera": true, "camp": true, "capital": true,
		"car": true, "cards": true, "care": true, "career": true, "careers": true,
		"cars": true, "casa": true, "cash": true, "casino": true, "catering": true,
		"center": true, "ceo": true, "charity": true, "chat": true,
		"cheap": true, "church": true, "city": true, "claims": true, "cleaning": true,
		"click": true, "clinic": true, "clothing": true, "cloud": true, "club": true,
		"coach": true, "codes": true, "coffee": true, "college": true, "community": true,
		"company": true, "computer": true, "condos": true, "construction": true, "consulting": true,
		"contact": true, "contractors": true, "cooking": true, "cool": true, "country": true,
		"coupons": true, "courses": true, "credit": true, "creditcard": true, "cruise": true,
		"crypto": true, "dance": true, "data": true, "date": true, "dating": true,
		"deals": true, "degree": true, "delivery": true, "democrat": true, "dental": true,
		"dentist": true, "design": true, "dev": true, "diamonds": true, "diet": true,
		"digital": true, "direct": true, "directory": true, "discount": true, "doctor": true,
		"dog": true, "domains": true, "download": true, "earth": true, "eat": true,
		"education": true, "email": true, "energy": true, "engineer": true, "engineering": true,
		"enterprises": true, "equipment": true, "estate": true, "events": true, "exchange": true,
		"expert": true, "exposed": true, "express": true, "fail": true, "faith": true,
		"family": true, "fan": true, "fans": true, "farm": true, "fashion": true,
		"fast": true, "feedback": true, "film": true, "finance": true, "financial": true,
		"fire": true, "fish": true, "fishing": true, "fit": true, "fitness": true,
		"flights": true, "florist": true, "flowers": true, "fly": true, "foo": true,
		"food": true, "football": true, "forex": true, "forum": true, "foundation": true,
		"free": true, "fun": true, "fund": true, "furniture": true, "futbol": true,
		"fyi": true, "gallery": true, "game": true, "games": true, "garden": true,
		"gay": true, "gift": true, "gifts": true, "gives": true, "glass": true,
		"global": true, "gmbh": true, "gold": true, "golf": true, "graphics": true,
		"gratis": true, "green": true, "gripe": true, "group": true, "guide": true,
		"guru": true, "hair": true, "hamburg": true, "health": true, "healthcare": true,
		"help": true, "hiphop": true, "hiv": true, "hockey": true, "holdings": true,
		"holiday": true, "home": true, "horse": true, "hospital": true, "host": true,
		"hosting": true, "hotel": true, "hotmail": true, "house": true, "how": true,
		"ice": true, "immo": true, "immobilien": true, "inc": true, "industries": true,
		"ink": true, "institute": true, "insurance": true, "insure": true, "international": true,
		"investments": true, "irish": true, "jetzt": true, "jewelry": true,
		"juegos": true, "kaufen": true, "kim": true, "kitchen": true, "kiwi": true,
		"land": true, "lat": true, "law": true, "lawyer": true, "lease": true,
		"legal": true, "lgbt": true, "life": true, "lighting": true, "limited": true,
		"limo": true, "link": true, "live": true, "loan": true, "loans": true,
		"lol": true, "london": true, "love": true, "ltd": true, "luxury": true,
		"makeup": true, "management": true, "market": true, "marketing": true, "markets": true,
		"mba": true, "media": true, "medical": true, "meet": true,
		"meme": true, "memorial": true, "men": true, "menu": true, "miami": true,
		"mobile": true, "moda": true, "moe": true, "mom": true, "money": true,
		"mortgage": true, "movie": true, "music": true, "navy": true, "network": true,
		"new": true, "news": true, "ngo": true, "ninja": true, "now": true,
		"nyc": true, "observer": true, "office": true, "one": true, "online": true,
		"ooo": true, "organic": true, "page": true, "paris": true, "partners": true,
		"parts": true, "party": true, "pay": true, "pet": true, "pharmacy": true,
		"photo": true, "photography": true, "photos": true, "pics": true, "pictures": true,
		"pink": true, "pizza": true, "place": true, "play": true, "plus": true,
		"poker": true, "porn": true, "press": true, "productions": true,
		"properties": true, "property": true, "protection": true, "pub": true, "public": true,
		"racing": true, "radio": true, "realestate": true, "recipes": true, "red": true,
		"rehab": true, "rent": true, "rentals": true, "repair": true, "report": true,
		"republican": true, "rest": true, "restaurant": true, "review": true, "reviews": true,
		"rich": true, "rip": true, "rocks": true, "rodeo": true, "run": true,
		"safe": true, "sale": true, "salon": true, "save": true, "school": true,
		"science": true, "search": true, "security": true, "select": true, "services": true,
		"sex": true, "sexy": true, "share": true, "shop": true, "shopping": true,
		"show": true, "singles": true, "site": true, "ski": true, "skin": true,
		"sky": true, "social": true, "software": true, "solar": true, "solutions": true,
		"space": true, "sport": true, "sports": true, "spot": true, "store": true,
		"stream": true, "studio": true, "study": true, "style": true, "sucks": true,
		"supplies": true, "supply": true, "support": true, "surf": true, "surgery": true,
		"systems": true, "tax": true, "taxi": true, "team": true, "tech": true,
		"technology": true, "tennis": true, "theater": true, "theatre": true, "tips": true,
		"tires": true, "today": true, "tools": true, "top": true, "tours": true,
		"town": true, "toys": true, "trade": true, "trading": true, "training": true,
		"tube": true, "university": true, "uno": true, "vacations": true,
		"vegas": true, "ventures": true, "vet": true, "video": true, "vip": true,
		"vision": true, "vote": true, "voto": true, "voyage": true, "watch": true,
		"web": true, "webcam": true, "website": true, "wedding": true, "wiki": true,
		"win": true, "wine": true, "work": true, "works": true, "world": true,
		"wtf": true, "xyz": true, "yoga": true, "zone": true,

		// Country Code TLDs (ccTLDs) - All 249 official ones
		"ac": true, "ad": true, "ae": true, "af": true, "ag": true, "ai": true,
		"al": true, "am": true, "ao": true, "aq": true, "ar": true, "as": true,
		"at": true, "au": true, "aw": true, "ax": true, "az": true, "ba": true,
		"bb": true, "bd": true, "be": true, "bf": true, "bg": true, "bh": true,
		"bi": true, "bj": true, "bl": true, "bm": true, "bn": true, "bo": true,
		"bq": true, "br": true, "bs": true, "bt": true, "bv": true, "bw": true,
		"by": true, "bz": true, "ca": true, "cc": true, "cd": true, "cf": true,
		"cg": true, "ch": true, "ci": true, "ck": true, "cl": true, "cm": true,
		"cn": true, "co": true, "cr": true, "cu": true, "cv": true, "cw": true,
		"cx": true, "cy": true, "cz": true, "de": true, "dj": true, "dk": true,
		"dm": true, "do": true, "dz": true, "ec": true, "ee": true, "eg": true,
		"eh": true, "er": true, "es": true, "et": true, "eu": true, "fi": true,
		"fj": true, "fk": true, "fm": true, "fo": true, "fr": true, "ga": true,
		"gb": true, "gd": true, "ge": true, "gf": true, "gg": true, "gh": true,
		"gi": true, "gl": true, "gm": true, "gn": true, "gp": true, "gq": true,
		"gr": true, "gs": true, "gt": true, "gu": true, "gw": true, "gy": true,
		"hk": true, "hm": true, "hn": true, "hr": true, "ht": true, "hu": true,
		"id": true, "ie": true, "il": true, "im": true, "in": true, "io": true,
		"iq": true, "ir": true, "is": true, "it": true, "je": true, "jm": true,
		"jo": true, "jp": true, "ke": true, "kg": true, "kh": true, "ki": true,
		"km": true, "kn": true, "kp": true, "kr": true, "kw": true, "ky": true,
		"kz": true, "la": true, "lb": true, "lc": true, "li": true, "lk": true,
		"lr": true, "ls": true, "lt": true, "lu": true, "lv": true, "ly": true,
		"ma": true, "mc": true, "md": true, "me": true, "mf": true, "mg": true,
		"mh": true, "mk": true, "ml": true, "mm": true, "mn": true, "mo": true,
		"mp": true, "mq": true, "mr": true, "ms": true, "mt": true, "mu": true,
		"mv": true, "mw": true, "mx": true, "my": true, "mz": true, "na": true,
		"nc": true, "ne": true, "nf": true, "ng": true, "ni": true, "nl": true,
		"no": true, "np": true, "nr": true, "nu": true, "nz": true, "om": true,
		"pa": true, "pe": true, "pf": true, "pg": true, "ph": true, "pk": true,
		"pl": true, "pm": true, "pn": true, "pr": true, "ps": true, "pt": true,
		"pw": true, "py": true, "qa": true, "re": true, "ro": true, "rs": true,
		"ru": true, "rw": true, "sa": true, "sb": true, "sc": true, "sd": true,
		"se": true, "sg": true, "sh": true, "si": true, "sj": true, "sk": true,
		"sl": true, "sm": true, "sn": true, "so": true, "sr": true, "ss": true,
		"st": true, "su": true, "sv": true, "sx": true, "sy": true, "sz": true,
		"tc": true, "td": true, "tf": true, "tg": true, "th": true, "tj": true,
		"tk": true, "tl": true, "tm": true, "tn": true, "to": true, "tr": true,
		"tt": true, "tv": true, "tw": true, "tz": true, "ua": true, "ug": true,
		"uk": true, "um": true, "us": true, "uy": true, "uz": true, "va": true,
		"vc": true, "ve": true, "vg": true, "vi": true, "vn": true, "vu": true,
		"wf": true, "ws": true, "ye": true, "yt": true, "za": true, "zm": true,
		"zw": true,

		// NOTE: the pseudo-TLDs "local", "localhost" and "test" are deliberately
		// NOT in this set (L8). They are dev/non-routable suffixes (k8s manifests,
		// /etc/hosts, .env files) and treating them as valid TLDs let
		// user@host.local surface at HIGH. Excluding them routes such addresses
		// through the small unknown-TLD penalty instead of full TLD validity.
	}

	parts := strings.Split(domain, ".")
	if len(parts) == 0 {
		return false
	}

	tld := strings.ToLower(parts[len(parts)-1])

	// Only accept TLDs from our comprehensive real TLD list
	// This eliminates fake TLDs like .JiMH, .cNU, .hF from random data
	return validTLDs[tld]
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

// isDebugEnabled checks if debug mode is enabled
func (v *Validator) isDebugEnabled() bool {
	return os.Getenv("FERRET_DEBUG") != ""
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

	// 1. Colon after domain: user@host:anything
	//    Examples: git@github.com:user/repo, user@host:22, postgres://user@host:5432
	//    Emails NEVER have colons immediately after the domain
	if afterMatch[0] == ':' {
		return true
	}

	// 2. Protocol separator: user@host://
	//    Examples: sftp://user@host://path
	if strings.HasPrefix(afterMatch, "://") {
		return true
	}

	// 3. Path separator immediately after: user@host/path
	//    Examples: user@server/share, registry.io/user@image
	if afterMatch[0] == '/' || afterMatch[0] == '\\' {
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

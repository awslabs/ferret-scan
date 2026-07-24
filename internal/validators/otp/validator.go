// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package otp

import (
	stdctx "context"
	"regexp"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/execguard"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
)

// Pre-compiled regex patterns used across validator methods.
var (
	// otpauth:// URIs — provisioning URLs typically encoded in QR codes.
	// Matches otpauth://totp/... or otpauth://hotp/... with parameters.
	reOTPAuthURI = regexp.MustCompile(`\botpauth://(?:totp|hotp)/[^\s"'<>]+`)

	// Base32-encoded TOTP/HOTP secrets: 16-64 uppercase letters A-Z and digits 2-7
	// (the RFC 4648 base32 alphabet). Requires word boundaries and exactly 16-64 chars.
	// We match only uppercase; CalculateConfidence normalizes to upper for validation.
	reBase32Secret = regexp.MustCompile(`\b[A-Z2-7]{16,64}\b`)

	// Lowercase base32 secrets: same charset but lowercase. Some tools/configs emit
	// secrets in lowercase (e.g., "jbswy3dpehpk3pxp"). Matched separately and only
	// considered when positive OTP context is present on the line.
	reBase32SecretLower = regexp.MustCompile(`\b[a-z2-7]{16,64}\b`)

	// Recovery/backup codes: groups of 4-10 alphanumeric blocks separated by dashes
	// or spaces. We detect lines that have 2+ such blocks (a single block is too
	// ambiguous). The typical pattern is XXXX-XXXX-XXXX or XXXXXXXX XXXXXXXX.
	// This matches a sequence of 2-5 dash-separated alphanumeric blocks (4-10 chars each).
	reRecoveryCodeBlock = regexp.MustCompile(`\b[A-Za-z0-9]{4,10}(?:-[A-Za-z0-9]{4,10}){1,4}\b`)

	// Patterns to reject: UUIDs, hex hashes, license keys with specific formats.
	reUUID    = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	reHexHash = regexp.MustCompile(`\b[0-9a-fA-F]{32,}\b`)

	// Partial UUID: 8-4-4-4 hex groups (first 4 segments of a UUID without the final 12-char group).
	rePartialUUID = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}\b`)

	// Hex-only dash block: all blocks are purely hex characters [0-9a-fA-F].
	reHexDashBlock = regexp.MustCompile(`(?i)^[0-9a-f]+(?:-[0-9a-f]+)+$`)

	// AWS access key pattern: starts with AKIA/ASIA followed by 16 alphanum chars.
	reAWSKeyID = regexp.MustCompile(`\b(AKIA|ASIA)[A-Z0-9]{16}\b`)

	// JWT pattern to exclude "token" keyword false positives.
	reJWT = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
)

// containsKeyword reports whether text contains keyword as a whole word/phrase,
// case-insensitively. Implements word-boundary-aware matching rather than plain
// strings.Contains.
func containsKeyword(text, keyword string) bool {
	if keyword == "" {
		return false
	}
	lt := strings.ToLower(text)
	lk := strings.ToLower(keyword)
	for from := 0; from+len(lk) <= len(lt); {
		i := strings.Index(lt[from:], lk)
		if i < 0 {
			return false
		}
		i += from
		leftOK := i == 0 || !isWordByte(lt[i-1])
		right := i + len(lk)
		rightOK := right >= len(lt) || !isWordByte(lt[right])
		if leftOK && rightOK {
			return true
		}
		from = i + 1
	}
	return false
}

// isWordByte reports whether b is a word character ([a-z0-9_]) for boundary detection.
func isWordByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

// Validator implements the detector.Validator interface for detecting
// OTP-related secrets: otpauth URIs, TOTP/HOTP secret keys, and recovery codes.
type Validator struct {
	pattern          string
	positiveKeywords []string
	negativeKeywords []string
	regex            *regexp.Regexp
	observer         observability.Observer
}

// NewValidator creates and returns a new OTP Validator instance.
func NewValidator() *Validator {
	v := &Validator{
		pattern: `otpauth://|[A-Z2-7]{16,64}|[A-Za-z0-9]{4,10}(?:-[A-Za-z0-9]{4,10}){1,4}`,
		positiveKeywords: []string{
			"two-factor", "2fa", "mfa", "authenticator", "recovery code",
			"backup code", "totp", "hotp", "secret key", "otpauth",
			"google authenticator", "authy", "otp", "one-time",
			"multi-factor", "verification code", "secret", "seed",
			"provisioning", "enrollment", "setup key",
			// Common OTP phrasings the list missed. "-" is a word boundary in
			// containsKeyword, so the hyphenated "one-time" literal does NOT match
			// the space form "one time" (or "one-time password"); both variants and
			// "passcode"/"two-step"/"two step" are added explicitly.
			"passcode", "one time", "one-time password", "one time password",
			"two-step", "two step", "authentication code", "security code",
		},
		negativeKeywords: []string{
			"license", "activation", "product key", "serial", "uuid",
			"hash", "session", "jwt", "bearer", "certificate",
			"test", "example", "sample", "placeholder", "fake", "mock", "demo",
			"padding", "encoded", "base64",
		},
	}

	v.regex = regexp.MustCompile(v.pattern)

	return v
}

// SetObserver sets the observability component.
func (v *Validator) SetObserver(observer observability.Observer) {
	v.observer = observer
}

// ValidateContent validates preprocessed content for OTP secrets.
func (v *Validator) ValidateContent(content string, originalPath string) ([]detector.Match, error) {
	return v.ValidateContentCtx(stdctx.Background(), content, originalPath)
}

// otpLineContext holds the per-line invariants, computed ONCE per line.
// AnalyzeContext ignores its match argument and only tests keyword PRESENCE
// over BeforeText+FullLine+AfterText — and Before/After are slices of the
// line, so its result is identical for every match on the line. The original
// code recomputed it (plus hasPositive/hasNegativeContext and the
// buildContextInfo keyword scans) per match, which is O(matches × line
// length × keywords) — the single-long-line CPU-exhaustion DoS the other
// validators were already hardened against. See the timing regression test.
type otpLineContext struct {
	impact  float64
	posKW   []string
	negKW   []string
	hasPos  bool
	hasNeg  bool
	uriLocs [][]int
}

func (v *Validator) buildOTPLineContext(line string) otpLineContext {
	return otpLineContext{
		impact: v.AnalyzeContext("", detector.ContextInfo{FullLine: line}),
		posKW:  v.findKeywords(line, v.positiveKeywords),
		negKW:  v.findKeywords(line, v.negativeKeywords),
		hasPos: v.hasPositiveContext(line),
		hasNeg: v.hasNegativeContext(line),
	}
}

// contextInfoAt builds the ContextInfo for a match at a known byte offset,
// reusing the per-line keyword sets — no strings.Index re-scan, no per-match
// keyword sweep.
func (v *Validator) contextInfoAt(line string, start, length int, lc otpLineContext) detector.ContextInfo {
	ci := detector.ContextInfo{
		FullLine:         line,
		PositiveKeywords: lc.posKW,
		NegativeKeywords: lc.negKW,
	}
	from := start - 50
	if from < 0 {
		from = 0
	}
	to := start + length + 50
	if to > len(line) {
		to = len(line)
	}
	ci.BeforeText = line[from:start]
	ci.AfterText = line[start+length : to]
	return ci
}

// insideAnySpan reports whether [start,end) falls inside any span in locs
// (sorted by start, as FindAllStringIndex returns them).
func insideAnySpan(locs [][]int, start, end int) bool {
	for _, l := range locs {
		if l[0] > start {
			return false
		}
		if end <= l[1] {
			return true
		}
	}
	return false
}

// ValidateContentCtx is the context-aware form of ValidateContent, implementing
// cooperative cancellation via execguard.LineLoopCancelled.
func (v *Validator) ValidateContentCtx(ctx stdctx.Context, content string, originalPath string) ([]detector.Match, error) {
	var matches []detector.Match

	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		if execguard.LineLoopCancelled(ctx, lineNum) {
			return matches, ctx.Err()
		}

		lc := v.buildOTPLineContext(line)

		// emit scores one candidate at a known offset and appends it if it
		// survives clamping. Confidence math is identical to the original
		// per-match path; only the redundant per-match line scans are gone.
		emit := func(start, length int, matchType string, applyNegative bool) {
			text := line[start : start+length]
			confidence, checks := v.CalculateConfidence(text)
			confidence += lc.impact
			if applyNegative && lc.hasNeg {
				confidence -= 30
			}
			confidence = v.clampConfidence(confidence)
			if confidence <= 0 {
				return
			}
			matches = append(matches, detector.Match{
				Text:       text,
				LineNumber: lineNum + 1,
				Type:       matchType,
				Confidence: confidence,
				Filename:   originalPath,
				Validator:  "otp",
				Context:    v.contextInfoAt(line, start, length, lc),
				Metadata: map[string]any{
					"validation_checks": checks,
					"context_impact":    lc.impact,
					"source":            "preprocessed_content",
					"original_file":     originalPath,
				},
			})
		}

		// Check for otpauth:// URIs
		lc.uriLocs = reOTPAuthURI.FindAllStringIndex(line, -1)
		for i, loc := range lc.uriLocs {
			if execguard.LineLoopCancelled(ctx, i) {
				return matches, ctx.Err()
			}
			emit(loc[0], loc[1]-loc[0], "OTPAUTH_URI", false)
		}

		// Check for base32 secrets (only with context keywords — a bare
		// base32 string is far too ambiguous on its own).
		if lc.hasPos {
			for i, loc := range reBase32Secret.FindAllStringIndex(line, -1) {
				if execguard.LineLoopCancelled(ctx, i) {
					return matches, ctx.Err()
				}
				secret := line[loc[0]:loc[1]]

				// Skip if inside an otpauth URI on this line (its secret= param)
				if insideAnySpan(lc.uriLocs, loc[0], loc[1]) {
					continue
				}
				// Reject UUID / hex-hash / AWS-key shaped tokens
				if reUUID.MatchString(secret) || reHexHash.MatchString(secret) || reAWSKeyID.MatchString(secret) {
					continue
				}
				if !v.isValidBase32(secret) {
					continue
				}
				emit(loc[0], loc[1]-loc[0], "OTP_SECRET", true)
			}

			// Lowercase base32 secrets (some tools/configs emit lowercase).
			// Normalized to uppercase for validation; original text reported.
			for i, loc := range reBase32SecretLower.FindAllStringIndex(line, -1) {
				if execguard.LineLoopCancelled(ctx, i) {
					return matches, ctx.Err()
				}
				secret := line[loc[0]:loc[1]]

				if insideAnySpan(lc.uriLocs, loc[0], loc[1]) {
					continue
				}
				upper := strings.ToUpper(secret)
				if reUUID.MatchString(secret) || reHexHash.MatchString(secret) {
					continue
				}
				if !v.isValidBase32(upper) {
					continue
				}
				// Reject uppercased forms that look like English words/patterns
				if v.isLikelyWord(upper) {
					continue
				}
				emit(loc[0], loc[1]-loc[0], "OTP_SECRET", true)
			}
		}

		// Check for recovery/backup code blocks
		recoveryLocs := reRecoveryCodeBlock.FindAllStringIndex(line, -1)
		if len(recoveryLocs) >= 2 && v.hasRecoveryContext(line) {
			// Multiple recovery-code-shaped blocks on the same line with context
			for i, loc := range recoveryLocs {
				if execguard.LineLoopCancelled(ctx, i) {
					return matches, ctx.Err()
				}
				code := line[loc[0]:loc[1]]
				// Skip UUIDs, partial UUIDs, and hex-only dash blocks
				if reUUID.MatchString(code) || rePartialUUID.MatchString(code) || reHexDashBlock.MatchString(code) {
					continue
				}
				emit(loc[0], loc[1]-loc[0], "RECOVERY_CODES", true)
			}
		}
	}

	return matches, nil
}

// CalculateConfidence calculates the confidence score for a potential OTP match.
func (v *Validator) CalculateConfidence(match string) (float64, map[string]bool) {
	checks := map[string]bool{
		"format":       true,
		"not_excluded": true,
		"valid_chars":  true,
	}

	// otpauth:// URIs are high-confidence by nature — they are unambiguous.
	if strings.HasPrefix(match, "otpauth://") {
		confidence := 90.0
		// Validate URI structure
		if strings.Contains(match, "secret=") {
			confidence = 95.0
			checks["has_secret_param"] = true
		}
		return confidence, checks
	}

	// Base32 secret keys: moderate base confidence, needs context to lift.
	upper := strings.ToUpper(match)
	if v.isValidBase32(upper) {
		confidence := 55.0
		length := len(match)

		// Longer secrets are more likely to be real TOTP seeds (RFC 6238
		// recommends 20+ bytes = 32+ base32 chars).
		if length >= 32 {
			confidence += 10
		} else if length >= 20 {
			confidence += 5
		}

		// Penalize heavily if the string has patterns unlikely in a real secret.
		// Max context boost is +40, so we need penalty >= 45 to ensure these
		// never exceed confidence 50 even with maximum positive context.
		if v.isLikelyWord(upper) {
			confidence -= 50
			checks["not_excluded"] = false
		}

		return confidence, checks
	}

	// Recovery code blocks
	confidence := 50.0
	parts := strings.Split(match, "-")
	if len(parts) >= 3 {
		confidence += 10 // More blocks = more likely a recovery code
	}
	// Check for uniform block length (real recovery codes tend to have equal-length blocks)
	if v.hasUniformBlockLength(parts) {
		confidence += 10
	}

	return confidence, checks
}

// AnalyzeContext analyzes the context around a match and returns a confidence adjustment.
func (v *Validator) AnalyzeContext(match string, context detector.ContextInfo) float64 {
	var impact float64

	fullContext := strings.ToLower(context.BeforeText + " " + context.FullLine + " " + context.AfterText)

	// Check for JWT context — if this line contains a JWT, "token" is not an OTP keyword.
	isJWTContext := reJWT.MatchString(context.FullLine)

	for _, keyword := range v.positiveKeywords {
		if containsKeyword(fullContext, keyword) {
			impact += 15
		}
	}

	for _, keyword := range v.negativeKeywords {
		if !negativeKeywordActive(keyword, isJWTContext) {
			continue
		}
		if containsKeyword(fullContext, keyword) {
			impact -= 15
		}
	}

	// Cap impact
	if impact > 40 {
		impact = 40
	} else if impact < -40 {
		impact = -40
	}

	return impact
}

// buildContextInfo constructs the ContextInfo for a match on a line.
func (v *Validator) buildContextInfo(line, match string) detector.ContextInfo {
	contextInfo := detector.ContextInfo{
		FullLine: line,
	}

	matchIndex := strings.Index(line, match)
	if matchIndex >= 0 {
		start := matchIndex - 50
		if start < 0 {
			start = 0
		}
		end := matchIndex + len(match) + 50
		if end > len(line) {
			end = len(line)
		}
		contextInfo.BeforeText = line[start:matchIndex]
		contextInfo.AfterText = line[matchIndex+len(match) : end]
	}

	contextInfo.PositiveKeywords = v.findKeywords(line, v.positiveKeywords)
	contextInfo.NegativeKeywords = v.findKeywords(line, v.negativeKeywords)

	return contextInfo
}

// findKeywords returns keywords found in the text.
func (v *Validator) findKeywords(text string, keywords []string) []string {
	var found []string
	for _, kw := range keywords {
		if containsKeyword(text, kw) {
			found = append(found, kw)
		}
	}
	return found
}

// hasPositiveContext checks if the line contains any positive OTP keywords.
func (v *Validator) hasPositiveContext(line string) bool {
	for _, kw := range v.positiveKeywords {
		if containsKeyword(line, kw) {
			return true
		}
	}
	return false
}

// negativeKeywordActive reports whether a negative keyword should count against
// an OTP candidate given the line's JWT context. "session" is a negative signal
// ONLY alongside a JWT (session tokens): on its own, a 2FA/TOTP setup line that
// merely mentions "session" is not evidence against an OTP secret. Both the
// per-keyword score (AnalyzeContext) and the presence gate (hasNegativeContext,
// which drives the -30 in emit) must apply this identically — otherwise the
// carve-out in one path is silently overridden by the -30 in the other.
func negativeKeywordActive(keyword string, isJWTContext bool) bool {
	if keyword == "session" && !isJWTContext {
		return false
	}
	return true
}

// hasNegativeContext checks if the line contains any active negative keyword,
// honoring the same JWT-aware carve-out AnalyzeContext uses (see
// negativeKeywordActive) so the emit-time -30 penalty cannot fire on a keyword
// that AnalyzeContext deliberately skipped.
//
// The JWT regex (reJWT) is the expensive check, and "session" is the ONLY
// keyword whose activeness depends on it, so we defer the JWT scan until we
// actually match "session" — on the common line (no session token) reJWT never
// runs. Every other negative keyword short-circuits the moment it matches.
func (v *Validator) hasNegativeContext(line string) bool {
	for _, kw := range v.negativeKeywords {
		if !containsKeyword(line, kw) {
			continue
		}
		if kw == "session" {
			// "session" only counts alongside a JWT (a session token); scan for
			// the JWT lazily, here, rather than once per line up front.
			if reJWT.MatchString(line) {
				return true
			}
			continue
		}
		return true
	}
	return false
}

// hasRecoveryContext checks if the line has keywords specific to recovery/backup codes
// AND does not have stronger non-recovery-code context that would suppress detection.
func (v *Validator) hasRecoveryContext(line string) bool {
	recoveryKeywords := []string{
		"recovery code", "backup code", "recovery codes", "backup codes",
		"recovery", "backup", "2fa", "mfa", "two-factor", "emergency",
	}
	hasPositive := false
	for _, kw := range recoveryKeywords {
		if containsKeyword(line, kw) {
			hasPositive = true
			break
		}
	}
	if !hasPositive {
		return false
	}

	// Suppress if the line has strong non-recovery-code indicators
	suppressionKeywords := []string{
		"product key", "product keys", "license", "activation", "serial",
		"version", "firmware", "patch", "release",
		"exit", "room", "door", "floor",
		// "device id" (a hardware identifier label) suppresses, but bare "device"
		// does NOT: real recovery codes are routinely described per device
		// ("recovery codes for this device"), and a lone "device" wrongly vetoed
		// them.
		"staff", "employee", "device id",
		"tracking", "order", "invoice",
		"disk", "contains key", "replacement",
	}
	for _, kw := range suppressionKeywords {
		if containsKeyword(line, kw) {
			return false
		}
	}
	return true
}

// isValidBase32 checks if the string is valid RFC 4648 base32 (A-Z, 2-7).
func (v *Validator) isValidBase32(s string) bool {
	if len(s) < 16 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7')) {
			return false
		}
	}
	return true
}

// isLikelyWord checks if a base32 string looks like it might be an English word,
// common abbreviation, placeholder, or patterned string rather than a random secret.
func (v *Validator) isLikelyWord(s string) bool {
	// Check for repeated characters (AAAAAAA...) which are unlikely to be real secrets
	if len(s) >= 8 {
		allSame := true
		for i := 1; i < len(s); i++ {
			if s[i] != s[0] {
				allSame = false
				break
			}
		}
		if allSame {
			return true
		}
	}

	// Check for simple repeating patterns of period 2 (ABABABAB)
	if len(s) >= 8 && len(s)%2 == 0 {
		pair := s[:2]
		repeating := true
		for i := 2; i < len(s); i += 2 {
			if s[i:i+2] != pair {
				repeating = false
				break
			}
		}
		if repeating {
			return true
		}
	}

	// Check for repeating patterns of period 3 or 4 (ABCABCABC..., ABCDABCDABCD...)
	for period := 3; period <= 4; period++ {
		if len(s) >= period*2 && len(s)%period == 0 {
			block := s[:period]
			repeating := true
			for i := period; i < len(s); i += period {
				if s[i:i+period] != block {
					repeating = false
					break
				}
			}
			if repeating {
				return true
			}
		}
	}

	// Check for sequential characters (ABCDEFGH...) — a string where each char
	// is within +1 of the previous in the base32 alphabet.
	if len(s) >= 16 && v.isSequentialBase32(s) {
		return true
	}

	// Check for alternating letter-digit patterns (A2B3C4D5...) which are
	// obviously patterned placeholders.
	if len(s) >= 16 && v.isAlternatingPattern(s) {
		return true
	}

	// Check for block-repetition (AAAABBBBCCCCDDDD): consecutive runs of 3+
	// of the same character covering most of the string.
	if len(s) >= 16 && v.hasBlockRepetition(s) {
		return true
	}

	// Check if the string is primarily composed of English dictionary substrings
	// (very coarse heuristic: if it contains a 6+ letter English-like substring).
	if v.containsLikelyEnglish(s) {
		return true
	}

	return false
}

// isSequentialBase32 checks whether the string follows a sequential pattern
// in the base32 alphabet (A-Z, 2-7).
func (v *Validator) isSequentialBase32(s string) bool {
	const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	sequential := 0
	for i := 1; i < len(s); i++ {
		prev := strings.IndexByte(base32Alphabet, s[i-1])
		curr := strings.IndexByte(base32Alphabet, s[i])
		if prev < 0 || curr < 0 {
			return false
		}
		diff := curr - prev
		if diff == 1 || diff == -1 {
			sequential++
		}
	}
	// If > 70% of transitions are sequential, it's patterned.
	return float64(sequential)/float64(len(s)-1) > 0.7
}

// isAlternatingPattern detects strings where characters alternate between two
// distinct classes (e.g., letter-digit-letter-digit: A2B3C4D5...) which are
// clearly placeholder/test values, not random secrets.
func (v *Validator) isAlternatingPattern(s string) bool {
	if len(s) < 16 {
		return false
	}
	// Check if even positions are all one class and odd positions are another
	evenLetters, evenDigits := 0, 0
	oddLetters, oddDigits := 0, 0
	for i, c := range s {
		isLetter := c >= 'A' && c <= 'Z'
		isDigit := c >= '2' && c <= '7'
		if !isLetter && !isDigit {
			return false
		}
		if i%2 == 0 {
			if isLetter {
				evenLetters++
			} else {
				evenDigits++
			}
		} else {
			if isLetter {
				oddLetters++
			} else {
				oddDigits++
			}
		}
	}
	half := len(s) / 2
	// Pattern: even=letters, odd=digits OR even=digits, odd=letters
	// Allow 80% threshold for slight deviations
	threshold := int(float64(half) * 0.8)
	if (evenLetters >= threshold && oddDigits >= threshold) ||
		(evenDigits >= threshold && oddLetters >= threshold) {
		return true
	}
	return false
}

// hasBlockRepetition detects patterns like AAAABBBBCCCCDDDD where there are
// consecutive runs of the same character of length >= 3, covering the majority of the string.
func (v *Validator) hasBlockRepetition(s string) bool {
	inBlock := 0
	i := 0
	for i < len(s) {
		j := i + 1
		for j < len(s) && s[j] == s[i] {
			j++
		}
		runLen := j - i
		if runLen >= 3 {
			inBlock += runLen
		}
		i = j
	}
	return float64(inBlock)/float64(len(s)) > 0.7
}

// containsLikelyEnglish checks if the string contains a common English word
// of 6+ characters that is entirely within the base32 alphabet (A-Z only).
func (v *Validator) containsLikelyEnglish(s string) bool {
	// Common English words that are valid base32 (only A-Z characters, 6+ chars)
	englishWords := []string{
		"DOCUMENT", "SECRET", "PRIVATE", "PUBLIC", "SERVER",
		"CLIENT", "ACCESS", "CHANGE", "DELETE", "CREATE",
		"UPDATE", "SELECT", "INSERT", "MASTER", "BACKUP",
		"RETURN", "EXPORT", "IMPORT", "SECURE",
	}
	upper := strings.ToUpper(s)
	for _, word := range englishWords {
		if strings.Contains(upper, word) {
			return true
		}
	}
	return false
}

// hasUniformBlockLength checks if all parts have the same length.
func (v *Validator) hasUniformBlockLength(parts []string) bool {
	if len(parts) < 2 {
		return false
	}
	length := len(parts[0])
	for _, p := range parts[1:] {
		if len(p) != length {
			return false
		}
	}
	return true
}

// clampConfidence ensures confidence stays within [0, 100].
func (v *Validator) clampConfidence(confidence float64) float64 {
	if confidence > 100 {
		return 100
	}
	if confidence < 0 {
		return 0
	}
	return confidence
}

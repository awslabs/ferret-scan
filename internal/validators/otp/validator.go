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
	"github.com/awslabs/ferret-scan/v2/internal/tabular"
	"github.com/awslabs/ferret-scan/v2/internal/validators/kwmatch"
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
	// secrets in lowercase (e.g., "k5cuwy3znrxw4z3t"). Matched separately and only
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

	// reOTPAuthSecretParam captures the secret= parameter of an otpauth:// URI, so
	// a URI carrying a published example secret can be recognized as the example
	// it is. Without this, suppressing the bare secret still left the enclosing
	// URI reported at 100 HIGH.
	reOTPAuthSecretParam = regexp.MustCompile(`(?i)[?&]secret=([A-Za-z2-7=]+)`)
)

// publishedSecretCeiling is the highest confidence a published test secret may
// carry — the top of LOW, matching phone's reservedFictionalCeiling and the cap
// creditcard applies to known test cards, so all three treat the same class of
// value alike.
const publishedSecretCeiling = 15.0

// publishedTestSecrets are shared secrets printed in specifications and vendor
// documentation, and therefore known to everyone.
//
// The reasoning differs from every other entry in this file. Elsewhere the
// question is "does this LOOK like a secret" — here the value provably is one,
// and is reported anyway because a secret published in an RFC and copied into
// every TOTP tutorial protects nothing. Even in the unlikely case that someone
// really provisioned one of these, disclosing it discloses nothing that was not
// already public, so there is nothing for a report to warn about and nothing for
// redaction to protect.
//
// Keys are uppercase, unpadded base32 — the canonical form equalBase32Fold
// compares against. A slice rather than a map so the scan order is fixed; at most
// one entry can match a given value, but a fixed order keeps that a property of
// the code rather than of Go's map iteration.
var publishedTestSecrets = []struct {
	key, source string
}{
	// RFC 6238 Appendix B test vector seed, ASCII "12345678901234567890".
	{"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "RFC 6238 Appendix B test vector"},
	// RFC 4226 Appendix D uses the same 20-byte ASCII seed for HOTP.
	{"GEZDGNBVGY3TQOJQ", "RFC 4226 / RFC 6238 test seed (first 10 bytes)"},
	// The secret in the Key Uri Format examples, reproduced in essentially every
	// authenticator tutorial and QR-code sample.
	{"JBSWY3DPEHPK3PXP", "otpauth Key Uri Format documentation example"},
}

// equalBase32Fold reports whether s is key, ignoring ASCII case and skipping the
// '=' padding base32 permits and the spaces or dashes humans add for readability.
//
// Allocation-free on purpose. The first version normalized s into a new string
// (strings.ToUpper over a strings.Replacer) before a map lookup, which ran for
// every candidate on every line: measured on a line of 800 base32 secrets that
// cost +127% bytes allocated and +19% wall time against main. Comparing in place
// removed all of it.
//
// Only those three characters are skipped, never "anything outside the base32
// alphabet" — that broader rule would fold "JBSWY3DPEHPK3PXP0" onto the published
// secret and demote a different value, which is exactly the over-reach a
// suppression must not have.
func equalBase32Fold(s, key string) bool {
	j := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '=' || c == ' ' || c == '-' {
			continue
		}
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		if j >= len(key) || c != key[j] {
			return false
		}
		j++
	}
	return j == len(key)
}

// publishedTestSecretFor returns the documentation source for an exact published
// secret, or false.
func publishedTestSecretFor(s string) (string, bool) {
	for _, p := range publishedTestSecrets {
		if equalBase32Fold(s, p.key) {
			return p.source, true
		}
	}
	return "", false
}

// publishedTestSecretIn reports the documentation source when text is, or
// carries, a published test secret.
//
// Handles both reported shapes: a bare secret (OTP_SECRET, whose Text is the
// secret) and a provisioning URI (OTPAUTH_URI, whose Text is the whole URI and
// whose secret sits in a query parameter).
// Both arms are length- and shape-gated first, so the common case — an ordinary
// secret or URI — costs two integer comparisons and one substring probe rather
// than a normalization (which allocates) plus a regex. emit runs this for every
// candidate on every line, and per-match line work is how this validator family
// became quadratic on dense input before.
func publishedTestSecretIn(text string) (string, bool) {
	// A bare secret. The keys are 16 and 32 characters; maxPublishedSecretLen
	// leaves room for '=' padding and readability separators, and anything longer
	// cannot normalize onto one.
	if len(text) >= minPublishedSecretLen && len(text) <= maxPublishedSecretLen {
		if src, ok := publishedTestSecretFor(text); ok {
			return src, true
		}
	}
	// A provisioning URI carrying one in its secret= parameter.
	if strings.Contains(text, "otpauth") {
		if m := reOTPAuthSecretParam.FindStringSubmatch(text); m != nil {
			if src, ok := publishedTestSecretFor(m[1]); ok {
				return src, true
			}
		}
	}
	return "", false
}

// Bounds on the raw length of a value that could normalize onto a
// publishedTestSecrets key. The shortest key is 16 characters; the longest is 32,
// and 48 leaves generous room for padding and space- or dash-grouping around it.
const (
	minPublishedSecretLen = 16
	maxPublishedSecretLen = 48
)

// containsKeyword reports whether text contains keyword as a whole word/phrase,
// case-insensitively.
//
// ModeAlnum treats '_' as a word boundary, so a keyword is found inside a
// snake_case identifier ("customer_ssn", "TEST_VALUE") exactly as it is
// between spaces. Code and config — where those identifiers dominate — are
// primary scan targets for this tool.
func containsKeyword(text, keyword string) bool {
	return kwmatch.Contains(text, keyword)
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
	// table and bounds resolve the header cell naming a match's own column.
	//
	// A base32 secret is admitted only with positive OTP context on the line, and in a
	// CSV export that context is the HEADER ROW, one or more lines above the value. So
	// a totp_secret column produced nothing while the identical value written inline as
	// "totp secret K5CUWY3ZNRXW4Z3T" scores 85 — and an unreported secret is never
	// redacted. Resolved per MATCH because the header varies along the row: folding the
	// row's headers together would let a totp_secret column vouch for a notes column.
	table  *tabular.Table
	bounds *tabular.LineBounds
	// headerPos is true when ANY column header carries OTP context, used for row
	// ADMISSION only; per-column standing is decided by columnHasPositiveContext.
	headerPos bool

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

// columnHasPositiveContext reports whether the header naming the column at byte offset
// off carries OTP context. Empty header (non-tabular, or the header row itself) is
// false, so a non-table document is unaffected.
func (v *Validator) columnHasPositiveContext(lc otpLineContext, off int) bool {
	if lc.table == nil || lc.bounds == nil {
		return false
	}
	h := lc.table.HeaderAt(lc.bounds, off)
	if h == "" {
		return false
	}
	return v.hasPositiveContext(h)
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

	// Conservative by construction (>=3 fields, consistent delimiter, word-like header
	// row), so a non-table document yields a nil table and behaviour is unchanged.
	// Analyzed ONCE per document.
	table := tabular.Analyze(content)

	for lineNum, line := range lines {
		if execguard.LineLoopCancelled(ctx, lineNum) {
			return matches, ctx.Err()
		}

		lc := v.buildOTPLineContext(line)
		if table.IsTable() && lineNum != table.HeaderLine() {
			lc.table = table
			lc.bounds = table.Bounds(line)
			for _, h := range table.Headers() {
				if v.hasPositiveContext(strings.ToLower(h)) {
					lc.headerPos = true
					break
				}
			}
		}

		// emit scores one candidate at a known offset and appends it if it
		// survives clamping. Confidence math is identical to the original
		// per-match path; only the redundant per-match line scans are gone.
		emit := func(start, length int, matchType string, applyNegative bool) {
			text := line[start : start+length]

			// A row admitted ONLY by its header row must carry the label in the
			// candidate's OWN column. Row-level admission is deliberately permissive so
			// candidates can be found at all; without this per-column requirement a
			// notes column's base32-shaped value would ride in on the totp_secret
			// column's header. The equivalent leak was measured in driverslicense,
			// where two routing_number values were reported as licences at 40.
			if !lc.hasPos && lc.headerPos && !v.columnHasPositiveContext(lc, start) {
				return
			}

			confidence, checks := v.CalculateConfidence(text)
			confidence += lc.impact
			if applyNegative && lc.hasNeg {
				confidence -= 30
			}
			confidence = v.clampConfidence(confidence)

			// Published-secret ceiling, applied AFTER context so context cannot
			// lift it. A secret printed in an RFC and copied into every
			// authenticator tutorial protects nothing, so it must not present as a
			// real credential: measured before this, "TOTP secret JBSWY3DPEHPK3PXP
			// for the authenticator app" scored 95 HIGH, the otpauth:// URI
			// carrying the same secret scored 100, and the RFC 6238 Appendix B seed
			// scored 100.
			//
			// Capped rather than dropped, for the reason spelled out in
			// phone/validator.go: only reported findings are redacted, and these
			// values are also what this repo's own fixtures and golden corpus use
			// to exercise OTP detection at all. A cap keeps that coverage and keeps
			// the redaction path, while making MEDIUM/HIGH unreachable.
			// Recorded in checks rather than as a new Metadata key so the flag
			// reaches --explain through the existing validation_checks channel
			// without adding a field to every OTP finding's output.
			if _, published := publishedTestSecretIn(text); published {
				checks["not_published_test_secret"] = false
				if confidence > publishedSecretCeiling {
					confidence = publishedSecretCeiling
				}
			}

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
		if lc.hasPos || lc.headerPos {
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

	// Offset of the earliest EXPLICIT recovery-code phrase, which is a stronger
	// signal than the bare topic mentions in recoveryKeywords.
	//
	// The distinction is load-bearing, and the adversarial suite is what proves
	// it: "2FA activated. Product keys: XXXX-YYYY-ZZZZ ...", "recovery disk
	// contains key: NKJFK-...", "emergency replacement devices: WXYZ-..." all put
	// a bare 2fa/recovery/emergency mention FIRST and the real label second. A
	// position rule keyed on those words alone reports every one of them as a
	// recovery code — which is precisely the false-positive class those tests
	// exist to prevent, and it is how the first version of this change failed.
	//
	// "recovery codes" / "backup codes" names the value itself, so only that
	// earns the positional treatment below.
	strongLabelAt := -1
	for _, kw := range []string{
		"recovery code", "recovery codes", "backup code", "backup codes",
	} {
		if i := keywordIndex(line, kw); i >= 0 && (strongLabelAt < 0 || i < strongLabelAt) {
			strongLabelAt = i
		}
	}

	// Suppress if the line has strong non-recovery-code indicators — but only
	// when such a word PRECEDES the recovery-code label.
	//
	// This used to suppress on the word appearing anywhere on the line, and every
	// one of these twenty words then deleted a labelled recovery-code line. Worse,
	// it deleted ALL codes on it at once: hasRecoveryContext gates the whole line,
	// so one ordinary word takes out every code present. Measured, with the
	// identical line minus the word reporting 2 findings:
	//
	//   "Recovery codes ABCD-... (license tier: enterprise)"   -> 0
	//   "Backup codes ABCD-... stored in room 402"             -> 0
	//   "Recovery codes ABCD-... issued to employee Chen"      -> 0
	//   "2FA recovery codes ABCD-... for the staff portal"     -> 0
	//   "Backup codes ABCD-... after the firmware update"      -> 0
	//
	// license tier, room number, employee name, staff portal, firmware update,
	// replacement set, disk image, tracking ticket — all ordinary things to write
	// on the same line as a recovery code, and because only reported findings are
	// handed to the redactor, every code stayed in cleartext.
	//
	// Position is the discriminator. In a genuine non-OTP line the word IS the
	// label and comes first ("Product key ABCD-...", "Serial number ABCD-...",
	// "Activation code ABCD-... for the license portal"). In a real recovery-code
	// line the recovery label leads and the other word trails. When there is no
	// recovery label at all the caller has already returned false, so the
	// conservative case is unchanged.
	//
	// Measured on 12 hand-written cases and 12 written afterwards as a held-out
	// set: 12/12 and 12/12. Same rule shape used for driverslicense and dob.
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
		i := keywordIndex(line, kw)
		if i < 0 {
			continue
		}
		// With no explicit "recovery codes" phrase the line has only a bare topic
		// mention, so keep the original line-global veto: the suppression word is
		// then the best evidence available about what the value actually is.
		if strongLabelAt < 0 {
			return false
		}
		// With an explicit phrase, suppress only when the other word LEADS it.
		if i < strongLabelAt {
			return false
		}
	}
	return true
}

// keywordIndex returns the byte offset of the first whole-word occurrence of
// keyword in text, or -1.
//
// It delegates to kwmatch.ContainsFunc rather than reimplementing the boundary
// rule, so it finds EXACTLY what containsKeyword finds. That equivalence is what
// makes the positional comparison in hasRecoveryContext sound: if one function
// saw a keyword the other missed, the offsets being compared would be
// meaningless.
//
// Reimplementing it was tried and was wrong. kwmatch treats "_" as a SEPARATOR
// (so "my_license_key" contains "license") while a hand-rolled word-character
// rule treats it as part of the word and misses it -- caught by
// TestKeywordIndexAgreesWithContainsKeyword, which compares the two directly.
func keywordIndex(text, keyword string) int {
	found := -1
	kwmatch.ContainsFunc(strings.ToLower(text), strings.ToLower(keyword),
		func(start, _ int) bool {
			found = start
			return true // accept the first match and stop
		})
	return found
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

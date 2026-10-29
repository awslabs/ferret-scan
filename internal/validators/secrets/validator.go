// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"bytes"
	stdctx "context"
	"encoding/base64"
	"math"
	"regexp"
	"regexp/syntax"
	"strings"
	"unicode/utf8"

	"github.com/awslabs/ferret-scan/v2/internal/context"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/execguard"
	"github.com/awslabs/ferret-scan/v2/internal/help"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/validators/kwmatch"
)

// Multi-line PEM-style secret patterns. Compiled once at package init —
// previously they were recompiled inside findMultiLineSecretsWithContext on
// every call, which is the per-file scan path. The string concatenations
// (`"-----" + "BEGIN"`) keep the literals from looking like real PEM markers
// to upstream secret scanners.
var (
	pemBeginMarker = "-----" + "BEGIN"
	pemEndMarker   = "-----" + "END"

	multiLineSSHPatterns = []*regexp.Regexp{
		regexp.MustCompile(pemBeginMarker + ` (RSA |DSA |EC |OPENSSH )?PRIVATE KEY` + "-----" + `[\s\S]*?` + pemEndMarker + ` (RSA |DSA |EC |OPENSSH )?PRIVATE KEY` + "-----"),
	}
	multiLineCertPatterns = []*regexp.Regexp{
		regexp.MustCompile(pemBeginMarker + ` CERTIFICATE` + "-----" + `[\s\S]*?` + pemEndMarker + ` CERTIFICATE` + "-----"),
		regexp.MustCompile(pemBeginMarker + ` ENCRYPTED PRIVATE KEY` + "-----" + `[\s\S]*?` + pemEndMarker + ` ENCRYPTED PRIVATE KEY` + "-----"),
	}
	multiLinePGPPatterns = []*regexp.Regexp{
		regexp.MustCompile(pemBeginMarker + ` PGP PRIVATE KEY BLOCK` + "-----" + `[\s\S]*?` + pemEndMarker + ` PGP PRIVATE KEY BLOCK` + "-----"),
	}
)

// candidate is a secret-shaped substring of a single line together with the
// byte span it occupies in that line. The span is what makes duplicate claims
// distinguishable from genuine repetition: several detection patterns hitting
// the same bytes is one secret, whereas the same value appearing twice on a
// line (`a = "AKIA…" and b = "AKIA…"`) is two, and detector.Match carries no
// offset to tell those apart after the fact.
type candidate struct {
	text  string
	start int
	end   int
	// gateable marks a candidate from the UNQUOTED-assignment family -- the unquoted and plural
	// unquoted patterns, the collection and list-tail paths, and block-sequence items. Only these
	// are subject to the lexical gate in expression-language files (#753, source_syntax.go). A
	// quoted pattern, a provider literal or an entropy hit is never gateable: quotes are the
	// author's statement that the bytes are a literal.
	gateable bool
}

// scopedCandidate is a candidate tagged with the detection path that produced
// it, so both single-line paths can be arbitrated in one pass while each keeps
// its own confidence threshold and reported detection_method.
type scopedCandidate struct {
	candidate
	method    string
	threshold float64
	// structural marks a candidate whose position in a grammar is its own corroboration: today a
	// password or token in URI user info (#766, uri_userinfo.go). It exempts the candidate from the
	// M24 cap, which exists for values nothing labels, and from nothing else.
	structural bool
	// ceiling, when positive, is a value-intrinsic upper bound published as ConfidenceCeilingKey,
	// combined with the other ceilings by taking the lowest. Set by uri_userinfo's LOW dispositions.
	ceiling float64
}

// spannedMatch is an emitted finding that still remembers the byte span of the
// line it came from, so same-span findings produced by different detection
// paths can be arbitrated before the span information is discarded (detector.
// Match has no offset field).
type spannedMatch struct {
	match detector.Match
	start int
	end   int
}

// genericSecretType is the label getSecretType falls back to when a value is
// secret-shaped but matches no provider signature. Any other type identifies
// what the secret actually is, which is strictly more useful to a reviewer.
const genericSecretType = "API_KEY_OR_SECRET"

// ConfidenceCeilingKey is the Match.Metadata key carrying a hard upper bound on a
// finding's confidence. The dual-path bridge reads it and clamps AFTER its context and
// cross-path adjustments — a ceiling applied only here would be undone by them, since a
// value scored 55 by this validator was reported at 80 in a real document once +20
// document context and +5 cross-path correlation had been added downstream.
//
// The literal is duplicated rather than imported to keep the dependency pointing one
// way (the bridge must not depend on a validator package). It is covered by a test that
// fails if the two drift apart.
const ConfidenceCeilingKey = "confidence_ceiling"

// unlabelledHexIdentifierCeiling keeps a bare hexadecimal value on a line that names
// nothing secret below the MEDIUM band, so it is reported as LOW.
//
// A ceiling and not a veto, deliberately. A 32-hex string genuinely can be a secret,
// and only reported findings reach the redactor — dropping one would leave the value
// in the "redacted" output, which is the failure mode this area keeps producing.
// Demoting keeps the row, keeps the redaction, and keeps it out of the band that
// drives blocking decisions.
const unlabelledHexIdentifierCeiling = 55.0

// bareHexIdentifier matches a value that is nothing but hex digits, at the lengths
// where identifiers live: 32 (GUID, MD5), 40 (SHA-1, git object), 64 (SHA-256).
// Shorter runs are too common to reason about; longer ones are rarer than the noise
// they would add.
var bareHexIdentifier = regexp.MustCompile(`^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$`)

// secretLabelWords are the words whose presence on a line means the value is being
// presented as a credential. Matched as substrings, and kept a superset of what
// containsSecretIndicators looks for, so the ceiling can never fire on a line that
// the indicator check would have called secret-labelled.
var secretLabelWords = []string{
	"key", "secret", "token", "password", "pass", "pwd", "auth",
	"credential", "private", "bearer", "jwt", "api", "signature", "hmac",
	"session", "cookie", "access", "refresh", "client_id", "clientid",
}

// unlabelledHexIdentifierCap returns the ceiling for a generic high-entropy finding
// whose value is a bare hex identifier on a line carrying no secret-ish label, or 0
// when no ceiling applies.
//
// The case that prompted it: an EXIF ImageUniqueID — `ImageUniqueID:
// "14f6364997257b9170c016a13d1f1127"` — is an image GUID, and it was reported as
// API_KEY_OR_SECRET at 80 in a real 10 MB .docx. It reaches the entropy path at all
// only because containsSecretIndicators admits any quoted value of 20+ bytes; no
// secret keyword is involved. Digests, ETags, commit ids and content hashes share the
// shape.
//
// The discriminator is the LINE'S LABEL read as a positive signal — the ceiling
// applies when nothing says "secret" — rather than a negative list of identifier
// field names. That direction is the point. A negative list would let an author
// suppress a REAL secret by writing `ImageUniqueID: "AKIA..."`, which is
// attacker-controlled suppression: the exact class of defect the surrounding changes
// have been removing. Here an author cannot trigger the ceiling by relabelling, since
// adding any secret-ish word only removes it. Measured on one 32-hex value:
// `api_key = "14f6..."` keeps 75, `ImageUniqueID: "14f6..."` becomes 55.
func unlabelledHexIdentifierCap(secretType, match, line string) float64 {
	if secretType != genericSecretType {
		return 0
	}
	if !bareHexIdentifier.MatchString(strings.ToLower(strings.Trim(match, `"'`))) {
		return 0
	}
	lower := strings.ToLower(line)
	for _, keyword := range secretLabelWords {
		if strings.Contains(lower, keyword) {
			return 0
		}
	}
	return unlabelledHexIdentifierCeiling
}

// awsDocPlaceholderCeiling is the highest confidence an AWS documentation
// placeholder credential may carry: 15, the top of LOW.
//
// 15 rather than a value of its own because three validators already agreed on it
// for the same class of value — creditcard's known test cards, phone's
// reservedFictionalCeiling (NANP 555-01xx) and otp's publishedSecretCeiling (the
// RFC 6238 seeds). Picking a fourth number would recreate the per-validator
// divergence #364 is about. Low enough that the CI filter this repo's own
// pre-commit hook uses (--confidence medium,high) never shows it; high enough that
// the finding still exists, so the value is still redacted.
const awsDocPlaceholderCeiling = 15.0

// awsDocPlaceholderMarker is the literal AWS embeds in the credential values it
// publishes in its documentation — AKIAIOSFODNN7EXAMPLE and
// wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY are the two canonical ones. Compared
// against the upper-cased value, matching the check this file already applied to
// the secret half.
const awsDocPlaceholderMarker = "EXAMPLE"

// awsDocPlaceholderCap returns the ceiling for an AWS credential whose OWN BYTES
// carry AWS's documentation-placeholder marker, or 0 when no ceiling applies.
//
// A ceiling and not a drop. Only reported findings reach the redactor, so dropping
// these would leave AKIAIOSFODNN7EXAMPLE in the cleartext of a "redacted"
// document — and it is a live finding in 39 of this repo's own golden files
// precisely because a reserved placeholder is the responsible value to commit.
// Nor is it standards-RESERVED: AKIAIOSFODNN7EXAMPLE sits inside the valid
// AKIA[0-9A-Z]{16} keyspace and no authority has withheld it from issue, so
// "cannot be real" is not available as a justification. Vendor documentation
// placeholder => demote; authority-withheld value => drop. See
// docs/proposals/CONFIDENCE_CONTRACT.md §7c.
//
// Restricted to the two AWS credential types on purpose, and this is the load-
// bearing part of the design. "Value contains EXAMPLE" is only safe where the
// attacker cannot put it there:
//
//   - AWS_ACCESS_KEY is a modeExact row of the provider grammar table
//     (provider_rules.go): the regex is the fixed window `AKIA[0-9A-Z]{16}` and
//     isAWSAccessKey is that same row anchored. The WINDOW is what carries the
//     argument, not the predicate: a real key with EXAMPLE appended is matched
//     as its first 20 bytes and the appended bytes are never in the matched
//     text, so the marker can only appear INSIDE a 20-char window, i.e. `AKIA`
//     + 9 free chars + `EXAMPLE`, which is a key AWS itself would have had to
//     issue in that shape. (An earlier version of this comment said the gate
//     "rejects a 27-char key outright"; it never saw one -- the window had
//     already cut it to 20. The conclusion was right, the reason was not, and
//     #769 measured both: AKIA + 16 + EXAMPLE reports the 20-byte window at
//     full confidence, uncapped, pinned by TestAKIAWindowPins.) This is why the
//     AWS row MUST stay modeExact: on a modeAtLeast row the appended marker
//     would be part of the match and the rule would be an evasion.
//   - AWS_SECRET_ACCESS_KEY is the 40-char capture of reAWSSecretCandidate, whose
//     trailing `($|[^A-Za-z0-9/+=])` means <real40>EXAMPLE yields no 40-char
//     window at all. The marker cannot coexist with a full real secret in one
//     capture.
//
// The generic API_KEY_OR_SECRET type is deliberately NOT included: it has no
// length gate, so `token = <real secret>EXAMPLE` would be attacker-controlled
// suppression — the failure mode unlabelledHexIdentifierCap's comment above
// describes. A documentation placeholder of a type this function does not name
// keeps its full confidence; that is the accepted side of the trade.

// clampToPublishedCeiling enforces a match's own ConfidenceCeilingKey at this
// validator's boundary, so the number it reports never exceeds the bound it publishes
// in the same metadata map.
//
// Deliberately duplicates what the dual-path bridge's clampToCeiling does, because the
// two guard different seams. The bridge's copy exists for the adjustments applied AFTER
// a validator returns (document context, cross-path correlation) and only runs on the
// bridge path. This copy exists for a raise applied INSIDE the validator
// (mergeBySpanKeepStrongest keeps the max confidence across detection paths) and runs
// for every caller, including pkg/redact and any embedder of ValidateContent.
//
// A clamp, never an assignment: it can only lower a score, so it can never resurrect a
// finding that scoring had already driven below a threshold. A non-positive or
// wrong-typed ceiling is ignored rather than treated as zero, matching the bridge —
// clamping to 0 would erase the confidence and could drop the finding from the report,
// which per the sink rule stops it being redacted.
func clampToPublishedCeiling(match *detector.Match) {
	ceiling, ok := match.Metadata[ConfidenceCeilingKey].(float64)
	if !ok || ceiling <= 0 {
		return
	}
	if match.Confidence > ceiling {
		match.Confidence = ceiling
	}
}

// TestProviderMarkerRuleOnlyOnExactRows (provider_rules_test.go) fails if the
// AWS_ACCESS_KEY row is ever moved to modeAtLeast: the paragraph above is the
// reason, and a test is what keeps a comment from becoming a wish.
func awsDocPlaceholderCap(secretType, match string) float64 {
	switch secretType {
	case "AWS_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY":
	default:
		return 0
	}
	if !strings.Contains(strings.ToUpper(strings.Trim(match, `"'`)), awsDocPlaceholderMarker) {
		return 0
	}
	return awsDocPlaceholderCeiling
}

// mergeBySpanKeepStrongest folds src into dst, treating findings that cover the
// identical byte span as one secret discovered twice: a quoted 40-char AWS
// secret is matched both by the context-gated AWS path (AWS_SECRET_ACCESS_KEY)
// and by the generic entropy path (API_KEY_OR_SECRET), and reporting both
// double-counts one leak.
//
// The survivor keeps the more specific type and the highest confidence either
// path assigned. Both are needed, and confidence alone is not enough to pick a
// winner: the entropy path's confidence is context-derived and routinely exceeds
// the AWS path's fixed 90, so ranking on confidence would discard the very label
// that says "this is an AWS secret key". Taking the maximum confidence also
// means a merge can never demote a finding into a lower severity band than it
// would have had before — the leak-safe direction.
//
// Ties keep the incumbent, so the outcome depends only on the order paths are
// merged in, never on map iteration order. A surviving finding stays at its
// original position, so byte order (and line numbering downstream) is stable.
func mergeBySpanKeepStrongest(dst, src []spannedMatch) []spannedMatch {
	if len(src) == 0 {
		return dst
	}
	type span struct{ start, end int }
	index := make(map[span]int, len(dst)+len(src))
	for i, m := range dst {
		index[span{m.start, m.end}] = i
	}
	for _, s := range src {
		key := span{s.start, s.end}
		i, exists := index[key]
		if !exists {
			index[key] = len(dst)
			dst = append(dst, s)
			continue
		}

		incumbentGeneric := dst[i].match.Type == genericSecretType
		challengerGeneric := s.match.Type == genericSecretType
		best := dst[i].match.Confidence
		if s.match.Confidence > best {
			best = s.match.Confidence
		}

		// Replace only when the challenger is more specific, or when neither is
		// generic and the challenger is strictly more confident. A generic
		// challenger never displaces a specific incumbent.
		if (incumbentGeneric && !challengerGeneric) ||
			(incumbentGeneric == challengerGeneric && s.match.Confidence > dst[i].match.Confidence) {
			dst[i] = s
		}
		dst[i].match.Confidence = best
	}
	return dst
}

// dedupeScopedBySpan collapses candidates that claim exactly the same bytes,
// keeping the first claim. Callers list the lower-threshold detection path
// first so that winning a tie can never drop a span the losing path would have
// reported. Order is preserved rather than sorted: the input is already in
// per-path byte order, and stable order keeps line numbers — and therefore
// suppression hashes — stable across runs.
//
// Overlapping-but-unequal spans are deliberately left alone. A shorter token
// nested in a longer one is a different question (which span is the real
// secret) from a literal double report of one span, and narrowing spans here
// would risk dropping a genuine distinct secret.
func dedupeScopedBySpan(cands []scopedCandidate) []scopedCandidate {
	if len(cands) < 2 {
		return cands
	}
	type span struct{ start, end int }
	seen := make(map[span]struct{}, len(cands))
	out := cands[:0:0] // fresh backing array: never alias the caller's slice
	for _, c := range cands {
		key := span{c.start, c.end}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, c)
	}
	return out
}

// Validator detects secrets using entropy analysis and keyword patterns
type Validator struct {
	// High entropy detection
	base64Charset string
	hexCharset    string
	base64Limit   float64
	hexLimit      float64

	// Keyword patterns
	keywordPatterns []*regexp.Regexp
	// unquotedPatterns match assignments whose value is NOT quoted; see
	// compileUnquotedPatterns for why they are separate.
	unquotedPatterns []*regexp.Regexp

	// The #746 sets, all ADDITIVE to the three above: a plural key name, and a key whose value
	// opens a bracketed collection. Kept as their own fields rather than appended to the sets
	// above so an existing finding's span -- and therefore its suppression hash -- cannot move.
	// See list_and_sequence.go.
	pluralUnquotedPatterns []*regexp.Regexp
	pluralQuotedPatterns   []*regexp.Regexp
	listOpenerPatterns     []*regexp.Regexp

	// Context keywords
	positiveKeywords []string
	negativeKeywords []string

	// Enhanced context analysis
	contextAnalyzer *context.ContextAnalyzer

	// Domain-specific keywords for enhanced validation
	devKeywords  []string
	prodKeywords []string
	testKeywords []string

	// Global test patterns database
	globalTestPatterns []string

	// Pre-compiled regex patterns for shell variable detection (performance optimization)
	shellCommandPattern *regexp.Regexp

	// Pre-compiled regex patterns for performance optimization
	base64Pattern     *regexp.Regexp
	hexPattern        *regexp.Regexp
	multiSpacePattern *regexp.Regexp
	configPattern     *regexp.Regexp
	variablePatterns  []*regexp.Regexp

	// Observability
	observer observability.Observer
}

// NewValidator creates a new secrets validator
func NewValidator() *Validator {
	v := &Validator{
		base64Charset: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\\-_",
		hexCharset:    "0123456789ABCDEFabcdef",
		base64Limit:   4.5,
		hexLimit:      3.0,

		keywordPatterns:  compileKeywordPatterns(),
		unquotedPatterns: compileUnquotedPatterns(),

		pluralUnquotedPatterns: compilePluralUnquotedPatterns(),
		pluralQuotedPatterns:   compilePluralQuotedPatterns(),
		listOpenerPatterns:     compileListOpenerPatterns(),

		// positiveKeywords corroborate that a nearby high-entropy string is a
		// credential (lifting it past the M24 generic-entropy cap). Matched by
		// lineHasKeyword with TOKEN boundaries (case-insensitive), so each word
		// matches its snake_case/kebab/camelCase forms ("token" hits
		// "authToken"/"AUTH_TOKEN"/"auth-token") but not incidental substrings
		// ("auth" no longer matches "author"). Because boundaries are enforced,
		// compound labels that a substring match used to catch for free must be
		// listed explicitly: "passphrase" and "connectionstring" are their own
		// tokens ("pass" does not match inside "passphrase").
		//
		// Deliberately EXCLUDES hash-scheme words ("hash"/"checksum"/"digest"/
		// "integrity"): those label the *protected*, non-reversible form, not a
		// credential, and treating them as positive turned every SBOM content
		// hash, SRI digest, and git SHA into a HIGH finding. A real password hash
		// still lifts on the "password"/"pass"/"pwd" token on its line, so
		// demoting the hash label loses no genuine credential — only bare
		// checksums, which fall to LOW.
		positiveKeywords: []string{
			"api", "key", "secret", "token", "password", "passwd", "pass", "pwd",
			"passphrase", "auth", "credential", "private", "access", "session",
			"bearer", "oauth", "jwt", "signature", "salt", "nonce", "seed",
			"entropy", "connectionstring",
		},

		negativeKeywords: []string{
			"test", "example", "demo", "sample", "fake", "mock", "dummy",
			"placeholder", "template", "default", "null", "empty", "none",
			"public", "open", "free", "guest", "anonymous", "debug",
		},

		// Initialize context analyzer
		contextAnalyzer: context.NewContextAnalyzer(),

		// Development/staging environment keywords
		// devKeywords are kept DISJOINT from testKeywords (M25): "test"/"testing"/
		// "demo" were in both sets, so they incremented both scores equally and
		// the testScore>devScore tie-break could essentially never fire, misclass-
		// ifying test content as "development" (-15 instead of -25).
		devKeywords: []string{
			"dev", "development", "staging", "stage",
			"local", "localhost", "sandbox", "preview",
		},

		// Production environment keywords
		// prodKeywords use only unambiguous production markers (M25): generic
		// tokens "main"/"master"/"real"/"actual"/"customer"/"client" were
		// dropped because they classified ordinary source ("package main",
		// "func main") as production and applied a spurious +10 boost to every
		// candidate in the file.
		prodKeywords: []string{
			"production", "prod-", "prod_", ".prod", "live", "release",
			"deploy", "stable", "node_env=production",
		},

		// Test-specific keywords
		testKeywords: []string{
			"test", "example", "sample", "demo", "mock", "fake", "dummy",
			"placeholder", "template", "tutorial", "readme", "documentation",
		},

		// Global test patterns database (includes obvious placeholders and test-specific patterns)
		globalTestPatterns: []string{
			// Obvious placeholder patterns that should never be detected
			"xxxxxxxxxxxxxxxx", "000000000000000", "1234567890abcdef",
			"abcdef123456789", "replace_with_actual", "insert_key_here",
			"your_api_key_here", "test_api_key_here",
			// Same your_*_here family as the entry above. Reachable only now that
			// unquoted assignments are detected at all: measured on an FP probe,
			// "password=your_password_here" was one of only two lines out of 18 that
			// reported, and it is the same placeholder shape as your_api_key_here.
			"your_password_here", "your_secret_here", "your_token_here",
			"insert_password_here", "insert_secret_here", "insert_token_here",
			// Test-specific patterns
			"example_secret_key", "placeholder_token", "sample_password", "demo_private_key",
			"mock_jwt_token", "fake_access_token", "dummy_credential",
			"tutorial_secret", "readme_example", "documentation_key",
		},

		// Pre-compiled regex patterns for shell variable detection (performance optimization)
		// These are used only for complex patterns that can't be handled with string operations
		shellCommandPattern: regexp.MustCompile(`\b(echo|print|curl|wget|http)\b`),

		// Pre-compiled regex patterns for performance optimization
		base64Pattern:     regexp.MustCompile(`["']([A-Za-z0-9+/=\\-_]{20,})["']`), // Default pattern
		hexPattern:        regexp.MustCompile(`["']([0-9A-Fa-f]{16,})["']`),        // Default pattern
		multiSpacePattern: regexp.MustCompile(`\s{2,}`),
		configPattern:     regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*\s*[=:]\s*["'][^"']*["']`),
		variablePatterns: []*regexp.Regexp{
			regexp.MustCompile(`^[a-z_]+$`),                // lowercase_with_underscores
			regexp.MustCompile(`^[A-Z_]+$`),                // UPPERCASE_WITH_UNDERSCORES
			regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`), // typical variable naming
		},
	}

	// Initialize patterns using the configured charsets to avoid duplication
	v.base64Pattern = regexp.MustCompile(`["']([` + regexp.QuoteMeta(v.base64Charset) + `]{20,})["']`)
	v.hexPattern = regexp.MustCompile(`["']([` + regexp.QuoteMeta(v.hexCharset) + `]{16,})["']`)

	return v
}

// SetObserver sets the observability component
func (v *Validator) SetObserver(observer observability.Observer) {
	v.observer = observer
}

// quotedSecretKeywords are the keyword stems the QUOTED assignment patterns are built from, two
// patterns per stem (`stem = "value"` and `"stem": "value"`). A package-level list rather than a
// local of compileKeywordPatterns so that keywordStem, the line gate's stem check, is derived from
// it instead of copying it.
var quotedSecretKeywords = []string{
	"api_?key", "auth_?key", "service_?key", "account_?key", "db_?key",
	"database_?key", "priv_?key", "private_?key", "client_?key",
	"password", "passwd", "pwd", "secret", "token", "bearer",
	"oauth", "jwt", "session", "credential", "access_?token",
}

// compileKeywordPatterns creates regex patterns for common secret keywords
func compileKeywordPatterns() []*regexp.Regexp {
	keywords := quotedSecretKeywords

	var patterns []*regexp.Regexp

	// SSH Private Key patterns (encoded to bypass Code Defender)
	beginPriv := "-----" + "BEGIN"
	endPriv := "-----" + "END"
	patterns = append(patterns, regexp.MustCompile(beginPriv+` (RSA |DSA |EC |OPENSSH )?PRIVATE KEY`+"-----"+`[\s\S]*?`+endPriv+` (RSA |DSA |EC |OPENSSH )?PRIVATE KEY`+"-----"))

	// Certificate Private Key patterns (encoded to bypass Code Defender)
	patterns = append(patterns, regexp.MustCompile(beginPriv+` CERTIFICATE`+"-----"+`[\s\S]*?`+endPriv+` CERTIFICATE`+"-----"))
	patterns = append(patterns, regexp.MustCompile(beginPriv+` ENCRYPTED PRIVATE KEY`+"-----"+`[\s\S]*?`+endPriv+` ENCRYPTED PRIVATE KEY`+"-----"))

	// JWT Token pattern (3 base64 parts separated by dots)
	patterns = append(patterns, regexp.MustCompile(`eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`))

	// Provider literals with a vendor-fixed length (AWS, GitHub, Google Cloud,
	// Docker), derived from the provider grammar table: the fixed window IS the
	// key, and the regex engine's non-overlapping scan is exactly that grammar.
	// Rows without a vendor length (Stripe, GitLab, Slack) are not here; they
	// are found by findProviderRuns, which takes the whole run and applies the
	// straddle and left-glue rules a regex cannot. See provider_rules.go, #769.
	for _, r := range providerRules {
		if r.Mode != modeExact {
			continue
		}
		for _, prefix := range r.Prefixes {
			patterns = append(patterns, regexp.MustCompile(r.pattern(prefix)))
		}
	}

	// PGP Private Keys. Concatenate the marker the same way pemBeginMarker /
	// pemEndMarker do at package level so this literal doesn't look like a
	// real PEM block to upstream secret scanners (notably the
	// detect-private-key pre-commit hook).
	patterns = append(patterns, regexp.MustCompile(pemBeginMarker+` PGP PRIVATE KEY BLOCK`+"-----"+`[\s\S]*?`+pemEndMarker+` PGP PRIVATE KEY BLOCK`+"-----"))

	for _, keyword := range keywords {
		// Pattern for assignment: keyword = "value"
		pattern := regexp.MustCompile(
			`(?i)` + keyword + `\s*[=:]\s*["']([^"']{8,})["']`,
		)
		patterns = append(patterns, pattern)

		// Pattern for JSON/YAML: "keyword": "value"
		pattern = regexp.MustCompile(
			`(?i)["']` + keyword + `["']\s*:\s*["']([^"']{8,})["']`,
		)
		patterns = append(patterns, pattern)

	}

	return patterns
}

// ValidateContent validates preprocessed content with enhanced context analysis
func (v *Validator) ValidateContent(content string, originalPath string) ([]detector.Match, error) {
	// Backward-compatible shim: run with a background context (never cancels).
	return v.ValidateContentCtx(stdctx.Background(), content, originalPath)
}

// ValidateContentCtx implements execguard.ContextAwareValidator: the context-aware
// form of ValidateContent, polling ctx once per line so a runaway multi-line scan
// (SECRETS' DoS shape is many dense lines) is reclaimed promptly (v2 Phase 3). On
// cancellation it returns the matches gathered so far plus ctx.Err().
func (v *Validator) ValidateContentCtx(ctx stdctx.Context, content string, originalPath string) ([]detector.Match, error) {
	return v.validateContentCtx(ctx, content, originalPath, sourceLanguageFor(originalPath))
}

// validateContentCtx is ValidateContentCtx with the lexical gate's grammar passed in rather than
// derived from originalPath. Production always derives it; tests pass langNone to get the exact
// behaviour of the same path with the gate removed, which is the oracle the gate's "everything
// else behaves exactly as today" promise is checked against.
func (v *Validator) validateContentCtx(ctx stdctx.Context, content string, originalPath string, lang sourceLanguage) ([]detector.Match, error) {
	var matches []detector.Match

	// Entry-level cancellation check (v2 Phase 3): the whole-content passes below
	// (context analysis, multi-line secret scan) run before the polled per-line
	// loop, so an already-cancelled/expired scan bails here rather than paying for
	// them. LineLoopCancelled at i==0 reduces to ctx.Err() != nil.
	if execguard.LineLoopCancelled(ctx, 0) {
		return matches, ctx.Err()
	}

	// Perform context analysis for the entire content
	contextInsights := v.contextAnalyzer.AnalyzeContext(content, originalPath)

	// Cache expensive computations for the entire content to avoid redundant processing
	isShellScript := v.IsShellScriptContext(content)
	envType := v.detectEnvironmentType(content)

	// First check for multi-line secrets (SSH keys, certificates, etc.)
	multiLineMatches := v.findMultiLineSecretsWithContext(content, originalPath, contextInsights, isShellScript, envType)
	matches = append(matches, multiLineMatches...)

	// Then check line by line for other patterns
	lines := strings.Split(content, "\n")

	// #746 shape (c): a YAML block sequence puts the key on one line and each credential on its
	// own later line, so no single line carries both and the per-line patterns have nothing to
	// anchor on:
	//
	//	api_keys:
	//	  - <secret>
	//	  - <secret2>
	//
	// Tracked as O(1) forward state rather than by walking backwards from each item line. A
	// backward walk would be O(n²) on a file that is one long sequence, and this package is
	// guarded against exactly that (TestValidatorComplexityIsSubQuadratic, and the audit finding
	// behind it). seqIndent is the indent of the governing key; the sequence ends at the first
	// line that is neither a deeper-indented item nor blank.
	inSecretSequence := false
	seqIndent := 0
	seqKeyLine := ""

	// #753: in a file whose extension names an expression language, an unquoted-family candidate
	// whose value starts in CODE position is an expression, not a literal, and is dropped here --
	// before dedupeScopedBySpan, so a quoted or entropy twin claiming the same span survives, and
	// never when a never-gated path claims exactly its span (gateDrops below). One whole-content
	// lex, then per candidate O(1) for the value start plus the value's length over 64 for the
	// backtick-text check. nil (no gate) for every other file and for every fail-open condition,
	// which keeps those files exactly as they were. See source_syntax.go.
	gate, _ := newSourceGate(content, lang)
	lineOffset := 0

	for lineNum, line := range lines {
		// Cooperative cancellation (v2 Phase 3): bail promptly on deadline/cancel.
		if execguard.LineLoopCancelled(ctx, lineNum) {
			return matches, ctx.Err()
		}
		lineStart := lineOffset
		lineOffset += len(line) + 1
		// Pre-check if this line contains shell variable references to optimize performance
		lineHasShellVars := v.LineContainsShellVariableReferences(line)

		// Process AWS secret access keys (context-gated; see findAWSSecretKeys).
		// Adjacent lines provide the AKIA-pairing context: credentials files list
		// aws_access_key_id and aws_secret_access_key on consecutive lines. Found
		// before the gate runs, because the gate must know which spans it claims.
		var prevLine, nextLine string
		if lineNum > 0 {
			prevLine = lines[lineNum-1]
		}
		if lineNum+1 < len(lines) {
			nextLine = lines[lineNum+1]
		}
		awsResults := v.findAWSSecretKeys(line, prevLine, nextLine, lineNum, originalPath)

		// Collect this line's candidates from both single-line detection paths
		// and collapse claims on identical bytes. One secret is routinely
		// matched several ways — `github_token = "ghp_…"` is hit by the ghp_
		// provider literal, by the token assignment pattern, and by the base64
		// entropy pattern — and each hit used to become its own finding, which
		// inflates finding counts and writes several byte-identical suppression
		// rules for a single leak. The same value appearing twice on one line
		// occupies different spans and is still reported twice.
		//
		// The entropy pass is listed first so it wins a tie, which is the
		// leak-safe direction: its confidence threshold (50) is the lower of
		// the two, so every span main reported is still reported here. Type and
		// confidence derive from the matched text alone, so the surviving
		// finding is identical apart from detection_method.
		entropy := v.findHighEntropyStrings(line)
		keyword := v.findKeywordSecrets(line)

		// gateDrops is the #753 gate for one unquoted-family candidate, with one exemption: a
		// span that a NEVER-gated path also claims on exactly the same bytes -- the entropy path,
		// a quoted pattern or provider literal, the AWS secret-key path -- is not gated. Dropping
		// such a twin removes nothing, since the span is still reported, but it can change what is
		// reported: mergeBySpanKeepStrongest below raises the AWS finding to the highest
		// confidence any candidate on its span reached, so an unquoted 40-char secret in code went
		// from main's 100 to the AWS path's own 95. Exempt, the span reports exactly as on main.
		// The claimed set is built only when a candidate would otherwise drop, so an ungated file
		// and a line with nothing to drop pay nothing for it.
		var claimed map[[2]int]struct{}
		gateDrops := func(start, end int, text string) bool {
			if !gate.drops(line, lineStart, start, text) {
				return false
			}
			if claimed == nil {
				claimed = make(map[[2]int]struct{}, len(entropy)+len(keyword)+len(awsResults))
				for _, c := range entropy {
					claimed[[2]int{c.start, c.end}] = struct{}{}
				}
				for _, c := range keyword {
					if !c.gateable {
						claimed[[2]int{c.start, c.end}] = struct{}{}
					}
				}
				for _, a := range awsResults {
					claimed[[2]int{a.start, a.end}] = struct{}{}
				}
			}
			_, twin := claimed[[2]int{start, end}]
			return !twin
		}

		cands := make([]scopedCandidate, 0, 8)
		for _, c := range entropy {
			cands = append(cands, scopedCandidate{candidate: c, method: "high_entropy", threshold: 50})
		}
		for _, c := range keyword {
			if c.gateable && gateDrops(c.start, c.end, c.text) {
				continue
			}
			cands = append(cands, scopedCandidate{candidate: c, method: "keyword_pattern", threshold: 60})
		}

		// #746 shape (c), continued. Order matters: the state is advanced AFTER this line is
		// examined, so the key line itself is never treated as an item of its own sequence.
		govKeyLine := ""
		if inSecretSequence {
			if itemIndent, isItem := sequenceItemIndent(line); isItem && itemIndent > seqIndent {
				for _, c := range v.findSequenceItemSecret(line) {
					if gateDrops(c.start, c.end, c.text) {
						continue
					}
					cands = append(cands, scopedCandidate{
						candidate: candidate{text: c.text, start: c.start, end: c.end, gateable: true},
						method:    "keyword_pattern", threshold: 60,
					})
				}
				// The key governs this item's confidence even though it is on an earlier line.
				govKeyLine = seqKeyLine
			} else if strings.TrimSpace(line) != "" {
				inSecretSequence = false
			}
		}
		if indent, opens := lineOpensSecretStemSequence(line); opens {
			inSecretSequence, seqIndent, seqKeyLine = true, indent, line
		}
		lineResults := v.processScopedCandidates(dedupeScopedBySpan(cands), line, lineNum, originalPath, content, contextInsights, lineHasShellVars, envType, isShellScript, govKeyLine)

		// The AWS path can claim bytes the entropy path already claimed (a
		// quoted 40-char secret is both), so merge rather than concatenate: the
		// specific, higher-confidence AWS_SECRET_ACCESS_KEY row replaces the
		// generic API_KEY_OR_SECRET row for that span instead of joining it.
		lineResults = mergeBySpanKeepStrongest(lineResults, awsResults)

		// #766: a password or token in URI user info. A separate, ADDITIVE source: it runs outside
		// containsSecretIndicators (so none of that function's arms changes, and a line it skips,
		// like an npm "resolved" registry URL, is still parsed), it is never gated (#753), and it
		// is appended after every other path has been arbitrated and merged, so it cannot change
		// what any of them reports -- not a type, a span or a confidence, which is what keeps
		// every existing suppression hash valid. See uri_userinfo.go.
		if uris := findURIUserinfo(line); len(uris) > 0 {
			lineResults = v.appendURIUserinfoResults(lineResults, uris, line, lineNum, originalPath, content, contextInsights, lineHasShellVars, envType, isShellScript, govKeyLine)
		}

		for _, r := range lineResults {
			m := r.match
			// The merge above RAISES confidence (it keeps the max across paths), so it
			// runs after every emit site and can undo a cap an emit site applied. That
			// is not hypothetical: the documented AWS secret
			// wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY was capped to 15 in
			// findAWSSecretKeys and this loop still handed out 75, because the generic
			// entropy path claimed the same span and scored it higher.
			//
			// The bridge also clamps, but only on the bridge path — pkg/redact and any
			// embedder calling ValidateContent directly never reach it, so a ceiling
			// enforced only there leaves this validator's own API reporting a number it
			// simultaneously declares impossible.
			clampToPublishedCeiling(&m)
			matches = append(matches, m)
		}
	}

	return matches, nil
}

// findHighEntropyStrings finds strings with high Shannon entropy
func (v *Validator) findHighEntropyStrings(line string) []candidate {
	// Early exit: if line doesn't have quotes, it can't have quoted high-entropy strings
	// This is safe because both base64Pattern and hexPattern explicitly match quoted strings
	if !strings.Contains(line, `"`) && !strings.Contains(line, `'`) {
		return nil
	}

	var matches []candidate

	// Base64 pattern: quoted strings with base64 characters (using pre-compiled pattern)
	// Pattern requires 20+ characters, so this will naturally filter short strings
	base64Matches := v.base64Pattern.FindAllStringSubmatchIndex(line, -1)
	for _, m := range base64Matches {
		if len(m) > 3 && m[2] >= 0 {
			text := line[m[2]:m[3]]
			if v.calculateShannonEntropy(text, v.base64Charset) > v.base64Limit {
				matches = append(matches, candidate{text: text, start: m[2], end: m[3]})
			}
		}
	}

	// Hex pattern: quoted strings with hex characters (using pre-compiled pattern)
	// Pattern requires 16+ characters, so this will naturally filter short strings.
	// A hex string is a subset of the base64 charset, so a quoted digest matches
	// both patterns on the same bytes; the caller's span dedup collapses that to
	// one claim.
	hexMatches := v.hexPattern.FindAllStringSubmatchIndex(line, -1)
	for _, m := range hexMatches {
		if len(m) > 3 && m[2] >= 0 {
			text := line[m[2]:m[3]]
			if v.calculateShannonEntropy(text, v.hexCharset) > v.hexLimit {
				matches = append(matches, candidate{text: text, start: m[2], end: m[3]})
			}
		}
	}

	return matches
}

// getSecretType determines the specific type of secret based on pattern analysis
func (v *Validator) getSecretType(match string) string {
	if v.isSSHPrivateKey(match) {
		return "SSH_PRIVATE_KEY"
	}
	if v.isCertificate(match) {
		return "CERTIFICATE"
	}
	if v.isJWTToken(match) {
		return "JWT_TOKEN"
	}
	// Provider literals (AWS, GitHub, Google Cloud, Stripe, GitLab, Docker,
	// Slack): one anchored predicate per row of the grammar table.
	if typ, _ := providerTypeOf(match); typ != "" {
		return typ
	}
	if v.isPGPPrivateKey(match) {
		return "PGP_PRIVATE_KEY"
	}

	// Default to generic secret type for high-entropy strings
	return "API_KEY_OR_SECRET"
}

// containsSecretIndicators is the line gate in front of the keyword pass: findKeywordSecrets runs
// keywordCandidates on a line only when this returns true. It is a performance optimization and
// nothing else, so its contract is soundness rather than judgement:
//
//	containsSecretIndicators(line) == false  ⇒  keywordCandidates(line) is empty
//
// A rejected line is one on which the keyword pass would have found nothing, so skipping it saves
// the regex work and changes no result; TestLineGateIsSound checks that over seeded lines built to
// break it. One known gap is in the generic admits' fall-through, not in the veto: `session` is a
// keyword stem but not an admit word, so `session=` with an 8- to 11-byte value on a line under 20
// bytes is rejected although the unquoted pattern would take the value. Only the keyword pass is
// behind this gate. The entropy pass, the AWS secret-key path, block-sequence items, URI user info
// (#766) and the multi-line pass run on every line.
//
// The ORDER of the arms is load-bearing (#765). Until then three whole-line substring checks ran
// first -- a version or boolean after the line's first colon, an "integrity"/"checksum" key beside
// the bytes `sha` or `md5`, a "url"/"resolved"/"homepage" key beside a scheme and a registry or
// forge host -- and a hit returned false before any admit was consulted. None of them was tied to a
// candidate's bytes, so one `"url": "https://github.com/..."` member, a `"bucket": "shared-assets"`
// beside a `"checksum"`, or a trailing `"verbose": true` hid an AKIA key id, a ghp_, glpat- or xoxb-
// token, a JWT or a keyword-assigned password anywhere else on the same line, and with it the
// redacted copy, the pre-commit exit status and the stdin gateway's redaction.
//
// So: only the length floor and the structural-token check may reject before the provider-literal
// admits, because a JWT, a provider prefix or a PEM marker IS a keyword-pass candidate. Then the one
// veto, benignManifestLine, which rejects a line only when it is wholly one benign manifest member
// and carries no keyword stem. Then the generic admits. TestLineGateArmOrder enumerates every
// `return false` here and fails on one that is not listed with its reason.
func (v *Validator) containsSecretIndicators(line string) bool {
	// Only skip extremely short lines that cannot possibly contain secrets
	// Even a minimal secret like "key=12345678" needs at least 12 characters
	if len(line) < 12 {
		return false
	}

	trimmed := strings.TrimSpace(line)

	// Skip structural JSON/YAML lines (brackets, braces, commas)
	if len(trimmed) <= 2 {
		if trimmed == "{" || trimmed == "}" || trimmed == "[" || trimmed == "]" ||
			trimmed == "{}" || trimmed == "[]" || trimmed == "," || trimmed == "-" {
			return false
		}
	}

	// Provider literals. Each of the three is itself a keyword-pass candidate -- the JWT regex,
	// the provider regexes and findProviderRuns, the PEM patterns -- so no veto may run before them.

	// Check for specific high-confidence patterns that don't need quotes
	// JWT tokens
	if strings.Contains(line, "eyJ") {
		return true
	}

	// Provider literals: every prefix of every row of the grammar table (AWS,
	// GitHub, Google Cloud, Stripe, GitLab, Docker, Slack). Derived, so a row
	// added to the table is admitted here without a second edit (#769).
	if lineHasProviderPrefix(line) {
		return true
	}

	// SSH/PGP key markers (encoded to bypass Code Defender)
	beginMarker := "-----" + "BEGIN"
	if strings.Contains(line, beginMarker) {
		return true
	}

	// PERFORMANCE: the one veto. An npm lockfile is half lines like `"version": "1.3.0",`,
	// `"resolved": "https://registry.npmjs.org/...tgz",` and `"integrity": "sha512-...",`, every one
	// of which the generic admits below would let through; skipping them is worth 2.2-2.7x of SECRETS
	// CPU on a lockfile (#765). See benignManifestLine for why such a line holds no candidate.
	if benignManifestLine(trimmed) {
		return false
	}

	// Check for common secret indicators using fast string operations
	hasQuotes := strings.Contains(line, `"`) || strings.Contains(line, `'`)
	hasEquals := strings.Contains(line, "=") || strings.Contains(line, ":")

	// SECURITY: Check for common secret-related keywords even without quotes
	// This catches cases like: api_key=abc123 or password:secret123
	lowerLine := strings.ToLower(line)
	secretKeywords := []string{
		"key", "secret", "token", "password", "pass", "pwd", "auth",
		"credential", "private", "bearer", "jwt", "api",
	}
	for _, keyword := range secretKeywords {
		if strings.Contains(lowerLine, keyword) && hasEquals {
			return true
		}
	}

	// If line has quotes but no assignment, it might still contain secrets
	// but with lower priority - check for minimum length
	if hasQuotes && len(line) >= 20 {
		return true
	}

	// SECURITY: If line has assignment operator and is long enough, scan it
	// This catches unquoted secrets like: SESSION_TOKEN=abc123def456ghi789
	if hasEquals && len(line) >= 20 {
		return true
	}

	return false
}

// benignManifestLine is containsSecretIndicators' one veto: it reports whether a trimmed line is
// wholly one benign package-manifest member. All three conditions must hold, each for a stated
// reason (#765):
//
//   - benignManifestMember: the line is exactly one JSON member `"<key>": <value>`, an optional
//     trailing comma and nothing else, and the value is a version under 20 bytes, `true`/`false`, an
//     SRI digest `"shaNNN-<base64>"`, or an http(s) or git+https URL with no user info, query or
//     `=`. The shape leaves no byte for a secret BESIDE the member -- no second member, comment or
//     trailing text -- which is where every one of #765's triggers put it.
//   - no keywordStem ANYWHERE on the line, key or value. Every keyword-pass candidate is anchored
//     on a provider literal, a JWT or a PEM marker -- all admitted before this veto runs -- or on a
//     stem from the lists the keyword patterns are compiled from. A line holding none of them has
//     no candidate whatever its shape, so soundness does not rest on reading the value grammar
//     right. Checking only the key, as #765's prototype did, is unsound for a host that ends in a
//     stem and has a port: in `"url": "https://api.session:8443/github.com/x"` the unquoted pattern
//     reads `session:` as an assignment and yields `8443/github.com/x`.
//   - legacyManifestVeto: one of the three checks this veto replaced fires as well. They ran before
//     every admit, so a line they let through was scanned; requiring one of them keeps this veto a
//     subset of theirs, so every line scanned before #765 is still scanned, which is what keeps the
//     change additive. Deleting the veto outright costs 2.2-2.7x of SECRETS CPU on npm lockfiles;
//     it can go, and should be re-timed, once the generic admits get a pattern-derived pre-check.
//
// Cheapest first: the leading quote, then the substring checks, then the shape regex and the stem
// scan, which in practice run only on manifest lines.
func benignManifestLine(trimmed string) bool {
	if len(trimmed) == 0 || trimmed[0] != '"' || !legacyManifestVeto(trimmed) {
		return false
	}
	if !benignManifestMember.MatchString(trimmed) {
		return false
	}
	// A version is benign only under 20 bytes, the bound the legacy check applied.
	if len(manifestVersionValue(trimmed)) >= 20 {
		return false
	}
	return !lineHasKeywordStem(trimmed)
}

// manifestVersionValue returns the version text, without its quotes, of a line benignManifestMember
// matched, or "" when the member's value is not a version. The key class holds no quote, so the
// first `":` is the member's colon; of the value arms only a version starts with a quote followed
// by `^`, `~` or a digit.
func manifestVersionValue(member string) string {
	i := strings.Index(member, `":`)
	if i < 0 {
		return ""
	}
	v := strings.TrimSuffix(strings.TrimSpace(member[i+2:]), ",")
	if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
		return ""
	}
	if c := v[1]; c != '^' && c != '~' && (c < '0' || c > '9') {
		return ""
	}
	return v[1 : len(v)-1]
}

// benignManifestMember is the shape half of benignManifestLine. The key class is an npm package
// name's, scoped names included. A URL's host may carry a port; its path may carry `@` (npm scopes)
// and percent-escapes; nothing in it may be user info, a query or an `=`.
var benignManifestMember = regexp.MustCompile(`^"[@A-Za-z0-9._/+-]+":[ \t]*(?:` +
	`"[\^~]?[0-9]+(?:\.[0-9]+){1,3}(?:[-+][0-9A-Za-z.-]+)?"` +
	`|true|false` +
	`|"sha(?:1|256|384|512)-[A-Za-z0-9+/]{20,}={0,2}"` +
	`|"(?:git\+)?https?://[A-Za-z0-9.-]+(?::[0-9]+)?(?:/[A-Za-z0-9@._~%/+-]*)?(?:#[A-Za-z0-9._-]*)?"` +
	`),?$`)

// keywordStem matches any stem a keyword-pass pattern is anchored on, case-insensitively, exactly as
// the patterns match it: the same fragments under the same (?i) in the same engine, so a case fold
// the patterns honour (`ſ` for `s`, the Kelvin sign for `k`) is honoured here too, which
// strings.ToLower would not do. Derived from the two lists the patterns are compiled from -- the
// quoted patterns range over quotedSecretKeywords; the unquoted, plural, collection and list-tail
// patterns over secretAssignmentKeywords -- never copied. TestKeywordStemCoversEveryPattern fails
// on a keyword-pass pattern whose anchor this does not cover.
var keywordStem = regexp.MustCompile(`(?i)(?:` + strings.Join(keywordPassStems(), "|") + `)`)

// keywordStemLiterals is every string keywordStem's alternatives can match, lower-cased, with any
// literal that contains a shorter one dropped (`secret_key` holds `secret`). Enumerated from the
// parsed stems, so a stem that is not a finite language -- a class, a star -- fails at init rather
// than being approximated.
var keywordStemLiterals = func() [][]byte {
	var all []string
	for _, stem := range keywordPassStems() {
		re, err := syntax.Parse(stem, syntax.Perl)
		if err != nil {
			panic("secrets: keyword stem " + stem + ": " + err.Error())
		}
		all = append(all, finiteLanguage(re.Simplify(), stem)...)
	}
	var out [][]byte
	for _, s := range all {
		redundant := false
		for _, t := range all {
			if t != s && strings.Contains(s, t) {
				redundant = true
				break
			}
		}
		if !redundant {
			out = append(out, []byte(strings.ToLower(s)))
		}
	}
	return out
}()

// finiteLanguage enumerates the strings a parsed stem matches. Only the shapes the stems use are
// accepted (literals, concatenation, `?`, alternation); anything else panics, naming the stem.
func finiteLanguage(re *syntax.Regexp, stem string) []string {
	switch re.Op {
	case syntax.OpLiteral:
		return []string{string(re.Rune)}
	case syntax.OpEmptyMatch:
		return []string{""}
	case syntax.OpConcat:
		out := []string{""}
		for _, sub := range re.Sub {
			var next []string
			for _, prefix := range out {
				for _, s := range finiteLanguage(sub, stem) {
					next = append(next, prefix+s)
				}
			}
			out = next
		}
		return out
	case syntax.OpQuest:
		return append([]string{""}, finiteLanguage(re.Sub[0], stem)...)
	case syntax.OpAlternate:
		var out []string
		for _, sub := range re.Sub {
			out = append(out, finiteLanguage(sub, stem)...)
		}
		return out
	}
	panic("secrets: keyword stem " + stem + " is not a finite set of literals (" + re.Op.String() + ")")
}

// lineHasKeywordStem is keywordStem.MatchString, fast on ASCII. On a line that is all ASCII, (?i)
// can only fold an ASCII letter to another ASCII letter -- the two non-ASCII folds of ASCII letters,
// U+212A for k and U+017F for s, are not ASCII -- so the match is a case-insensitive substring
// search for keywordStemLiterals, done as one pass over the lower-cased line that tries the
// literals only where a literal's first two bytes start. Any other line goes to the regexp itself.
// TestLineHasKeywordStemIsTheRegexp checks the two agree.
func lineHasKeywordStem(s string) bool {
	var buf [256]byte
	lower := buf[:0]
	if len(s) > len(buf) {
		lower = make([]byte, 0, len(s))
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= utf8.RuneSelf {
			return keywordStem.MatchString(s)
		}
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		lower = append(lower, c)
	}
	for i := 0; i+1 < len(lower); i++ {
		p := uint16(lower[i])<<8 | uint16(lower[i+1])
		if keywordStemPairs[p/64]&(1<<(p%64)) == 0 {
			continue
		}
		for _, lit := range keywordStemLiterals {
			if bytes.HasPrefix(lower[i:], lit) {
				return true
			}
		}
	}
	return false
}

// keywordStemPairs is the set of first-two-byte pairs of keywordStemLiterals, as a bitset over
// all 65,536 pairs. Every stem is at least three bytes long; a shorter one fails at init.
var keywordStemPairs = func() (set [65536 / 64]uint64) {
	for _, lit := range keywordStemLiterals {
		if len(lit) < 2 {
			panic("secrets: keyword stem literal " + string(lit) + " is shorter than two bytes")
		}
		p := uint16(lit[0])<<8 | uint16(lit[1])
		set[p/64] |= 1 << (p % 64)
	}
	return set
}()

// keywordPassStems is the union of the stem lists the keyword-pass patterns are compiled from,
// first occurrence kept.
func keywordPassStems() []string {
	seen := make(map[string]bool, len(quotedSecretKeywords)+len(secretAssignmentKeywords))
	var out []string
	for _, list := range [][]string{quotedSecretKeywords, secretAssignmentKeywords} {
		for _, stem := range list {
			if !seen[stem] {
				seen[stem] = true
				out = append(out, stem)
			}
		}
	}
	return out
}

// legacyManifestVeto reports whether one of the three whole-line checks containsSecretIndicators
// ran before #765 fires on a trimmed line: the logic is theirs, verbatim, returning true where they
// returned false. It no longer rejects anything by itself; benignManifestLine requires it so that
// its own veto can only be narrower.
//
//   - V1: the text after the line's FIRST colon, trimmed of spaces, one trailing comma and quotes,
//     is under 20 bytes and is `true`/`false`, or starts with a digit, `^` or `~` and holds a `.`.
//   - V2: an "integrity" or "checksum" key, and the bytes `sha` or `md5` anywhere (`shared` too).
//   - V3: a "resolved", "url" or "homepage" key, a scheme, and `registry.`, github.com, gitlab.com
//     or bitbucket.org, as three independent substrings.
func legacyManifestVeto(trimmed string) bool {
	if strings.Contains(trimmed, `":`) {
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) == 2 {
			value := strings.TrimSpace(parts[1])
			value = strings.TrimSuffix(value, ",")
			value = strings.Trim(value, `"'`)
			if len(value) > 0 && len(value) < 20 {
				if strings.Contains(value, ".") && (value[0] >= '0' && value[0] <= '9' || value[0] == '^' || value[0] == '~') {
					return true
				}
				if value == "true" || value == "false" {
					return true
				}
			}
		}
	}
	if strings.Contains(trimmed, `"integrity"`) || strings.Contains(trimmed, `"checksum"`) {
		if strings.Contains(trimmed, "sha") || strings.Contains(trimmed, "md5") {
			return true
		}
	}
	if strings.Contains(trimmed, `"resolved"`) || strings.Contains(trimmed, `"url"`) || strings.Contains(trimmed, `"homepage"`) {
		if strings.Contains(trimmed, "https://") || strings.Contains(trimmed, "http://") {
			if strings.Contains(trimmed, "registry.") || strings.Contains(trimmed, "github.com") ||
				strings.Contains(trimmed, "gitlab.com") || strings.Contains(trimmed, "bitbucket.org") {
				return true
			}
		}
	}
	return false
}

// secretAssignmentKeywords are the keyword stems used for UNQUOTED assignments.
//
// Same stems the quoted patterns use, kept as their own list so the two sets cannot be
// changed independently by accident and so the unquoted patterns can carry a stricter value
// filter without touching the quoted ones.
var secretAssignmentKeywords = []string{
	"api_?key", "auth_?key", "service_?key", "account_?key", "db_?key",
	"database_?key", "priv_?key", "private_?key", "client_?key",
	// access_key is the stem the highest-value credential class uses. Without it
	// AWS_SECRET_ACCESS_KEY= does not match: "secret" IS present but is followed by
	// "_ACCESS_KEY=", so `secret\s*[=:]` never fires. Measured — 7 of 8 real
	// assignments matched and this was the miss.
	"access_?key", "secret_?access_?key", "secret_?key",
	"password", "passwd", "pwd", "secret", "token", "bearer",
	"oauth", "jwt", "session", "credential", "access_?token",
}

// compileUnquotedPatterns builds the assignment patterns for values with NO quotes.
//
// compileKeywordPatterns emits two patterns per keyword and both require ["'] on either side
// of the value, so no unquoted assignment could match anything — while containsSecretIndicators
// admits exactly those lines and its comment promises them ("This catches cases like:
// api_key=abc123 or password:secret123"). The line was let through and nothing could claim it.
// Measured before this: password=, PASSWORD=, db_password:, DATABASE_PASSWORD=, secret=,
// api_key= and token= all reported NOTHING at any confidence, while the same values in quotes
// were found. See #360.
//
// Unquoted is the dominant real-world form, not an edge case: .env, shell exports, CI
// variables, Dockerfile ENV, systemd/ini and unquoted YAML all write it that way, and those
// are where credentials sit.
//
// Kept SEPARATE from keywordPatterns rather than appended to it, because these need a value
// filter the quoted patterns must not get. Quotes are themselves evidence of intent — someone
// wrote `password="something"` deliberately — whereas an unquoted capture takes whatever
// follows the delimiter, so it needs plausibleUnquotedSecret to reject prose.
//
// '/' is deliberately allowed in the value even though excluding it would remove the
// file-path false positives, because a real AWS secret access key contains it: the reference
// value wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY has two. Losing a real credential class to
// tidy up a cosmetic one is the wrong trade.
//
// SCOPE. The config grammars above are where an unquoted right-hand side is a literal, and in
// those files -- and in any input with no file type -- these patterns run everywhere on the line.
// In a file whose extension names an expression language (Python, JS/TS, Go, Terraform/HCL), a
// candidate whose value starts in CODE position is an identifier, call or type rather than a
// literal, and ValidateContentCtx drops it before dedupe (#753, source_syntax.go). The patterns
// themselves are unchanged, so every span they report keeps its text and its suppression hash.
func compileUnquotedPatterns() []*regexp.Regexp {
	patterns := make([]*regexp.Regexp, 0, len(secretAssignmentKeywords))
	for _, keyword := range secretAssignmentKeywords {
		patterns = append(patterns, regexp.MustCompile(
			`(?i)`+keyword+`\s*[=:]\s*([^\s"\';,#<${(\[][^\s"\';,#]{7,})`,
		))
	}
	return patterns
}

// queryParamSeparator is a run of `&` that begins a new query-string parameter: followed by a
// key and `=`. A bare `&` inside a credential (`P&ss...`) does not match. The run is taken whole
// so that an empty parameter (`a=1&&b=2`) does not leave a trailing `&` on the previous value.
var queryParamSeparator = regexp.MustCompile(`&+[A-Za-z_][\w.-]*=`)

// isQueryKeyByte reports whether b can appear in a query-string key: [A-Za-z0-9_.-].
func isQueryKeyByte(b byte) bool {
	return b == '_' || b == '.' || b == '-' || (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// plausibleUnquotedSecret reports whether an unquoted captured value could be a secret.
//
// This is the whole reason the unquoted patterns are a separate set. Measured on 400 real
// third-party files the unquoted pattern added exactly ONE finding over the baseline, and that
// one was the word "creating" — captured from a line like `token: creating` and scored HIGH.
// Probing the shape directly produced more of the same:
//
//	token: creating      -> HIGH
//	password: something  -> HIGH
//	secret: available    -> MEDIUM
//
// The existing commonWords list cannot catch these (it holds six entries: password, secret,
// example, test, sample, default) and the entropy penalty does not demote them far enough. A
// secrets validator that calls "something" a HIGH-confidence credential trains people to
// ignore it, which costs more than the detection gains.
//
// The rejections below are shape-based rather than a word list, because a word list is a list
// of words someone thought of:
//
//   - all-lowercase-alphabetic AND shorter than 16 characters. Real credentials carry a digit,
//     an uppercase letter or a symbol; English words in log lines and prose do not. The length
//     floor keeps a genuine all-lowercase passphrase ("correcthorsebatterystaple") accepted,
//     since dictionary words in this position are short.
//   - all digits, which is a phone number, port, timestamp or id rather than a secret.
//   - digits and hyphens only, which is a date or a formatted number.
//   - UUID shape, which identifies a thing rather than authenticating one.
//   - entirely mask characters, which is this tool's OWN redacted output rather than a secret, or
//     a provider prefix followed only by mask characters, which is another tool's (#807).
//
// A genuinely all-lowercase short secret is rejected, and that is a deliberate, stated cost.
//
// SCOPE. This filter judges the VALUE and runs on every unquoted candidate, on every channel. It
// is the only defence in config, prose and untyped input. In expression-language source files the
// broader class it was chasing there -- types, calls and member accesses captured as values -- is
// closed by the file's grammar instead (#753): a code-position value is dropped whatever its
// shape. In a .py both now exclude `session: Optional[Session]`; the Ident[...] veto below is what
// still excludes it from a file the gate cannot type.
func plausibleUnquotedSecret(v string) bool {
	if len(v) < 8 {
		return false
	}

	// Already-masked output. `AWS_SECRET_ACCESS_KEY=****...` is what this tool WRITES, and
	// re-scanning a redacted file is a normal thing to do — it is how you verify a redaction.
	// Reported at MEDIUM 75, that run of asterisks then drove format_preserving to replace it with
	// a run of asterisks of the same length, so the "redacted" copy came back byte-identical to its
	// input with Success true at rc 0, and the audit log recorded equal original and redacted file
	// hashes. See #522.
	//
	// A mask that kept the token's provider prefix is the same thing: `gho_` and 36 `*` is how
	// several tools print a token in a log, and it carries no secret byte either, because the prefix
	// is public by construction and the rest is the mask. It is not ENTIRELY mask characters,
	// though, so until #807 it cleared every veto here and reported at MEDIUM 75 on a log line and
	// at HIGH 100 in a .docx whose tab-separated cover block added the +20 tabular boost.
	// isMaskedValue strips a prefix from the provider grammar table and asks the same question of
	// what is left.
	//
	// Safe as a veto rather than a confidence ceiling, unlike unlabelledHexIdentifierCap above,
	// because it is VALUE-INTRINSIC: a value containing nothing but mask characters carries no
	// secret, so an author cannot use it to hide one. The relabelling attack that rules out a
	// negative list of field names has no analogue here — there is nothing to relabel. A prefix
	// changes nothing: what follows it must still be nothing but `*`, so hiding a token this way
	// means deleting it.
	if isMaskedValue(v) {
		return false
	}

	// Language type annotation, e.g. `session: Optional[Session]`, `tokens: List[str]`,
	// `creds: Dict[str,Secret]`. The unquoted capture grabs the annotation value when the
	// field name carries a secret stem (session, password, api_key, ...), and a mixed-case
	// Optional[Session] clears every other veto here, so it is scored a HIGH-confidence
	// credential. This is the inverse of the #360/#395 fix: #395 taught the detector to catch
	// unquoted assignments but never excluded the parameterized-type-annotation shape, which is
	// pervasive in typed Python / TypeScript generics. See #742.
	//
	// Safe as a veto rather than a confidence ceiling because it is VALUE-INTRINSIC, like
	// isAllMaskCharacters above: a value shaped Ident[...] carries no secret, so an author
	// cannot relabel a real credential into this shape to hide it. Scoped to the unquoted
	// path only; a quoted `token = "Optional[X]"` is still handled by the quoted patterns.
	if typeAnnotationValue.MatchString(v) {
		return false
	}

	var hasLower, hasUpper, hasDigit, hasOther bool
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9':
			hasDigit = true
		default:
			hasOther = true
		}
	}

	// Prose: only lowercase letters, and short enough to be a dictionary word.
	if hasLower && !hasUpper && !hasDigit && !hasOther && len(v) < 16 {
		return false
	}
	// Numbers and formatted numbers.
	if hasDigit && !hasLower && !hasUpper {
		if !hasOther {
			return false
		}
		if uuidLikeValue.MatchString(v) || digitsAndDashes.MatchString(v) {
			return false
		}
	}
	if uuidLikeValue.MatchString(v) {
		return false
	}
	return true
}

var (
	uuidLikeValue   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	digitsAndDashes = regexp.MustCompile(`^[0-9-]+$`)
	// typeAnnotationValue matches a bare generic/parameterized type annotation such as
	// Optional[Session], List[str], Dict[str,int] or typing.Optional[str] — a dotted-or-plain
	// identifier followed by a single bracketed parameter list spanning the whole value. Used
	// by plausibleUnquotedSecret to reject annotations the unquoted-assignment patterns capture.
	typeAnnotationValue = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*\[[^\]]*\]$`)
)

// isAllMaskCharacters reports whether a value consists ONLY of the character this tool masks with.
//
// Scoped to '*' alone, deliberately. That is the only mask byte anything in this repo emits —
// replacement.FormatPreserving and the legacy OLE redactor's maskByte — so it is the only one whose
// presence here is evidence of the tool's own output rather than of the document's content.
//
// Widening it to 'X' or '#' would start rejecting values a person could plausibly have chosen, and a
// suppressor that rejects a real secret is worse than the false positive it removes. ENTIRELY, not
// "contains": a real credential with asterisks in it stays reported, which has its own test.
func isAllMaskCharacters(v string) bool {
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] != '*' {
			return false
		}
	}
	return true
}

// providerMaskTailMin is the shortest run of mask characters after a provider prefix that
// isMaskedValue accepts: 8, the floor plausibleUnquotedSecret puts under every unquoted value.
// Masking tools print the body's own length or a fixed run of at least that; a shorter tail is
// nearer to something a person could have typed as a value, so it is left to ordinary scoring.
const providerMaskTailMin = 8

// isMaskedValue reports whether a value is masked output that carries no secret byte: entirely
// mask characters (isAllMaskCharacters, #522), or a provider prefix followed by at least
// providerMaskTailMin mask characters and nothing else, the way a log prints `gho_` and 36 `*`
// (#807).
//
// The prefixes are the grammar table's own, allProviderPrefixes, so a row added to providerRules
// is covered here with no second list to keep in step. The remainder test is isAllMaskCharacters
// itself, with its ENTIRELY rule: `gho_****abcd****` keeps real characters and stays reported.
// Prefixes match exactly as the table spells them, case and all, as the provider regexes do.
// Slack's head digit groups are not stripped: `xoxb-` and a mask is masked output,
// `xoxb-<digits>-<digits>-` and a mask is not, by this rule.
func isMaskedValue(v string) bool {
	if isAllMaskCharacters(v) {
		return true
	}
	for _, p := range allProviderPrefixes {
		if rest, ok := strings.CutPrefix(v, p); ok && len(rest) >= providerMaskTailMin && isAllMaskCharacters(rest) {
			return true
		}
	}
	return false
}

// findKeywordSecrets is the keyword pass behind its line gate: keywordCandidates on every line
// containsSecretIndicators admits, nothing on a line it rejects. The gate's contract is that a
// rejected line has no candidate, so this returns what keywordCandidates would (save the one gap
// containsSecretIndicators documents); the split exists so that the contract can be tested.
func (v *Validator) findKeywordSecrets(line string) []candidate {
	// Early exit: skip lines that clearly don't contain secrets
	if !v.containsSecretIndicators(line) {
		return nil
	}
	return v.keywordCandidates(line)
}

// keywordCandidates finds secrets on one line using keyword patterns, with no gate in front.
//
// Every pattern that hits contributes a candidate, and several patterns
// routinely claim the very same bytes: `apiKey = "AKIA…"` matches both the
// AKIA provider literal (full-match branch) and the api_?key assignment
// pattern (capture-group branch). Candidates therefore carry their byte span
// so the caller can collapse same-span claims instead of reporting one secret
// two or three times; see dedupeScopedBySpan.
func (v *Validator) keywordCandidates(line string) []candidate {
	var matches []candidate

	// Provider tokens without a vendor-fixed length (Stripe, GitLab, Slack), each
	// taken as its WHOLE run with the straddle and left-glue rules applied. Listed
	// first so that when a keyword pattern below claims exactly the same span --
	// `STRIPE_SECRET_KEY=<sk>` is both -- dedupeScopedBySpan keeps the provider
	// candidate, which is not gateable and carries the provider type. See
	// provider_rules.go and #769.
	matches = append(matches, findProviderRuns(line)...)

	for _, pattern := range v.keywordPatterns {
		found := pattern.FindAllStringSubmatchIndex(line, -1)
		for _, m := range found {
			// Capture group match (keyword patterns) when the pattern has one
			// that participated in this match; otherwise the full match (SSH
			// keys, JWT tokens, provider literals).
			if len(m) > 3 && m[2] >= 0 && m[3]-m[2] >= 8 {
				matches = append(matches, candidate{text: line[m[2]:m[3]], start: m[2], end: m[3]})
			} else if m[1]-m[0] >= 8 {
				matches = append(matches, candidate{text: line[m[0]:m[1]], start: m[0], end: m[1]})
			}
		}
	}

	// Unquoted assignments, filtered. Separate loop because these candidates must pass
	// plausibleUnquotedSecret and the quoted ones must not — quotes are evidence of intent.
	for _, pattern := range v.unquotedPatterns {
		for _, m := range pattern.FindAllStringSubmatchIndex(line, -1) {
			if len(m) <= 3 || m[2] < 0 || m[3]-m[2] < 8 {
				continue
			}
			keyStart := m[0]
			for keyStart > 0 && isQueryKeyByte(line[keyStart-1]) {
				keyStart--
			}
			if keyStart == 0 || strings.IndexByte("?&", line[keyStart-1]) < 0 {
				// Not a query-string parameter: the value is taken whole, as before #758, because
				// outside a query string a credential may contain `&x=`. `;` delimits connection
				// strings and a leading `#` or `;` marks a commented-out assignment, so neither counts.
				if value := line[m[2]:m[3]]; plausibleUnquotedSecret(value) {
					matches = append(matches, candidate{text: value, start: m[2], end: m[3], gateable: true})
				}
				continue
			}
			// A query-string parameter. The pattern's greedy value runs over every later `&key=`
			// in the same query string, so split that one span at its separators: the first
			// segment is this parameter's value, and each later `key=value` segment is matched on
			// its own. The segments are disjoint, so the whole line costs one pass however many
			// parameters it holds; resuming the regex after each '&' instead re-scanned to the end
			// of the line every time (quadratic).
			appendValue := func(start, end int) {
				if end-start >= 8 {
					if value := line[start:end]; plausibleUnquotedSecret(value) {
						matches = append(matches, candidate{text: value, start: start, end: end, gateable: true})
					}
				}
			}
			seps := queryParamSeparator.FindAllStringIndex(line[m[2]:m[3]], -1)
			segEnd := m[3]
			if len(seps) > 0 {
				segEnd = m[2] + seps[0][0]
			}
			appendValue(m[2], segEnd)
			for k, sep := range seps {
				segStart, segStop := m[2]+sep[0]+1, m[3]
				if k+1 < len(seps) {
					segStop = m[2] + seps[k+1][0]
				}
				if sm := pattern.FindStringSubmatchIndex(line[segStart:segStop]); sm != nil && len(sm) > 3 && sm[2] >= 0 {
					appendValue(segStart+sm[2], segStart+sm[3])
				}
			}
		}
	}

	// A plural key name — `tokens:`, `api_keys:` — matches no pattern above, because the stem has
	// to sit immediately before the delimiter. Same two filters as their singular counterparts:
	// the quoted set takes the value as written, the unquoted set must clear
	// plausibleUnquotedSecret. See #746 shape (d).
	for _, pattern := range v.pluralQuotedPatterns {
		for _, m := range pattern.FindAllStringSubmatchIndex(line, -1) {
			if len(m) > 3 && m[2] >= 0 && m[3]-m[2] >= 8 {
				matches = append(matches, candidate{text: line[m[2]:m[3]], start: m[2], end: m[3]})
			}
		}
	}
	for _, pattern := range v.pluralUnquotedPatterns {
		for _, m := range pattern.FindAllStringSubmatchIndex(line, -1) {
			if len(m) > 3 && m[2] >= 0 && m[3]-m[2] >= 8 {
				value := line[m[2]:m[3]]
				if !plausibleUnquotedSecret(value) {
					continue
				}
				matches = append(matches, candidate{text: value, start: m[2], end: m[3], gateable: true})
			}
		}
	}

	// Collections, and the tail of a non-bracketed list — #746 shapes (b) and (a). Both carry
	// their own element filters; see list_and_sequence.go.
	//
	// All of them are unquoted-family candidates for the #753 lexical gate, the QUOTED collection
	// elements included: the gate anchors on the value start, and a quoted element's value starts
	// inside its quotes, so it keeps reporting after a code-position head. Marked here rather than
	// in list_and_sequence.go so the gate does not depend on how those paths are built.
	for _, c := range v.findCollectionSecrets(line) {
		matches = append(matches, candidate{text: c.text, start: c.start, end: c.end, gateable: true})
	}
	for _, c := range v.findListTailSecrets(line) {
		matches = append(matches, candidate{text: c.text, start: c.start, end: c.end, gateable: true})
	}

	return matches
}

// LineIndex stores line offsets for efficient line number lookups
type LineIndex struct {
	offsets []int
}

// buildLineIndex creates an index of line start positions
func buildLineIndex(content string) *LineIndex {
	offsets := []int{0} // First line starts at position 0
	for i, char := range content {
		if char == '\n' {
			offsets = append(offsets, i+1)
		}
	}
	return &LineIndex{offsets: offsets}
}

// findLineNumber finds the line number using binary search on the line index
func (li *LineIndex) findLineNumber(position int) int {
	if position < 0 || len(li.offsets) == 0 {
		return 1
	}

	// Binary search for the line containing this position
	left, right := 0, len(li.offsets)-1
	for left <= right {
		mid := (left + right) / 2
		if li.offsets[mid] <= position {
			if mid == len(li.offsets)-1 || li.offsets[mid+1] > position {
				return mid + 1
			}
			left = mid + 1
		} else {
			right = mid - 1
		}
	}
	return 1
}

// findLineNumber finds the line number where a match starts using optimized lookup
func (v *Validator) findLineNumber(content, match string) int {
	index := strings.Index(content, match)
	if index == -1 {
		return 1
	}

	// For small content, use simple counting
	if len(content) < 1000 {
		lineNum := 1
		for i := 0; i < index; i++ {
			if content[i] == '\n' {
				lineNum++
			}
		}
		return lineNum
	}

	// For larger content, use binary search with line index
	lineIndex := buildLineIndex(content)
	return lineIndex.findLineNumber(index)
}

// calculateShannonEntropy calculates Shannon entropy for a string
func (v *Validator) calculateShannonEntropy(data, charset string) float64 {
	if len(data) == 0 {
		return 0
	}

	entropy := 0.0
	for _, char := range charset {
		count := strings.Count(data, string(char))
		if count > 0 {
			p := float64(count) / float64(len(data))
			entropy += -p * math.Log2(p)
		}
	}

	return entropy
}

// CalculateConfidence calculates confidence score for a potential secret
func (v *Validator) CalculateConfidence(match string) (float64, map[string]bool) {
	checks := map[string]bool{
		"min_length":       len(match) >= 8,
		"not_common_word":  true,
		"has_entropy":      true,
		"not_test_data":    true,
		"valid_format":     true,
		"specific_pattern": false,
	}

	confidence := 85.0

	// Check for specific high-confidence patterns first
	if v.isSSHPrivateKey(match) {
		confidence = 95.0
		checks["specific_pattern"] = true
		checks["valid_format"] = true
		return confidence, checks
	}

	if v.isCertificate(match) {
		confidence = 90.0
		checks["specific_pattern"] = true
		checks["valid_format"] = true
		return confidence, checks
	}

	if v.isJWTToken(match) {
		confidence = 92.0
		checks["specific_pattern"] = true
		checks["valid_format"] = true
		return confidence, checks
	}

	// Provider literals: the base confidence is a column of the grammar table,
	// so a row cannot be matched at one length and scored at another (#769).
	if typ, base := providerTypeOf(match); typ != "" {
		confidence = base
		checks["specific_pattern"] = true
		checks["valid_format"] = true
		return confidence, checks
	}

	if v.isPGPPrivateKey(match) {
		confidence = 96.0
		checks["specific_pattern"] = true
		checks["valid_format"] = true
		return confidence, checks
	}

	// Length check
	if len(match) < 8 {
		confidence -= 30
		checks["min_length"] = false
	} else if len(match) > 100 {
		confidence -= 10 // Very long strings might be less likely to be secrets
	}

	// Check for common words/patterns. Only penalize when the word DOMINATES the
	// token (the match is essentially that word), not when it is an incidental
	// substring of a long high-entropy value — a 30-char random secret that
	// merely begins with "test" or contains "secret" is still a real secret
	// (M26). Require the common word to make up at least half the match.
	lowerMatch := strings.ToLower(match)
	commonWords := []string{"password", "secret", "example", "test", "sample", "default"}
	for _, word := range commonWords {
		if strings.Contains(lowerMatch, word) && len(word)*2 >= len(lowerMatch) {
			confidence -= 20
			checks["not_common_word"] = false
			break
		}
	}

	// Entropy check
	base64Entropy := v.calculateShannonEntropy(match, v.base64Charset)
	hexEntropy := v.calculateShannonEntropy(match, v.hexCharset)
	maxEntropy := math.Max(base64Entropy, hexEntropy)

	if maxEntropy < 3.0 {
		confidence -= 25
		checks["has_entropy"] = false
	}

	// Test data patterns. Like the common-word check above, only penalize when the
	// token IS essentially the test word (delimiter-bounded or dominating the
	// length), not when "test"/"demo" is an incidental substring of a long
	// high-entropy secret (M26).
	testPatterns := []string{"test", "demo", "example", "sample", "fake", "mock"}
	for _, pattern := range testPatterns {
		if strings.Contains(lowerMatch, pattern) && len(pattern)*3 >= len(lowerMatch) {
			confidence -= 30
			checks["not_test_data"] = false
			break
		}
	}

	// Format validation (basic checks)
	if strings.Contains(match, " ") || strings.Contains(match, "\t") {
		confidence -= 15
		checks["valid_format"] = false
	}

	// Ensure confidence bounds
	if confidence < 0 {
		confidence = 0
	} else if confidence > 100 {
		confidence = 100
	}

	return confidence, checks
}

// AnalyzeContext analyzes context around a match
func (v *Validator) AnalyzeContext(match string, context detector.ContextInfo) float64 {
	// Token-boundary matching (lineHasKeyword) instead of substring containment:
	// "auth" no longer scores "author", "pass" no longer scores "passenger", and
	// negative "open" no longer penalizes "openai_api_key". lineHasKeyword is
	// case-insensitive, so no ToLower allocation is needed (the previous code
	// lowercased context.FullLine once PER keyword inside the loop).
	fullLine := context.FullLine
	surrounding := context.BeforeText + " " + context.AfterText
	var confidenceImpact float64 = 0

	// Positive keywords increase confidence
	for _, keyword := range v.positiveKeywords {
		if lineHasKeyword(fullLine, keyword) {
			confidenceImpact += 10 // Same line
		} else if lineHasKeyword(surrounding, keyword) {
			confidenceImpact += 5 // Nearby context
		}
	}

	// Negative keywords decrease confidence
	for _, keyword := range v.negativeKeywords {
		if lineHasKeyword(fullLine, keyword) {
			confidenceImpact -= 20 // Same line
		} else if lineHasKeyword(surrounding, keyword) {
			confidenceImpact -= 10 // Nearby context
		}
	}

	// Cap impact
	if confidenceImpact > 30 {
		confidenceImpact = 30
	} else if confidenceImpact < -40 {
		confidenceImpact = -40
	}

	return confidenceImpact
}

// isSSHPrivateKey checks if the match is an SSH private key
func (v *Validator) isSSHPrivateKey(match string) bool {
	beginMarker := "-----" + "BEGIN"
	privateKeyMarker := "PRIVATE KEY" + "-----"
	endMarker := "-----" + "END"
	return strings.Contains(match, beginMarker) &&
		strings.Contains(match, privateKeyMarker) &&
		strings.Contains(match, endMarker)
}

// isCertificate checks if the match is a certificate
func (v *Validator) isCertificate(match string) bool {
	beginCert := "-----" + "BEGIN CERTIFICATE" + "-----"
	beginEncPriv := "-----" + "BEGIN " + "ENCRYPTED " + "PRIVATE KEY" + "-----"
	endMarker := "-----" + "END"
	return (strings.Contains(match, beginCert) ||
		strings.Contains(match, beginEncPriv)) &&
		strings.Contains(match, endMarker)
}

// isJWTToken checks if the match is a JWT token. Beyond the "eyJ" prefix and
// three dot-separated parts, it requires non-trivial segment lengths AND that
// the header segment base64url-decodes to JSON containing "alg". The previous
// prefix-and-dot-count check accepted "eyJ..", minified-JS identifiers
// ("eyJfile.min.js") and arbitrary "eyJabc.def.ghi" strings as confidence-100
// JWTs.
func (v *Validator) isJWTToken(match string) bool {
	parts := strings.Split(match, ".")
	if len(parts) != 3 || !strings.HasPrefix(match, "eyJ") {
		return false
	}
	// Real JWT header/payload are non-trivial; the signature is shorter but
	// never empty.
	if len(parts[0]) < 10 || len(parts[1]) < 10 || len(parts[2]) < 5 {
		return false
	}
	// The header must base64url-decode to JSON declaring an algorithm.
	decoded, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	return strings.Contains(string(decoded), `"alg"`)
}

// isAWSAccessKey checks if the match is an AWS access key: the table's
// AWS_ACCESS_KEY row, an exact 20-byte window. Before #769 this was a prefix
// and a length with no character-class check; the table adds the class, so a
// 20-byte token with a lowercase letter after AKIA is generic, not AWS.
func (v *Validator) isAWSAccessKey(match string) bool {
	typ, _ := providerTypeOf(match)
	return typ == "AWS_ACCESS_KEY"
}

// AWS secret access key detection (issue #147 item 4). The secret half of an
// AWS credential pair is exactly 40 chars of [A-Za-z0-9/+=] with NO
// distinguishing prefix — bare, that shape collides with SHA-1-adjacent
// tokens, git blob refs, and arbitrary base64, so the pattern is consulted
// ONLY when an AWS-specific context gate opens (see awsSecretContextOpen).
var (
	// reAWSSecretCandidate matches a 40-char secret-shaped token. Word
	// boundaries via explicit charset exclusion (base64 chars incl. / and +
	// are not regex word chars, so \b alone would split tokens). The LEFT
	// boundary permits '=' — base64 padding never leads a token, and the
	// KEY=value assignment form puts '=' immediately before the secret.
	reAWSSecretCandidate = regexp.MustCompile(`(^|[^A-Za-z0-9/+])([A-Za-z0-9/+]{40})(=*)($|[^A-Za-z0-9/+=])`)

	// reAWSSecretKeyName matches the ways the secret is labeled in real
	// configs: env style (AWS_SECRET_ACCESS_KEY), credentials-file style
	// (aws_secret_access_key), SDK/CloudFormation style (SecretAccessKey),
	// and loose prose ("secret access key"). Case-insensitive.
	reAWSSecretKeyName = regexp.MustCompile(`(?i)(?:aws_?)?secret_?access_?key|aws_?secret(?:_?key)?`)

	// reAKIAAnywhere detects a paired access-key ID nearby — the strongest
	// possible signal that a 40-char token is the matching secret.
	reAKIAAnywhere = regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)
)

// containsWordBoundary reports whether keyword appears in text as a whole
// word (text must already be lowercased). Prevents "test" from matching inside
// "latest" or "attestation".
//
// ModeAlnum treats '_' as a word boundary, so a keyword is found inside a
// snake_case identifier ("customer_ssn", "TEST_VALUE") exactly as it is
// between spaces. Code and config — where those identifiers dominate — are
// primary scan targets for this tool.
func containsWordBoundary(text, keyword string) bool {
	return kwmatch.ContainsLower(text, keyword)
}

// isKeywordAlnum reports whether b is an ASCII letter or digit.
func isKeywordAlnum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// isKeywordUpper reports whether b is an ASCII uppercase letter.
func isKeywordUpper(b byte) bool { return b >= 'A' && b <= 'Z' }

// isKeywordLowerOrDigit reports whether b is an ASCII lowercase letter or digit.
func isKeywordLowerOrDigit(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

// lineHasKeyword reports whether the lowercase keyword kw appears in text as a
// distinct token, matched case-insensitively. Unlike a plain strings.Contains,
// token boundaries are respected: string edges, any non-alphanumeric byte (so
// "api" and "key" BOTH match "api_key", "api-key", and "API_KEY"), and
// camelCase humps (so "token" matches "authToken" and "access" matches
// "accessToken").
//
// This eliminates the substring false positives that plain containment caused —
// "auth" no longer matches "author", "pass" no longer matches "passenger" /
// "bypass", "open" no longer matches "openai" / "openssl", "access" no longer
// matches "accessibility" — while still recognizing the snake_case, SCREAMING_
// SNAKE, kebab, and camelCase credential labels that real configs use. Unlike
// containsWordBoundary, '_' is treated as a boundary (not a word byte) so the
// dominant "api_key"/"access_token" labels keep matching their components.
func lineHasKeyword(text, kw string) bool {
	n, klen := len(text), len(kw)
	if klen == 0 || klen > n {
		return false
	}
	first := kw[0] // keywords are lowercase ASCII
	for from := 0; from+klen <= n; from++ {
		// Cheap first-byte reject (case-insensitive) before the full compare.
		c := text[from]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		if c != first {
			continue
		}
		if !strings.EqualFold(text[from:from+klen], kw) {
			continue
		}
		// Left boundary: string start, non-alnum predecessor, or a camelCase
		// hump where the match begins an uppercase run (e.g. "Token" in
		// "authToken").
		leftOK := from == 0 ||
			!isKeywordAlnum(text[from-1]) ||
			(isKeywordLowerOrDigit(text[from-1]) && isKeywordUpper(text[from]))
		if !leftOK {
			continue
		}
		end := from + klen
		// Right boundary: string end, non-alnum successor, or a camelCase hump
		// where an uppercase run starts right after the match (e.g. "access"
		// in "accessToken").
		rightOK := end == n ||
			!isKeywordAlnum(text[end]) ||
			(isKeywordLowerOrDigit(text[end-1]) && isKeywordUpper(text[end])) ||
			// A trailing plural "s" is the same context signal as the singular: `tokens:`,
			// `secrets:` and `passwords:` name a collection of exactly the thing the keyword
			// names. Without this the boundary check rejects them, and the consequence is not
			// cosmetic — measured, `tokens = "<credential>"` scored 55 against the keyword
			// path's threshold of 60 and was dropped, while `token = "<same credential>"`
			// scored 97. `api_keys` escaped only by accident, because it also contains the
			// standalone keyword "api".
			//
			// This is the same class of miss as the '_'-as-word-byte bug the corpus case
			// context_keywords_snake_case was written to lock: a keyword that is really present
			// going unrecognised because the boundary rule is stricter than the way identifiers
			// are actually written. See #746.
			//
			// The plural must itself end at a boundary, so this admits `tokens:` but not
			// `tokensize` or `secretsmanager`.
			isPluralBoundary(text, end)
		if rightOK {
			return true
		}
	}
	return false
}

// awsSecretContextOpen reports whether line (with its immediate neighbors)
// carries AWS-secret context: the secret's own key name on the line, or a
// paired AKIA/ASIA access key on the same or an adjacent line (credentials
// files list the two on consecutive lines).
func (v *Validator) awsSecretContextOpen(line, prevLine, nextLine string) bool {
	if reAWSSecretKeyName.MatchString(line) {
		return true
	}
	return reAKIAAnywhere.MatchString(line) ||
		reAKIAAnywhere.MatchString(prevLine) ||
		reAKIAAnywhere.MatchString(nextLine)
}

// findAWSSecretKeys detects AWS secret access keys on a line. Guards, in
// order: the context gate above (no gate, no scan — bare 40-char base64 is
// far too common); a placeholder/test-pattern check; an all-one-case check
// (real secrets mix cases — hex digests and YOUR_SECRET_HERE style
// placeholders typically don't); and a Shannon-entropy floor reusing the
// validator's base64 machinery. AKIA-prefixed tokens are excluded (they are
// the ID half, already detected). Runs O(line length) once per line.
func (v *Validator) findAWSSecretKeys(line, prevLine, nextLine string, lineNum int, originalPath string) []spannedMatch {
	if len(line) < 40 {
		return nil
	}
	if !v.awsSecretContextOpen(line, prevLine, nextLine) {
		return nil
	}
	// Test/documentation context suppresses the whole line — matching the
	// suppression the other secrets paths get from the context-aware
	// confidence calculation ("test secret_access_key example ..." is a
	// fixture, not a leak). Checked on the line only, not neighbors: a real
	// secret adjacent to a test line must still be reported.
	lowerLine := strings.ToLower(line)
	for _, kw := range []string{"test", "example", "sample", "fake", "mock", "placeholder", "dummy"} {
		if containsWordBoundary(lowerLine, kw) {
			return nil
		}
	}

	var results []spannedMatch
	for _, m := range reAWSSecretCandidate.FindAllStringSubmatchIndex(line, -1) {
		start, end := m[4], m[5] // capture group 2: the 40-char token
		candidate := line[start:end]

		// The ID half is handled by the AKIA pattern; don't double-report.
		if strings.HasPrefix(candidate, "AKIA") || strings.HasPrefix(candidate, "ASIA") {
			continue
		}
		// Placeholder / documentation values ("EXAMPLE", "wJalr..." is
		// intentionally NOT excluded — it is AWS's canonical doc secret and
		// the golden fixtures prove users paste it; test-context keywords are
		// the right suppressor for docs, not a value denylist).
		if v.isObviousPlaceholder(candidate) {
			continue
		}
		lower := strings.ToLower(candidate)
		if lower == candidate || strings.ToUpper(candidate) == candidate {
			// All-lowercase or all-uppercase 40-char runs are usually hashes,
			// hex blobs, or shouty placeholders, not AWS secrets (which are
			// base64 of random bytes — mixed case with overwhelming odds).
			continue
		}
		if v.calculateShannonEntropy(candidate, v.base64Charset) <= v.base64Limit {
			continue
		}

		confidence := 90.0 // context-gated + shape + entropy: strong evidence
		// Both signals are captured into variables so they can be RECORDED as validation
		// checks below, not only consumed by the score.
		//
		// The pairing regex is evaluated unconditionally, where the original expression
		// short-circuited it behind the label check. That is deliberate: recording
		// "paired_access_key_id: false" for a value whose pairing was never examined would be
		// a false statement in user-facing output, and the two conditions are independent —
		// an AKIA can sit beside an unlabelled secret. The cost is one regex over two lines,
		// negligible next to the Shannon-entropy computation that already gated this point.
		labeledKeyName := reAWSSecretKeyName.MatchString(line)
		pairedAccessKeyID := reAKIAAnywhere.MatchString(prevLine + nextLine)
		if labeledKeyName && pairedAccessKeyID {
			confidence = 95.0 // labeled AND paired with an access key ID
		}
		// A literal "EXAMPLE" embedded in the value is near-proof of an AWS
		// documentation placeholder (wJalr...CYEXAMPLEKEY and friends): real
		// secrets are random base64, where a 7-char literal is a ~1-in-10^9
		// event. Demote but keep it visible/redactable — mirroring how the
		// AKIA...EXAMPLE access-key ID stays detected rather than being
		// value-denylisted.
		//
		// Two things changed here for #364. The bound moved from a local 65 to the
		// shared awsDocPlaceholderCeiling (15, top of LOW) so this validator agrees
		// with creditcard/phone/otp instead of inventing its own number. And the
		// bound is PUBLISHED, because clamping locally did not hold: measured,
		// wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY was capped to 65 right here and
		// still reported at 75 — mergeBySpanKeepStrongest takes the max of this
		// path and the generic entropy path, and the bridge then adds document
		// context, both after this line runs. The bridge honours the published
		// ceiling (clampToCeiling) after every raise, which is the only place the
		// cap can actually be made to stick.
		placeholderCeiling := awsDocPlaceholderCap("AWS_SECRET_ACCESS_KEY", candidate)
		exampleEmbedded := placeholderCeiling > 0
		if exampleEmbedded && confidence > placeholderCeiling {
			confidence = placeholderCeiling
		}

		meta := map[string]any{
			"detection_method": "aws_secret_context",
			"source":           "preprocessed_content",
			"secret_type":      "AWS_SECRET_ACCESS_KEY",
			"example_embedded": exampleEmbedded,
			// This dedicated AWS-secret path set no validation_checks, so --explain
			// had nothing to narrate: a 75% MEDIUM secret — exactly the finding a
			// reviewer needs help judging — explained as "Flagged as an AWS secret
			// access key. (confidence 75%, medium)" and nothing more (#363). The
			// package's OTHER emit sites do record checks; this one was missed.
			//
			// Every value below was already computed above, so this records rather
			// than decides: no confidence changes, and metadata is not a suppression
			// hash input.
			//
			// not_test_data is spelled to match the key the explain layer already
			// consults for a test signal, so an EXAMPLE-embedded placeholder now
			// reports its own test judgement instead of hiding it in a metadata field
			// nothing reads.
			"validation_checks": map[string]bool{
				"valid_shape":          true, // charset and length gate above
				"entropy":              true, // above v.base64Limit
				"labeled_key_name":     labeledKeyName,
				"paired_access_key_id": pairedAccessKeyID,
				"not_test_data":        !exampleEmbedded,
			},
		}
		if placeholderCeiling > 0 {
			meta[ConfidenceCeilingKey] = placeholderCeiling
		}

		results = append(results, spannedMatch{
			start: start,
			end:   end,
			match: detector.Match{
				Text:       candidate,
				LineNumber: lineNum + 1,
				Type:       "AWS_SECRET_ACCESS_KEY",
				Confidence: confidence,
				Filename:   originalPath,
				Validator:  "secrets",
				Metadata:   meta,
				// The line is already an input to the confidence above (the
				// reAWSSecretKeyName gate), so recording it is inert for scoring
				// and only preserves what a reviewer needs to judge the finding.
				Context: detector.LineContext(line, start, end),
			},
		})
	}
	return results
}

// The per-provider predicates below are thin wrappers over the grammar table's
// anchored predicate (provider_rules.go), kept under their old names because
// tests and the explain layer call them by provider. Each is exactly "the table
// says this match is a complete token of that type": a prefix, the body charset
// and the row's length rule, which for Stripe, GitLab and Slack is a minimum
// and for the others an exact window. Before #769 each was its own prefix-plus-
// length check, locked to the same fixed windows as the regexes, so a longer
// token was neither matched whole nor recognised whole.

// isGitHubToken checks if the match is a GitHub token
func (v *Validator) isGitHubToken(match string) bool {
	typ, _ := providerTypeOf(match)
	return typ == "GITHUB_TOKEN"
}

// isGoogleCloudAPIKey checks if the match is a Google Cloud API key
func (v *Validator) isGoogleCloudAPIKey(match string) bool {
	typ, _ := providerTypeOf(match)
	return typ == "GOOGLE_CLOUD_API_KEY"
}

// isStripeAPIKey checks if the match is a Stripe API key
func (v *Validator) isStripeAPIKey(match string) bool {
	typ, _ := providerTypeOf(match)
	return typ == "STRIPE_API_KEY"
}

// isGitLabToken checks if the match is a GitLab personal access token
func (v *Validator) isGitLabToken(match string) bool {
	typ, _ := providerTypeOf(match)
	return typ == "GITLAB_TOKEN"
}

// isDockerToken checks if the match is a Docker Hub personal access token
func (v *Validator) isDockerToken(match string) bool {
	typ, _ := providerTypeOf(match)
	return typ == "DOCKER_TOKEN"
}

// isSlackToken checks if the match is a Slack token. It validates the full token
// structure rather than just the prefix: the previous prefix-only check returned
// true for any string starting with the bot/user token prefix and scored it 94.
func (v *Validator) isSlackToken(match string) bool {
	typ, _ := providerTypeOf(match)
	return typ == "SLACK_TOKEN"
}

// isPGPPrivateKey checks if the match is a PGP private key. Markers are
// concatenated to avoid tripping detect-private-key style scanners (matches
// the convention used by pemBeginMarker / pemEndMarker at package level).
func (v *Validator) isPGPPrivateKey(match string) bool {
	return strings.Contains(match, pemBeginMarker+" PGP PRIVATE KEY BLOCK"+"-----") &&
		strings.Contains(match, pemEndMarker+" PGP PRIVATE KEY BLOCK"+"-----")
}

// IsShellVariableReference checks if a match is just a shell variable reference rather than an actual secret
func (v *Validator) IsShellVariableReference(line, match string) bool {
	// Handle cases where match already includes the $ sign
	var baseMatch string
	if strings.HasPrefix(match, "$") {
		baseMatch = match[1:] // Remove the $ prefix
	} else {
		baseMatch = match
	}

	return v.checkDirectVariableReference(line, match) ||
		v.checkShellPatterns(line, baseMatch) ||
		v.checkVariableUsagePatterns(line, baseMatch)
}

// checkDirectVariableReference checks if the full match (including $) appears as a direct variable reference
func (v *Validator) checkDirectVariableReference(line, match string) bool {
	if strings.HasPrefix(match, "$") && strings.Contains(line, match) {
		// Fast string-based check for assignment patterns (avoid regex)
		// Look for patterns like $session_token="value" or $session_token='value'
		if strings.Contains(line, match+`="`) || strings.Contains(line, match+`='`) {
			return false // This is an assignment, not a reference
		}
		return true
	}
	return false
}

// checkShellPatterns checks for standard shell variable patterns like $var and ${var}
func (v *Validator) checkShellPatterns(line, baseMatch string) bool {
	// Fast string-based checks (no regex compilation overhead)
	if strings.Contains(line, "$"+baseMatch) || strings.Contains(line, "${"+baseMatch+"}") {
		// Make sure this isn't an assignment like session_token="actual_value"
		if !strings.Contains(line, baseMatch+`="`) && !strings.Contains(line, baseMatch+`='`) {
			return true
		}
	}
	return false
}

// checkVariableUsagePatterns checks for shell variable usage in common command contexts
func (v *Validator) checkVariableUsagePatterns(line, baseMatch string) bool {
	// Fast string-based checks for common shell commands
	if v.shellCommandPattern.MatchString(line) && strings.Contains(line, "$"+baseMatch) {
		return true
	}

	// Check for quoted variable references like "$session_token"
	if strings.Contains(line, `"`+"$"+baseMatch+`"`) || strings.Contains(line, `'`+"$"+baseMatch+`'`) {
		return true
	}

	return false
}

// isMatchShellVariableReference is an optimized version of IsShellVariableReference
// that assumes the line has already been pre-checked to contain shell variables
func (v *Validator) isMatchShellVariableReference(line, match string) bool {
	// Handle cases where match already includes the $ sign
	var baseMatch string
	if strings.HasPrefix(match, "$") {
		baseMatch = match[1:] // Remove the $ prefix
		// Direct check for full match (including $) in shell variable context
		if strings.Contains(line, match) {
			// Quick check: if it's in quotes and looks like a variable reference
			if strings.Contains(line, `"`+match+`"`) || strings.Contains(line, `'`+match+`'`) {
				return true
			}
		}
	} else {
		baseMatch = match
	}

	// Fast string-based checks for common patterns (avoid regex when possible)
	if strings.Contains(line, "$"+baseMatch) || strings.Contains(line, "${"+baseMatch+"}") {
		// Additional check: make sure this isn't an assignment like session_token="actual_value"
		if !strings.Contains(line, baseMatch+`="`) && !strings.Contains(line, baseMatch+`='`) {
			return true
		}
	}

	return false
}

// isObviousPlaceholder checks if a match is an obvious placeholder that should never be detected
func (v *Validator) isObviousPlaceholder(match string) bool {
	lowerMatch := strings.ToLower(match)

	// Check against globalTestPatterns for obvious placeholder patterns
	// This eliminates duplication by using the existing patterns in the validator
	for _, testPattern := range v.globalTestPatterns {
		if lowerMatch == strings.ToLower(testPattern) {
			// Only consider patterns that are obvious placeholders (not test-specific patterns)
			if v.isObviousPlaceholderPattern(testPattern) {
				return true
			}
		}
	}
	return false
}

// isObviousPlaceholderPattern determines if a pattern is an obvious placeholder vs a test-specific pattern
func (v *Validator) isObviousPlaceholderPattern(pattern string) bool {
	// Obvious placeholders are the first 8 patterns in globalTestPatterns
	// This eliminates duplication by using the existing patterns
	obviousPlaceholderCount := 8

	lowerPattern := strings.ToLower(pattern)
	for i, testPattern := range v.globalTestPatterns {
		if i >= obviousPlaceholderCount {
			break // Only check the first 8 patterns (obvious placeholders)
		}
		if lowerPattern == strings.ToLower(testPattern) {
			return true
		}
	}
	return false
}

// processScopedCandidates is a unified method for processing both entropy and
// keyword matches. This eliminates code duplication between the two detection
// methods; each candidate carries the detection path it came from, so both can
// be arbitrated against each other by span (see dedupeScopedBySpan) and still
// be judged against their own confidence threshold and labelled with their own
// detection_method.
// govKeyLine, when non-empty, is the line carrying the key that GOVERNS every candidate on this
// line, for a value that does not sit on the same line as its key. Today that is only a YAML block
// sequence (#746 shape (c)):
//
//	api_keys:          <- govKeyLine
//	  - <secret>       <- line
//
// Without it the item scores as though no keyword were present anywhere, because on its own line
// none is — which is wrong in substance, and measurably so: of two credentials under the same key,
// `Sup3rS3cretDbPass!` reached 100 on its intrinsic character classes alone while
// `AnotherS3cretValue99` fell below the reporting threshold and vanished. The key is what makes
// both of them credentials; it just is not on their line.
func (v *Validator) processScopedCandidates(matches []scopedCandidate, line string, lineNum int, originalPath string, content string, contextInsights context.ContextInsights, lineHasShellVars bool, envType string, isShellScript bool, govKeyLine string) []spannedMatch {
	var results []spannedMatch

	// Hoisted out of the candidate loop: the nearby-keyword answer depends only on the
	// line, so computing it per candidate made the scan quadratic in the number of
	// candidates on one line. See lineKeywordState for the measurement.
	lineKw := v.lineHasAnyPositiveKeyword(line)
	if lineKw != lineKeywordPresent && govKeyLine != "" {
		if govKw := v.lineHasAnyPositiveKeyword(govKeyLine); govKw == lineKeywordPresent {
			lineKw = govKw
		}
	}

	for _, cand := range matches {
		match := cand.text
		detectionMethod := cand.method
		confidenceThreshold := cand.threshold
		// Skip shell variable references that aren't actual secret values
		// Only perform expensive regex checks if the line potentially has shell variables
		if lineHasShellVars && v.isMatchShellVariableReference(line, match) {
			continue
		}

		// PERFORMANCE: pass the known line as the nearby-keyword hint so the
		// confidence calculation does not rescan the whole content per match
		// (strings.Index over fullContent). For per-line matches the match
		// always originates from this exact line, so this is behavior-preserving
		// and additionally avoids the latent first-occurrence bug where a
		// duplicated token resolves to a different line's context.
		confidence, checks := v.calculateEnhancedConfidenceWithCacheAndEnvAndLine(match, content, line, lineKw, contextInsights, isShellScript, envType, cand.structural)

		// Skip matches with 0% confidence - they are false positives
		if confidence <= 0 {
			continue
		}

		if confidence > confidenceThreshold {
			secretType := v.getSecretType(match)
			meta := map[string]any{
				"validation_checks": checks,
				"detection_method":  detectionMethod,
				"source":            "preprocessed_content",
				"context_domain":    contextInsights.Domain,
				"context_doc_type":  contextInsights.DocumentType,
				"environment_type":  envType,
				"secret_type":       secretType,
			}
			// A bare hex identifier on an unlabelled line gets a hard ceiling that the
			// bridge's downstream context and cross-path adjustments must respect.
			// Clamping here alone would not hold: those adjustments are applied after
			// the validator returns and took one such value from 55 to 80.
			//
			// An AWS documentation placeholder gets one for the same reason: measured
			// on AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE, this path's own score is 94
			// and the reported result was 84 — a downstream adjustment, not a clamp,
			// so a locally-applied cap would have been lifted straight back.
			//
			// The lowest applicable ceiling wins. The two cannot both fire today
			// (one requires genericSecretType, the other excludes it), but selecting
			// the minimum keeps that from becoming a silent precedence bug if a third
			// ceiling is added, and keeps the PUBLISHED bound equal to the applied one.
			ceiling := unlabelledHexIdentifierCap(secretType, match, line)
			if c := awsDocPlaceholderCap(secretType, match); c > 0 {
				if ceiling == 0 || c < ceiling {
					ceiling = c
				}
				// Record the judgement, do not just act on it. not_test_data is the key
				// the explain layer consults for a test signal, and without it a capped
				// placeholder explained as "uncertain" while the validator knew exactly
				// why it had demoted the value — the disclosure half of #363/#364. The
				// AWS-secret path at findAWSSecretKeys already spells it this way.
				checks["not_test_data"] = false
			}
			if c := cand.ceiling; c > 0 && (ceiling == 0 || c < ceiling) {
				ceiling = c
			}
			if ceiling > 0 {
				meta[ConfidenceCeilingKey] = ceiling
				if confidence > ceiling {
					confidence = ceiling
				}
			}
			results = append(results, spannedMatch{
				start: cand.start,
				end:   cand.end,
				match: detector.Match{
					Text:       match,
					LineNumber: lineNum + 1,
					Type:       secretType,
					Confidence: confidence,
					Filename:   originalPath,
					Validator:  "secrets",
					Metadata:   meta,
					// calculateEnhancedConfidenceWithCacheAndEnvAndLine and
					// unlabelledHexIdentifierCap both already read this line, so
					// this records the context they judged against.
					Context: detector.LineContext(line, cand.start, cand.end),
				},
			})
		}
	}

	return results
}

// LineContainsShellVariableReferences performs a fast check to see if a line contains shell variable patterns
// This optimization avoids expensive regex operations when no shell variables are present
func (v *Validator) LineContainsShellVariableReferences(line string) bool {
	// Fast string-based checks first (no regex)
	if !strings.Contains(line, "$") {
		return false // No shell variables possible without $
	}

	// Quick pattern checks for common shell variable formats
	if strings.Contains(line, "${") {
		return true // ${var} format
	}

	// Check for $var format (simple character-based check, no regex)
	for i, char := range line {
		if char == '$' && i+1 < len(line) {
			nextChar := rune(line[i+1])
			// Check if next character could start a variable name
			if (nextChar >= 'a' && nextChar <= 'z') ||
				(nextChar >= 'A' && nextChar <= 'Z') ||
				nextChar == '_' {
				return true
			}
		}
	}

	return false
}

// IsShellScriptContext determines if the content appears to be from a shell script
func (v *Validator) IsShellScriptContext(content string) bool {
	shellIndicators := []string{
		"#!/bin/bash", "#!/bin/sh", "#!/usr/bin/env bash",
		"set -e", "set -x", "export ", "source ", ". ",
		"if [", "then", "fi", "for ", "while ", "do", "done",
		"echo ", "printf ", "curl ", "wget ",
	}

	lowerContent := strings.ToLower(content)
	indicatorCount := 0

	for _, indicator := range shellIndicators {
		if strings.Contains(lowerContent, strings.ToLower(indicator)) {
			indicatorCount++
		}
	}

	// If we find multiple shell indicators, it's likely a shell script
	return indicatorCount >= 2
}

// looksLikeVariableName checks if a match looks like a variable name rather than a secret value
func (v *Validator) looksLikeVariableName(match string) bool {
	// Variable names typically:
	// - Contain underscores
	// - Are all lowercase or UPPERCASE
	// - Don't contain special characters typical of secrets
	// - Are relatively short (variable names vs long secret values)

	if len(match) > 50 {
		return false // Too long to be a typical variable name
	}

	// Check for variable naming patterns (using pre-compiled patterns)
	for _, pattern := range v.variablePatterns {
		if pattern.MatchString(match) {
			// Additional check: common variable name endings
			commonVarSuffixes := []string{"_token", "_key", "_secret", "_password", "_auth", "_credential"}
			for _, suffix := range commonVarSuffixes {
				if strings.HasSuffix(strings.ToLower(match), suffix) {
					return true
				}
			}
		}
	}

	return false
}

// findMultiLineSecretsWithContext finds multi-line secrets with enhanced context analysis
//
// The matches emitted here deliberately carry no Context. ContextInfo describes a
// match's position within one line -- FullLine plus the text either side of it --
// and a PEM block spans dozens, so there is no line for the value to sit in and no
// honest way to fill the fields. A caller reading empty context on an
// SSH_PRIVATE_KEY / CERTIFICATE / PGP_PRIVATE_KEY finding is seeing "not
// applicable", which is the same thing the field's doc comment already tells them
// empty means. Single-line secrets, which are the overwhelming majority, do record
// it -- see findAWSSecretKeys and processScopedCandidates.
func (v *Validator) findMultiLineSecretsWithContext(content, filePath string, contextInsights context.ContextInsights, isShellScript bool, envType string) []detector.Match {
	var matches []detector.Match

	// Process SSH keys
	for _, pattern := range multiLineSSHPatterns {
		found := pattern.FindAllString(content, -1)
		for _, match := range found {
			lineNum := v.findLineNumber(content, match)
			confidence, checks := v.calculateEnhancedConfidenceWithCacheAndEnv(match, content, contextInsights, isShellScript, envType)

			matches = append(matches, detector.Match{
				Text:       match,
				LineNumber: lineNum,
				Type:       "SSH_PRIVATE_KEY",
				Confidence: confidence,
				Filename:   filePath,
				Validator:  "secrets",
				// #nosec G101 -- detection metadata; secret_type is a label
				// classifying what we found, not a credential value.
				Metadata: map[string]any{
					"validation_checks": checks,
					"detection_method":  "ssh_private_key",
					"secret_type":       "SSH_PRIVATE_KEY",
					"context_domain":    contextInsights.Domain,
					"context_doc_type":  contextInsights.DocumentType,
					"environment_type":  envType,
				},
			})
		}
	}

	// Process certificates
	for _, pattern := range multiLineCertPatterns {
		found := pattern.FindAllString(content, -1)
		for _, match := range found {
			lineNum := v.findLineNumber(content, match)
			confidence, checks := v.calculateEnhancedConfidenceWithCacheAndEnv(match, content, contextInsights, isShellScript, envType)

			matches = append(matches, detector.Match{
				Text:       match,
				LineNumber: lineNum,
				Type:       "CERTIFICATE",
				Confidence: confidence,
				Filename:   filePath,
				Validator:  "secrets",
				Metadata: map[string]any{
					"validation_checks": checks,
					"detection_method":  "certificate",
					"secret_type":       "CERTIFICATE",
					"context_domain":    contextInsights.Domain,
					"context_doc_type":  contextInsights.DocumentType,
					"environment_type":  envType,
				},
			})
		}
	}

	// Process PGP private keys
	for _, pattern := range multiLinePGPPatterns {
		found := pattern.FindAllString(content, -1)
		for _, match := range found {
			lineNum := v.findLineNumber(content, match)
			confidence, checks := v.calculateEnhancedConfidenceWithCacheAndEnv(match, content, contextInsights, isShellScript, envType)

			matches = append(matches, detector.Match{
				Text:       match,
				LineNumber: lineNum,
				Type:       "PGP_PRIVATE_KEY",
				Confidence: confidence,
				Filename:   filePath,
				Validator:  "secrets",
				// #nosec G101 -- detection metadata; secret_type is a label
				// classifying what we found, not a credential value.
				Metadata: map[string]any{
					"validation_checks": checks,
					"detection_method":  "pgp_private_key",
					"secret_type":       "PGP_PRIVATE_KEY",
					"context_domain":    contextInsights.Domain,
					"context_doc_type":  contextInsights.DocumentType,
					"environment_type":  envType,
				},
			})
		}
	}

	return matches
}

// CalculateEnhancedConfidence calculates confidence with context analysis
func (v *Validator) CalculateEnhancedConfidence(match, fullContent string, contextInsights context.ContextInsights) (float64, map[string]bool) {
	// Use the optimized version with shell script context detection
	isShellScript := v.IsShellScriptContext(fullContent)
	envType := v.detectEnvironmentType(fullContent)
	return v.calculateEnhancedConfidenceWithCache(match, fullContent, contextInsights, isShellScript, envType)
}

// calculateEnhancedConfidenceWithCache is an optimized version of CalculateEnhancedConfidence
// that accepts pre-computed context values to avoid redundant computation
func (v *Validator) calculateEnhancedConfidenceWithCache(match, fullContent string, contextInsights context.ContextInsights, isShellScript bool, envType string) (float64, map[string]bool) {
	return v.calculateEnhancedConfidenceWithCacheAndEnv(match, fullContent, contextInsights, isShellScript, envType)
}

// calculateEnhancedConfidenceWithCacheAndEnv is the fully optimized confidence calculation
// that accepts all pre-computed context values to maximize performance.
// It is used by the multi-line detection path, which never reaches the
// nearby-keyword check (those matches are always specific_pattern=true), so it
// passes an empty line hint.
func (v *Validator) calculateEnhancedConfidenceWithCacheAndEnv(match, fullContent string, contextInsights context.ContextInsights, isShellScript bool, envType string) (float64, map[string]bool) {
	return v.calculateEnhancedConfidenceWithCacheAndEnvAndLine(match, fullContent, "", lineKeywordUnknown, contextInsights, isShellScript, envType, false)
}

// calculateEnhancedConfidenceWithCacheAndEnvAndLine is identical to
// calculateEnhancedConfidenceWithCacheAndEnv but additionally accepts the known
// line containing the match. When non-empty, the nearby-keyword corroboration
// check inspects that line directly instead of rescanning the whole content via
// strings.Index — eliminating an O(content) scan per match (the O(n^2) hot path)
// and the latent first-occurrence bug for duplicated tokens.
//
// structural is scopedCandidate.structural: it exempts the candidate from the M24
// cap and changes nothing else.
func (v *Validator) calculateEnhancedConfidenceWithCacheAndEnvAndLine(match, fullContent, lineHint string, lineKw lineKeywordState, contextInsights context.ContextInsights, isShellScript bool, envType string, structural bool) (float64, map[string]bool) {
	// Start with base confidence calculation
	confidence, checks := v.CalculateConfidence(match)

	// Apply context-based adjustments
	contextAdjustment := v.contextAnalyzer.GetConfidenceAdjustment(contextInsights, "secrets")
	confidence += contextAdjustment

	// Environment / domain / document-type adjustments accumulate into ctxDelta
	// rather than being applied directly, so the POSITIVE stack can be clamped
	// for generic matches (see below). Penalties are unbounded — we never want
	// to cap how far a test/dev signal can pull a candidate down.
	var ctxDelta float64

	// Whether a positive secret keyword shares the match's line. Computed here,
	// ahead of the environment switch, because two decisions below depend on it:
	// the file-wide penalty waiver just under this comment and the M24 cap at the
	// end. The multi-line path passes lineKeywordUnknown and still pays the one
	// strings.Index it always paid; the per-line path passes the hoisted answer.
	nearbyKeyword := lineKw == lineKeywordPresent
	if lineKw == lineKeywordUnknown {
		nearbyKeyword = v.hasNearbySecretKeyword(fullContent, match, lineHint)
	}

	// corroborated means the candidate carries its own evidence of being a
	// credential: a typed provider literal (AWS, GitHub, Stripe, JWT, ...) or a
	// secret keyword on its line. The file-wide test/dev verdict was written for
	// the OTHER population -- bare high-entropy strings that nothing on their
	// line labels -- and it keeps its full, unbounded reach there. On a
	// corroborated candidate it is waived (#785). Applied to everything, one
	// marker anywhere in the file moved every credential in it: a comment saying
	// "pinned to the latest image" took a GitHub token from HIGH 93 to MEDIUM 68
	// and the shipped pre-commit gate let the commit through, and two hostnames
	// containing "example" took a six-line credentials file to exactly 60, where
	// the strict threshold dropped all six -- "No matches found", exit 0, no
	// redacted copy. The production boost is not a penalty and stays file-wide;
	// the M27 cap below already bounds it for generic matches.
	corroborated := checks["specific_pattern"] || nearbyKeyword

	// Environment-specific adjustments (using pre-computed environment type)
	switch envType {
	case "development":
		// Development environments may have test secrets
		if !corroborated {
			ctxDelta -= 15.0
			checks["dev_environment_penalty"] = true
		}
	case "production":
		// Production environments more likely to have real secrets
		ctxDelta += 10.0
		checks["prod_environment_boost"] = true
	case "test":
		// Test environments likely have fake secrets
		if !corroborated {
			ctxDelta -= 25.0
			checks["test_environment_penalty"] = true
		}
	}

	// Domain-specific adjustments
	switch contextInsights.Domain {
	case "Financial":
		// Financial domain more likely to have API keys
		ctxDelta += 12.0
		checks["financial_domain_boost"] = true
	case "Healthcare":
		// Healthcare may have fewer API keys, more certificates
		if v.isCertificate(match) || v.isSSHPrivateKey(match) {
			ctxDelta += 8.0
		} else {
			ctxDelta -= 5.0
		}
		checks["healthcare_domain_adjustment"] = true
	}

	// Document type adjustments
	switch contextInsights.DocumentType {
	case "Configuration":
		// Configuration files very likely to contain secrets
		ctxDelta += 15.0
		checks["config_file_boost"] = true
	case "Code":
		// Code files may have hardcoded secrets (bad practice)
		ctxDelta += 8.0
		checks["code_file_boost"] = true
	case "JSON", "YAML":
		// Structured config files
		ctxDelta += 12.0
		checks["structured_config_boost"] = true
	}

	// For generic matches (no specific typed pattern like AWS/JWT/GitHub), clamp
	// the NET positive environmental stack to +30 so structured-config boosts
	// cannot compound (prod +10, Financial +12, Config +15 = +37) into a flat
	// HIGH on shape alone. Specific patterns are already self-evidently
	// credentials and keep the full boost. Negative deltas pass through
	// unchanged. This complements the M24 cap, which handles uncorroborated
	// generic matches; this handles corroborated-but-only-structurally-boosted
	// ones (M27).
	if !checks["specific_pattern"] && ctxDelta > 30.0 {
		ctxDelta = 30.0
		checks["generic_context_boost_capped"] = true
	}
	confidence += ctxDelta

	// Global test pattern check - hard filter for obvious placeholders
	if v.matchesGlobalTestPatterns(match) {
		// For obvious placeholder patterns, set confidence to 0 to completely filter them
		if v.isObviousPlaceholder(match) {
			confidence = 0
		} else {
			confidence -= 35.0
		}
		checks["global_test_pattern"] = true
	}

	// Shell script context adjustments (using cached result for performance)
	if isShellScript {
		// In shell scripts, reduce confidence for variable-like patterns
		if v.looksLikeVariableName(match) {
			confidence -= 20.0
			checks["shell_variable_penalty"] = true
		}
	}

	// Generic high-entropy strings (git SHAs, UUIDs, base64 asset hashes) start at
	// base 85 and the doc-type boosts above can push them to HIGH with no evidence
	// they are credentials (M24). When the match is NOT a specific typed pattern
	// (AWS/JWT/GitHub/...) and there is no corroborating secret keyword nearby,
	// cap it just below the MEDIUM threshold so it does not surface as MEDIUM/HIGH
	// on shape alone. A specific pattern, or a nearby secret keyword, lifts it.
	// nearbyKeyword was computed above, ahead of the environment switch.
	//
	// A structural candidate is exempt: a password in URI user info is labelled by the URI
	// grammar itself, and capping it at 55 held every keyword-free DATABASE_URL under the
	// reporting threshold of the paths that could see one (#766).
	if !checks["specific_pattern"] && !nearbyKeyword && !structural {
		if confidence > 55 {
			confidence = 55
		}
	}

	// Ensure confidence bounds
	if confidence < 0 {
		confidence = 0
	} else if confidence > 100 {
		confidence = 100
	}

	return confidence, checks
}

// lineKeywordState memoizes hasNearbySecretKeyword's answer for one line.
//
// The answer depends only on the LINE, so it is identical for every candidate on that
// line — but it was recomputed per candidate, and each recomputation scans the whole
// line once per positive keyword. On a single line holding K assignments the line
// length grows with K, so the cost was O(K x lineLen x keywords), i.e. quadratic in K.
//
// Measured on one line of K quoted password= assignments, before this:
//
//	K =  1000   0.46s
//	K =  2000   0.37s
//	K =  4000   1.22s   3.30x
//	K =  8000   4.62s   3.79x
//	K = 16000  17.70s   3.83x   <- converging on 4x, i.e. quadratic
//
// with findings staying linear in K. A CPU profile attributed 86% of the run to
// lineHasKeyword and 100% of THAT to hasNearbySecretKeyword — not to AnalyzeContext,
// which #362 also names. The keyword scan itself is fine; calling it per candidate is
// not.
//
// A tri-state rather than a bool because the multi-line fallback path calls the
// confidence function with no line hint and must keep computing the answer itself.
type lineKeywordState int8

const (
	// lineKeywordUnknown means the caller has no per-line answer, so the callee
	// computes it as before.
	lineKeywordUnknown lineKeywordState = iota
	lineKeywordAbsent
	lineKeywordPresent
)

// lineHasAnyPositiveKeyword computes the per-line answer once, for hoisting out of a
// per-candidate loop.
func (v *Validator) lineHasAnyPositiveKeyword(line string) lineKeywordState {
	for _, kw := range v.positiveKeywords {
		if lineHasKeyword(line, kw) {
			return lineKeywordPresent
		}
	}
	return lineKeywordAbsent
}

// hasNearbySecretKeyword reports whether a positive secret keyword appears on the
// same line as the match — corroboration that a generic high-entropy string is a
// credential rather than an incidental hash/UUID/blob.
//
// When lineHint is non-empty it is the already-known line containing the match
// (the per-line detection path), so we inspect it directly and skip the
// O(content) strings.Index rescan. The empty-hint fallback (used by the
// multi-line path, which in practice never reaches this check) reconstructs the
// line from the full content exactly as before.
func (v *Validator) hasNearbySecretKeyword(fullContent, match, lineHint string) bool {
	line := lineHint
	if line == "" {
		line = match
		if idx := strings.Index(fullContent, match); idx >= 0 {
			start := strings.LastIndexByte(fullContent[:idx], '\n') + 1
			end := idx + len(match)
			if nl := strings.IndexByte(fullContent[end:], '\n'); nl >= 0 {
				end += nl
			} else {
				end = len(fullContent)
			}
			line = fullContent[start:end]
		}
	}
	// Token-boundary matching (lineHasKeyword, case-insensitive) so an
	// incidental substring — "auth" inside "author", "key" inside "monkey" —
	// no longer corroborates an unrelated high-entropy hash as a credential.
	for _, kw := range v.positiveKeywords {
		if lineHasKeyword(line, kw) {
			return true
		}
	}
	return false
}

// detectEnvironmentType detects if content is from development, test, or production environment.
//
// The verdict is FILE-WIDE: one marker anywhere in the content classifies every
// candidate in it, and the classification moves every candidate's confidence
// (see the envType switch in calculateEnhancedConfidenceWithCacheAndEnvAndLine).
// That reach is why the markers are matched as whole tokens and not as
// substrings (#785). Matched by strings.Contains, "test" fired on "latest" and
// "attestation", "dev" on "device", "local" on "locale", "live" on "delivery",
// ".prod" on "metadata.Producer" and "stage" on "stages": measured with these
// lists on the golden corpus, 67 of 455 fixtures took their verdict ONLY from a
// substring inside a longer word, and one comment saying "pinned to the latest
// image" moved a GitHub token from HIGH 93 to MEDIUM 68 -- below the shipped
// pre-commit gate. See hasEnvMarker for the token rule.
func (v *Validator) detectEnvironmentType(content string) string {
	lowerContent := strings.ToLower(content)

	// Count keywords for each environment type
	devScore := 0
	testScore := 0
	prodScore := 0

	for _, keyword := range v.devKeywords {
		if hasEnvMarker(lowerContent, keyword) {
			devScore++
		}
	}

	for _, keyword := range v.testKeywords {
		if hasEnvMarker(lowerContent, keyword) {
			testScore++
		}
	}

	for _, keyword := range v.prodKeywords {
		if hasEnvMarker(lowerContent, keyword) {
			prodScore++
		}
	}

	// Determine environment based on highest score
	if testScore > devScore && testScore > prodScore && testScore > 0 {
		return "test"
	} else if devScore > prodScore && devScore > 0 {
		return "development"
	} else if prodScore > 0 {
		return "production"
	}

	return "unknown"
}

// hasEnvMarker reports whether marker occurs in lowerContent as a whole token.
// Both arguments must already be lowercased.
//
// A plain-word marker ("test", "dev", "live") is bounded on both sides by the
// string edge or a non-word byte, under the word definition the kwmatch package
// documents: [a-z0-9] are word bytes and '_' is a boundary. So "test" is found
// in "TEST_VALUE" and "unit_test" but not in "latest" or "attestation"; "dev" in
// "dev-db" and "/dev/" but not in "device"; "local" in "local.yml" but not in
// "locale". That half is kwmatch.ContainsLower, the one implementation every
// validator's context scoring shares.
//
// An AFFIX marker -- one whose first or last byte is itself a separator, which is
// how the production list spells "prod-", "prod_" and ".prod" to stay clear of
// "product" and "produce" -- is bounded only on its word side. ".prod" must not
// run on into a word ("db.prod" and "db.prod.internal" match, "metadata.producer"
// does not), while the byte before its '.' is unconstrained, because the '.' is
// the boundary. kwmatch cannot express that: it requires a non-word byte on both
// sides of the whole marker, so "prod-" would match only when followed by
// another separator and ".prod" only when preceded by one, i.e. "my-prod-db" and
// "db.prod" would both be missed.
func hasEnvMarker(lowerContent, marker string) bool {
	if marker == "" {
		return false
	}
	wordLeft := isKeywordLowerOrDigit(marker[0])
	wordRight := isKeywordLowerOrDigit(marker[len(marker)-1])
	if wordLeft && wordRight {
		return kwmatch.ContainsLower(lowerContent, marker)
	}
	for from := 0; from+len(marker) <= len(lowerContent); {
		i := strings.Index(lowerContent[from:], marker)
		if i < 0 {
			return false
		}
		i += from
		end := i + len(marker)
		leftOK := !wordLeft || i == 0 || !isKeywordLowerOrDigit(lowerContent[i-1])
		rightOK := !wordRight || end == len(lowerContent) || !isKeywordLowerOrDigit(lowerContent[end])
		if leftOK && rightOK {
			return true
		}
		from = i + 1
	}
	return false
}

// matchesGlobalTestPatterns checks if match is in the global test patterns database
func (v *Validator) matchesGlobalTestPatterns(match string) bool {
	lowerMatch := strings.ToLower(match)

	for _, testPattern := range v.globalTestPatterns {
		lowerPattern := strings.ToLower(testPattern)

		// Exact match
		if lowerMatch == lowerPattern {
			return true
		}

		// Only flag if the match is clearly a test pattern, not just containing test words
		// Check for full test patterns or obvious test values
		if len(testPattern) >= 8 && strings.Contains(lowerMatch, lowerPattern) {
			// Additional check: make sure it's not just a coincidental substring
			// For example, "AKIAIOSFODNN7EXAMPLE" shouldn't match "example_secret_key"
			// unless it's clearly a test pattern
			if strings.HasPrefix(lowerMatch, "test_") ||
				strings.HasPrefix(lowerMatch, "example_") ||
				strings.HasPrefix(lowerMatch, "demo_") ||
				strings.HasPrefix(lowerMatch, "sample_") ||
				strings.HasSuffix(lowerMatch, "_test") ||
				strings.HasSuffix(lowerMatch, "_example") ||
				strings.HasSuffix(lowerMatch, "_demo") ||
				strings.HasSuffix(lowerMatch, "_sample") {
				return true
			}
		}

		// Obvious placeholder patterns are handled by isObviousPlaceholder method
		// No need for duplicate checking here
	}

	return false
}

// isTabularData checks if the secret appears to be in a tabular format
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
	if len(v.multiSpacePattern.FindAllString(line, -1)) >= 2 {
		return true
	}

	// Check for common configuration patterns (keys followed by secrets)
	return v.configPattern.MatchString(line)
}

// GetCheckInfo implements the help.Provider interface
func (v *Validator) GetCheckInfo() help.CheckInfo {
	return help.CheckInfo{
		Name:             "SECRETS",
		ShortDescription: "Detects API keys, tokens, passwords, and other secrets using entropy analysis",
		DetailedDescription: `The Secrets Validator detects API keys, tokens, passwords, and other sensitive credentials using techniques inspired by the detect-secrets project.

It combines three main detection methods:
1. High Entropy String Analysis - Uses Shannon entropy to identify random-looking strings that are likely cryptographic material
2. Keyword Pattern Matching - Searches for common secret keywords and patterns
3. Credentials in URI user info - Parses the authority of every URI (RFC 3986) and reports the password in scheme://user:password@host, or a token-shaped user name in https://token@host, with no keyword needed: DATABASE_URL, broker, proxy and registry URLs and JDBC DSNs

SUPPORTED SECRET TYPES:
• SSH_PRIVATE_KEY - SSH private keys and certificates
• CERTIFICATE - X.509 certificates and encrypted private keys
• JWT_TOKEN - JSON Web Tokens
• AWS_ACCESS_KEY - Amazon Web Services access keys
• GITHUB_TOKEN - GitHub personal access tokens
• GOOGLE_CLOUD_API_KEY - Google Cloud Platform API keys
• STRIPE_API_KEY - Stripe payment processing API keys
• GITLAB_TOKEN - GitLab personal access tokens
• DOCKER_TOKEN - Docker Hub personal access tokens
• SLACK_TOKEN - Slack bot and user tokens
• PGP_PRIVATE_KEY - PGP/GPG private keys
• API_KEY_OR_SECRET - Generic high-entropy secrets and API keys

The validator automatically identifies the specific type of secret and displays it in the TYPE column for better categorization and handling.

The validator analyzes character distribution, applies contextual analysis, and uses configurable confidence scoring to minimize false positives.`,
		Patterns: append(append([]string{
			"SSH Private Keys: -----" + "BEGIN [RSA|DSA|EC|OPENSSH] PRIVATE KEY" + "-----",
			"Certificate Private Keys: -----" + "BEGIN CERTIFICATE" + "----- or -----" + "BEGIN " + "ENCRYPTED " + "PRIVATE KEY" + "-----",
			"PGP Private Keys: -----" + "BEGIN " + "PGP PRIVATE KEY BLOCK" + "-----",
			"JWT Tokens: eyJ[base64].[base64].[base64]",
		},
			// Provider literals, one line per row of the grammar table (#769).
			providerCheckInfo()...),
			"Base64 strings with high entropy (threshold 4.5, 20+ characters)",
			"Hex strings with high entropy (threshold 3.0, 16+ characters)",
			"api_key = \"value\"",
			"\"password\": \"value\"",
			"auth_token = \"value\"",
			"private_key: \"value\"",
			"Credentials in URI user info: scheme://user:password@host for any scheme (JDBC included), and a token as the user name; default credentials such as postgres:postgres are reported LOW",
		),
		SupportedFormats: []string{
			"Text files with quoted strings",
			"Configuration files (JSON, YAML, INI)",
			"Source code files",
			"Environment files (.env)",
			"Preprocessed content from documents and images",
		},
		ConfidenceFactors: []help.ConfidenceFactor{
			{Name: "Specific Pattern", Description: "Matches known secret patterns (SSH keys, JWT, AWS keys, etc.)", Weight: 50},
			{Name: "Min Length", Description: "String must be at least 8 characters", Weight: 30},
			{Name: "High Entropy", Description: "Shannon entropy above threshold for charset", Weight: 25},
			{Name: "Not Common Word", Description: "Doesn't contain common words like 'password'", Weight: 20},
			{Name: "Not Test Data", Description: "Doesn't match test patterns like 'test', 'example'", Weight: 30},
			{Name: "Valid Format", Description: "No spaces or tabs in the secret value", Weight: 15},
		},
		PositiveKeywords: v.positiveKeywords,
		NegativeKeywords: v.negativeKeywords,
		ConfigurationInfo: `The Secrets Validator uses built-in patterns and entropy thresholds. No additional configuration is required.

Entropy Thresholds:
- Base64 strings: 4.5 (20+ characters)
- Hex strings: 3.0 (16+ characters)

Keyword patterns automatically detect common secret assignment formats in various programming languages and configuration files.

Unquoted assignments in source code: in Python (.py .pyi .pyw), JavaScript (.js .mjs .cjs), TypeScript (.ts .mts .cts), Go (.go) and Terraform/HCL (.tf .tfvars .hcl) files, an unquoted value that starts in code position, such as secret = config.secret_key, is an expression rather than a credential and is not reported. Values inside strings, comments, docstrings and heredocs still are, and so is a value that runs into a backtick string. A file the lexer cannot read as source is scanned as before: a .js file containing JSX, and any of these files holding a typographic quote in code position. The file type comes from the file name, --stdin-name, or a library label; input with no extension is scanned as before.`,
		Examples: []string{
			"ferret-scan --file config.json --checks SECRETS",
			"ferret-scan --file .env --checks SECRETS --confidence high",
			"ferret-scan --file app.py --checks SECRETS --verbose",
			// A quoted directory, not an unquoted *.js. The shell expands a glob before the binary
			// sees it, so with two or more matches `--file` takes the first, the rest become
			// positional paths, Go's flag parsing stops, and `--checks` and `--format` are dropped —
			// measured: every validator ran and the output was text, not JSON, at exit 0. The same
			// shape in the general help advertised PDF redaction that can never succeed (#686).
			"ferret-scan --file ./src --recursive --checks SECRETS --format json",
		},
	}
}

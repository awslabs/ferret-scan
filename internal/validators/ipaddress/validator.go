// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ipaddress

import (
	stdctx "context"
	"net"
	"regexp"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/execguard"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
)

// Structural signals that a dotted-decimal token is being used as a network
// address rather than (say) a software version: a trailing port (":8080") or
// CIDR suffix ("/24").
var (
	rePortSuffix = regexp.MustCompile(`^:\d{1,5}\b`)
	reCIDRSuffix = regexp.MustCompile(`^/\d{1,2}\b`)
)

// ipContainsKeyword reports whether text contains keyword as a whole word,
// case-insensitively. Whole-word matching avoids "ip"/"nat" firing inside
// unrelated words. Implemented as a plain string scan (not a regex) to keep the
// per-match context check cheap; a word byte is [a-z0-9].
func ipContainsKeyword(text, keyword string) bool {
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
		leftOK := i == 0 || !isIPWordByte(lt[i-1])
		right := i + len(lk)
		rightOK := right >= len(lt) || !isIPWordByte(lt[right])
		if leftOK && rightOK {
			return true
		}
		from = i + 1
	}
	return false
}

// isIPWordByte reports whether b is a word character ([a-z0-9]) for keyword
// boundary detection. text is already lowercased by the caller.
func isIPWordByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

// Validator implements the detector.Validator interface for detecting
// IP addresses using regex patterns and contextual analysis.
type Validator struct {
	patterns []ipPattern

	// Keywords that suggest an IP address context
	positiveKeywords []string

	// Keywords that suggest this is not a real IP
	negativeKeywords []string

	// Known test patterns that indicate test data
	knownTestPatterns []string

	// Private IP ranges for classification
	privateRanges []string

	// Reserved IP ranges
	reservedRanges []string

	// Pre-parsed CIDR networks (cached at init to avoid repeated parsing)
	privateNetworks  []*net.IPNet
	reservedNetworks []*net.IPNet
	multicastNetwork *net.IPNet
	// nonSensitiveNets holds ranges that should never be reported (documentation,
	// link-local, ULA, loopback, APIPA). Membership is tested via net.IPNet so
	// that zero-padding and "::" compression are normalized — a textual prefix
	// check missed the canonical RFC 3849 form 2001:0db8:... written zero-padded.
	nonSensitiveNets []*net.IPNet

	// Observability
	observer observability.Observer
}

// ipPattern represents an IP address pattern with its type info
type ipPattern struct {
	name        string
	regex       *regexp.Regexp
	version     string
	description string
}

// NewValidator creates and returns a new Validator instance
// with predefined patterns, keywords, and validation rules for detecting IP addresses.
func NewValidator() *Validator {
	v := &Validator{
		positiveKeywords: []string{
			"ip", "address", "host", "server", "client", "endpoint", "node",
			"network", "subnet", "gateway", "router", "dns", "nameserver",
			"connection", "tcp", "udp", "http", "https", "ftp", "ssh",
			"ping", "traceroute", "nslookup", "dig", "whois", "firewall",
			"proxy", "vpn", "nat", "dhcp", "static", "dynamic", "lease",
		},
		negativeKeywords: []string{
			"test", "example", "fake", "mock", "sample", "dummy", "placeholder",
			"demo", "template", "tutorial", "documentation", "readme",
			"lorem", "ipsum", "foo", "bar", "baz", "temp", "temporary",
			"invalid", "nonexistent", "blackhole", "devnull", "null",
			"version", "build", "revision", "release",
		},
		knownTestPatterns: []string{
			"192.0.2", "198.51.100", "203.0.113", // RFC 5737 test ranges
			"127.0.0.1", "0.0.0.0", "255.255.255.255",
			"1.1.1.1", "8.8.8.8", "1.2.3.4", "10.0.0.1",
		},
		privateRanges: []string{
			"10.0.0.0/8",     // 10.0.0.0 - 10.255.255.255
			"172.16.0.0/12",  // 172.16.0.0 - 172.31.255.255
			"192.168.0.0/16", // 192.168.0.0 - 192.168.255.255
		},
		reservedRanges: []string{
			"0.0.0.0/8",      // Current network
			"127.0.0.0/8",    // Loopback
			"169.254.0.0/16", // Link-local
			"224.0.0.0/4",    // Multicast
			"240.0.0.0/4",    // Reserved
		},
	}

	// Initialize IP patterns
	v.patterns = []ipPattern{
		// IPv4 patterns
		{
			name:        "IPv4_Standard",
			regex:       regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
			version:     "IPv4",
			description: "Standard IPv4 address",
		},
		{
			name:        "IPv4_CIDR",
			regex:       regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:3[0-2]|[12]?[0-9])\b`),
			version:     "IPv4",
			description: "IPv4 address with CIDR notation",
		},
		// IPv6 patterns
		{
			name:        "IPv6_Full",
			regex:       regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b`),
			version:     "IPv6",
			description: "Full IPv6 address",
		},
		{
			name: "IPv6_Compressed",
			// Compressed IPv6 (with a "::" run). The previous pattern
			// `\b(?:hex:)*::(?:hex:)*hex\b` was broken for FindString: the
			// leading \b plus a greedy prefix meant that for an address like
			// "2606:4700:4700::1111" RE2's leftmost-first matcher anchored at
			// the "::" and captured only the "::1111" fragment, which the
			// isEmbeddedInString guard (alnum char immediately before "::")
			// then discarded — so virtually all real public IPv6 was missed.
			//
			// This is the canonical compressed-form alternation, ordered by
			// POST-"::" group count DESCENDING so leftmost-first selects the
			// form capturing the most trailing groups (otherwise a
			// 1-trailing-group form truncates "2001:db8::ff00:42:8329"). No
			// surrounding \b: the boundary is handled by isEmbeddedInString,
			// and any over-match is rejected downstream by net.ParseIP in
			// isSensitiveIP (unparseable IPs are dropped), so the broader
			// pattern cannot introduce false positives.
			regex: regexp.MustCompile(`(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}` +
				`|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}` +
				`|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}` +
				`|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}` +
				`|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}` +
				`|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6}` +
				`|(?:[0-9A-Fa-f]{1,4}:){1,7}:` +
				`|:(?::[0-9A-Fa-f]{1,4}){1,7}`),
			version:     "IPv6",
			description: "Compressed IPv6 address with ::",
		},
		{
			name:        "IPv6_Mixed",
			regex:       regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){6}(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
			version:     "IPv6",
			description: "IPv6 address with embedded IPv4",
		},
		{
			name:        "IPv6_CIDR",
			regex:       regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}/(?:12[0-8]|1[01][0-9]|[1-9]?[0-9])\b`),
			version:     "IPv6",
			description: "IPv6 address with CIDR notation",
		},
	}

	// Pre-parse CIDR ranges once at init to avoid repeated parsing per-match
	for _, cidr := range v.privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			v.privateNetworks = append(v.privateNetworks, network)
		}
	}
	for _, cidr := range v.reservedRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			v.reservedNetworks = append(v.reservedNetworks, network)
		}
	}
	_, v.multicastNetwork, _ = net.ParseCIDR("224.0.0.0/4")

	// Non-sensitive ranges, parsed so zero-padded / compressed forms are matched.
	for _, cidr := range []string{
		"2001:db8::/32",   // RFC 3849 IPv6 documentation
		"fe80::/10",       // IPv6 link-local
		"fc00::/7",        // IPv6 unique local (ULA)
		"::1/128",         // IPv6 loopback
		"169.254.0.0/16",  // IPv4 APIPA / link-local
		"192.0.2.0/24",    // RFC 5737 TEST-NET-1
		"198.51.100.0/24", // RFC 5737 TEST-NET-2
		"203.0.113.0/24",  // RFC 5737 TEST-NET-3
		"100.64.0.0/10",   // RFC 6598 carrier-grade NAT shared space (not end-user identifying)
		"198.18.0.0/15",   // RFC 2544 benchmarking
		"192.0.0.0/24",    // RFC 7335 IETF protocol assignments
	} {
		if _, network, err := net.ParseCIDR(cidr); err == nil {
			v.nonSensitiveNets = append(v.nonSensitiveNets, network)
		}
	}

	return v
}

// SetObserver sets the observability component
func (v *Validator) SetObserver(observer observability.Observer) {
	v.observer = observer
}

// ValidateContent validates preprocessed content for IP addresses
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
		finishTiming = v.observer.StartTiming("ipaddress_validator", "validate_content", originalPath)
	}

	var matches []detector.Match

	// Split content into lines for processing
	lines := strings.Split(content, "\n")

	// Process each pattern type
	for lineNum, line := range lines {
		// Cooperative cancellation (v2 Phase 3): bail promptly on deadline/cancel.
		if execguard.LineLoopCancelled(ctx, lineNum) {
			if finishTiming != nil {
				finishTiming(false, map[string]interface{}{"cancelled": true, "match_count": len(matches)})
			}
			return matches, ctx.Err()
		}
		// Cheap per-line fast paths: every IPv6 form needs a ":" and the
		// compressed form additionally needs a "::". Skipping the (multi-branch)
		// IPv6 regexes on lines that cannot possibly contain such an address
		// avoids the bulk of their cost on ordinary text without changing any
		// match result.
		hasColon := strings.Contains(line, ":")
		hasDoubleColon := strings.Contains(line, "::")

		// PERF: hoist per-line work out of the per-match loop. The context
		// analysis only ever inspects the matched line (BeforeText/AfterText are
		// the ±50 window around the match, both substrings of `line`), so the
		// set of keywords present in the analysis context is exactly the set
		// present in the lowercased line. Lowercasing the line ONCE here and
		// reusing it avoids re-lowercasing a megabyte-long line for every match,
		// which was the O(n^2) DoS (a single long line dense with IPs).
		lowerLine := strings.ToLower(line)

		// PERF: the keyword-derived quantities below depend ONLY on the line, not
		// on the individual match, so compute them ONCE per line. Previously each
		// match re-scanned the whole (possibly megabyte-long) line for all ~35
		// positive + ~25 negative keywords — the dominant O(n^2) cost. Hoisting
		// them here makes the per-match work bounded by the local context window.
		//   - lineContextImpact: the AnalyzeContext result for this line (same for
		//     every match, since BeforeText/AfterText are substrings of the line).
		//   - linePositiveKeywords / lineNegativeKeywords: the findKeywords result.
		//   - lineHasPositiveKeyword: the keyword half of hasIPContextSignal.
		lineContextImpact := v.analyzeContextLower(lowerLine)
		linePositiveKeywords := v.findKeywordsLower(lowerLine, v.positiveKeywords)
		lineNegativeKeywords := v.findKeywordsLower(lowerLine, v.negativeKeywords)
		lineHasPositiveKeyword := len(linePositiveKeywords) > 0

		// PERF: dedup per line via a map keyed by the cleaned IP instead of the
		// previous O(M^2) scan of all prior matches. Behavior is identical: the
		// original isDuplicateMatch only compared against matches on the SAME
		// line number, and emission order is unchanged (first pattern to produce
		// a given cleaned IP on a line wins, exactly as before).
		seenOnLine := make(map[string]struct{})

		for _, pattern := range v.patterns {
			if pattern.version == "IPv6" {
				if !hasColon {
					continue
				}
				if pattern.name == "IPv6_Compressed" && !hasDoubleColon {
					continue
				}
			}

			// PERF: FindAllStringIndex gives each match's byte offset directly,
			// eliminating the per-match strings.Index(line, match) rescans (which
			// were O(line length) each and quadratic in aggregate). It also fixes
			// a latent correctness bug: strings.Index finds the FIRST occurrence
			// of a duplicated token, not the actual match position.
			foundIdx := pattern.regex.FindAllStringIndex(line, -1)

			for _, loc := range foundIdx {
				matchIndex, matchEnd := loc[0], loc[1]
				match := line[matchIndex:matchEnd]

				// Skip if this match was already found by another pattern on this
				// line (same cleaned IP, same line). Map lookup is O(1).
				cleanForDedup := v.cleanIPAddress(match)
				if _, dup := seenOnLine[cleanForDedup]; dup {
					continue
				}

				// Skip if this IP is embedded within a longer alphanumeric string.
				// Offset-based check avoids a fresh strings.Index scan of the line.
				if v.isEmbeddedInStringAt(match, line, matchIndex, matchEnd) {
					continue
				}

				// Calculate confidence
				confidence, checks := v.CalculateConfidence(match)

				// Analyze IP structure
				ipInfo := v.AnalyzeIPStructure(match, pattern)

				// For preprocessed content, create a context info
				contextInfo := detector.ContextInfo{
					FullLine: line,
				}

				// Extract context around the match in the line using the known
				// offset (no rescan). The ±50-char window is unchanged.
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

				// Analyze context and adjust confidence. The keyword-derived
				// impact is line-global (BeforeText/AfterText are substrings of
				// `line`, so the "same line" weighting branch of AnalyzeContext
				// always applies for this call site), so it was computed once per
				// line above and is reused here unchanged.
				contextImpact := lineContextImpact
				confidence += contextImpact

				// A bare dotted-decimal IPv4 with no corroborating signal is
				// ambiguous: software versions (5.4.36.180), pi digits
				// (3.14.15.92) and arbitrary numeric tuples are structurally
				// identical to a routable IP, and previously scored 100 (HIGH)
				// because the base is 100 + a +10 public boost. The same applies
				// to a FULL-form 8-group IPv6 with no "::" — a MAC-like or random
				// hex tuple (12:34:56:78:90:ab:cd:ef) parses as valid IPv6 and
				// scored 100. Cap such context-free matches below HIGH so they
				// surface as MEDIUM unless an IP keyword or structural signal
				// (port, CIDR) is present. A compressed IPv6 (contains "::") is
				// unambiguous and is left untouched.
				ambiguousShape := pattern.version == "IPv4" ||
					(pattern.name == "IPv6_Full" && !strings.Contains(match, "::"))
				if ambiguousShape && confidence >= 90 &&
					!v.hasIPContextSignalAt(lineHasPositiveKeyword, line, matchEnd) {
					confidence = 75
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

				// Skip non-sensitive IP addresses (private, reserved, test ranges, etc.)
				if !v.isSensitiveIP(v.cleanIPAddress(match)) {
					continue
				}

				// Store keywords found in context. These are line-global (the
				// keyword set over the analysis context equals the set over the
				// line, as argued above), so they were computed once per line and
				// are reused here — identical result to the per-match findKeywords.
				contextInfo.PositiveKeywords = linePositiveKeywords
				contextInfo.NegativeKeywords = lineNegativeKeywords
				contextInfo.ConfidenceImpact = contextImpact

				// Record this cleaned IP so later patterns on the same line dedup.
				seenOnLine[cleanForDedup] = struct{}{}

				matches = append(matches, detector.Match{
					Text:       match,
					LineNumber: lineNum + 1, // 1-based line numbering
					Type:       "IP_ADDRESS",
					Confidence: confidence,
					Filename:   originalPath,
					Validator:  "ipaddress",
					Context:    contextInfo,
					Metadata: map[string]any{
						"version":           ipInfo["version"],
						"type":              ipInfo["type"],
						"pattern_name":      ipInfo["pattern_name"],
						"is_private":        ipInfo["is_private"],
						"is_reserved":       ipInfo["is_reserved"],
						"clean_ip":          ipInfo["clean_ip"],
						"validation_checks": checks,
						"context_impact":    contextInfo.ConfidenceImpact,
						"source":            "preprocessed_content",
						"original_file":     originalPath,
					},
				})
			}
		}
	}

	if finishTiming != nil {
		finishTiming(true, map[string]interface{}{
			"match_count":     len(matches),
			"lines_processed": len(strings.Split(content, "\n")),
			"content_length":  len(content),
		})
	}

	return matches, nil
}

// AnalyzeContext analyzes the context around a match and returns a confidence adjustment
func (v *Validator) AnalyzeContext(match string, context detector.ContextInfo) float64 {
	// Combine all context text for analysis
	var sb strings.Builder
	sb.WriteString(context.BeforeText)
	sb.WriteString(" ")
	sb.WriteString(context.FullLine)
	sb.WriteString(" ")
	sb.WriteString(context.AfterText)
	fullContext := strings.ToLower(sb.String())

	var confidenceImpact float64 = 0

	// Check for positive keywords (increase confidence). Whole-word matching only,
	// so short keywords ("ip"/"nat") don't fire inside "description"/"signature".
	for _, keyword := range v.positiveKeywords {
		if ipContainsKeyword(fullContext, keyword) {
			// Give more weight to keywords that are closer to the match
			if ipContainsKeyword(context.FullLine, keyword) {
				confidenceImpact += 12 // +12% for keywords in the same line
			} else {
				confidenceImpact += 6 // +6% for keywords in surrounding context
			}
		}
	}

	// Check for negative keywords (decrease confidence). Whole-word matching, so
	// "null"/"bar"/"baz"/"temp" don't fire inside nullable/barometer/bazaar/template.
	for _, keyword := range v.negativeKeywords {
		if ipContainsKeyword(fullContext, keyword) {
			// Give more weight to keywords that are closer to the match
			if ipContainsKeyword(context.FullLine, keyword) {
				confidenceImpact -= 30 // -30% for negative keywords in the same line
			} else {
				confidenceImpact -= 15 // -15% for negative keywords in surrounding context
			}
		}
	}

	// Cap the impact to reasonable bounds
	if confidenceImpact > 40 {
		confidenceImpact = 40 // Maximum +40% boost
	} else if confidenceImpact < -80 {
		confidenceImpact = -80 // Maximum -80% reduction
	}

	return confidenceImpact
}

// analyzeContextLower is the hot-path equivalent of AnalyzeContext for the
// ValidateContent call site, taking an already-lowercased line.
//
// In ValidateContent the analysis context is BeforeText + " " + FullLine + " " +
// AfterText, where BeforeText and AfterText are the ±50-char window around the
// match and are therefore substrings of FullLine. The two join points are spaces,
// so no whole word spans a boundary; hence every keyword present in the
// concatenated context is also present in FullLine. AnalyzeContext's "surrounding
// context only" branch (+6 / -15) can never be reached for this call site — the
// "same line" branch (+12 / -30) always applies. This function reproduces exactly
// that branch (and the same +40 / -80 caps), so the returned impact is identical
// to AnalyzeContext for ValidateContent, while lowercasing the line only ONCE per
// line instead of once per match.
func (v *Validator) analyzeContextLower(lowerLine string) float64 {
	var confidenceImpact float64 = 0

	for _, keyword := range v.positiveKeywords {
		if ipContainsKeyword(lowerLine, keyword) {
			confidenceImpact += 12
		}
	}
	for _, keyword := range v.negativeKeywords {
		if ipContainsKeyword(lowerLine, keyword) {
			confidenceImpact -= 30
		}
	}

	if confidenceImpact > 40 {
		confidenceImpact = 40
	} else if confidenceImpact < -80 {
		confidenceImpact = -80
	}

	return confidenceImpact
}

// findKeywordsLower is the hot-path equivalent of findKeywords for the
// ValidateContent call site. As argued in analyzeContextLower, the keyword set
// present in the concatenated analysis context equals the set present in the
// (lowercased) line, so iterating the keyword list over lowerLine yields the
// same slice (same order, same membership) as findKeywords — without
// re-lowercasing the line per match.
func (v *Validator) findKeywordsLower(lowerLine string, keywords []string) []string {
	var found []string
	for _, keyword := range keywords {
		if ipContainsKeyword(lowerLine, keyword) {
			found = append(found, keyword)
		}
	}
	return found
}

// findKeywords returns a list of keywords found in the context
func (v *Validator) findKeywords(context detector.ContextInfo, keywords []string) []string {
	var sb strings.Builder
	sb.WriteString(context.BeforeText)
	sb.WriteString(" ")
	sb.WriteString(context.FullLine)
	sb.WriteString(" ")
	sb.WriteString(context.AfterText)
	fullContext := strings.ToLower(sb.String())

	var found []string
	for _, keyword := range keywords {
		if ipContainsKeyword(fullContext, keyword) {
			found = append(found, keyword)
		}
	}

	return found
}

// CalculateConfidence calculates the confidence score for a potential IP address
func (v *Validator) CalculateConfidence(match string) (float64, map[string]bool) {
	// Find the best matching pattern for this IP address
	var bestPattern ipPattern
	found := false

	for _, pattern := range v.patterns {
		if pattern.regex.MatchString(match) {
			bestPattern = pattern
			found = true
			break
		}
	}

	// If no pattern matches, use a default pattern
	if !found {
		bestPattern = ipPattern{
			name:        "Unknown",
			version:     "Unknown",
			description: "Unknown IP format",
		}
	}

	return v.calculateConfidenceWithPattern(match, bestPattern)
}

// calculateConfidenceWithPattern calculates confidence with a specific pattern
func (v *Validator) calculateConfidenceWithPattern(match string, pattern ipPattern) (float64, map[string]bool) {
	checks := map[string]bool{
		"valid_format":   true,
		"valid_ip":       true,
		"not_test_ip":    true,
		"not_reserved":   true,
		"reasonable_use": true,
	}

	confidence := 100.0

	// Validate IP format using Go's net package (20%)
	cleanIP := v.cleanIPAddress(match)
	if net.ParseIP(cleanIP) == nil {
		confidence -= 20
		checks["valid_ip"] = false
	}

	// Check if it's a known test IP (25%)
	if v.isTestIP(match) {
		confidence -= 25
		checks["not_test_ip"] = false
	}

	// Check if it's reserved (different treatment for private vs reserved)
	if v.isReservedIP(cleanIP) {
		if v.isPrivateIP(cleanIP) {
			// Private IPs are common and valid, small penalty
			confidence -= 5
		} else {
			// Other reserved IPs (loopback, multicast, etc.) are less likely to be real data
			confidence -= 15
			checks["not_reserved"] = false
		}
	}

	// Boost confidence for public IPs (more sensitive)
	if !v.isPrivateIP(cleanIP) && !v.isReservedIP(cleanIP) {
		confidence += 10
	}

	// Special handling for common patterns
	if v.isCommonPublicDNS(cleanIP) {
		confidence += 5 // Google DNS, Cloudflare, etc.
	}

	if confidence < 0 {
		confidence = 0
	}
	return confidence, checks
}

// AnalyzeIPStructure breaks down the IP address into components
func (v *Validator) AnalyzeIPStructure(ip string, pattern ipPattern) map[string]string {
	cleanIP := v.cleanIPAddress(ip)

	result := map[string]string{
		"pattern_name": pattern.name,
		"version":      pattern.version,
		"clean_ip":     cleanIP,
		"original":     ip,
		"type":         "Unknown",
		"is_private":   "false",
		"is_reserved":  "false",
	}

	// Classify IP type
	if v.isPrivateIP(cleanIP) {
		result["type"] = "Private"
		result["is_private"] = "true"
	} else if v.isReservedIP(cleanIP) {
		result["type"] = "Reserved"
		result["is_reserved"] = "true"

		// More specific reserved types
		if strings.HasPrefix(cleanIP, "127.") {
			result["type"] = "Loopback"
		} else if strings.HasPrefix(cleanIP, "169.254.") {
			result["type"] = "Link-Local"
		} else if v.isMulticastIP(cleanIP) {
			result["type"] = "Multicast"
		}
	} else {
		result["type"] = "Public"
	}

	// Add CIDR info if present
	if strings.Contains(ip, "/") {
		parts := strings.Split(ip, "/")
		if len(parts) == 2 {
			result["cidr_mask"] = parts[1]
			result["type"] = result["type"] + "_Network"
		}
	}

	return result
}

// Helper methods
func (v *Validator) cleanIPAddress(ip string) string {
	// Remove CIDR notation if present
	if strings.Contains(ip, "/") {
		parts := strings.Split(ip, "/")
		return parts[0]
	}
	return strings.TrimSpace(ip)
}

func (v *Validator) isTestIP(ip string) bool {
	cleanIP := v.cleanIPAddress(ip)

	// Single-host test/example addresses are matched by EXACT equality, not
	// HasPrefix: a prefix test made "1.1.1.1" also match real public IPs like
	// "1.1.1.10".."1.1.1.199" and "8.8.8.8" match "8.8.8.88", silently dropping
	// genuine addresses (L15). Multi-host /24 prefixes keep HasPrefix below.
	for _, pattern := range v.knownTestPatterns {
		if strings.HasSuffix(pattern, ".") {
			if strings.HasPrefix(cleanIP, pattern) {
				return true
			}
		} else if cleanIP == pattern {
			return true
		}
	}

	// RFC 5737 test ranges (/24 prefixes)
	testRanges := []string{
		"192.0.2.",    // TEST-NET-1
		"198.51.100.", // TEST-NET-2
		"203.0.113.",  // TEST-NET-3
	}

	for _, testRange := range testRanges {
		if strings.HasPrefix(cleanIP, testRange) {
			return true
		}
	}

	return false
}

func (v *Validator) isPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	for _, network := range v.privateNetworks {
		if network.Contains(parsedIP) {
			return true
		}
	}

	return false
}

func (v *Validator) isReservedIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// Check private ranges first
	for _, network := range v.privateNetworks {
		if network.Contains(parsedIP) {
			return true
		}
	}

	// Check other reserved ranges
	for _, network := range v.reservedNetworks {
		if network.Contains(parsedIP) {
			return true
		}
	}

	return false
}

func (v *Validator) isMulticastIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	return v.multicastNetwork != nil && v.multicastNetwork.Contains(parsedIP)
}

func (v *Validator) isCommonPublicDNS(ip string) bool {
	commonDNS := map[string]bool{
		"8.8.8.8":         true, // Google DNS
		"8.8.4.4":         true, // Google DNS
		"1.1.1.1":         true, // Cloudflare DNS
		"1.0.0.1":         true, // Cloudflare DNS
		"208.67.222.222":  true, // OpenDNS
		"208.67.220.220":  true, // OpenDNS
		"9.9.9.9":         true, // Quad9 DNS
		"149.112.112.112": true, // Quad9 DNS
	}

	return commonDNS[ip]
}

// isSensitiveIP determines if an IP address is sensitive enough to report
// Returns false for private, reserved, test, and other non-identifying IP addresses
func (v *Validator) isSensitiveIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false // Invalid IP addresses are not sensitive
	}

	// Skip private IP addresses (10.x.x.x, 192.168.x.x, 172.16-31.x.x)
	if v.isPrivateIP(ip) {
		return false
	}

	// Skip reserved/special use addresses
	if v.isReservedIP(ip) {
		return false
	}

	// Skip test IP addresses
	if v.isTestIP(ip) {
		return false
	}

	// Skip well-known public DNS servers (these are not uniquely identifying)
	if v.isCommonPublicDNS(ip) {
		return false
	}

	// Skip broadcast addresses
	if ip == "255.255.255.255" {
		return false
	}

	// Skip documentation / link-local / ULA / loopback / APIPA ranges. Tested via
	// pre-parsed net.IPNet membership so zero-padded ("2001:0db8:...") and
	// "::"-compressed forms are normalized — a textual prefix check missed the
	// canonical zero-padded RFC 3849 documentation address.
	for _, network := range v.nonSensitiveNets {
		if network.Contains(parsedIP) {
			return false
		}
	}

	// Skip localhost variations
	if ip == "0.0.0.0" || strings.HasPrefix(ip, "127.") {
		return false
	}

	// Skip IPv6 unique local addresses written fd.. (covered by fc00::/7 above,
	// but keep the textual guard for any non-parsing edge form)
	if strings.HasPrefix(strings.ToLower(ip), "fc") || strings.HasPrefix(strings.ToLower(ip), "fd") {
		return false
	}

	// Skip IPv6 loopback
	if strings.ToLower(ip) == "::1" {
		return false
	}

	// At this point, the IP appears to be a public, routable IP address
	// that could potentially be sensitive/identifying
	return true
}

// hasIPContextSignal reports whether the line carries a corroborating signal
// that `match` is a network address rather than an incidental dotted-decimal
// number (a version, build tag, or numeric tuple). A signal is either an IP
// context keyword on the line (host/server/endpoint/...) or a structural suffix
// immediately after the address — a port (":8080") or CIDR ("/24").
func (v *Validator) hasIPContextSignal(match, line string) bool {
	for _, kw := range v.positiveKeywords {
		if ipContainsKeyword(line, kw) {
			return true
		}
	}
	if idx := strings.Index(line, match); idx >= 0 {
		after := line[idx+len(match):]
		if rePortSuffix.MatchString(after) || reCIDRSuffix.MatchString(after) {
			return true
		}
	}
	return false
}

// hasIPContextSignalAt is the hot-path equivalent of hasIPContextSignal.
//
// The keyword half of the signal (does the line contain ANY positive IP
// keyword?) is line-global, so the caller computes it ONCE per line and passes
// it as lineHasPositiveKeyword — this avoids re-scanning a megabyte line for all
// positive keywords on every match, which was the dominant O(n^2) cost. The
// remaining half — a port (":8080") or CIDR ("/24") suffix immediately after the
// address — is match-specific and is tested against the bounded slice starting
// at the match's real end offset (the original used strings.Index's first
// occurrence; the true offset is identical on normal input and strictly more
// correct on duplicated tokens). The suffix regexes are ^-anchored, so the
// MatchString call only inspects the start of the slice, not its whole length.
func (v *Validator) hasIPContextSignalAt(lineHasPositiveKeyword bool, line string, matchEnd int) bool {
	if lineHasPositiveKeyword {
		return true
	}
	if matchEnd <= len(line) {
		// Both suffix patterns are ^-anchored and match at most a few bytes
		// (":" + up to 5 digits, or "/" + up to 2 digits). Cap the slice to a
		// short prefix so MatchString is O(1) regardless of how long the rest of
		// the line is — this cannot change the result, since neither pattern can
		// match beyond the first ~8 bytes.
		after := line[matchEnd:]
		if len(after) > 16 {
			after = after[:16]
		}
		if rePortSuffix.MatchString(after) || reCIDRSuffix.MatchString(after) {
			return true
		}
	}
	return false
}

// isEmbeddedInString checks if an IP address match is embedded within a longer alphanumeric string
// This helps filter out false positives like "AWS::EC2::Instance" where "::EC2" matches IPv6 pattern
func (v *Validator) isEmbeddedInString(match, line string) bool {
	matchIndex := strings.Index(line, match)
	if matchIndex == -1 {
		return false
	}

	// Check character before the match
	if matchIndex > 0 {
		charBefore := line[matchIndex-1]
		// If the character before is alphanumeric, this IP is embedded in a longer string
		if (charBefore >= 'a' && charBefore <= 'z') ||
			(charBefore >= 'A' && charBefore <= 'Z') ||
			(charBefore >= '0' && charBefore <= '9') {
			return true
		}
	}

	// Check character after the match
	matchEnd := matchIndex + len(match)
	if matchEnd < len(line) {
		charAfter := line[matchEnd]
		// If the character after is alphanumeric, this IP is embedded in a longer string
		if (charAfter >= 'a' && charAfter <= 'z') ||
			(charAfter >= 'A' && charAfter <= 'Z') ||
			(charAfter >= '0' && charAfter <= '9') {
			return true
		}
	}

	// For a dotted-decimal IPv4 match, a '.' immediately before or after means the
	// match is the leading/trailing four octets of a LONGER dotted sequence (e.g.
	// "40.71.74.0" extracted from "40.71.74.0.99") — not a standalone IP. The
	// previous alnum-only check missed this because '.' is not alphanumeric.
	if strings.Contains(match, ".") && !strings.Contains(match, ":") {
		if matchIndex > 0 && line[matchIndex-1] == '.' {
			return true
		}
		if matchEnd < len(line) && line[matchEnd] == '.' {
			return true
		}
	}

	return false
}

// isEmbeddedInStringAt is the hot-path equivalent of isEmbeddedInString that
// uses the match's known byte offsets instead of re-scanning the line with
// strings.Index. The neighbor-character logic is identical; on normal input the
// result is the same, and on a duplicated token it inspects the ACTUAL match's
// neighbors (the strings.Index version inspected the first occurrence's
// neighbors, a latent bug).
func (v *Validator) isEmbeddedInStringAt(match, line string, matchIndex, matchEnd int) bool {
	// Check character before the match
	if matchIndex > 0 {
		charBefore := line[matchIndex-1]
		if (charBefore >= 'a' && charBefore <= 'z') ||
			(charBefore >= 'A' && charBefore <= 'Z') ||
			(charBefore >= '0' && charBefore <= '9') {
			return true
		}
	}

	// Check character after the match
	if matchEnd < len(line) {
		charAfter := line[matchEnd]
		if (charAfter >= 'a' && charAfter <= 'z') ||
			(charAfter >= 'A' && charAfter <= 'Z') ||
			(charAfter >= '0' && charAfter <= '9') {
			return true
		}
	}

	// For a dotted-decimal IPv4 match, a '.' immediately before or after means the
	// match is the leading/trailing four octets of a LONGER dotted sequence (e.g.
	// "40.71.74.0" extracted from "40.71.74.0.99") — not a standalone IP.
	if strings.Contains(match, ".") && !strings.Contains(match, ":") {
		if matchIndex > 0 && line[matchIndex-1] == '.' {
			return true
		}
		if matchEnd < len(line) && line[matchEnd] == '.' {
			return true
		}
	}

	return false
}

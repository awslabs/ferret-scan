// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ipaddress

import (
	"net"
	"os"
	"regexp"
	"strings"

	"ferret-scan/internal/detector"
	"ferret-scan/internal/observability"
)

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

	// Observability
	observer *observability.StandardObserver
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
			name:        "IPv6_Compressed",
			regex:       regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:)*::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}\b`),
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
		finishTiming = v.observer.StartTiming("ipaddress_validator", "validate_file", filePath)
		if v.observer.DebugObserver != nil {
			finishStep = v.observer.DebugObserver.StartStep("ipaddress_validator", "validate_file", filePath)
		}
	}

	// IP address validator should not process files directly - only preprocessed content
	// Return empty results to avoid processing file system data
	if finishTiming != nil {
		finishTiming(true, map[string]interface{}{"match_count": 0, "direct_file_processing": false})
	}
	if finishStep != nil {
		finishStep(true, "IP address validator only processes preprocessed content")
	}
	return []detector.Match{}, nil
}

// ValidateContent validates preprocessed content for IP addresses
func (v *Validator) ValidateContent(content string, originalPath string) ([]detector.Match, error) {
	var finishTiming func(bool, map[string]interface{})
	if v.observer != nil {
		finishTiming = v.observer.StartTiming("ipaddress_validator", "validate_content", originalPath)
	}

	var matches []detector.Match

	// Split content into lines for processing
	lines := strings.Split(content, "\n")

	// Process each pattern type
	for lineNum, line := range lines {
		for _, pattern := range v.patterns {
			foundMatches := pattern.regex.FindAllString(line, -1)

			for _, match := range foundMatches {
				// Skip if this match was already found by another pattern
				if v.isDuplicateMatch(matches, match, lineNum+1) {
					continue
				}

				// Skip if this IP is embedded within a longer alphanumeric string
				if v.isEmbeddedInString(match, line) {
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

				// Extract context around the match in the line
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

				// Analyze context and adjust confidence
				contextImpact := v.AnalyzeContext(match, contextInfo)
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

				// Skip non-sensitive IP addresses (private, reserved, test ranges, etc.)
				if !v.isSensitiveIP(v.cleanIPAddress(match)) {
					continue
				}

				// Store keywords found in context
				contextInfo.PositiveKeywords = v.findKeywords(contextInfo, v.positiveKeywords)
				contextInfo.NegativeKeywords = v.findKeywords(contextInfo, v.negativeKeywords)
				contextInfo.ConfidenceImpact = contextImpact

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

// isDuplicateMatch checks if a match was already found (same IP, same line)
func (v *Validator) isDuplicateMatch(existing []detector.Match, newMatch string, lineNum int) bool {
	cleanNew := v.cleanIPAddress(newMatch)

	for _, match := range existing {
		if match.LineNumber == lineNum {
			cleanExisting := v.cleanIPAddress(match.Text)
			if cleanExisting == cleanNew {
				return true
			}
		}
	}
	return false
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

	// Check for positive keywords (increase confidence)
	for _, keyword := range v.positiveKeywords {
		if strings.Contains(fullContext, strings.ToLower(keyword)) {
			// Give more weight to keywords that are closer to the match
			if strings.Contains(context.FullLine, strings.ToLower(keyword)) {
				confidenceImpact += 12 // +12% for keywords in the same line
			} else {
				confidenceImpact += 6 // +6% for keywords in surrounding context
			}
		}
	}

	// Check for negative keywords (decrease confidence)
	for _, keyword := range v.negativeKeywords {
		if strings.Contains(fullContext, strings.ToLower(keyword)) {
			// Give more weight to keywords that are closer to the match
			if strings.Contains(context.FullLine, strings.ToLower(keyword)) {
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
		if strings.Contains(fullContext, strings.ToLower(keyword)) {
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

	// Check against known test patterns
	for _, pattern := range v.knownTestPatterns {
		if strings.HasPrefix(cleanIP, pattern) {
			return true
		}
	}

	// RFC 5737 test ranges
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

	for _, cidr := range v.privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
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
	if v.isPrivateIP(ip) {
		return true
	}

	// Check other reserved ranges
	for _, cidr := range v.reservedRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
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

	// IPv4 multicast: 224.0.0.0/4
	_, multicastNet, _ := net.ParseCIDR("224.0.0.0/4")
	return multicastNet.Contains(parsedIP)
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

	// Skip documentation IP ranges (RFC 5737)
	documentationRanges := []string{
		"192.0.2.",    // TEST-NET-1
		"198.51.100.", // TEST-NET-2
		"203.0.113.",  // TEST-NET-3
	}

	for _, docRange := range documentationRanges {
		if strings.HasPrefix(ip, docRange) {
			return false
		}
	}

	// Skip IPv6 documentation prefix (RFC 3849)
	if strings.HasPrefix(strings.ToLower(ip), "2001:db8:") {
		return false
	}

	// Skip localhost variations
	if ip == "0.0.0.0" || strings.HasPrefix(ip, "127.") {
		return false
	}

	// Skip link-local addresses
	if strings.HasPrefix(ip, "169.254.") {
		return false
	}

	// Skip APIPA (Automatic Private IP Addressing) range
	_, apipaNet, _ := net.ParseCIDR("169.254.0.0/16")
	if apipaNet != nil && apipaNet.Contains(parsedIP) {
		return false
	}

	// Skip IPv6 link-local addresses (fe80::/10)
	if strings.HasPrefix(strings.ToLower(ip), "fe80:") {
		return false
	}

	// Skip IPv6 unique local addresses (fc00::/7)
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

	return false
}

// isDebugEnabled checks if debug mode is enabled
func (v *Validator) isDebugEnabled() bool {
	return os.Getenv("FERRET_DEBUG") != ""
}

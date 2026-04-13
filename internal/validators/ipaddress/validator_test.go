// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ipaddress

import (
	"testing"

	"ferret-scan/internal/detector"
)

func TestIPAddressValidator_PublicIPs(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name        string
		content     string
		expectMatch bool
		description string
	}{
		{
			name:        "Public IP 203.0.113.50 is in TEST-NET-3 range",
			content:     "server address 203.0.113.50 for access",
			expectMatch: false,
			description: "RFC 5737 TEST-NET-3 range should be filtered as non-sensitive",
		},
		{
			name:        "Public IP 198.51.100.14 is in TEST-NET-2 range",
			content:     "host 198.51.100.14 running services",
			expectMatch: false,
			description: "RFC 5737 TEST-NET-2 range should be filtered as non-sensitive",
		},
		{
			name:        "Public IP 172.217.14.206 (Google)",
			content:     "connection to server 172.217.14.206 established",
			expectMatch: true,
			description: "Public routable IP should be detected as sensitive",
		},
		{
			name:        "Public IP 54.239.28.85 (AWS range)",
			content:     "endpoint 54.239.28.85 is live",
			expectMatch: true,
			description: "Public AWS IP should be detected as sensitive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := v.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent returned error: %v", err)
			}
			if tt.expectMatch && len(matches) == 0 {
				t.Errorf("Expected match but got none: %s", tt.description)
			}
			if !tt.expectMatch && len(matches) > 0 {
				t.Errorf("Expected no match but got %d: %s", len(matches), tt.description)
			}
		})
	}
}

func TestIPAddressValidator_PrivateIPs(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "Private 10.0.0.1",
			content: "server at 10.0.0.1 running",
		},
		{
			name:    "Private 192.168.1.1",
			content: "router gateway 192.168.1.1",
		},
		{
			name:    "Private 172.16.0.0",
			content: "subnet 172.16.0.0 configured",
		},
		{
			name:    "Private 10.255.255.255",
			content: "address 10.255.255.255 in use",
		},
		{
			name:    "Private 192.168.0.100",
			content: "dhcp lease 192.168.0.100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := v.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent returned error: %v", err)
			}
			if len(matches) > 0 {
				t.Errorf("Private IP should NOT be detected as sensitive, got %d matches", len(matches))
			}
		})
	}
}

func TestIPAddressValidator_ReservedIPs(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "Loopback 127.0.0.1",
			content: "localhost 127.0.0.1 running",
		},
		{
			name:    "All zeros 0.0.0.0",
			content: "bind to 0.0.0.0 for all interfaces",
		},
		{
			name:    "Broadcast 255.255.255.255",
			content: "broadcast address 255.255.255.255",
		},
		{
			name:    "Link-local 169.254.1.1",
			content: "APIPA address 169.254.1.1 assigned",
		},
		{
			name:    "Link-local 169.254.254.254",
			content: "link-local 169.254.254.254 detected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := v.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent returned error: %v", err)
			}
			if len(matches) > 0 {
				t.Errorf("Reserved IP should NOT be detected as sensitive, got %d matches", len(matches))
			}
		})
	}
}

func TestIPAddressValidator_MulticastIPs(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "Multicast 224.0.0.1",
			content: "multicast group 224.0.0.1",
		},
		{
			name:    "Multicast 239.255.255.255",
			content: "multicast 239.255.255.255 joined",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := v.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent returned error: %v", err)
			}
			if len(matches) > 0 {
				t.Errorf("Multicast IP should NOT be detected as sensitive, got %d matches", len(matches))
			}
		})
	}
}

func TestIPAddressValidator_CommonDNS(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "Google DNS 8.8.8.8",
			content: "nameserver 8.8.8.8",
		},
		{
			name:    "Cloudflare DNS 1.1.1.1",
			content: "dns server 1.1.1.1",
		},
		{
			name:    "Google DNS secondary 8.8.4.4",
			content: "nameserver 8.8.4.4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := v.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent returned error: %v", err)
			}
			// Common public DNS servers are filtered out as non-sensitive
			if len(matches) > 0 {
				t.Errorf("Common public DNS IP should NOT be detected as sensitive, got %d matches", len(matches))
			}
		})
	}
}

func TestIPAddressValidator_FalsePositives(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name        string
		content     string
		description string
	}{
		{
			name:        "Version number 4.12.0.1 has reduced confidence",
			content:     "version 4.12.0.1 released",
			description: "Version numbers with 'version' context should have reduced confidence",
		},
		{
			name:        "Build number 2.0.0.1 has reduced confidence",
			content:     "build 2.0.0.1 is ready",
			description: "Build numbers with 'build' context should have reduced confidence",
		},
		{
			name:        "IP in test context has reduced confidence",
			content:     "test data: 54.239.28.85 for demo",
			description: "IPs in test context should have reduced confidence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := v.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent returned error: %v", err)
			}
			// These are technically routable IPs, so they may still match but with reduced confidence.
			// The negative context keywords (version, build, test) reduce confidence via AnalyzeContext.
			if len(matches) > 0 {
				for _, m := range matches {
					if m.Confidence >= 100 {
						t.Errorf("Expected reduced confidence for %q in negative context, got %f: %s",
							m.Text, m.Confidence, tt.description)
					}
				}
			}
		})
	}
}

func TestIPAddressValidator_ContextAnalysis(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name           string
		match          string
		contextLine    string
		expectPositive bool
		description    string
	}{
		{
			name:           "Server context boosts confidence",
			match:          "172.217.14.206",
			contextLine:    "the server IP is 172.217.14.206 for production",
			expectPositive: true,
			description:    "Server/host context should boost confidence",
		},
		{
			name:           "Network context boosts confidence",
			match:          "172.217.14.206",
			contextLine:    "network endpoint 172.217.14.206 configured",
			expectPositive: true,
			description:    "Network context should boost confidence",
		},
		{
			name:           "Version context reduces confidence",
			match:          "4.12.0.1",
			contextLine:    "release version 4.12.0.1 is available",
			expectPositive: false,
			description:    "Version/build context should reduce confidence",
		},
		{
			name:           "Build context reduces confidence",
			match:          "2.0.0.1",
			contextLine:    "build revision 2.0.0.1 deployed",
			expectPositive: false,
			description:    "Build/revision context should reduce confidence",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contextInfo := detector.ContextInfo{
				FullLine: tt.contextLine,
			}
			impact := v.AnalyzeContext(tt.match, contextInfo)
			if tt.expectPositive && impact <= 0 {
				t.Errorf("Expected positive context impact, got %f: %s", impact, tt.description)
			}
			if !tt.expectPositive && impact >= 0 {
				t.Errorf("Expected negative context impact, got %f: %s", impact, tt.description)
			}
		})
	}
}

func TestIPAddressValidator_EdgeCases(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name        string
		content     string
		expectMatch bool
		description string
	}{
		{
			name:        "IP with port - private IP",
			content:     "connect to 192.168.1.1:8080 for the service",
			expectMatch: false,
			description: "Private IP with port should not be detected",
		},
		{
			name:        "CIDR notation - private range",
			content:     "subnet 10.0.0.0/8 is configured",
			expectMatch: false,
			description: "Private IP in CIDR notation should not be detected",
		},
		{
			name:        "Multiple IPs on one line - all private",
			content:     "route from 10.0.0.1 to 192.168.1.1 via gateway",
			expectMatch: false,
			description: "Multiple private IPs should not produce matches",
		},
		{
			name:        "Empty content",
			content:     "",
			expectMatch: false,
			description: "Empty content should produce no matches",
		},
		{
			name:        "No IPs in content",
			content:     "This is just a regular line of text with no IPs",
			expectMatch: false,
			description: "Content without IPs should produce no matches",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, err := v.ValidateContent(tt.content, "test.txt")
			if err != nil {
				t.Fatalf("ValidateContent returned error: %v", err)
			}
			if tt.expectMatch && len(matches) == 0 {
				t.Errorf("Expected match but got none: %s", tt.description)
			}
			if !tt.expectMatch && len(matches) > 0 {
				t.Errorf("Expected no match but got %d: %s", len(matches), tt.description)
			}
		})
	}
}

func TestIPAddressValidator_CalculateConfidence(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name              string
		ip                string
		expectHighConf    bool
		expectTestIPCheck bool
		description       string
	}{
		{
			name:              "Public routable IP gets high confidence",
			ip:                "172.217.14.206",
			expectHighConf:    true,
			expectTestIPCheck: true,
			description:       "Public IPs should get confidence boost",
		},
		{
			name:              "Private IP gets lower confidence",
			ip:                "192.168.1.1",
			expectHighConf:    false,
			expectTestIPCheck: true,
			description:       "Private IPs should get a confidence penalty",
		},
		{
			name:              "Known test IP gets penalty",
			ip:                "192.0.2.1",
			expectHighConf:    false,
			expectTestIPCheck: false,
			description:       "RFC 5737 test IPs should fail the not_test_ip check",
		},
		{
			name:              "Loopback gets penalty",
			ip:                "127.0.0.1",
			expectHighConf:    false,
			expectTestIPCheck: false,
			description:       "Loopback should fail test IP check and get reserved penalty",
		},
		{
			name:              "Common DNS gets boost",
			ip:                "8.8.8.8",
			expectHighConf:    false,
			expectTestIPCheck: false,
			description:       "8.8.8.8 is in knownTestPatterns so not_test_ip is false",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			confidence, checks := v.CalculateConfidence(tt.ip)

			if tt.expectHighConf && confidence < 80 {
				t.Errorf("Expected high confidence for %s, got %f: %s", tt.ip, confidence, tt.description)
			}
			if !tt.expectHighConf && confidence >= 100 {
				t.Errorf("Expected reduced confidence for %s, got %f: %s", tt.ip, confidence, tt.description)
			}
			if checks["not_test_ip"] != tt.expectTestIPCheck {
				t.Errorf("Expected not_test_ip=%v for %s, got %v: %s",
					tt.expectTestIPCheck, tt.ip, checks["not_test_ip"], tt.description)
			}
		})
	}
}

func TestIPAddressValidator_AnalyzeIPStructure(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name         string
		ip           string
		patternName  string
		expectedType string
		description  string
	}{
		{
			name:         "Private IP classification",
			ip:           "10.0.0.1",
			patternName:  "IPv4_Standard",
			expectedType: "Private",
			description:  "10.x.x.x should be classified as Private",
		},
		{
			name:         "Loopback classification",
			ip:           "127.0.0.1",
			patternName:  "IPv4_Standard",
			expectedType: "Loopback",
			description:  "127.x.x.x should be classified as Loopback",
		},
		{
			name:         "Public IP classification",
			ip:           "172.217.14.206",
			patternName:  "IPv4_Standard",
			expectedType: "Public",
			description:  "Routable IP should be classified as Public",
		},
		{
			name:         "Multicast classification",
			ip:           "224.0.0.1",
			patternName:  "IPv4_Standard",
			expectedType: "Multicast",
			description:  "224.x.x.x should be classified as Multicast",
		},
		{
			name:         "Link-local classification",
			ip:           "169.254.1.1",
			patternName:  "IPv4_Standard",
			expectedType: "Link-Local",
			description:  "169.254.x.x should be classified as Link-Local",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern := ipPattern{
				name:    tt.patternName,
				version: "IPv4",
			}
			result := v.AnalyzeIPStructure(tt.ip, pattern)
			if result["type"] != tt.expectedType {
				t.Errorf("Expected type %s for %s, got %s: %s",
					tt.expectedType, tt.ip, result["type"], tt.description)
			}
		})
	}
}

func TestIPAddressValidator_IsSensitiveIP(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name        string
		ip          string
		isSensitive bool
		description string
	}{
		{
			name:        "Public routable IP is sensitive",
			ip:          "172.217.14.206",
			isSensitive: true,
			description: "Public IPs should be considered sensitive",
		},
		{
			name:        "Private IP is not sensitive",
			ip:          "192.168.1.1",
			isSensitive: false,
			description: "Private IPs are not sensitive",
		},
		{
			name:        "Loopback is not sensitive",
			ip:          "127.0.0.1",
			isSensitive: false,
			description: "Loopback is not sensitive",
		},
		{
			name:        "Google DNS is not sensitive",
			ip:          "8.8.8.8",
			isSensitive: false,
			description: "Well-known DNS servers are not uniquely identifying",
		},
		{
			name:        "Test range is not sensitive",
			ip:          "192.0.2.50",
			isSensitive: false,
			description: "RFC 5737 documentation ranges are not sensitive",
		},
		{
			name:        "Invalid IP is not sensitive",
			ip:          "999.999.999.999",
			isSensitive: false,
			description: "Invalid IPs should not be considered sensitive",
		},
		{
			name:        "Broadcast is not sensitive",
			ip:          "255.255.255.255",
			isSensitive: false,
			description: "Broadcast address is not sensitive",
		},
		{
			name:        "All zeros is not sensitive",
			ip:          "0.0.0.0",
			isSensitive: false,
			description: "0.0.0.0 is not sensitive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.isSensitiveIP(tt.ip)
			if result != tt.isSensitive {
				t.Errorf("isSensitiveIP(%s) = %v, want %v: %s",
					tt.ip, result, tt.isSensitive, tt.description)
			}
		})
	}
}

func TestIPAddressValidator_IsEmbeddedInString(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name     string
		match    string
		line     string
		embedded bool
	}{
		{
			name:     "Standalone IP",
			match:    "10.0.0.1",
			line:     "server 10.0.0.1 running",
			embedded: false,
		},
		{
			name:     "IP preceded by letter",
			match:    "10.0.0.1",
			line:     "abc10.0.0.1 text",
			embedded: true,
		},
		{
			name:     "IP followed by letter",
			match:    "10.0.0.1",
			line:     "text 10.0.0.1abc",
			embedded: true,
		},
		{
			name:     "IP at start of line",
			match:    "10.0.0.1",
			line:     "10.0.0.1 is the address",
			embedded: false,
		},
		{
			name:     "IP at end of line",
			match:    "10.0.0.1",
			line:     "address is 10.0.0.1",
			embedded: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.isEmbeddedInString(tt.match, tt.line)
			if result != tt.embedded {
				t.Errorf("isEmbeddedInString(%q, %q) = %v, want %v",
					tt.match, tt.line, result, tt.embedded)
			}
		})
	}
}

func TestIPAddressValidator_Validate_ReturnsEmpty(t *testing.T) {
	v := NewValidator()

	matches, err := v.Validate("somefile.txt")
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("Validate should return empty results (direct file processing not supported), got %d", len(matches))
	}
}

func TestIPAddressValidator_CleanIPAddress(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{name: "Plain IP", input: "10.0.0.1", expected: "10.0.0.1"},
		{name: "CIDR notation", input: "10.0.0.0/8", expected: "10.0.0.0"},
		{name: "IP with spaces", input: "  10.0.0.1  ", expected: "10.0.0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.cleanIPAddress(tt.input)
			if result != tt.expected {
				t.Errorf("cleanIPAddress(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIPAddressValidator_IsTestIP(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name   string
		ip     string
		isTest bool
	}{
		{name: "RFC 5737 TEST-NET-1", ip: "192.0.2.1", isTest: true},
		{name: "RFC 5737 TEST-NET-2", ip: "198.51.100.1", isTest: true},
		{name: "RFC 5737 TEST-NET-3", ip: "203.0.113.1", isTest: true},
		{name: "Loopback", ip: "127.0.0.1", isTest: true},
		{name: "Google DNS", ip: "8.8.8.8", isTest: true},
		{name: "Cloudflare DNS", ip: "1.1.1.1", isTest: true},
		{name: "Regular public IP", ip: "172.217.14.206", isTest: false},
		{name: "Regular public IP 2", ip: "54.239.28.85", isTest: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.isTestIP(tt.ip)
			if result != tt.isTest {
				t.Errorf("isTestIP(%s) = %v, want %v", tt.ip, result, tt.isTest)
			}
		})
	}
}

func TestIPAddressValidator_IsPrivateIP(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name      string
		ip        string
		isPrivate bool
	}{
		{name: "10.x range", ip: "10.0.0.1", isPrivate: true},
		{name: "172.16.x range", ip: "172.16.0.1", isPrivate: true},
		{name: "172.31.x range", ip: "172.31.255.255", isPrivate: true},
		{name: "192.168.x range", ip: "192.168.1.1", isPrivate: true},
		{name: "Public IP", ip: "172.217.14.206", isPrivate: false},
		{name: "Loopback is not private", ip: "127.0.0.1", isPrivate: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.isPrivateIP(tt.ip)
			if result != tt.isPrivate {
				t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, result, tt.isPrivate)
			}
		})
	}
}

func TestIPAddressValidator_IsMulticastIP(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name        string
		ip          string
		isMulticast bool
	}{
		{name: "Multicast start", ip: "224.0.0.1", isMulticast: true},
		{name: "Multicast end", ip: "239.255.255.255", isMulticast: true},
		{name: "Non-multicast", ip: "172.217.14.206", isMulticast: false},
		{name: "Private", ip: "10.0.0.1", isMulticast: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.isMulticastIP(tt.ip)
			if result != tt.isMulticast {
				t.Errorf("isMulticastIP(%s) = %v, want %v", tt.ip, result, tt.isMulticast)
			}
		})
	}
}

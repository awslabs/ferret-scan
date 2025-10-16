// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ipaddress

import "ferret-scan/internal/help"

// GetCheckInfo returns standardized information about the IP address check
func (v *Validator) GetCheckInfo() help.CheckInfo {
	return help.CheckInfo{
		Name:             "IP_ADDRESS",
		ShortDescription: "Detects IPv4 and IPv6 addresses in various formats",
		DetailedDescription: `The IP Address check detects both IPv4 and IPv6 addresses using comprehensive pattern matching and validation.

It supports standard IPv4 addresses, IPv4 with CIDR notation, full IPv6 addresses, compressed IPv6 notation, and IPv6 with embedded IPv4. The validator classifies IPs as private, public, reserved, or test addresses and applies appropriate confidence adjustments.

The check validates IP addresses using Go's built-in net package, identifies RFC test ranges, and distinguishes between different IP types (loopback, link-local, multicast, etc.). It uses contextual keywords to improve accuracy in network-related documents.`,

		Patterns: []string{
			"IPv4: 192.168.1.1, 10.0.0.1, 172.16.0.1",
			"IPv4 with CIDR: 192.168.1.0/24, 10.0.0.0/8",
			"IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			"IPv6 compressed: 2001:db8:85a3::8a2e:370:7334",
			"IPv6 with embedded IPv4: ::ffff:192.168.1.1",
			"IPv6 with CIDR: 2001:db8::/32",
		},

		SupportedFormats: []string{
			"IPv4 standard format (XXX.XXX.XXX.XXX)",
			"IPv4 with CIDR notation (/0-32)",
			"IPv6 full format (8 groups of 4 hex digits)",
			"IPv6 compressed format (using ::)",
			"IPv6 with embedded IPv4",
			"IPv6 with CIDR notation (/0-128)",
			"Private IP ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x)",
			"Reserved IP ranges (127.x.x.x, 169.254.x.x, etc.)",
		},

		ConfidenceFactors: []help.ConfidenceFactor{
			{Name: "Valid Format", Description: "Must match IP address patterns", Weight: 20},
			{Name: "Valid IP", Description: "Must parse as valid IP using Go net package", Weight: 20},
			{Name: "Not Test IP", Description: "Must not match RFC test ranges", Weight: 25},
			{Name: "Not Reserved", Description: "Higher confidence for non-reserved ranges", Weight: 15},
			{Name: "Reasonable Use", Description: "Context-appropriate IP address usage", Weight: 20},
		},

		PositiveKeywords: v.positiveKeywords,
		NegativeKeywords: v.negativeKeywords,

		Examples: []string{
			"ferret-scan --file network-config.txt --checks IP_ADDRESS",
			"ferret-scan --file server-logs.log --confidence medium | grep IP_ADDRESS",
			"ferret-scan --file infrastructure.json --verbose --checks IP_ADDRESS",
		},
	}
}

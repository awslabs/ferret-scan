// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ipaddress

import (
	"testing"
)

// #937: tokens that are not addresses read IP_ADDRESS at 100 HIGH. Measured on main @ 2fb4719
// with each line below alone in a file (--config /dev/null --confidence all --checks IP_ADDRESS):
// the first three rows of each table read 100 HIGH. These tests use only ValidateContent, so they
// run unchanged against the parent commit, where they fail.

// reportedConfidences returns every confidence the validator reports for value on content.
func reportedConfidences(t *testing.T, content, value string) []float64 {
	t.Helper()
	matches, err := NewValidator().ValidateContent(content, "probe.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	var got []float64
	for _, m := range matches {
		if m.Text == value {
			got = append(got, m.Confidence)
		}
	}
	return got
}

// TestADoubleColonIdentifierIsNotAnIPv6Address covers the IPv6 half.
//
// "::EC2" parses as ::ec2, inside ::/96: the deprecated IPv4-compatible block (RFC 4291, 2.5.5)
// that also holds :: and ::1. No current stack assigns an address there, and the validator already
// dropped ::1 from it. A "::"-separated identifier lands there whenever an all-hex segment starts
// the token. The other form, a hex-only head followed by a second "::", is not one address because
// an address holds at most one "::" (RFC 4291, 2.2).
func TestADoubleColonIdentifierIsNotAnIPv6Address(t *testing.T) {
	cases := []struct {
		name, line, value string
	}{
		// The issue's own row: this package's comment at validator.go:1109 on main.
		{"the source comment", `// This helps filter out false positives like "AWS::EC2::Instance" where "::EC2" matches IPv6 pattern`, "::EC2"},
		{"a scope written from its root", "the ::EC2::Instance resource type", "::EC2"},
		{"a scope prefix alone", "the ::EC2 namespace", "::EC2"},
		{"another all-hex service segment", "the ::CE::AnomalyMonitor type", "::CE"},
		{"a hex-only head before a second ::", "call `Face::Add::Bead` here", "Face::Add"},
		{"three hex-only segments", "see Dead::Beef::Cafe in the dump", "Dead::Beef"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := reportedConfidences(t, tc.line, tc.value); len(got) != 0 {
				t.Errorf("%q reported as IP_ADDRESS at %v; a \"::\"-separated identifier is not an "+
					"address (#937)", tc.value, got)
			}
		})
	}
}

// TestAGenuineIPv6AddressIsUnaffectedByTheIdentifierRules is the recall half: every public
// compressed address keeps 100, including ones that end in "::" or sit in brackets with a port.
func TestAGenuineIPv6AddressIsUnaffectedByTheIdentifierRules(t *testing.T) {
	cases := []struct {
		name, line, value string
	}{
		{"compressed with a keyword", "connecting to host 2606:4700:4700::1111 over ipv6", "2606:4700:4700::1111"},
		{"compressed without a keyword", "Peer 2a05:d018:76c:b600::5 now", "2a05:d018:76c:b600::5"},
		{"bracketed with a port", "endpoint [2600:1f18:4a3:6901::10]:443 now", "2600:1f18:4a3:6901::10"},
		{"a prefix ending in ::", "the prefix 2606:4700:: belongs to the host", "2606:4700::"},
		{"zone suffix", "link 2600:1f18:4a3:6901::10%eth0 up", "2600:1f18:4a3:6901::10"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := reportedConfidences(t, tc.line, tc.value)
			if len(got) != 1 || got[0] < 90 {
				t.Errorf("%q reported at %v, want one finding at HIGH: a genuine compressed address "+
					"must not be touched by the identifier rules", tc.value, got)
			}
		})
	}
}

// TestAVersionBesideItsOwnProductTokenIsAVersion covers the first IPv4 shape: the same quad
// quoted bare and then where it came from, on one line that also carries an IP keyword.
//
// The per-line dedup reports only the first occurrence, so the bare quote was scored and the
// product token, which says what the value is, was skipped.
func TestAVersionBesideItsOwnProductTokenIsAVersion(t *testing.T) {
	// CHANGELOG.md:1918 on main, verbatim.
	line := "  **Measured across 788 real files: 201 findings gained, 0 lost, and every gain on a " +
		"`.ott`/`.ots` — zero on any non-template file.** Chiefly `AUTHOR_INFO` (58), " +
		"`APPLICATION_INFO` (58), `LAST_MODIFIED_BY` (32), `DOCUMENT_DESCRIPTION` (22) and " +
		"`PERSON_NAME` (3). Reported honestly rather than counted as all wins: 4 are `IP_ADDRESS` " +
		"at 80 matching `4.3.3.2` out of `Application: LibreOffice/4.3.3.2$Linux_X86_64...`, which " +
		"is the **pre-existing** [#513](https://github.com/awslabs/ferret-scan/issues/513)"
	got := reportedConfidences(t, line, "4.3.3.2")
	if len(got) != 1 {
		t.Fatalf("4.3.3.2 reported %d times (%v), want once: this rule demotes, it never drops", len(got), got)
	}
	if got[0] != productVersionCeiling {
		t.Errorf("4.3.3.2 reported at %v, want the product-version ceiling %v: the line itself "+
			"writes it as LibreOffice's version", got[0], productVersionCeiling)
	}

	// Control: the same bare quote with no product token on the line keeps the keyword escape.
	control := "4 are `IP_ADDRESS` at 80 matching `52.94.236.248` out of the log"
	if c := reportedConfidences(t, control, "52.94.236.248"); len(c) != 1 || c[0] < 90 {
		t.Errorf("control %q reported at %v, want HIGH", control, c)
	}
}

// TestAVersionAfterAProductNameIsNotLiftedByAKeywordElsewhere covers the second IPv4 shape.
//
// The keyword escape is line-global: one "server" anywhere on the line clears the cap for every
// quad. In both lines below the keyword belongs to something else, a product name or another
// value, and the quad's own label is the capitalised name right before it.
func TestAVersionAfterAProductNameIsNotLiftedByAKeywordElsewhere(t *testing.T) {
	cases := []struct {
		name, line, value string
	}{
		// CHANGELOG.md:2270 and :2272 on main, verbatim.
		{"keyword inside the product name", "  Server Manager 26.8.0.3` → `IP_ADDRESS` 100, and the " +
			"same escape exists in `ssn`, `creditcard`,", "26.8.0.3"},
		{"keyword labelling another value", "  Manager 26.8.0.3` is indistinguishable from `Server " +
			"10.0.0.1 is down`), so it needs the metadata-field", "26.8.0.3"},
		{"the whole product signature on one line", "Application: Acme Server Manager 26.8.0.3", "26.8.0.3"},
		{"a browser name", "Chrome 138.0.0.0 fetched http://example.org/", "138.0.0.0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := reportedConfidences(t, tc.line, tc.value)
			if len(got) != 1 {
				t.Fatalf("%s reported %d times (%v), want once: the rule withholds an escape, it "+
					"never drops", tc.value, len(got), got)
			}
			if got[0] != ambiguousShapeCap {
				t.Errorf("%s reported at %v, want the context-free cap %v", tc.value, got[0], ambiguousShapeCap)
			}
		})
	}
}

// TestALabelledAddressKeepsItsScore holds the controls the issue names, and the ones the name
// rule must not reach: a keyword or a preposition directly before the value, a lower-case or
// all-capitals word, a suffix welded to the value, and a URL authority.
func TestALabelledAddressKeepsItsScore(t *testing.T) {
	cases := []struct {
		name, line, value string
	}{
		{"keyword before the value", "Server 52.94.236.248 is down", "52.94.236.248"},
		{"URL authority", "See http://52.94.236.248 now", "52.94.236.248"},
		{"a preposition before the value", "From 52.94.236.248 the server replied", "52.94.236.248"},
		{"Via", "Via 104.18.32.7 through the proxy", "104.18.32.7"},
		{"lower-case word", "Host is 104.18.32.7 behind the proxy", "104.18.32.7"},
		{"all-capitals log field", "ACCEPT 52.94.236.248 tcp", "52.94.236.248"},
		{"a port after a name", "Manager 52.94.236.248:8443 on the server", "52.94.236.248"},
		{"a CIDR after a name", "Allowlist 52.94.236.248/24 on the gateway", "52.94.236.248"},
		{"two spaces are a column, not a name", "Primary  52.94.236.248  server", "52.94.236.248"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := reportedConfidences(t, tc.line, tc.value)
			if len(got) != 1 || got[0] < 90 {
				t.Errorf("%q reported at %v, want one finding at HIGH", tc.value, got)
			}
		})
	}
}

// TestAColumnHeaderStillLiftsAValueAfterAName: the name rule withholds only the LINE keyword.
// A header naming the column an IP is the value's own label, so it still clears the cap. Each data
// row carries a line keyword ("server") and a name before the value, so with both escapes withheld
// the values would read 75.
func TestAColumnHeaderStillLiftsAValueAfterAName(t *testing.T) {
	const csv = "role,Source IP address,region\n" +
		"web server,Primary 44.205.141.46,us-east-1\n" +
		"db server,Standby 44.205.141.47,us-east-1\n"
	for _, value := range []string{"44.205.141.46", "44.205.141.47"} {
		got := reportedConfidences(t, csv, value)
		if len(got) != 1 || got[0] < 90 {
			t.Errorf("%s in a \"Source IP address\" column reported at %v, want HIGH", value, got)
		}
	}
}

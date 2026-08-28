// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ipaddress

import (
	"fmt"
	"strings"
	"testing"
)

// #513: a four-part software version in a metadata field was reported as IP_ADDRESS at
// HIGH, on every LibreOffice-authored ODF document.
//
// Two independent causes, both fixed here:
//
//  1. The validator's ambiguity cap was applied to its local `confidence` variable and
//     nowhere else. The dual-path bridge then added a document-level context adjustment
//     to every match, so the cap did not survive. Measured on ten real .odt documents
//     carrying a BYTE-IDENTICAL generator string: eight reported HIGH 95 and two
//     MEDIUM 75, the difference being body text the match has nothing to do with. The
//     cap is now published as a confidence ceiling, which the bridge honours.
//
//  2. The cap-escape is a keyword search over the match's own line, so one "http"
//     anywhere on the line lifted a version to HIGH — a User-Agent logged beside a URL
//     scored HIGH 92. A product-token shape now outranks that line-global signal.
//
// Both are precision-only. Measured across 2,198 real files: 0 findings lost, 0 gained,
// 12 demoted out of HIGH (all 12 verified versions — 8 LibreOffice generators and 4
// Chrome User-Agents) and 4,674 genuine addresses raised from HIGH 95 to HIGH 100 by the
// column-header arm below.

// confidenceOf runs the validator over content and returns the confidence reported for
// value, or -1 when it was not reported at all.
func confidenceOf(t *testing.T, content, value string) float64 {
	t.Helper()
	matches, err := NewValidator().ValidateContent(content, "probe.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	for _, m := range matches {
		if m.Text == value {
			return m.Confidence
		}
	}
	return -1
}

// TestAProductVersionIsNotReportedAsHigh covers cause 2 and the interaction with cause 1.
//
// Every "want" here is MEDIUM rather than absent: the rule DEMOTES and does not drop.
//
// Its precision on real files is high. Sweeping the public directories of this host found
// 2,157 product-token occurrences on values the validator would report, and every product
// name was a software component: IslandUpdater (2,045), Firefox (36), Versions (24),
// Chrome, BraveUpdater, HarfBuzzSharp, Electron.Library, and an X.509 OID "2.5.4.97"
// following "Ltd." in a certificate. None was an address.
//
// It is still not a veto, because the same sweep found the shape on genuine addresses in
// path segments — "/LDAPv3/10.0.1.42/Groups/admin" and "esp/tunnel/10.1.1.2-10.1.1.1",
// both from Xcode SDK man pages. Every such instance was loopback or private and therefore
// already suppressed for an unrelated reason, which is luck rather than a guarantee. A
// demoted finding is still reported and still redacted, so when this rule is wrong it costs
// a confidence band; dropping would cost the value in cleartext.
func TestAProductVersionIsNotReportedAsHigh(t *testing.T) {
	// Transcribed from real files on this host: the LibreOffice generator is the string
	// every .odt authored by the installed LibreOffice carries, and the Chrome
	// User-Agent is the shape found in two real CloudTrail CSV exports and two real
	// .docx documents.
	cases := []struct {
		name  string
		line  string
		value string
	}{
		{
			name:  "LibreOffice generator",
			line:  "Application: LibreOffice/24.8.4.2$MacOSX_AARCH64 LibreOffice_project/bce9dfa1",
			value: "24.8.4.2",
		},
		{
			name:  "Chrome User-Agent",
			line:  "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/138.0.0.0 Safari/537.36",
			value: "138.0.0.0",
		},
		{
			// The line-global keyword escape: "http" is a positive keyword, and before
			// this fix its presence anywhere on the line took the version to HIGH 92.
			name:  "version on a line that also mentions http",
			line:  "Referrer: http://example.org/ with Chrome/138.0.0.0 logged",
			value: "138.0.0.0",
		},
		{
			name:  "framework version directory",
			line:  "Loaded Island Framework.framework/Versions/151.1.98.30/Island",
			value: "151.1.98.30",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := confidenceOf(t, tc.line, tc.value)
			if got < 0 {
				t.Fatalf("%s was not reported at all. This rule must DEMOTE, not drop: "+
					"the same shape occurs on genuine addresses in path segments, and only a "+
					"reported finding is handed to the redactor.", tc.value)
			}
			if got >= 90 {
				t.Errorf("%s reported at %v (HIGH); a product-token version must stay below "+
					"the HIGH boundary of 90 (#513)", tc.value, got)
			}
			if got != ambiguousShapeCap {
				t.Errorf("%s reported at %v, want the ambiguity cap %v", tc.value, got, ambiguousShapeCap)
			}
		})
	}
}

// TestAGenuineAddressIsUnaffected is the control, and it is the half that matters most:
// a suppressing rule that also silences real addresses is worse than the noise it fixes.
//
// The URL case is the reason isProductVersionAt requires a LETTER before the '/'. In
// "http://52.94.236.248" the character before the quad is also a '/', and a rule that
// treated any preceding '/' as a version would have demoted all 10 URL-authority
// addresses measured in the corpus, several of them public.
func TestAGenuineAddressIsUnaffected(t *testing.T) {
	cases := []struct {
		name  string
		line  string
		value string
	}{
		{"labelled address", "Server address: 52.94.236.248", "52.94.236.248"},
		{"URL authority", "Endpoint: http://52.94.236.248/health", "52.94.236.248"},
		{"URL with port", "Endpoint: https://104.18.32.7:8443/v1", "104.18.32.7"},
		{"websocket URL", "Connect to ws://17.253.144.10:9222/devtools", "17.253.144.10"},
		{"CIDR suffix", "Allow 17.253.144.10/24 inbound", "17.253.144.10"},
		{"keyword on the line", "Host is 104.18.32.7 behind the proxy", "104.18.32.7"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := confidenceOf(t, tc.line, tc.value)
			if got < 90 {
				t.Errorf("%s reported at %v, want HIGH (>=90). A genuine corroborated address "+
					"must not be demoted by the version rule.", tc.value, got)
			}
		})
	}
}

// TestAStructuralSuffixOutranksTheProductTokenShape.
//
// A port or CIDR welded to the value is value-adjacent, exactly like the shape, so it is
// not overridden. Only the LABEL signals — the line keyword and the column header — lose
// to the shape.
func TestAStructuralSuffixOutranksTheProductTokenShape(t *testing.T) {
	for _, tc := range []struct {
		name, line, value string
	}{
		{"port", "Proxied via Gateway/52.94.236.248:8443 today", "52.94.236.248"},
		{"CIDR", "Route via Gateway/52.94.236.248/24 today", "52.94.236.248"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := confidenceOf(t, tc.line, tc.value); got < 90 {
				t.Errorf("%s reported at %v, want HIGH: a port or CIDR suffix is welded to the "+
					"value and corroborates an address as directly as the shape contradicts it",
					tc.value, got)
			}
		})
	}
}

// TestTheAmbiguityCapPublishesItsCeiling covers cause 1 at this end of the contract.
//
// Setting the local `confidence` variable is not enough — the bridge raises confidence
// afterwards. The ceiling must be in the metadata for that clamp to have anything to
// read. The companion test in internal/validators drives the bridge's own clamp with
// what this validator actually publishes, so the key cannot drift.
func TestTheAmbiguityCapPublishesItsCeiling(t *testing.T) {
	matches, err := NewValidator().ValidateContent(
		"Application: LibreOffice/24.8.4.2$MacOSX_AARCH64", "probe.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("got %d matches, want 1", len(matches))
	}

	raw, ok := matches[0].Metadata[confidenceCeilingKey]
	if !ok {
		t.Fatalf("a capped match published no %q. Assigning to the local confidence "+
			"variable bounds only what this validator returns; the bridge adds a "+
			"document-level adjustment afterwards, and without the ceiling the cap is "+
			"undone (#513: capped to 75 here, reported at HIGH 95).", confidenceCeilingKey)
	}
	// float64 specifically: the bridge ignores any other type rather than treating it
	// as zero, so an int here would be a silent no-op.
	got, isFloat := raw.(float64)
	if !isFloat {
		t.Fatalf("%s = %T, want float64. The bridge ignores a ceiling of any other type, "+
			"which would make this a silent no-op.", confidenceCeilingKey, raw)
	}
	if got != ambiguousShapeCap {
		t.Errorf("%s = %v, want %v", confidenceCeilingKey, got, ambiguousShapeCap)
	}
}

// TestAnUncappedMatchPublishesNoCeiling is the other half. A ceiling on a corroborated
// address would stop it reaching HIGH, turning a precision fix into a recall regression.
func TestAnUncappedMatchPublishesNoCeiling(t *testing.T) {
	matches, err := NewValidator().ValidateContent("Server address: 52.94.236.248", "probe.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("got %d matches, want 1", len(matches))
	}
	if _, ok := matches[0].Metadata[confidenceCeilingKey]; ok {
		t.Errorf("a corroborated address published a confidence ceiling; that would hold a " +
			"genuine finding below HIGH")
	}
}

// TestAColumnHeaderNamingAnIPCorroboratesTheAddress.
//
// The cap-escape searches the match's own LINE for a keyword, and in a CSV export the
// label lives in the header ROW. So every address in a "Source IP address" column was
// treated as context-free and capped, then rescued only by the document-level adjustment
// this change removes — which is why the header arm is REQUIRED here rather than a
// separate improvement. Without it, making the cap stick would demote 4,549 genuine
// public addresses in one real CloudTrail export.
//
// The header row and column names are transcribed verbatim from a real CloudTrail CSV
// export. That detail matters: a hand-written "sourceIPAddress" in camelCase does NOT
// match, because the keyword search is whole-word and "ip" inside "sourceipaddress" is
// not a word. The real export writes "Source IP address" with spaces. The synthetic
// fixture passed while the real file would have failed.
func TestAColumnHeaderNamingAnIPCorroboratesTheAddress(t *testing.T) {
	const csv = "User name,AWS access key,Event time,Event source,Event name,AWS region,Source IP address,User agent\n" +
		"alice,ASIASCMWFOX3LXMN6MSD,2024-04-16T22:18:03Z,ssm.amazonaws.com,UpdateInstanceInformation,us-east-1,44.205.141.46,aws-sdk-go\n"

	// Non-vacuity: the data row must carry NO IP keyword of its own, or the header arm
	// is not what cleared the cap and this test proves nothing.
	dataRow := strings.Split(csv, "\n")[1]
	v := NewValidator()
	for _, kw := range v.positiveKeywords {
		if ipContainsKeyword(strings.ToLower(dataRow), kw) {
			t.Fatalf("the data row already carries the IP keyword %q, so the line-global "+
				"escape clears the cap and the header arm is untested", kw)
		}
	}

	if got := confidenceOf(t, csv, "44.205.141.46"); got < 90 {
		t.Errorf("an address in a column headed \"Source IP address\" reported at %v, want "+
			"HIGH. The header is the only label a CSV data row has; without it every address "+
			"in a real export is treated as context-free.", got)
	}
}

// TestAHeaderThatNamesNothingLeavesTheScoreAlone bounds the header arm's blast radius.
//
// It only ever ADDS a corroborating signal. There is deliberately no "header
// contradicts" arm: suppressing an address because a column is named something else
// would be suppression chosen by whoever wrote the file.
func TestAHeaderThatNamesNothingLeavesTheScoreAlone(t *testing.T) {
	const csv = "product,appVersion,vendor\n" +
		"Writer,24.8.4.2,LibreOffice\n"

	got := confidenceOf(t, csv, "24.8.4.2")
	if got < 0 {
		t.Fatal("the version was dropped rather than demoted")
	}
	if got >= 90 {
		t.Errorf("a version in an \"appVersion\" column reported at %v (HIGH); no header "+
			"keyword is present, so the cap must hold", got)
	}
}

// TestAQuadOnTheHeaderRowIsStillReportedAndStillCapped.
//
// The header row is skipped when resolving columns, because there a cell is a column name
// rather than a value in a column. What that guard must NOT do is stop the header row
// being scanned: it is ordinary text and a quad in it is an ordinary finding.
//
// Only this direction is asserted, and deliberately. The opposite claim — that skipping
// the header row prevents a wrong PROMOTION — is not constructible: the header cell that
// would name a column is the very text the value sits in, so a quad on the header row can
// only ever be attributed to its own cell, and its own cell is not an IP-named column
// unless it says so. A test for that direction would pass whether or not the guard were
// there. The guard stays because it mirrors the ssn validator and is correct, not because
// a test can distinguish it.
func TestAQuadOnTheHeaderRowIsStillReportedAndStillCapped(t *testing.T) {
	const csv = "name,build 24.8.4.2,region\n" +
		"alice,x,us-east-1\n" +
		"bob,y,us-west-2\n"

	// Non-vacuity: no IP keyword anywhere in the content, so nothing else can clear the
	// cap and the assertion below is about this change alone.
	v := NewValidator()
	for _, kw := range v.positiveKeywords {
		if ipContainsKeyword(strings.ToLower(csv), kw) {
			t.Fatalf("the fixture carries the IP keyword %q, which clears the cap on its own", kw)
		}
	}

	got := confidenceOf(t, csv, "24.8.4.2")
	if got < 0 {
		t.Fatal("a quad on the header row was not reported at all; the header row is skipped " +
			"for COLUMN RESOLUTION only and must still be scanned as text")
	}
	if got >= 90 {
		t.Errorf("a quad on the header row reported at %v (HIGH), want the cap %v",
			got, ambiguousShapeCap)
	}
}

// TestNonTabularContentIsCompletelyUnchangedByTheHeaderArm.
//
// tabular.Analyze is conservative, and this asserts the consequence rather than trusting
// it: prose with commas is not a table, so the header arm contributes nothing and the
// behaviour is exactly the pre-existing one.
func TestNonTabularContentIsCompletelyUnchangedByTheHeaderArm(t *testing.T) {
	cases := []struct {
		name, content, value string
		wantHigh             bool
	}{
		{
			name:     "comma-rich prose with a keyword",
			content:  "The server, which we rebuilt, answers on 52.94.236.248, as expected.",
			value:    "52.94.236.248",
			wantHigh: true,
		},
		{
			name:     "comma-rich prose with a version",
			content:  "We shipped, at last, LibreOffice/24.8.4.2 to everyone, finally.",
			value:    "24.8.4.2",
			wantHigh: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := confidenceOf(t, tc.content, tc.value)
			if tc.wantHigh && got < 90 {
				t.Errorf("%s reported at %v, want HIGH", tc.value, got)
			}
			if !tc.wantHigh && got >= 90 {
				t.Errorf("%s reported at %v, want below HIGH", tc.value, got)
			}
		})
	}
}

// TestIsProductVersionAtDiscriminatesTheUrlAuthority is the unit-level statement of the
// asymmetry, kept because it is the single decision the whole rule rests on.
func TestIsProductVersionAtDiscriminatesTheUrlAuthority(t *testing.T) {
	cases := []struct {
		line string
		want bool
		why  string
	}{
		{"LibreOffice/24.8.4.2", true, "letter before the slash: a product token"},
		{"Chrome/138.0.0.0", true, "letter before the slash"},
		{"http://52.94.236.248", false, "'//' before: a URL authority, a real address"},
		{"ws://17.253.144.10", false, "'//' before"},
		{"52.94.236.248", false, "no slash at all"},
		{"v/1.2.3.4", true, "single letter still names a product"},
		{"/52.94.236.248", false, "slash at offset 0 has nothing before it"},
		{"1.4.0/2.1.5.2", false, "digit before the slash: a version path, not a product token"},
		{"Gateway_/52.94.236.248", false, "'_' before the slash is not a letter"},
	}
	for _, tc := range cases {
		t.Run(tc.line, func(t *testing.T) {
			idx := strings.LastIndex(tc.line, "/")
			// For the no-slash case the match starts at 0.
			start := idx + 1
			if got := isProductVersionAt(tc.line, start); got != tc.want {
				t.Errorf("isProductVersionAt(%q, %d) = %v, want %v (%s)",
					tc.line, start, got, tc.want, tc.why)
			}
		})
	}
}

// TestTheProductTokenRuleIsBoundedByOffsetZero guards the two-byte lookbehind against a
// slice panic, which is the only way this helper can fail catastrophically.
func TestTheProductTokenRuleIsBoundedByOffsetZero(t *testing.T) {
	for _, line := range []string{"", "/", "a/", "1.2.3.4"} {
		for off := 0; off <= len(line); off++ {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("isProductVersionAt(%q, %d) panicked: %v", line, off, r)
					}
				}()
				isProductVersionAt(line, off)
			}()
		}
	}
}

// TestTheStructuralSuffixExtractionIsFaithful.
//
// hasStructuralSuffixAt is the port/CIDR half lifted out of hasIPContextSignalAt so the
// cap-escape can weigh the two signals separately. Both sides here are production
// functions: if the extraction lost a case, the composition below stops matching the
// function it was taken from, and with it the guarantee that ordinary content — no
// product token, no table — behaves exactly as before.
func TestTheStructuralSuffixExtractionIsFaithful(t *testing.T) {
	v := NewValidator()
	const ip = "52.94.236.248"
	for _, keyword := range []bool{false, true} {
		for _, line := range []string{
			"bare " + ip + " alone",
			"trailing " + ip + ":8080 port",
			"trailing " + ip + "/24 cidr",
			"trailing " + ip + ":99999 too many digits",
			"trailing " + ip + "/64 out of ipv4 range",
			"at the very end " + ip,
		} {
			t.Run(fmt.Sprintf("keyword=%v/%s", keyword, line), func(t *testing.T) {
				matchEnd := strings.Index(line, ip) + len(ip)
				want := v.hasIPContextSignalAt(keyword, line, matchEnd)
				got := keyword || hasStructuralSuffixAt(line, matchEnd)
				if got != want {
					t.Errorf("keyword||hasStructuralSuffixAt = %v but hasIPContextSignalAt = %v "+
						"for %q; the extraction must be exact, or ordinary content changes "+
						"behaviour", got, want, line)
				}
			})
		}
	}
}

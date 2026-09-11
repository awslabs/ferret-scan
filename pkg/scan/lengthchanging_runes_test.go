// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scan_test

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/awslabs/ferret-scan/v2/pkg/scan"
)

// This file is the authoritative guard for one invariant:
//
//	A scan's output must not depend on whether the input contains a rune whose
//	Unicode case mapping changes byte length.
//
// # Why it is stated as an invariant and not as a list of symptoms
//
// The first version of this guard, shipped with #658, asserted only that the
// finding COUNT did not drop. That oracle was chosen to match the failure that had
// been observed — a validator panicking and losing every finding for the file — and
// it is structurally blind to the rest of the class:
//
//	a 92 HIGH -> 57 LOW demotion   is still one finding, so the count is unchanged
//	a finding GAINED                is not a drop, so a false positive is invisible
//	a finding moving line           is not a drop
//
// Both remaining instances of the bug were of exactly those shapes, and both
// survived the guard: PERSON_NAME was demoted out of the HIGH band (so it vanished
// from the default `--confidence high` view) and DATE_OF_BIRTH gained a finding by
// silently defeating its own synthetic-marker suppression. Neither panicked, so
// #658's disclosure fix could not see them either.
//
// So this guard compares the FULL finding signature — type, line, and NUMERIC
// confidence — against a control, which catches drops, gains, band shifts and
// line shifts with one assertion. Deriving the oracle from the invariant rather
// than from the symptom is the whole point: it does not need to know which failure
// mode comes next.
//
// # The control is byte-length-identical, deliberately
//
// A hostile rune has a byte length, and simply removing it changes every offset
// after it — so a shorter control would differ for reasons that have nothing to do
// with folding. Each control therefore uses ASCII 'q' repeated to the SAME original
// byte count. 'q' folds to itself, is a word byte, and is not a keyword in any
// validator, so the only variable between the two runs is whether the fold changes
// length.

// lengthChangingRunes is the COMPLETE set of runes whose case mapping changes byte
// length, obtained by enumerating the whole code point space rather than by
// choosing characters that look suspicious. See internal/bytefold.
//
// The direction is recorded because it decides the failure mode: shrink makes an
// offset overshoot (panic, or a clamp that silently fails open), grow makes it land
// mid-value (a wrong answer with no signal at all).
var lengthChangingRunes = []struct {
	r      rune
	family string
}{
	// strings.ToLower shrinks: 25 runes.
	{0x0130, "lower-shrink"}, {0x1E9E, "lower-shrink"}, {0x2126, "lower-shrink"},
	{0x212A, "lower-shrink"}, {0x212B, "lower-shrink"}, {0x2C62, "lower-shrink"},
	{0x2C64, "lower-shrink"}, {0x2C6D, "lower-shrink"}, {0x2C6E, "lower-shrink"},
	{0x2C6F, "lower-shrink"}, {0x2C70, "lower-shrink"}, {0x2C7E, "lower-shrink"},
	{0x2C7F, "lower-shrink"}, {0xA78D, "lower-shrink"}, {0xA7AA, "lower-shrink"},
	{0xA7AB, "lower-shrink"}, {0xA7AC, "lower-shrink"}, {0xA7AD, "lower-shrink"},
	{0xA7AE, "lower-shrink"}, {0xA7B0, "lower-shrink"}, {0xA7B1, "lower-shrink"},
	{0xA7B2, "lower-shrink"}, {0xA7C5, "lower-shrink"}, {0xA7CB, "lower-shrink"},
	{0xA7DC, "lower-shrink"},
	// strings.ToLower grows: 2 runes. These corrupt silently.
	{0x023A, "lower-grow"}, {0x023E, "lower-grow"},
	// strings.ToUpper shrinks: 13 runes.
	{0x0131, "upper-shrink"}, {0x017F, "upper-shrink"}, {0x1C80, "upper-shrink"},
	{0x1C81, "upper-shrink"}, {0x1C82, "upper-shrink"}, {0x1C83, "upper-shrink"},
	{0x1C84, "upper-shrink"}, {0x1C85, "upper-shrink"}, {0x1C86, "upper-shrink"},
	{0x1C87, "upper-shrink"}, {0x1FBE, "upper-shrink"}, {0x2C65, "upper-shrink"},
	{0x2C66, "upper-shrink"},
	// strings.ToUpper grows: 20 runes.
	{0x019B, "upper-grow"}, {0x023F, "upper-grow"}, {0x0240, "upper-grow"},
	{0x0250, "upper-grow"}, {0x0251, "upper-grow"}, {0x0252, "upper-grow"},
	{0x025C, "upper-grow"}, {0x0261, "upper-grow"}, {0x0264, "upper-grow"},
	{0x0265, "upper-grow"}, {0x0266, "upper-grow"}, {0x026A, "upper-grow"},
	{0x026B, "upper-grow"}, {0x026C, "upper-grow"}, {0x0271, "upper-grow"},
	{0x027D, "upper-grow"}, {0x0282, "upper-grow"}, {0x0287, "upper-grow"},
	{0x029D, "upper-grow"}, {0x029E, "upper-grow"},
}

// foldFixtures is one positive sample per detection type, each on its OWN LINE so a
// per-line signature attributes any divergence to a specific validator instead of
// reporting "something changed".
//
// Two entries are not simple positives and are the reason the suppression side is
// covered at all:
//
//	dob-suppressed  must produce NOTHING — the "(test)" marker is a synthetic-value
//	                rule, and a hostile rune defeating it is a false positive at
//	                HIGH, which a "did we lose a finding" oracle cannot see.
//	name-with-geo   carries a street address on the same line, which triggers the
//	                geo proximity PENALTY. That penalty is distance-based, so it is
//	                the one most sensitive to a desynchronised offset.
var foldFixtures = []struct{ name, text string }{
	{"bank", "Wire to routing number 021000089 account 1234567890 at the branch."},
	{"cloud", "Deploy to arn:aws:s3:::acme-prod-customer-exports-2024 immediately."},
	{"card", "Card number 4111-1111-1111-1111 exp 12/28 for the subscription."},
	{"dob", "Patient date of birth: 03/14/1985 per the intake form."},
	{"dob-suppressed", "Patient date of birth: 03/14/1985 (test) per the intake form."},
	{"dl", "California driver license number I1234567 on file."},
	{"email", "Contact jordan.ellis@acmehealthcorp.example about the invoice."},
	{"ip-prose", "CONFIDENTIAL AND PROPRIETARY - Trade Secret - All Rights Reserved."},
	{"ip-addr", "Origin server address is 172.217.14.206 behind the load balancer."},
	{"medical", "Member ID 1EG4-TE5-MK73 on the Medicare card."},
	{"otp", `totp_uri = "otpauth://totp/Production:admin@corp.example?secret=NBSWY3DP&issuer=Production"`},
	{"passport", "Visa application: passport C87654321, nationality: British"},
	{"name", "Please forward the claim to Jonathan Whitfield in claims review."},
	{"name-with-geo", "Ship to Marcus Whitfield, 1247 Oakmont Street, Springfield"},
	{"phone", "Call the patient at (415) 555-0142 to confirm the appointment."},
	{"address", "Ship to 1600 Amphitheatre Parkway, Mountain View, CA 94043 today."},
	{"secret", "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
	{"ssn", "Employee SSN 219-09-9999 on the W-2 form."},
	{"vin", "Vehicle identification number 1HGBH41JXMN109186 on the title."},
}

// signature is the full per-finding identity: type, line, and NUMERIC confidence.
//
// Numeric, not the band. A band-level signature would have caught the two known
// instances (92 HIGH -> 57 LOW crosses a boundary) but would let a 92 -> 85 shift
// through, and an attacker-steerable confidence is the mechanism regardless of
// whether it happens to cross a display threshold on one fixture.
func signature(t *testing.T, text string) map[string]int {
	t.Helper()
	res, err := scan.ScanText(context.Background(), text, scan.TextOptions{
		Label: "<fold-guard>",
		// Pinned: without this, detection depends on the caller's working
		// directory, and a stray config.yaml would make this guard's result
		// depend on where `go test` ran.
		DisableConfigDiscovery: true,
	})
	if err != nil {
		t.Fatalf("ScanText: %v", err)
	}
	sig := map[string]int{}
	for _, f := range res.Findings {
		sig[fmt.Sprintf("%s@L%d=%.1f", f.Type, f.LineNumber, f.Confidence)]++
	}
	return sig
}

func diffSignature(want, got map[string]int) []string {
	var out []string
	seen := map[string]bool{}
	for k := range want {
		seen[k] = true
	}
	for k := range got {
		seen[k] = true
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if want[k] != got[k] {
			out = append(out, fmt.Sprintf("%s: control=%d hostile=%d", k, want[k], got[k]))
		}
	}
	return out
}

// TestOutputDoesNotDependOnLengthChangingRunes is the guard.
//
// For every length-changing rune, at several run lengths, it scans the whole fixture
// set with the rune prepended to each line and compares the full finding signature
// against a byte-length-identical ASCII control. Any difference is a bug: the rune
// is not part of any value, so it must not change what is reported about the values.
func TestOutputDoesNotDependOnLengthChangingRunes(t *testing.T) {
	build := func(pad string) string {
		var b strings.Builder
		for _, f := range foldFixtures {
			b.WriteString(pad)
			b.WriteString(" ")
			b.WriteString(f.text)
			b.WriteString("\n")
		}
		return b.String()
	}

	// Non-vacuity: the fixture set must produce a substantial signature with no
	// hostile rune at all, or "no difference" would be trivially true.
	baseline := signature(t, build(""))
	total := 0
	for _, n := range baseline {
		total += n
	}
	if total < 10 {
		t.Fatalf("baseline produced only %d findings across %d fixtures; this guard "+
			"cannot detect a change it has nothing to change", total, len(foldFixtures))
	}
	t.Logf("baseline: %d findings, %d distinct signatures, %d fixtures",
		total, len(baseline), len(foldFixtures))

	// Run lengths: the overshoot is a THRESHOLD, not a switch, and it differs per
	// validator — measured at >= 8 shrinking runes for VIN and >= 28 for bankaccount.
	// A single short run proves nothing, so span the range.
	lengths := []int{2, 4, 8, 20, 40}
	if testing.Short() {
		lengths = []int{4, 40}
	}

	for _, hostile := range lengthChangingRunes {
		if !utf8.ValidRune(hostile.r) {
			t.Fatalf("U+%04X is not a valid rune — the table is corrupt", hostile.r)
		}
		ch := string(hostile.r)
		// Precondition: if a rune in this table stops changing length (a Go Unicode
		// table update), this guard is silently testing nothing for it. Say so.
		if len(strings.ToLower(ch)) == len(ch) && len(strings.ToUpper(ch)) == len(ch) {
			t.Errorf("U+%04X (%s) no longer changes length under either fold — "+
				"this table entry is stale and is asserting nothing", hostile.r, hostile.family)
			continue
		}
		nbytes := len(ch)
		divergences := map[string][]int{}

		for _, n := range lengths {
			hostileText := build(strings.Repeat(ch, n))
			// Byte-length-identical control: ASCII 'q' folds to itself, so the ONLY
			// variable between the two runs is whether the fold changes length.
			controlText := build(strings.Repeat("q", nbytes*n))

			if len(hostileText) != len(controlText) {
				t.Fatalf("U+%04X n=%d: control is %d bytes and hostile is %d — the "+
					"comparison would attribute an offset shift to folding",
					hostile.r, n, len(controlText), len(hostileText))
			}

			control := signature(t, controlText)
			if len(control) == 0 {
				t.Fatalf("U+%04X n=%d: the CONTROL produced no findings, so this "+
					"comparison cannot detect a loss", hostile.r, n)
			}
			got := signature(t, hostileText)

			// Accumulate across ALL lengths; never stop at the first divergence.
			//
			// The first draft broke out of the length loop on the first failure, to keep
			// the log short. That silently capped coverage, because the overshoot
			// threshold DIFFERS PER VALIDATOR: measured, PERSON_NAME and DATE_OF_BIRTH
			// diverge from n=2, VIN panics from n=8 and bankaccount from n=28. So a rune
			// that failed at n=2 never reached n=8, and running this same guard against
			// v2.4.4 named only PERSON_NAME and DATE_OF_BIRTH while VIN and
			// BANK_ACCOUNT — two confirmed bugs live at that commit — went unmentioned.
			// A guard that stops at the first thing it finds reports the first bug, not
			// the class.
			for _, line := range diffSignature(control, got) {
				divergences[line] = append(divergences[line], n)
			}
		}

		if len(divergences) > 0 {
			keys := make([]string, 0, len(divergences))
			for k := range divergences {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			var b strings.Builder
			for _, k := range keys {
				fmt.Fprintf(&b, "\n  %s   (at run lengths %v)", k, divergences[k])
			}
			t.Errorf("U+%04X (%s) changed the output.%s\n\n"+
				"The rune is not part of any value on any line, so it must not change what is "+
				"reported about the values. A DROP is a redaction bypass (only reported findings "+
				"reach the redactor); a GAIN is attacker-driven noise; a CONFIDENCE change steers a "+
				"finding across the band a reviewer filters on. The cause is almost always a "+
				"case-folded copy indexed with offsets taken from the unfolded line — use "+
				"internal/bytefold, which preserves byte length and byte positions by construction.",
				hostile.r, hostile.family, b.String())
		}
	}
}

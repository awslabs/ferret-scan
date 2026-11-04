// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package bankaccount

import (
	stdctx "context"
	"fmt"
	"math/rand"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// syntheticIBAN builds the value #862's sweep uses for a country: every 'a' position an X, every
// 'n' or 'c' position the next of 1234567890, and real check digits.
func syntheticIBAN(t *testing.T, cc string) string {
	t.Helper()
	f, ok := ibanRegistry[cc]
	if !ok {
		t.Fatalf("%s not in the registry", cc)
	}
	layout, err := expandBBANStructure(f.structure)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, len(layout))
	for i, class := range []byte(layout) {
		if class == 'a' {
			b[i] = 'X'
		} else {
			b[i] = "1234567890"[i%10]
		}
	}
	return withCheckDigits(cc, string(b))
}

// withCheckDigits returns cc + the ISO 7064 check digits + bban.
func withCheckDigits(cc, bban string) string {
	rem := 0
	for _, c := range bban + cc + "00" {
		switch {
		case c >= '0' && c <= '9':
			rem = (rem*10 + int(c-'0')) % 97
		default:
			rem = (rem*100 + int(c-'A') + 10) % 97
		}
	}
	return fmt.Sprintf("%s%02d%s", cc, 98-rem, bban)
}

// groupIBAN prints an IBAN in groups of four joined by sep.
func groupIBAN(s, sep string) string {
	var groups []string
	for i := 0; i < len(s); i += 4 {
		end := i + 4
		if end > len(s) {
			end = len(s)
		}
		groups = append(groups, s[i:end])
	}
	return strings.Join(groups, sep)
}

// ibanFindings returns the IBAN matches for content, in order.
func ibanFindings(t *testing.T, v *Validator, content string) []detector.Match {
	t.Helper()
	ms, err := v.ValidateContent(content, "test.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	var out []detector.Match
	for _, m := range ms {
		if m.Type == "IBAN" {
			out = append(out, m)
		}
	}
	return out
}

func ibanTexts(t *testing.T, v *Validator, content string) []string {
	t.Helper()
	var out []string
	for _, m := range ibanFindings(t, v, content) {
		out = append(out, m.Text)
	}
	return out
}

func registryCodes() []string {
	codes := make([]string, 0, len(ibanRegistry))
	for cc := range ibanRegistry {
		codes = append(codes, cc)
	}
	sort.Strings(codes)
	return codes
}

// TestIBANDisplayFormsEveryCountry is #862's sweep as a unit test: one synthetic IBAN per registry
// country, in every form and before every trailing word the issue measured. On main the spaced
// form before a 1-4 character word was lost for the 29 countries whose length is a multiple of 4,
// the hyphen and double-space forms for all of them, and every form for the 15 countries missing
// from the hand-written map. Each line must give exactly one IBAN, with the whole value as its
// text and, for a grouped form, the separator-free value as Metadata["normalized"].
func TestIBANDisplayFormsEveryCountry(t *testing.T) {
	v := NewValidator()
	type form struct {
		name    string
		text    func(iban string) string // the reported text
		line    func(text, cc string) string
		grouped bool
	}
	spaced := func(s string) string { return groupIBAN(s, " ") }
	forms := []form{
		{"compact", func(s string) string { return s }, func(x, _ string) string { return "IBAN: " + x }, false},
		{"spaced at end of line", spaced, func(x, _ string) string { return "IBAN: " + x }, true},
		{"hyphen-grouped", func(s string) string { return groupIBAN(s, "-") }, func(x, _ string) string { return "IBAN: " + x }, true},
		{"double-space-grouped", func(s string) string { return groupIBAN(s, "  ") }, func(x, _ string) string { return "IBAN: " + x }, true},
		{"Ref AB12 before it", spaced, func(x, _ string) string { return "Ref AB12 " + x }, true},
		{"lowercase", func(s string) string { return strings.ToLower(spaced(s)) }, func(x, _ string) string { return "iban " + x + " for payroll" }, true},
	}
	for _, suffix := range []string{".", ",", " BIC: EXMP%sXX", " for payroll", " per invoice", " EUR", " 2026", " (EUR)", " payroll"} {
		suffix := suffix
		forms = append(forms, form{"spaced + " + strings.ReplaceAll(suffix, "%s", "<CC>"), spaced, func(x, cc string) string {
			return "IBAN: " + x + strings.ReplaceAll(suffix, "%s", cc)
		}, true})
	}

	codes := registryCodes()
	if len(codes) != 89 {
		t.Fatalf("registry has %d countries, the sweep was measured on 89", len(codes))
	}
	for _, f := range forms {
		f := f
		t.Run(f.name, func(t *testing.T) {
			lines := make([]string, len(codes))
			want := make([]string, len(codes))
			for i, cc := range codes {
				iban := syntheticIBAN(t, cc)
				want[i] = f.text(iban)
				lines[i] = f.line(want[i], cc)
			}
			byLine := map[int][]detector.Match{}
			for _, m := range ibanFindings(t, v, strings.Join(lines, "\n")) {
				byLine[m.LineNumber] = append(byLine[m.LineNumber], m)
			}
			lost := 0
			for i, cc := range codes {
				got := byLine[i+1]
				if len(got) != 1 || got[0].Text != want[i] {
					lost++
					var texts []string
					for _, m := range got {
						texts = append(texts, m.Text)
					}
					t.Errorf("%s %q: reported %q, want exactly [%q]", cc, lines[i], texts, want[i])
					continue
				}
				norm, has := got[0].Metadata["normalized"]
				if f.grouped && (!has || norm != strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(want[i]))) {
					t.Errorf("%s %q: normalized = %v", cc, lines[i], norm)
				}
			}
			if lost > 0 {
				t.Logf("%d of %d countries lost in form %q", lost, len(codes), f.name)
			}
		})
	}
}

// TestIBANDisplayFormsEveryOrderedPair: two spaced IBANs on one line are both reported, for every
// ordered pair of registry countries. The old regex read the second IBAN's head into the first
// candidate whenever the first country's length is a multiple of 4, and lost both.
func TestIBANDisplayFormsEveryOrderedPair(t *testing.T) {
	v := NewValidator()
	codes := registryCodes()
	var lines []string
	var want [][2]string
	for _, a := range codes {
		for _, b := range codes {
			x, y := groupIBAN(syntheticIBAN(t, a), " "), groupIBAN(syntheticIBAN(t, b), " ")
			lines = append(lines, "IBANs: "+x+" "+y)
			want = append(want, [2]string{x, y})
		}
	}
	byLine := map[int][]string{}
	for _, m := range ibanFindings(t, v, strings.Join(lines, "\n")) {
		byLine[m.LineNumber] = append(byLine[m.LineNumber], m.Text)
	}
	bad := 0
	for i, w := range want {
		got := byLine[i+1]
		if len(got) != 2 || got[0] != w[0] || got[1] != w[1] {
			if bad++; bad <= 10 {
				t.Errorf("%q: reported %q", lines[i], got)
			}
		}
	}
	if bad > 0 {
		t.Errorf("%d of %d ordered pairs not reported as exactly their two IBANs", bad, len(lines))
	}
}

// TestIBANUnderscoreJoinIsLabelGated: '_' is a word byte to RE2's \b, so no form joined by it was
// ever matched. A '_'-joined value is reported only when the identifier names it.
func TestIBANUnderscoreJoinIsLabelGated(t *testing.T) {
	v := NewValidator()
	const de = "DE89370400440532013000"
	spaced := groupIBAN(de, " ")
	long := strings.Repeat("x", underscoreLabelWindow)
	cases := []struct {
		line string
		want []string
	}{
		{"iban_" + de, []string{de}},
		{"bank_iban_" + spaced, []string{spaced}},
		{"customer_iban_" + groupIBAN(de, "-"), []string{groupIBAN(de, "-")}},
		{de + "_iban", []string{de}},
		{"wire_" + de + "_2026", []string{de}},
		{"statement_" + de + ".pdf", nil},
		{de + "_2026.pdf", nil},
		{"x_" + de, nil},
		{"xbank_" + de, nil},             // "bank" glued to x is not the keyword
		{"iban_" + long + "_" + de, nil}, // label beyond the window, partial segment dropped
		{"iban_" + long[:40] + "_" + de, []string{de}},
		{"iban: " + de, []string{de}}, // control: ordinary boundary, compact pass
	}
	for _, tc := range cases {
		got := ibanTexts(t, v, tc.line)
		if strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("%q: reported %q, want %q", tc.line, got, tc.want)
		}
	}
}

// TestIBANHyphenGroupedValueMustNotContinueARun: a hyphen-grouped value is reported on its own,
// not as a cut out of a longer hyphenated token on either side.
func TestIBANHyphenGroupedValueMustNotContinueARun(t *testing.T) {
	v := NewValidator()
	h := groupIBAN("DE89370400440532013000", "-")
	cases := []struct {
		line string
		want bool
	}{
		{"IBAN: " + h, true},
		{"IBAN: " + h + ".", true},
		{"IBAN: " + h + "-", true},
		{"IBAN: (" + h + ")", true},
		{"key ABCD-" + h, false},
		{"key " + h + "-ABCD", false},
		{"key " + h + "-2026", false},
		{"IBAN: " + groupIBAN("DE89370400440532013000", " ") + "-2026", true}, // spaced: trailing run allowed
	}
	for _, tc := range cases {
		got := ibanTexts(t, v, tc.line)
		if tc.want != (len(got) == 1) {
			t.Errorf("%q: reported %q, want reported=%v", tc.line, got, tc.want)
		}
	}
}

// TestIBANStructureGateRemovesDecoys covers the false positives #862 measured on main and the
// documented residual.
func TestIBANStructureGateRemovesDecoys(t *testing.T) {
	v := NewValidator()
	for _, line := range []string{
		"build id DE34EXAMPLE00000000000", // IBAN 85 on main; a DE BBAN is 18 digits
		"license key BE16 KEYE XAMP LE00", // IBAN 85 on main; a BE BBAN is 12 digits
		"00000010: be07 f027 2368 203d 0a1b 2c3d 4e5f 6071  ..#h =.,=N_`q",
		"8a2c0f10: 4703 35d9 ee38 263d f7c1 e6d6 3873 9f45  G.5..8&=...8s.E",
		"ref DE40PR7DXBFIZXPGVRA6UH", // IBAN 85 on main: passes mod-97, has letters
	} {
		if got := ibanTexts(t, v, line); len(got) != 0 {
			t.Errorf("%q reported as IBAN %q", line, got)
		}
	}

	// Seeded letter-bearing DE tokens, the issue's "ref DE<kk><18 random A-Z0-9>" shape. Some pass
	// mod-97 (about one in 97), which is what main reported; none conforms to 8!n10!n.
	r := rand.New(rand.NewSource(1))
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var lines []string
	checksumValid := 0
	for len(lines) < 20000 {
		b := make([]byte, 18)
		hasLetter := false
		for i := range b {
			b[i] = alphabet[r.Intn(len(alphabet))]
			hasLetter = hasLetter || b[i] >= 'A'
		}
		if !hasLetter {
			continue
		}
		tok := fmt.Sprintf("DE%02d%s", r.Intn(100), b)
		if ibanChecksumValid(tok) && tok[2:4] != "00" && tok[2:4] != "01" && tok[2:4] != "99" {
			checksumValid++
		}
		lines = append(lines, "ref "+tok)
	}
	if checksumValid < 100 {
		t.Fatalf("only %d of %d tokens pass mod-97; the decoy set is too weak to show anything", checksumValid, len(lines))
	}
	if got := ibanFindings(t, v, strings.Join(lines, "\n")); len(got) != 0 {
		t.Errorf("%d of %d letter-bearing DE tokens reported as IBAN (%d pass mod-97); first %q",
			len(got), len(lines), checksumValid, got[0].Text)
	}

	// The documented residual: GT's BBAN is all-"c", so a licence key that happens to be exactly a
	// GT IBAN's length and passes mod-97 is still reported. Pinned so the gap stays visible.
	if got := ibanTexts(t, v, "license key GT03-EXAM-PLEK-EY00-0000-0000-ABCD"); len(got) != 1 {
		t.Errorf("residual GT key: reported %q; if this is now rejected, update the docs that name it", got)
	}
}

// reOldSpacedIBAN is the regex the display scan replaced, kept here as the oracle.
var reOldSpacedIBAN = regexp.MustCompile(`\b[A-Z]{2}\d{2}(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,4})?\b`)

type span struct{ start, end int }

// oldSpacedSpans is today's spaced pass: the old regex over the uppercased line, normalized, and
// the isValidIBAN gate.
func oldSpacedSpans(v *Validator, upper string) []span {
	var out []span
	for _, loc := range reOldSpacedIBAN.FindAllStringIndex(upper, -1) {
		if v.isValidIBAN(strings.ReplaceAll(upper[loc[0]:loc[1]], " ", "")) {
			out = append(out, span{loc[0], loc[1]})
		}
	}
	return out
}

// spanMismatches lists every oracle span that got does not contain exactly.
func spanMismatches(oracle, got []span) []string {
	have := map[span]bool{}
	for _, s := range got {
		have[s] = true
	}
	var miss []string
	for _, s := range oracle {
		if !have[s] {
			miss = append(miss, fmt.Sprintf("[%d,%d)", s.start, s.end))
		}
	}
	return miss
}

// TestDisplayScanSpanIdentityWithTheOldRegex: wherever the old regex and isValidIBAN reported a
// value, the display scan reports the same [start, end), and the finding carries the same Text and
// Context. That is what keeps every existing finding's suppression-hash inputs unchanged. The
// lines are random mixes of real spaced IBANs, look-alike groups, heads and trailing words.
func TestDisplayScanSpanIdentityWithTheOldRegex(t *testing.T) {
	v := NewValidator()
	codes := registryCodes()
	r := rand.New(rand.NewSource(862))
	const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	words := []string{"IBAN:", "BIC", "EUR", "for", "2026", "payroll", "per invoice", ".", ",", ";", "|", "(EUR)",
		"pay to", "Ref", "AB12", "XK12", "\t", "\"", "de", "Konto"}
	piece := func() string {
		switch r.Intn(5) {
		case 0, 1:
			return groupIBAN(syntheticIBAN(t, codes[r.Intn(len(codes))]), " ")
		case 2:
			ex := ibanRegistryExamples[codes[r.Intn(len(codes))]]
			return groupIBAN(ex, " ")
		case 3:
			g := make([]byte, 1+r.Intn(4))
			for i := range g {
				g[i] = alnum[r.Intn(len(alnum))]
			}
			return string(g)
		default:
			return words[r.Intn(len(words))]
		}
	}

	oracleTotal := 0
	for n := 0; n < 4000; n++ {
		parts := make([]string, 1+r.Intn(5))
		for i := range parts {
			parts[i] = piece()
		}
		line := strings.Join(parts, " ")
		if r.Intn(3) == 0 {
			line = strings.ToLower(line)
		}
		upper, upperMap := upperWithOffsets(line)
		oracle := oldSpacedSpans(v, upper)
		oracleTotal += len(oracle)
		var got []span
		for _, d := range v.findDisplayIBANs(stdctx.Background(), upper) {
			got = append(got, span{d.start, d.end})
		}
		if miss := spanMismatches(oracle, got); len(miss) > 0 {
			t.Fatalf("line %q: old-regex spans %v not reproduced by the display scan (got %v)", line, miss, got)
		}

		// Text and Context of the emitted finding, for the same spans.
		findings := ibanFindings(t, v, line)
		for _, s := range oracle {
			oStart, oEnd := origSpan(upperMap, s.start, s.end)
			wantCtx := v.buildContextInfo(line, oStart, oEnd-oStart)
			found := false
			for _, m := range findings {
				if m.Text == line[oStart:oEnd] && m.Context.BeforeText == wantCtx.BeforeText && m.Context.AfterText == wantCtx.AfterText {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("line %q: no finding with the old span's Text %q and Context", line, line[oStart:oEnd])
			}
		}
	}
	if oracleTotal < 1000 {
		t.Fatalf("the oracle reported only %d spans; the comparison is too thin to prove identity", oracleTotal)
	}
	t.Logf("%d old-regex spans reproduced exactly", oracleTotal)

	// The comparison must notice an end moved by one character, or it proves nothing.
	oracle := []span{{6, 33}}
	for _, moved := range [][]span{{{6, 32}}, {{6, 34}}, {{5, 33}}} {
		if len(spanMismatches(oracle, moved)) == 0 {
			t.Errorf("spanMismatches did not notice %v vs %v", moved, oracle)
		}
	}
}

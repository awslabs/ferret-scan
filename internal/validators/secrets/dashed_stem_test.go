// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// Tests for #764: every multi-word stem was spelled `_?`, so its kebab-case spelling -- `api-key`,
// `private-key`, the `X-Api-Key` HTTP header -- matched no keyword pattern, quoted or unquoted, and
// reported nothing at any confidence while `api_key` reported the same value at 100. The stems are
// now spelled `[_-]?`, and the quoted JSON/dict key pattern takes the header's `x-` prefix.
//
// Values are uriPW's synthetic consonant-and-digit strings, 16 bytes: under the entropy path's
// 20-byte floor, so only a keyword pattern can report them and a dashed line that matches nothing
// stays silent instead of being rescued.

// dashedTwins returns, for every literal of stems that holds an underscore, the literal and its
// dash spelling: `api_key` gives {`api_key`, `api-key`}, `secret_access_key` gives
// {`secret_access_key`, `secret-access-key`}. Derived from the stem lists, so a stem added there is
// covered here with nothing to update.
func dashedTwins(stems []string) [][2]string {
	var out [][2]string
	seen := map[string]bool{}
	for _, lit := range stemLiteralsOf(stems) {
		if !strings.Contains(lit, "_") || strings.Contains(lit, "-") || seen[lit] {
			continue
		}
		seen[lit] = true
		out = append(out, [2]string{lit, strings.ReplaceAll(lit, "_", "-")})
	}
	return out
}

// keywordFindings is every finding on a one-line input, reduced to what identifies it.
func keywordFindings(t *testing.T, v *Validator, line string) []string {
	t.Helper()
	// .json fixes the document type by extension (DetectStructure short-circuits it), so the
	// underscore and the dash spelling are scored under the same type: the Configuration
	// pattern's key class has no dash, and a .txt would type `api_key=<v>` Configuration (+15)
	// and `api-key=<v>` Unknown, which is that pattern's behaviour, not this fix's.
	var out []string
	for _, m := range secretsOn(t, v, line, "fixture.json") {
		out = append(out, describeMatch(m))
	}
	return out
}

func describeMatch(m detector.Match) string {
	return fmt.Sprintf("%s %q %.0f %v", m.Type, m.Text, m.Confidence, m.Metadata["detection_method"])
}

// TestDashedStemSpellingReportsLikeUnderscore is the issue's table for every stem: the dash
// spelling of a key reports exactly what its underscore spelling reports -- the same value, type,
// confidence and detection method -- in each shape the stem's list is compiled into. On main every
// dash spelling here reported nothing. The controls at the end are the same comparison for lines
// both spellings must leave silent.
func TestDashedStemSpellingReportsLikeUnderscore(t *testing.T) {
	v := NewValidator()
	type shape struct {
		name   string
		stems  []string
		format func(key, value string) string
	}
	shapes := []shape{
		{"unquoted =", secretAssignmentKeywords, func(k, val string) string { return k + "=" + val }},
		{"unquoted YAML", secretAssignmentKeywords, func(k, val string) string { return k + ": " + val }},
		{"unquoted upper", secretAssignmentKeywords, func(k, val string) string { return strings.ToUpper(k) + ": " + val }},
		{"unquoted plural", secretAssignmentKeywords, func(k, val string) string { return k + "s: " + val }},
		{"quoted =", quotedSecretKeywords, func(k, val string) string { return k + ` = "` + val + `"` }},
		{"quoted JSON", quotedSecretKeywords, func(k, val string) string { return `{"` + k + `": "` + val + `"}` }},
	}
	seed, checked := 0, 0
	for _, s := range shapes {
		for _, twin := range dashedTwins(s.stems) {
			seed++
			value := uriPW(764000+seed, 16)
			underscore := keywordFindings(t, v, s.format(twin[0], value))
			dashed := keywordFindings(t, v, s.format(twin[1], value))
			if len(underscore) == 0 {
				t.Fatalf("%s %s: the underscore control %q reports nothing, so this row tests nothing",
					s.name, twin[0], s.format(twin[0], value))
			}
			if strings.Join(dashed, "; ") != strings.Join(underscore, "; ") {
				t.Errorf("%s: %q reports [%s], want what %q reports: [%s]", s.name,
					s.format(twin[1], value), strings.Join(dashed, "; "), s.format(twin[0], value), strings.Join(underscore, "; "))
			}
			checked++
		}
	}
	if checked < 60 {
		t.Fatalf("only %d twins checked; the stem lists are no longer what this test enumerates", checked)
	}

	// The AWS secret-key path is gated on the key's label, not on a stem list, and spelled its
	// label with the same `_?`: the dashed label must open the gate and type the value
	// AWS_SECRET_ACCESS_KEY, as the underscore label does.
	for i, twin := range [][2]string{
		{"aws_secret_access_key", "aws-secret-access-key"},
		{"AWS_SECRET_KEY", "AWS-SECRET-KEY"},
	} {
		value := uriPW(764500+i, 40)
		underscore := keywordFindings(t, v, twin[0]+": "+value)
		dashed := keywordFindings(t, v, twin[1]+": "+value)
		if len(underscore) != 1 || !strings.HasPrefix(underscore[0], "AWS_SECRET_ACCESS_KEY ") {
			t.Fatalf("%s: the underscore control reports [%s], want one AWS_SECRET_ACCESS_KEY finding",
				twin[0], strings.Join(underscore, "; "))
		}
		if strings.Join(dashed, "; ") != strings.Join(underscore, "; ") {
			t.Errorf("%s: reports [%s], want what %s reports: [%s]", twin[1],
				strings.Join(dashed, "; "), twin[0], strings.Join(underscore, "; "))
		}
	}

	// The controls: the widened stems bring no new shape with them. The unquoted path's value
	// vetoes judge a dashed key's value as they judge an underscore key's, and a stem still has to
	// sit right before its delimiter, so each of these stays silent in both spellings.
	for _, c := range []struct{ key, value, why string }{
		{"x-api-key", "creating", "prose: a short lower-case word"},
		{"api-key", "${API_KEY}", "a reference, excluded as the value's first byte"},
		{"X-Api-Key", "<YOUR_API_KEY>", "a placeholder, excluded as the value's first byte"},
		{"api-key", "2024-01-15", "digits and dashes: a date"},
		{"secret-key", "[REDACTED]", "a redaction marker inside a collection"},
		{"private-key", strings.Repeat("*", 19), "this tool's own mask"},
		{"api-key-id", uriPW(764400, 16), "the stem is not right before the delimiter"},
		{"private-key-file", "/etc/ssl/private/server.key", "the stem is not right before the delimiter"},
	} {
		line := c.key + ": " + c.value
		twin := strings.ReplaceAll(c.key, "-", "_") + ": " + c.value
		got, want := keywordFindings(t, v, line), keywordFindings(t, v, twin)
		if len(got) != 0 || len(want) != 0 {
			t.Errorf("%s: %q reports [%s] and its twin %q reports [%s]; want both silent",
				c.why, line, strings.Join(got, "; "), twin, strings.Join(want, "; "))
		}
	}
}

// TestDashedHeaderShapesReport is the issue's header rows, each reporting exactly its value from
// the keyword pass: a curl header, an upper-case header line, a query parameter, and the quoted
// JSON and Python-dict header maps, whose `x-` sits inside the quotes before the stem.
func TestDashedHeaderShapesReport(t *testing.T) {
	v := NewValidator()
	for i, format := range []string{
		`curl -H "X-Api-Key: %s" https://api.orders.invalid/v1`,
		`X-API-KEY: %s`,
		`https://api.orders.invalid/cb?x-api-key=%s`,
		`{"headers": {"x-api-key": "%s"}}`,
		`headers = {'X-Api-Key': '%s'}`,
		`{"X_API_KEY": "%s"}`,
		`{"x-access-token": "%s"}`,
		`api-keys: ["%s"]`,
	} {
		value := uriPW(764100+i, 16)
		line := fmt.Sprintf(format, value)
		ms := secretsOn(t, v, line, "request.txt")
		if len(ms) != 1 || ms[0].Text != value || ms[0].Type != genericSecretType {
			var got []string
			for _, m := range ms {
				got = append(got, describeMatch(m))
			}
			t.Errorf("%q: got [%s], want one %s finding of the value", line, strings.Join(got, "; "), genericSecretType)
		}
	}
}

// TestDashedStemPatternsOnlyAdd is the additivity the fix rests on: every span a keyword-pass
// pattern matched with the `_?` spelling, and without the header prefix, it still matches, at the
// same position with the same capture, so no finding that reported before changes its text or its
// suppression hash. The old patterns are rebuilt from the new ones' source. The second half is
// what makes this fail on main: the dash spellings must match somewhere the old patterns did not.
func TestDashedStemPatternsOnlyAdd(t *testing.T) {
	v := NewValidator()
	old := func(re *regexp.Regexp) *regexp.Regexp {
		src := strings.ReplaceAll(re.String(), "(?:x[_-])?", "")
		return regexp.MustCompile(strings.ReplaceAll(src, "[_-]?", "_?"))
	}
	var lines []string
	g := gateSecrets{r: &gateRand{x: 764200}}
	for i := 0; i < 1500; i++ {
		lines = append(lines, g.plantedLine(), g.inShapeLine(), g.shortAssignmentLine())
	}
	for i, twin := range dashedTwins(keywordPassStems()) {
		value := uriPW(764300+i, 16)
		for _, k := range twin {
			lines = append(lines, k+"="+value, `"`+k+`": "`+value+`"`, `{"x-`+k+`": "`+value+`"}`,
				k+"s: ["+value+"]", "cb?"+k+"="+value+"&next="+value)
		}
	}
	sets := [][]*regexp.Regexp{v.keywordPatterns, v.unquotedPatterns, v.pluralQuotedPatterns,
		v.pluralUnquotedPatterns, v.listOpenerPatterns}
	widened := 0
	for _, set := range sets {
		for _, re := range set {
			was := old(re)
			for _, line := range lines {
				now := map[string]bool{}
				for _, m := range re.FindAllStringSubmatchIndex(line, -1) {
					now[fmt.Sprint(m)] = true
				}
				before := was.FindAllStringSubmatchIndex(line, -1)
				for _, m := range before {
					if !now[fmt.Sprint(m)] {
						t.Errorf("%q no longer matches %q at %v", re.String(), line, m)
					}
				}
				if len(now) > len(before) {
					widened++
				}
			}
		}
	}
	if widened == 0 {
		t.Error("no pattern matches a dash spelling the `_?` spelling did not: the stems are not widened")
	}
}

// TestFiniteLanguageSeparatorClass pins the one class finiteLanguage enumerates and the classes it
// refuses: a letter, which would need the case-fold reasoning lineHasKeywordStem's ASCII fast path
// does not do, and a class too large to enumerate.
func TestFiniteLanguageSeparatorClass(t *testing.T) {
	lits := stemLiteralsOf([]string{"api[_-]?key"})
	if got := strings.Join(lits, ","); got != "apikey,api-key,api_key" && got != "apikey,api_key,api-key" {
		t.Errorf("api[_-]?key enumerates %v, want apikey, api_key and api-key", lits)
	}
	for _, stem := range []string{"api[kK]ey", "api[^a]key", "api[!-/]key"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("finiteLanguage accepted %q", stem)
				}
			}()
			stemLiteralsOf([]string{stem})
		}()
	}
}

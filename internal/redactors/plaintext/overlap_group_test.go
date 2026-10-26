// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package plaintext

import (
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// Every value below is synthetic: 512010001 (area 512), names and addresses from the repo's
// fixtures, a password built from a fixed alphabet walk, a card with a computed Luhn digit.

func lineMatch(line string, n int, typ, text, validator string, conf float64) detector.Match {
	return detector.Match{
		Text: text, Type: typ, Validator: validator, Confidence: conf, LineNumber: n,
		Context: detector.ContextInfo{FullLine: line},
	}
}

func redactAll(t *testing.T, content string, ms []detector.Match, st redactors.RedactionStrategy) string {
	t.Helper()
	ptr := NewPlainTextRedactor(nil, nil)
	ptr.SetPositionCorrelationEnabled(false)
	out, _, err := ptr.RedactString(content, ms, st)
	if err != nil {
		t.Fatalf("RedactString(%s): %v", st, err)
	}
	return out
}

const (
	residence = "Residence: 77 August Lane, Boise ID 83702"
	names     = "Renée Müller, José García, François Lefèvre"
	passport  = "Passport number: 512010001"
)

func residenceMatches(n int) []detector.Match {
	return []detector.Match{
		lineMatch(residence, n, "US_STREET_ADDRESS", "77 August Lane", "physical_address", 95),
		lineMatch(residence, n, "PERSON_NAME", "August Lane", "PERSON_NAME", 92),
		lineMatch(residence, n, "PERSON_NAME", "Lane, Boise", "PERSON_NAME", 67),
	}
}

func passportMatches(n int) []detector.Match {
	return []detector.Match{
		lineMatch(passport, n, "PASSPORT", "512010001", "passport", 100),
		lineMatch(passport, n, "SSN", "512010001", "ssn", 50),
	}
}

// The issue's lines, every strategy: no byte of any member survives.
func TestOverlapGroupsLeaveNoMemberByte(t *testing.T) {
	type tc struct {
		name    string
		content string
		ms      []detector.Match
		want    map[redactors.RedactionStrategy]string
		absent  []string
	}
	pw := "Xq7Rj2Lp9Vw4Ns8Kd3Hf6Tb1"
	pwLine := `password = "` + pw + `@example.org"`
	card := `secret = "4532-0000-0000-0009"`
	cases := []tc{
		{
			name: "residence: partial + contained", content: residence, ms: residenceMatches(1),
			want: map[redactors.RedactionStrategy]string{
				redactors.RedactionSimple:           "Residence: [US_STREET_ADDRESS-REDACTED] ID 83702",
				redactors.RedactionFormatPreserving: "Residence: ********************* ID 83702",
			},
			absent: []string{"77", "August", "Lane", "Boise"},
		},
		{
			name: "accented names: partial, one type", content: names,
			ms: []detector.Match{
				lineMatch(names, 1, "PERSON_NAME", "Renée Müller", "PERSON_NAME", 100),
				lineMatch(names, 1, "PERSON_NAME", "Müller, José García", "PERSON_NAME", 100),
			},
			want: map[redactors.RedactionStrategy]string{
				redactors.RedactionSimple: "[PERSON-NAME-REDACTED], François Lefèvre",
			},
			absent: []string{"Renée", "José", "García"},
		},
		{
			name: "passport: identical", content: passport, ms: passportMatches(1),
			want: map[redactors.RedactionStrategy]string{
				redactors.RedactionSimple:           "Passport number: [PASSPORT-REDACTED]",
				redactors.RedactionFormatPreserving: "Passport number: *********",
			},
			absent: []string{"0001", "512"},
		},
		{
			name: "password: identical SECRETS/EMAIL", content: pwLine,
			ms: []detector.Match{
				lineMatch(pwLine, 1, "API_KEY_OR_SECRET", pw+"@example.org", "secrets", 75),
				lineMatch(pwLine, 1, "BUSINESS", pw+"@example.org", "email", 40),
			},
			want: map[redactors.RedactionStrategy]string{
				redactors.RedactionSimple:           `password = "[API_KEY_OR_SECRET-REDACTED]"`,
				redactors.RedactionFormatPreserving: `password = "` + strings.Repeat("*", len(pw)+12) + `"`,
			},
			absent: []string{pw[:1] + "*", "example.org"},
		},
		{
			name: "card in a secret: identical", content: card,
			ms: []detector.Match{
				lineMatch(card, 1, "VISA", "4532-0000-0000-0009", "creditcard", 85),
				lineMatch(card, 1, "API_KEY_OR_SECRET", "4532-0000-0000-0009", "secrets", 75),
			},
			want: map[redactors.RedactionStrategy]string{
				redactors.RedactionSimple:           `secret = "[CREDIT-CARD-REDACTED]"`,
				redactors.RedactionFormatPreserving: `secret = "****-****-****-****"`,
			},
			absent: []string{"0009", "4532"},
		},
	}
	for _, c := range cases {
		for _, st := range allStrategies() {
			t.Run(c.name+"/"+st.String(), func(t *testing.T) {
				got := redactAll(t, c.content, c.ms, st)
				if want, ok := c.want[st]; ok && got != want {
					t.Fatalf("got  %q\nwant %q", got, want)
				}
				for _, a := range c.absent {
					if strings.Contains(got, a) {
						t.Fatalf("%q survived: %q", a, got)
					}
				}
			})
		}
	}
}

// fixture builds k unrelated email lines, the passport line, and k more: 2k+2 matches.
func passportFixture(k int) (string, []detector.Match) {
	var lines []string
	var ms []detector.Match
	add := func() {
		i := len(lines) + 1
		l := fmt.Sprintf("Contact %d: user%d@example.com", i, i)
		lines = append(lines, l)
		ms = append(ms, lineMatch(l, i, "EMAIL", fmt.Sprintf("user%d@example.com", i), "email", 70))
	}
	for i := 0; i < k; i++ {
		add()
	}
	lines = append(lines, passport)
	ms = append(ms, passportMatches(len(lines))...)
	for i := 0; i < k; i++ {
		add()
	}
	return strings.Join(lines, "\n") + "\n", ms
}

// ORDER INDEPENDENCE. 200 shuffles at sizes either side of sort.Slice's insertion-sort threshold
// (12 elements) must all produce the same bytes, and the passport line the rule's rendering.
// Measured before the fix: the passport line came out as the PASSPORT or the SSN rendering about
// half the time each at every size, because the identical pair tied in the writer's sort.
func TestOverlapGroupRenderingIsOrderIndependent(t *testing.T) {
	rng := rand.New(rand.NewSource(773))
	for _, n := range []int{2, 12, 13, 50} {
		k := (n - 2) / 2
		content, base := passportFixture(k)
		if len(base) != 2*k+2 {
			t.Fatalf("fixture has %d matches, want %d", len(base), 2*k+2)
		}
		for _, st := range []redactors.RedactionStrategy{redactors.RedactionSimple, redactors.RedactionFormatPreserving} {
			want := map[redactors.RedactionStrategy]string{
				redactors.RedactionSimple:           "Passport number: [PASSPORT-REDACTED]",
				redactors.RedactionFormatPreserving: "Passport number: *********",
			}[st]
			var first string
			for p := 0; p < 200; p++ {
				ms := append([]detector.Match(nil), base...)
				rng.Shuffle(len(ms), func(i, j int) { ms[i], ms[j] = ms[j], ms[i] })
				got := redactAll(t, content, ms, st)
				if p == 0 {
					first = got
					if !strings.Contains(got, want+"\n") {
						t.Fatalf("n=%d %s: passport line not rendered by the rule:\n%s", len(base), st, got)
					}
					continue
				}
				if got != first {
					t.Fatalf("n=%d %s: permutation %d changed the output:\n%s\nvs\n%s", len(base), st, p, got, first)
				}
			}
		}
	}
}

// SAFEGUARDS. Shapes that form no group, and contained groups, are written exactly as they were.
// These pass on main by design; they exist so the group rule cannot reach them.
func TestNonGroupShapesAreByteIdentical(t *testing.T) {
	type tc struct {
		name    string
		content string
		ms      []detector.Match
		fp      string
		simple  string
	}
	disjoint := "call 212-555-0142 or card 4532-0151-1283-0366"
	touching := "4532-0151-1283-0366212-555-0142"
	contained := "spaced 4532 0151 1283 0366"
	l1, l2 := "card 4532 0151 1283 0366", "phone 0151 1283 0366"
	ip := "host 10.12.19.85 up"
	cases := []tc{
		{"disjoint same line", disjoint, []detector.Match{
			lineMatch(disjoint, 1, "PHONE", "212-555-0142", "phone", 40),
			lineMatch(disjoint, 1, "VISA", "4532-0151-1283-0366", "creditcard", 90)},
			"call ***-***-0142 or card ****-****-****-0366", "call [PHONE-REDACTED] or card [CREDIT-CARD-REDACTED]"},
		{"touching", touching, []detector.Match{
			lineMatch(touching, 1, "VISA", "4532-0151-1283-0366", "creditcard", 90),
			lineMatch(touching, 1, "PHONE", "212-555-0142", "phone", 40)},
			"****-****-****-0366***-***-0142", "[CREDIT-CARD-REDACTED][PHONE-REDACTED]"},
		{"other line", l1 + "\n" + l2, []detector.Match{
			lineMatch(l1, 1, "VISA", "4532 0151 1283 0366", "creditcard", 90),
			lineMatch(l2, 2, "PHONE", "0151 1283 0366", "phone", 40)},
			"card **** **** **** 0366\nphone **** **** 0366", "card [CREDIT-CARD-REDACTED]\nphone [PHONE-REDACTED]"},
		{"contained", contained, []detector.Match{
			lineMatch(contained, 1, "PHONE", "0151 1283 0366", "phone", 40),
			lineMatch(contained, 1, "VISA", "4532 0151 1283 0366", "creditcard", 90)},
			"spaced **** **** **** 0366", "spaced [CREDIT-CARD-REDACTED]"},
		{"contained IP over a date", ip, []detector.Match{
			lineMatch(ip, 1, "IP_ADDRESS", "10.12.19.85", "ipaddress", 80),
			lineMatch(ip, 1, "DATE_OF_BIRTH", "12.19.85", "dob", 40)},
			"host 10.12.*.* up", "host [IP-ADDRESS-REDACTED] up"},
		{"unresolvable position", "ssn 449-87-4100 and 212-555-0142", []detector.Match{
			{Text: "449-87-4100", Type: "SSN", LineNumber: 1, Confidence: 90},
			{Text: "212-555-0142", Type: "PHONE", LineNumber: 1, Confidence: 40}},
			"ssn ***-**-4100 and ***-***-0142", "ssn [SSN-REDACTED] and [PHONE-REDACTED]"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := redactAll(t, c.content, c.ms, redactors.RedactionFormatPreserving); got != c.fp {
				t.Errorf("format_preserving:\n got %q\nwant %q", got, c.fp)
			}
			if got := redactAll(t, c.content, c.ms, redactors.RedactionSimple); got != c.simple {
				t.Errorf("simple:\n got %q\nwant %q", got, c.simple)
			}
		})
	}
}

// One write, one audit entry, naming every finding it covered.
func TestOverlapGroupRecordsOneMappingWithMemberTypes(t *testing.T) {
	ptr := NewPlainTextRedactor(nil, nil)
	ptr.SetPositionCorrelationEnabled(false)
	_, mappings, err := ptr.RedactString(residence, residenceMatches(1), redactors.RedactionFormatPreserving)
	if err != nil {
		t.Fatal(err)
	}
	if len(mappings) != 1 {
		t.Fatalf("one group must be one mapping, got %d", len(mappings))
	}
	got := mappings[0]
	if got.DataType != "US_STREET_ADDRESS" || got.Metadata[redactors.OverlapGroupKindKey] != "partial" ||
		!reflect.DeepEqual(got.Metadata[redactors.OverlapMemberTypesKey], []string{"PERSON_NAME", "PERSON_NAME", "US_STREET_ADDRESS"}) {
		t.Fatalf("mapping must carry the group's label and every member type, got %+v", got)
	}
}

// NO SILENT SKIP. A group whose union is not in the text (an extractor joined two physical lines into
// the reported one) refuses the redaction instead of writing whichever member it can find.
func TestUnwritableOverlapGroupRefuses(t *testing.T) {
	content := "Residence: 77 August Lane,\nBoise ID 83702"
	for _, st := range allStrategies() {
		ptr := NewPlainTextRedactor(nil, nil)
		out, _, err := ptr.RedactString(content, residenceMatches(1), st)
		if err == nil {
			t.Fatalf("%s: an unwritable group must refuse, wrote %q", st, out)
		}
		for _, leak := range []string{"77 August", "Lane", "Boise"} {
			if strings.Contains(err.Error(), leak) {
				t.Fatalf("%s: the refusal must name types, not values: %v", st, err)
			}
		}
		if !strings.Contains(err.Error(), "US_STREET_ADDRESS") {
			t.Fatalf("%s: the refusal should name the member types: %v", st, err)
		}
	}
}

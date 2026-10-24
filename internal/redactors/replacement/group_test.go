// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package replacement

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// Render must be Generate plus the copies, never a second implementation that can drift.
func TestRenderTextIsGenerate(t *testing.T) {
	values := []struct{ v, typ string }{
		{"4532-0151-1283-0366", "VISA"}, {"449-87-4100", "SSN"}, {"(212) 555-0142", "PHONE"},
		{"john.doe@example.com", "EMAIL"}, {"a@b.co", "EMAIL"}, {"@b.co", "EMAIL"}, {"203.0.113.42", "IP_ADDRESS"},
		{"512010001", "PASSPORT"}, {"77 August Lane", "US_STREET_ADDRESS"}, {"123", "SSN"},
	}
	for _, c := range values {
		for _, st := range []redactors.RedactionStrategy{redactors.RedactionSimple, redactors.RedactionFormatPreserving} {
			if got, want := Render(c.v, c.typ, st).Text, Generate(c.v, c.typ, st); got != want {
				t.Errorf("Render(%q,%s,%s).Text = %q, Generate = %q", c.v, c.typ, st, got, want)
			}
		}
	}
}

// Every reported copy must really be the original's bytes at the stated offsets, for every strategy,
// and the copies must be the ones the issue names.
func TestRenderCopiesAreTheBytesKeptByConstruction(t *testing.T) {
	cases := []struct {
		v, typ string
		st     redactors.RedactionStrategy
		kept   string // the value bytes the copies hold, concatenated
	}{
		{"4532-0151-1283-0366", "VISA", redactors.RedactionFormatPreserving, "0366"},
		{"449-87-4100", "SSN", redactors.RedactionFormatPreserving, "4100"},
		{"512010001", "SSN", redactors.RedactionFormatPreserving, "0001"},
		{"(212) 555-0142", "PHONE", redactors.RedactionFormatPreserving, "0142"},
		{"john.doe@example.com", "EMAIL", redactors.RedactionFormatPreserving, "jexamplecom"},
		{"a@b.co", "EMAIL", redactors.RedactionFormatPreserving, "bco"},
		{"203.0.113.42", "IP_ADDRESS", redactors.RedactionFormatPreserving, "2030"},
		{"512010001", "PASSPORT", redactors.RedactionFormatPreserving, ""},
		{"77 August Lane", "US_STREET_ADDRESS", redactors.RedactionFormatPreserving, ""},
		{"123", "SSN", redactors.RedactionFormatPreserving, ""},
		{"4532-0151-1283-0366", "VISA", redactors.RedactionSynthetic, "4532"},
		{"449-87-4100", "SSN", redactors.RedactionSynthetic, ""},
		{"john.doe@example.com", "EMAIL", redactors.RedactionSynthetic, ""},
		{"4532-0151-1283-0366", "VISA", redactors.RedactionSimple, ""},
	}
	for _, c := range cases {
		r := Render(c.v, c.typ, c.st)
		var kept strings.Builder
		for _, cp := range r.Copies {
			if got, want := r.Text[cp.Out:cp.Out+cp.Len], c.v[cp.In:cp.In+cp.Len]; got != want {
				t.Fatalf("Render(%q,%s,%s): copy %+v writes %q, original holds %q", c.v, c.typ, c.st, cp, got, want)
			}
			for _, b := range []byte(c.v[cp.In : cp.In+cp.Len]) {
				if isValueByte(b) {
					kept.WriteByte(b)
				}
			}
		}
		if kept.String() != c.kept || r.Kept() != len(c.kept) {
			t.Errorf("Render(%q,%s,%s) keeps %q (Kept=%d), want %q", c.v, c.typ, c.st, kept.String(), r.Kept(), c.kept)
		}
	}
}

// group builds matches on one line and resolves them the way every writer does.
func group(t *testing.T, line string, ms ...detector.Match) (redactors.OverlapGroup, []detector.Match) {
	t.Helper()
	for i := range ms {
		ms[i].LineNumber = 1
		ms[i].Context.FullLine = line
	}
	gs := redactors.ResolveOverlaps(ms)
	for _, g := range gs {
		if g.IsGroup() {
			return g, ms
		}
	}
	t.Fatalf("no group formed on %q", line)
	return redactors.OverlapGroup{}, nil
}

func m(typ, text, validator string, conf float64) detector.Match {
	return detector.Match{Type: typ, Text: text, Validator: validator, Confidence: conf}
}

// The rule table, row by row, both input orders where order could matter.
func TestRenderGroupRuleTable(t *testing.T) {
	type row struct {
		name   string
		line   string
		ms     []detector.Match
		simple string
		fp     string
	}
	rows := []row{
		{
			name:   "identical PASSPORT+SSN: nothing kept a member would hide",
			line:   "Passport number: 512010001",
			ms:     []detector.Match{m("PASSPORT", "512010001", "passport", 100), m("SSN", "512010001", "ssn", 50)},
			simple: "[PASSPORT-REDACTED]", fp: "*********",
		},
		{
			name:   "identical, SSN representative: its last four are still masked",
			line:   "id 512010001",
			ms:     []detector.Match{m("SSN", "512010001", "ssn", 90), m("DRIVERS_LICENSE", "512010001", "driverslicense", 40)},
			simple: "[SSN-REDACTED]", fp: "*********",
		},
		{
			name:   "identical card+secret: separators kept, no digit",
			line:   `secret = "4532-0000-0000-0009"`,
			ms:     []detector.Match{m("VISA", "4532-0000-0000-0009", "creditcard", 85), m("API_KEY_OR_SECRET", "4532-0000-0000-0009", "secrets", 75)},
			simple: "[CREDIT-CARD-REDACTED]", fp: "****-****-****-****",
		},
		{
			name:   "identical secret+email: the secret's label, no byte kept",
			line:   `password = "Xq7Rj2Lp9Vw4Ns8Kd3Hf6Tb1@example.org"`,
			ms:     []detector.Match{m("API_KEY_OR_SECRET", "Xq7Rj2Lp9Vw4Ns8Kd3Hf6Tb1@example.org", "secrets", 75), m("BUSINESS", "Xq7Rj2Lp9Vw4Ns8Kd3Hf6Tb1@example.org", "email", 40)},
			simple: "[API_KEY_OR_SECRET-REDACTED]", fp: strings.Repeat("*", 36),
		},
		{
			name: "identical same type: the shared rendering is kept",
			line: "call 2125550100",
			ms:   []detector.Match{m("PHONE", "2125550100", "phone", 40), m("PHONE", "2125550100", "phone", 30)},
			// both members keep the last four, so the rule keeps them
			simple: "[PHONE-REDACTED]", fp: "******0100",
		},
		{
			name: "{{U18}}: a national ID on the same bytes as an SSN is fully masked",
			line: "national id 512010001",
			ms:   []detector.Match{m("NATIONAL_ID", "512010001", "nationalid", 60), m("SSN", "512010001", "ssn", 95)},
			// the SSN represents (95 > 60), and its last four are masked because the ID's rendering hides them
			simple: "[SSN-REDACTED]", fp: "*********",
		},
		{
			name: "partial, mixed types: the union, masked whole",
			line: "Residence: 77 August Lane, Boise ID 83702",
			ms: []detector.Match{m("US_STREET_ADDRESS", "77 August Lane", "physical_address", 95),
				m("PERSON_NAME", "August Lane", "PERSON_NAME", 92), m("PERSON_NAME", "Lane, Boise", "PERSON_NAME", 67)},
			simple: "[US_STREET_ADDRESS-REDACTED]", fp: strings.Repeat("*", len("77 August Lane, Boise")),
		},
		{
			name:   "partial, one shared type: that type's rendering of the union",
			line:   "Renée Müller, José García, François Lefèvre",
			ms:     []detector.Match{m("PERSON_NAME", "Renée Müller", "PERSON_NAME", 100), m("PERSON_NAME", "Müller, José García", "PERSON_NAME", 100)},
			simple: "[PERSON-NAME-REDACTED]", fp: strings.Repeat("*", len("Renée Müller, José García")),
		},
		{
			name: "partial phones: only digits both crossing phones would keep survive",
			line: "dial 212-555-0142-555-0199 now",
			ms:   []detector.Match{m("PHONE", "212-555-0142", "phone", 40), m("PHONE", "555-0142-555-0199", "phone", 40)},
			// the union's rendering keeps its last four, which only the second phone covers and keeps
			simple: "[PHONE-REDACTED]", fp: "***-***-****-***-0199",
		},
		{
			name: "contained, not SECRETS: the widest rendering, unchanged (#687 owns IP over DOB)",
			line: "host 10.12.19.85 up",
			ms:   []detector.Match{m("IP_ADDRESS", "10.12.19.85", "ipaddress", 80), m("DATE_OF_BIRTH", "12.19.85", "dob", 40)},
			// format_preserving keeps two octets of an IP; one of them sits inside the date, and stays
			simple: "[IP-ADDRESS-REDACTED]", fp: "10.12.*.*",
		},
		{
			name: "#766: a SECRETS match inside an EMAIL leaves no secret byte",
			line: "REDIS_URL=redis://default:B7vgQ3hD54kWtK97@cache.orders-svc.io",
			ms: []detector.Match{m("BUSINESS", "B7vgQ3hD54kWtK97@cache.orders-svc.io", "email", 90),
				m("API_KEY_OR_SECRET", "B7vgQ3hD54kWtK97", "secrets", 95)},
			simple: "[EMAIL-REDACTED]", fp: "****************@cache.orders-svc.io",
		},
		{
			name: "an unattributed member counts as SECRETS",
			line: "REDIS_URL=redis://default:B7vgQ3hD54kWtK97@cache.orders-svc.io",
			ms: []detector.Match{m("BUSINESS", "B7vgQ3hD54kWtK97@cache.orders-svc.io", "email", 90),
				m("SOMETHING", "B7vgQ3hD54kWtK97", "", 10)},
			simple: "[EMAIL-REDACTED]", fp: "****************@cache.orders-svc.io",
		},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			orders := [][]detector.Match{r.ms}
			rev := make([]detector.Match, len(r.ms))
			for i := range r.ms {
				rev[len(r.ms)-1-i] = r.ms[i]
			}
			orders = append(orders, rev)
			for _, ms := range orders {
				g, ms := group(t, r.line, append([]detector.Match(nil), ms...)...)
				if got := RenderGroup(g, ms, redactors.RedactionSimple).Text; got != r.simple {
					t.Errorf("simple: got %q, want %q", got, r.simple)
				}
				if got := RenderGroup(g, ms, redactors.RedactionFormatPreserving).Text; got != r.fp {
					t.Errorf("format_preserving: got %q, want %q", got, r.fp)
				}
				syn := RenderGroup(g, ms, redactors.RedactionSynthetic)
				if strings.Contains(syn.Text, "0009") || strings.Contains(syn.Text, "B7vg") {
					t.Errorf("synthetic kept a byte a member would hide: %q", syn.Text)
				}
			}
		})
	}
}

// A synthetic group whose representative would copy a byte another member hides falls back to the
// representative's placeholder: a plausible fake must not carry the card's issuer prefix when the
// secret on the same bytes would have hidden it.
func TestRenderGroupSyntheticFallsBackToThePlaceholder(t *testing.T) {
	g, ms := group(t, `secret = "4532-0000-0000-0009"`,
		m("VISA", "4532-0000-0000-0009", "creditcard", 85), m("API_KEY_OR_SECRET", "4532-0000-0000-0009", "secrets", 75))
	if got := RenderGroup(g, ms, redactors.RedactionSynthetic).Text; got != "[CREDIT-CARD-REDACTED]" {
		t.Fatalf("synthetic card over a secret must fall back to the placeholder, got %q", got)
	}
	// Two cards on the same bytes both keep the issuer prefix, so the fake is allowed to.
	g, ms = group(t, "card 4532-0000-0000-0009",
		m("VISA", "4532-0000-0000-0009", "creditcard", 85), m("CREDIT_CARD", "4532-0000-0000-0009", "creditcard", 60))
	if got := RenderGroup(g, ms, redactors.RedactionSynthetic).Text; !strings.HasPrefix(got, "4532-") || got == "4532-0000-0000-0009" {
		t.Fatalf("two cards agree on the prefix, so a synthetic card is expected, got %q", got)
	}
}

// {{U31}} Resolution 8, as far as today's single-strategy runs can state it: two adjacent values of
// different checks that share no byte are NOT merged, so each keeps its own rendering.
func TestRenderGroupDoesNotOverMergeAdjacentValues(t *testing.T) {
	line := "4532-0151-1283-0366212-555-0142"
	ms := []detector.Match{m("VISA", "4532-0151-1283-0366", "creditcard", 90), m("PHONE", "212-555-0142", "phone", 40)}
	for i := range ms {
		ms[i].LineNumber, ms[i].Context.FullLine = 1, line
	}
	gs := redactors.ResolveOverlaps(ms)
	if len(gs) != 2 {
		t.Fatalf("touching values must stay apart, got %d groups", len(gs))
	}
	var got []string
	for _, g := range gs {
		got = append(got, RenderGroup(g, ms, redactors.RedactionFormatPreserving).Text)
	}
	if strings.Join(got, "|") != "****-****-****-0366|***-***-0142" {
		t.Fatalf("each adjacent value keeps its own rendering, got %v", got)
	}
}

// A single match renders exactly as before: the rule only ever applies to groups.
func TestRenderGroupSingleIsRender(t *testing.T) {
	ms := []detector.Match{m("SSN", "449-87-4100", "ssn", 90)}
	ms[0].LineNumber, ms[0].Context.FullLine = 1, "ssn 449-87-4100"
	g := redactors.ResolveOverlaps(ms)[0]
	for _, st := range []redactors.RedactionStrategy{redactors.RedactionSimple, redactors.RedactionFormatPreserving} {
		if got, want := RenderGroup(g, ms, st).Text, Generate("449-87-4100", "SSN", st); got != want {
			t.Errorf("%s: got %q, want %q", st, got, want)
		}
	}
}

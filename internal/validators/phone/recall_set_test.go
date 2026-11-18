// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phone

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// #882's recall set, committed as a validator test: 31 carriers x 20 NANP-shaped numbers, 620 labels,
// every one reported at MEDIUM or above, and the labelled carriers at HIGH. The issue measured it
// through the CLI and did not commit it; the 15 carriers it lists are here verbatim, the 16 it
// summarised ("labelled Phone:, Mobile:, Fax, ..., header-labelled columns, formatted toll-free")
// are spelled out below; the header carriers have three columns, the shape the issue measured (a
// two-column table gets no header credit and reads 85, still MEDIUM). ValidateContent is the validator's own score, before the document bridge,
// which can only lift an uncorroborated match to its published 85 ceiling (evidence_test.go).

// recallNumber is one synthetic NANP-possible number: area and exchange [2-9]XX, neither N11, the
// area not toll-free and the exchange not 555, so nothing here is a reserved or fictional value the
// validator caps.
type recallNumber struct{ npa, nxx, line string }

func (n recallNumber) plain() string  { return n.npa + n.nxx + n.line }
func (n recallNumber) dashed() string { return n.npa + "-" + n.nxx + "-" + n.line }
func (n recallNumber) parens() string { return "(" + n.npa + ") " + n.nxx + "-" + n.line }

// recallNumbers generates the 20 numbers at test time from a fixed seed (4242, the issue's), so the
// set is the same on every run and no value is printed in the repository.
func recallNumbers() []recallNumber {
	rng := rand.New(rand.NewSource(4242))
	tollFree := map[string]bool{"800": true, "833": true, "844": true, "855": true, "866": true, "877": true, "888": true}
	nxx := func() string {
		for {
			s := fmt.Sprintf("%d%02d", 2+rng.Intn(8), rng.Intn(100))
			if s[1:] != "11" {
				return s
			}
		}
	}
	var out []recallNumber
	for len(out) < 20 {
		n := recallNumber{nxx(), nxx(), fmt.Sprintf("%04d", rng.Intn(10000))}
		if tollFree[n.npa] || n.nxx == "555" {
			continue
		}
		out = append(out, n)
	}
	return out
}

// recallCarrier renders one number into a line (or a small document) and names the text the finding
// must cover.
type recallCarrier struct {
	name    string
	minBand string // "HIGH" (>= 90) or "MEDIUM" (>= 60)
	render  func(n recallNumber) (content, text string)
}

func recallCarriers() []recallCarrier {
	line := func(f string, form func(recallNumber) string) func(recallNumber) (string, string) {
		return func(n recallNumber) (string, string) { return fmt.Sprintf(f, form(n)) + "\n", form(n) }
	}
	plain, dashed, parens := recallNumber.plain, recallNumber.dashed, recallNumber.parens
	tollFree := func(n recallNumber) string { return "877" + n.nxx + n.line }
	tollFreeFormatted := func(n recallNumber) string { return "(877) " + n.nxx + "-" + n.line }
	return []recallCarrier{
		// The 15 carriers #882 lists.
		{"direct_line", "MEDIUM", line("Direct line %s", dashed)},
		{"office_label", "MEDIUM", line("Charlotte office: %s", dashed)},
		{"dr_cell", "MEDIUM", line("Dr. Robinson, cell %s", dashed)},
		{"call_anytime", "MEDIUM", line("Call anytime: %s", dashed)},
		{"whatsapp", "MEDIUM", func(n recallNumber) (string, string) {
			return "WhatsApp +1 " + n.dashed() + "\n", n.dashed()
		}},
		{"sms_plain", "MEDIUM", line("SMS sent to %s", plain)},
		{"json_phone", "MEDIUM", line(`{"phone": "%s"}`, plain)},
		{"assign_phone", "MEDIUM", line("phone = '%s'", plain)},
		{"bare_dashed", "MEDIUM", line("%s", dashed)},
		{"contact_name", "MEDIUM", line("Contact Jane Klein at %s", dashed)},
		{"reach_name", "MEDIUM", line("Reach Ricardo Stein on %s or by email.", dashed)},
		{"work_no_colon", "MEDIUM", line("Work %s", dashed)},
		{"bare_plain", "MEDIUM", line("%s", plain)},
		{"headerless_csv", "MEDIUM", line("Jane Roe,%s,Boston", plain)},
		{"reservations_tollfree", "MEDIUM", line("Reservations %s", tollFree)},
		// The 16 labelled carriers the issue summarised as 20/0/0 (HIGH) in every column.
		{"phone_label", "HIGH", line("Phone: %s", dashed)},
		{"phone_label_parens", "HIGH", line("Phone: %s", parens)},
		{"mobile_label", "HIGH", line("Mobile: %s", dashed)},
		{"cell_label", "HIGH", line("Cell: %s", dashed)},
		{"tel_label", "HIGH", line("Tel: %s", dashed)},
		{"telephone_label", "HIGH", line("Telephone: %s", parens)},
		{"fax_label", "HIGH", line("Fax %s", dashed)},
		{"home_phone", "HIGH", line("Home phone: %s", dashed)},
		{"phone_number_plain", "HIGH", line("Phone number: %s", plain)},
		{"contact_number", "HIGH", line("Contact number: %s", dashed)},
		{"tollfree_formatted", "HIGH", line("Call us toll-free at %s", tollFreeFormatted)},
		{"header_phone", "HIGH", func(n recallNumber) (string, string) {
			return "name,phone,city\nJane Roe," + n.plain() + ",Boston\n", n.plain()
		}},
		{"header_mobile_number", "HIGH", func(n recallNumber) (string, string) {
			return "name,mobileNumber,city\nJane Roe," + n.plain() + ",Boston\n", n.plain()
		}},
		{"header_phone_number_tab", "HIGH", func(n recallNumber) (string, string) {
			return "name\tphone_number\tcity\nJane Roe\t" + n.dashed() + "\tBoston\n", n.dashed()
		}},
		{"header_quoted_phone", "HIGH", func(n recallNumber) (string, string) {
			return "\"name\",\"phone\",\"city\"\n\"Jane Roe\",\"" + n.plain() + "\",\"Boston\"\n", n.plain()
		}},
		{"vcard_tel", "HIGH", line("TEL;TYPE=cell:%s", parens)},
	}
}

func TestRecallSetAtMediumOrAbove(t *testing.T) {
	numbers, carriers := recallNumbers(), recallCarriers()
	if got := len(numbers) * len(carriers); got != 620 {
		t.Fatalf("recall set has %d labels, want 620 (31 carriers x 20 numbers)", got)
	}
	for _, c := range carriers {
		floor := 60.0
		if c.minBand == "HIGH" {
			floor = 90
		}
		var low []string
		for _, n := range numbers {
			content, text := c.render(n)
			ms := phoneFindings(t, content)
			var hit bool
			for _, m := range ms {
				if strings.Contains(m.Text, text) { // the finding covers the whole number
					hit = true
					if m.Confidence < floor {
						low = append(low, fmt.Sprintf("%s=%.0f", m.Text, m.Confidence))
					}
				}
			}
			if !hit {
				low = append(low, fmt.Sprintf("%s=missed (%s)", text, describe(ms)))
			}
		}
		if len(low) > 0 {
			t.Errorf("%s: %d of %d below %s: %s", c.name, len(low), len(numbers), c.minBand, strings.Join(low, ", "))
		}
	}
}

// csvDocumentBoost is the most a CSV-typed document adds to a finding at the bridge
// (validators/dual_path_bridge.go), unless the finding publishes a lower confidence_ceiling.
const csvDocumentBoost = 20.0

// TestDecoysStayBelowHigh is #882's MaxBand list, committed as a validator test: each decoy may be
// reported (redaction ignores confidence, so #882 moved scores and never the emitted set), but never
// HIGH, here or after the CSV document boost.
func TestDecoysStayBelowHigh(t *testing.T) {
	for _, c := range []struct{ content, text string }{
		{"\toffset32 = 2166136261\n", "2166136261"},
		{"    offset32 = 2166136261\n", "2166136261"},
		{"\tMaxUint32 = 1<<32 - 1 // 4294967295\n", "4294967295"},
		{"customer,order_id,total\nJane Roe,2972030405,42.50\n", "2972030405"},
		{`{"order_id": "2972030405"}` + "\n", "2972030405"},
		{"seed(a, b, 2972030405)\n", "2972030405"},
		{"String value 2972030405\n", "2972030405"},
		{"next cursor 2972030405\n", "2972030405"},
		{"hotel booking 2972030405\n", "2972030405"},
		{"network packets 2972030405\n", "2972030405"},
		{"Order 2972800405 shipped\n", "2972800405"},
		{"Tracking number: 2972030405\n", "2972030405"},
		{"row,00200001,active\n", "00200001"},
		{"Employee number 2972030405\n", "2972030405"},
		{"employee number 2972030405\n", "2972030405"},
		{"2024-03-01,2972030405,42.50,USD\n", "2972030405"},
	} {
		for _, m := range phoneFindings(t, c.content) {
			if !strings.Contains(m.Text, c.text) {
				continue
			}
			worst := m.Confidence + csvDocumentBoost
			if ceil, ok := m.Metadata[confidenceCeilingKey].(float64); ok && ceil < worst {
				worst = ceil
			}
			if m.Confidence >= 90 || worst >= 90 {
				t.Errorf("%q: %q scored %.0f (ceiling %v), so it can read HIGH; want below 90", c.content, m.Text, m.Confidence, m.Metadata[confidenceCeilingKey])
			}
		}
	}
	upper := phoneFindings(t, "Employee number 2972030405\n")
	lower := phoneFindings(t, "employee number 2972030405\n")
	if len(upper) != 1 || len(lower) != 1 || upper[0].Confidence != lower[0].Confidence {
		t.Errorf("Employee number: %s, employee number: %s; want one finding each at the same score", describe(upper), describe(lower))
	}
}

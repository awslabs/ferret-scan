// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redact_test

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/pkg/redact"
)

// checkFixtures maps every name ValidCheckNames() advertises to a positive
// sample that the corresponding validator must detect. Values are lifted from
// each validator's own positive test rows (deliberately: a fixture invented
// here could be wrong in a way that makes the gate lie).
//
// Every value is synthetic test data — none is a real credential or identifier.
var checkFixtures = map[string]string{
	"BANK_ACCOUNT":          "Wire to routing number 021000021 account 1234567890 at the branch.",
	"CLOUD_RESOURCES":       "Deploy to arn:aws:s3:::acme-prod-customer-exports-2024 immediately.",
	"CREDIT_CARD":           "Card number 4111-1111-1111-1111 exp 12/28 for the subscription.",
	"DATE_OF_BIRTH":         "Patient date of birth: 03/14/1985 per the intake form.",
	"DRIVERS_LICENSE":       "California driver license number I1234567 on file.",
	"EMAIL":                 "Contact jordan.ellis@acmehealthcorp.example about the invoice.",
	"INTELLECTUAL_PROPERTY": "CONFIDENTIAL AND PROPRIETARY - Trade Secret - All Rights Reserved.",
	"IP_ADDRESS":            "Origin server address is 172.217.14.206 behind the load balancer.",
	"MEDICAL_ID":            "Member ID 1EG4-TE5-MK73 on the Medicare card.",
	"OTP":                   "totp_uri = \"otpauth://totp/Production:admin@corp.example?secret=NBSWY3DP&issuer=Production\"",
	"PASSPORT":              "Visa application: passport C87654321, nationality: British",
	"PERSON_NAME":           "Please forward the claim to Jonathan Whitfield in claims review.",
	"PHONE":                 "Call the patient at (415) 555-0142 to confirm the appointment.",
	"PHYSICAL_ADDRESS":      "Ship to 1600 Amphitheatre Parkway, Mountain View, CA 94043 today.",
	"SECRETS":               "export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	"SSN":                   "Employee SSN 219-09-9999 on the W-2 form.",
	"VIN":                   "Vehicle identification number 1HGBH41JXMN109186 on the title.",
}

// TestValidCheckNames_AllDetectAndRedact is the honesty gate on the public
// advertisement: every name ValidCheckNames() returns must be a name that can
// actually produce a finding AND change the output through Engine.Redact.
//
// The existing TestValidCheckNames asserts only that each name constructs an
// engine without error. That is not enough — a validator with no built-in
// patterns constructs fine, reports zero findings, and returns the input
// verbatim. A caller who selects it gets a successful call, an empty finding
// list and cleartext, which is the worst possible failure mode for a redaction
// library: it looks exactly like "there was nothing sensitive here".
//
// The `Redacted != input` half is what makes this a leak gate rather than a
// reporting gate. A validator could in principle report a finding the redactor
// then fails to act on, and that is the case that actually leaks bytes.
//
// The table is derived FROM ValidCheckNames(), never hardcoded, so a newly
// added validator must either work on this path or be explicitly excluded via
// checksUnsupportedInMemory. It cannot silently join the advertisement.
func TestValidCheckNames_AllDetectAndRedact(t *testing.T) {
	names := redact.ValidCheckNames()
	if len(names) == 0 {
		t.Fatal("ValidCheckNames() is empty, so this test cannot detect anything")
	}

	// Fail loudly on a name with no fixture rather than skipping it — a skip
	// would let a new validator escape the gate unnoticed.
	var missing []string
	for _, name := range names {
		if _, ok := checkFixtures[name]; !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("no positive fixture for advertised check(s) %v.\n"+
			"Either add a fixture (lifted from that validator's own positive test rows) "+
			"or, if the validator genuinely cannot work on the in-memory path, add it to "+
			"checksUnsupportedInMemory in engine.go so it is no longer advertised.",
			missing)
	}

	// Conversely: a fixture for a name that is no longer advertised is stale.
	advertised := make(map[string]bool, len(names))
	for _, n := range names {
		advertised[n] = true
	}
	for name := range checkFixtures {
		if !advertised[name] {
			t.Errorf("checkFixtures has a stale entry %q that ValidCheckNames() no longer returns", name)
		}
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			input := checkFixtures[name]

			engine, err := redact.NewEngine(redact.EngineOptions{
				Checks:   []string{name},
				Strategy: redact.Simple,
			})
			if err != nil {
				t.Fatalf("NewEngine(Checks=[%q]) failed: %v", name, err)
			}
			defer func() { _ = engine.Close() }()

			res, err := engine.Redact(context.Background(), redact.Request{Text: input})
			if err != nil {
				t.Fatalf("Redact failed: %v", err)
			}

			if len(res.Findings()) == 0 {
				t.Errorf("%s is advertised by ValidCheckNames() but produced NO finding on a "+
					"positive fixture, so a caller selecting it gets a successful call, an empty "+
					"finding list and cleartext output — indistinguishable from clean input.\n"+
					"  input: %q", name, input)
			}

			if res.Redacted == input {
				t.Errorf("%s left the output byte-identical to the input, so the sensitive value "+
					"was returned in cleartext.\n  input:    %q\n  redacted: %q", name, input, res.Redacted)
			}
		})
	}
}

// TestUnsupportedInMemoryChecksFailClosed pins the fail-closed contract: a
// Checks list naming ONLY validators that cannot work on this path must return
// an error, not a live engine that silently finds nothing.
//
// METADATA already behaved this way (it needs filesystem access, so NewEngine
// deletes it and the empty set errors). SOCIAL_MEDIA did not: it has no
// built-in patterns and its only pattern source is Configure(cfg), which
// NewEngine deliberately never calls, so it constructed successfully and
// no-opped forever. Same class of limitation, opposite handling — that
// inconsistency was the defect.
func TestUnsupportedInMemoryChecksFailClosed(t *testing.T) {
	for _, name := range []string{"METADATA", "SOCIAL_MEDIA"} {
		t.Run(name, func(t *testing.T) {
			engine, err := redact.NewEngine(redact.EngineOptions{Checks: []string{name}})
			if err == nil {
				if engine != nil {
					_ = engine.Close()
				}
				t.Fatalf("NewEngine(Checks=[%q]) succeeded; it must fail closed because that "+
					"validator cannot produce a finding on the in-memory path", name)
			}
			if !strings.Contains(err.Error(), "no validators enabled") {
				t.Errorf("unexpected error for %q: %v (want the \"no validators enabled\" error)", name, err)
			}
		})
	}
}

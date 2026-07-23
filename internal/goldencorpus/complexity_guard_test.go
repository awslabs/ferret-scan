// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package goldencorpus

import (
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/validators/address"
	"github.com/awslabs/ferret-scan/v2/internal/validators/bankaccount"
	"github.com/awslabs/ferret-scan/v2/internal/validators/cloudresources"
	"github.com/awslabs/ferret-scan/v2/internal/validators/creditcard"
	"github.com/awslabs/ferret-scan/v2/internal/validators/dob"
	"github.com/awslabs/ferret-scan/v2/internal/validators/driverslicense"
	"github.com/awslabs/ferret-scan/v2/internal/validators/email"
	"github.com/awslabs/ferret-scan/v2/internal/validators/intellectualproperty"
	"github.com/awslabs/ferret-scan/v2/internal/validators/ipaddress"
	"github.com/awslabs/ferret-scan/v2/internal/validators/medicalid"
	"github.com/awslabs/ferret-scan/v2/internal/validators/otp"
	"github.com/awslabs/ferret-scan/v2/internal/validators/passport"
	"github.com/awslabs/ferret-scan/v2/internal/validators/personname"
	"github.com/awslabs/ferret-scan/v2/internal/validators/phone"
	"github.com/awslabs/ferret-scan/v2/internal/validators/secrets"
	"github.com/awslabs/ferret-scan/v2/internal/validators/socialmedia"
	"github.com/awslabs/ferret-scan/v2/internal/validators/ssn"
	"github.com/awslabs/ferret-scan/v2/internal/validators/vin"
)

// This file is the second half of the Phase 0 regression net (the first being
// the golden snapshots): a COMPLEXITY guard. The v2 audit found that ~12 of 13
// validators shared an O(n^2) per-line rescan pattern, fixed ad hoc. As the
// consolidation introduces a shared scanning primitive (Move C), there is a real
// risk of reintroducing quadratic behavior. These tests assert that each
// validator's runtime grows roughly LINEARLY with input size on a dense,
// match-bearing input — so a regression to O(n^2) fails loudly here instead of
// silently becoming a DoS vector in production.
//
// The assertion is deliberately loose (it allows a large constant-factor and
// GC/scheduler noise) because we are catching algorithmic class changes
// (linear -> quadratic), not micro-benchmarking. A 10x input that takes ~10x
// time passes; one that takes ~100x fails.

// validatorUnderTest is the minimal shape every validator exposes.
type validatorUnderTest interface {
	ValidateContent(content string, originalPath string) ([]detector.Match, error)
}

// complexityTargets are validators driven directly (bypassing the bridge stack)
// so the timing reflects the validator's own scanning cost, not orchestration.
// Each builder returns a fresh validator and a single-line unit of input that
// the validator will scan densely.
var complexityTargets = []struct {
	name      string
	new       func() validatorUnderTest
	unit      string // one "row" of input; repeated to scale size
	threshold time.Duration
}{
	{
		name: "ssn",
		new:  func() validatorUnderTest { return ssn.NewValidator() },
		// Dense near-SSN tokens on one line stress the per-match context rescan.
		unit:      "ssn 449-87-4100 and 555-12-3456 and 111-22-3333 ",
		threshold: 5 * time.Second,
	},
	{
		name:      "ipaddress",
		new:       func() validatorUnderTest { return ipaddress.NewValidator() },
		unit:      "ip 203.0.113.42 host 10.0.0.5 gw 192.168.1.1 dns 8.8.8.8 ",
		threshold: 5 * time.Second,
	},
	{
		name:      "email",
		new:       func() validatorUnderTest { return email.NewValidator() },
		unit:      "mail a@b.com x@y.org user@example.net admin@corp.co ",
		threshold: 5 * time.Second,
	},
	{
		name:      "phone",
		new:       func() validatorUnderTest { return phone.NewValidator() },
		unit:      "call 212-555-0142 or 415-555-0199 or 312-555-0123 ",
		threshold: 5 * time.Second,
	},
	{
		name:      "creditcard",
		new:       func() validatorUnderTest { return creditcard.NewValidator() },
		unit:      "card 4532015112830366 5425233430109903 374245455400126 ",
		threshold: 5 * time.Second,
	},
	// The 13 remaining text-mode validators (METADATA excluded — it scans
	// extracted file metadata, not text windows). Each unit is a dense,
	// match-bearing line; keyword-gated validators (dob, driverslicense,
	// medicalid, otp, passport, bankaccount US-account) carry their trigger
	// keyword so the per-match context scan — the O(n^2)-prone path — is
	// actually exercised, not short-circuited by an empty candidate set.
	{
		name:      "address",
		new:       func() validatorUnderTest { return address.NewValidator() },
		unit:      "ship to 123 Main St and 456 Oak Ave and 789 Elm Blvd, Springfield IL 62704 ",
		threshold: 5 * time.Second,
	},
	{
		name:      "bankaccount",
		new:       func() validatorUnderTest { return bankaccount.NewValidator() },
		unit:      "routing 026009593 account 1234567890 iban DE89370400440532013000 swift BOFAUS3N ",
		threshold: 5 * time.Second,
	},
	{
		name:      "cloudresources",
		new:       func() validatorUnderTest { return cloudresources.NewValidator() },
		unit:      "arn:aws:iam::123456789012:role/Admin arn:aws:s3:::my-bucket/key i-0abcd1234ef567890 ",
		threshold: 5 * time.Second,
	},
	{
		name:      "dob",
		new:       func() validatorUnderTest { return dob.NewValidator() },
		unit:      "dob 03/14/1987 born 05/22/1990 birthdate 1978-11-02 date of birth 12/01/1985 ",
		threshold: 5 * time.Second,
	},
	{
		name:      "driverslicense",
		new:       func() validatorUnderTest { return driverslicense.NewValidator() },
		unit:      "driver license D1234567 dl 12345678 licence D123-4567-8901 dmv A9876543 ",
		threshold: 5 * time.Second,
	},
	{
		name:      "intellectualproperty",
		new:       func() validatorUnderTest { return intellectualproperty.NewValidator() },
		unit:      "Copyright 2026 Acme. Confidential and Proprietary. Trade Secret. Patent Pending. ",
		threshold: 5 * time.Second,
	},
	{
		name:      "medicalid",
		new:       func() validatorUnderTest { return medicalid.NewValidator() },
		unit:      "npi 1234567893 dea FC9825487 mbi 1EG4-TE5-MK73 mrn 8432197 patient record ",
		threshold: 5 * time.Second,
	},
	{
		name:      "otp",
		new:       func() validatorUnderTest { return otp.NewValidator() },
		unit:      "2fa secret JBSWY3DPEHPK3PXP totp KRUGKIDROVUWG2ZA backup code abcd-efgh-1234 ",
		threshold: 5 * time.Second,
	},
	{
		name:      "passport",
		new:       func() validatorUnderTest { return passport.NewValidator() },
		unit:      "passport 512345678 travel document L8837362 visa passport no 987654321 ",
		threshold: 5 * time.Second,
	},
	{
		name: "personname",
		new:  func() validatorUnderTest { return personname.NewValidator() },
		unit: "contact Maria Delgado and James Wilson and Sarah Chen and Robert Brown ",
		// personname and secrets are the heaviest validators per byte
		// (dictionary lookups per candidate token; entropy + multi-pattern
		// secret scanning). They scale LINEARLY — the ratio check below is the
		// true O(n^2) guard and holds for them — but their linear constant is
		// large enough that the 128KB 4x input runs ~6s on the slow, shared
		// macos CI runner (well under 100ms locally). A 15s absolute ceiling
		// keeps a genuine quadratic blowup (which would be many tens of
		// seconds on this input) failing loudly while tolerating runner noise.
		threshold: 15 * time.Second,
	},
	{
		name:      "secrets",
		new:       func() validatorUnderTest { return secrets.NewValidator() },
		unit:      "AWS_KEY=AKIAIOSFODNN7EXAMPLE token=ghp_1234567890abcdefghij1234567890abcdef ",
		threshold: 15 * time.Second, // see personname note: heavy-but-linear
	},
	{
		name:      "socialmedia",
		new:       func() validatorUnderTest { return socialmedia.NewValidator() },
		unit:      "follow @alice_smith and @bob.jones and twitter.com/carol on socials ",
		threshold: 5 * time.Second,
	},
	{
		name:      "vin",
		new:       func() validatorUnderTest { return vin.NewValidator() },
		unit:      "vin 1HGCM82633A004352 vehicle 2FMDK3GC4BBA12345 vin JH4KA7561PC008269 ",
		threshold: 5 * time.Second,
	},
}

// TestValidatorComplexityIsSubQuadratic checks that doubling input size does not
// roughly quadruple runtime for any validator. It measures at two sizes and
// asserts the growth ratio stays well under the quadratic expectation.
func TestValidatorComplexityIsSubQuadratic(t *testing.T) {
	if testing.Short() {
		t.Skip("complexity guard skipped in -short mode")
	}

	for _, tgt := range complexityTargets {
		tgt := tgt
		t.Run(tgt.name, func(t *testing.T) {
			// Two single-line inputs: base and 4x. A single long line is the
			// worst case for the per-line rescan pattern.
			const baseReps = 400
			baseLine := strings.Repeat(tgt.unit, baseReps)
			bigLine := strings.Repeat(tgt.unit, baseReps*4) // 4x size

			// Absolute ceiling: even the big input must finish quickly. With
			// bounded execution and linear scanning this is generous; an O(n^2)
			// blowup on a dense line would blow past it.
			tBase := timeValidate(t, tgt.new(), baseLine)
			tBig := timeValidate(t, tgt.new(), bigLine)

			if tBig > tgt.threshold {
				t.Errorf("%s: 4x input took %v (> %v ceiling) — possible O(n^2) regression on a single long line",
					tgt.name, tBig, tgt.threshold)
			}

			// Relative growth: 4x input under linear scaling is ~4x time; under
			// quadratic it is ~16x. Fail above 12x (generous headroom for
			// constant factors, GC, and measurement noise on small absolute
			// times). Only meaningful when the base time is large enough to
			// measure; below 2ms the ratio is dominated by noise.
			if tBase > 2*time.Millisecond {
				ratio := float64(tBig) / float64(tBase)
				if ratio > 12.0 {
					t.Errorf("%s: 4x input took %.1fx longer (base=%v big=%v) — superlinear growth suggests an O(n^2) regression",
						tgt.name, ratio, tBase, tBig)
				}
			}
		})
	}
}

// timeValidate runs ValidateContent once and returns the wall-clock duration.
func timeValidate(t *testing.T, v validatorUnderTest, content string) time.Duration {
	t.Helper()
	start := time.Now()
	if _, err := v.ValidateContent(content, "<complexity>"); err != nil {
		t.Fatalf("ValidateContent error: %v", err)
	}
	return time.Since(start)
}

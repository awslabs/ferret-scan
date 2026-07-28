// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package validators

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// TestSetupValidators_RegistrationOrderIsFixed locks the order document
// validators are registered in.
//
// SetupValidators receives a map of check name -> validator and used to range it
// directly, so registration order was randomized per process. Registration order
// is not cosmetic: it decides which validator gets to claim a span of text first
// when two of them match the same bytes, and nothing arbitrates between such
// claims today. NPI 1234567893 is simultaneously a checksum-valid NPI and a
// well-formed 10-digit phone number, and it was redacted as [NPI-REDACTED] on
// one run and [PHONE-REDACTED] on the next for the same input file.
//
// Sorting by check name is not claimed to be the *right* precedence — picking
// one is the cross-validator arbitration problem, which is separate. It only
// guarantees the choice is the same every run.
func TestSetupValidators_RegistrationOrderIsFixed(t *testing.T) {
	// Supplied via a map, so the input has no order of its own. Deliberately
	// includes METADATA, which is routed to the metadata bridge instead and must
	// not appear among the document validators.
	names := []string{"SSN", "NPI", "PHONE", "EMAIL", "CREDIT_CARD", "ADDRESS", "IP_ADDRESS", "METADATA"}
	want := []string{"ADDRESS", "CREDIT_CARD", "EMAIL", "IP_ADDRESS", "NPI", "PHONE", "SSN"}

	// Repeat so a randomized map order cannot coincide with the wanted order on
	// every attempt.
	for i := 0; i < 100; i++ {
		supplied := make(map[string]detector.Validator, len(names))
		for _, n := range names {
			supplied[n] = &bridgeOrderValidator{name: n}
		}

		d := NewDetector(nil)
		if err := d.SetupValidators(supplied); err != nil {
			t.Fatalf("iteration %d: SetupValidators: %v", i, err)
		}

		got := registeredDocumentNames(d)
		if len(got) != len(want) {
			t.Fatalf("iteration %d: registered %d document validators, want %d: %v",
				i, len(got), len(want), got)
		}
		for j := range want {
			if got[j] != want[j] {
				t.Fatalf("iteration %d: registration %d = %q, want %q\nfull order: %v",
					i, j, got[j], want[j], got)
			}
		}
	}
}

// TestSetupValidators_RegistersEveryValidator guards against the trivially wrong
// version of the fix. Ordering the registrations must not drop one: a validator
// that never registers never runs, and for a secret scanner that is an
// undetected secret rather than a cosmetic problem.
func TestSetupValidators_RegistersEveryValidator(t *testing.T) {
	names := []string{"SSN", "NPI", "PHONE", "EMAIL", "CREDIT_CARD"}
	supplied := make(map[string]detector.Validator, len(names))
	for _, n := range names {
		supplied[n] = &bridgeOrderValidator{name: n}
	}

	d := NewDetector(nil)
	if err := d.SetupValidators(supplied); err != nil {
		t.Fatalf("SetupValidators: %v", err)
	}

	got := registeredDocumentNames(d)
	if len(got) != len(names) {
		t.Fatalf("registered %d validators, want %d: %v", len(got), len(names), got)
	}
	registered := strings.Join(got, ",")
	for _, n := range names {
		if !strings.Contains(registered, n) {
			t.Errorf("validator %q was not registered (registered: %s)", n, registered)
		}
	}
}

// registeredDocumentNames returns the check names of the document validators in
// registration order.
func registeredDocumentNames(d *Detector) []string {
	dvb := d.bridge.documentBridge
	dvb.mu.RLock()
	defer dvb.mu.RUnlock()

	out := make([]string, 0, len(dvb.validators))
	for _, nv := range dvb.validators {
		out = append(out, nv.name)
	}
	return out
}

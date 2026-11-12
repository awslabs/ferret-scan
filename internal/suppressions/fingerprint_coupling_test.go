// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suppressions

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// The fingerprint IS the suppression identity minus the line number — that is
// its whole contract, and nothing else pins it. These assertions fail the
// moment a refactor decouples the two formulas (a salt, per-manager state, a
// reordered composite), which must be a deliberate, versioned change
// (ferretFindingIdentity/v2), never drift.
func TestFingerprintIsTheIdentityFormulaWithoutTheLine(t *testing.T) {
	match := detector.Match{
		Text: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", Type: "AWS_SECRET_ACCESS_KEY",
		Confidence: 95, LineNumber: 12, Filename: "src/config.py", Validator: "secrets",
		Context: detector.ContextInfo{
			FullLine:   `aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`,
			BeforeText: "import os",
			AfterText:  "client = boto3.client()",
		},
	}

	head, tail := fingerprintHasher.identityParts(match, hashVersionCurrent)

	// The published fingerprint is sha256(head + tail), nothing more.
	want := sha256.Sum256([]byte(head + tail))
	if got := FindingIdentityFingerprint(match); got != hex.EncodeToString(want[:]) {
		t.Fatalf("FindingIdentityFingerprint diverged from identityParts: got %s", got)
	}

	// And the scan-time rule hash is the SAME parts with the line slotted in,
	// computed by a real manager — so the two formulas cannot drift apart
	// while this passes.
	sm := &SuppressionManager{}
	lined := sha256.Sum256([]byte(head + strconv.Itoa(match.LineNumber) + tail))
	if got := sm.generateFindingHash(match); got != hex.EncodeToString(lined[:]) {
		t.Fatalf("generateFindingHash no longer equals sha256(head+line+tail): got %s", got)
	}
}

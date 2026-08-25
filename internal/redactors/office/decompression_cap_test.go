// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package office

import (
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/embedded"
)

// TestOfficeTotalCapTracksTheSharedBudget is a decay guard on an alias, not a tautology.
//
// maxOfficeTotalBytes and embedded.BudgetBytes were two independent 200MB literals charged against
// the same archive from opposite directions: the read side while extracting embedded parts, the
// write side while repackaging entries. Either could have been tuned alone, and the result — a
// document the scanner reads in full but the redactor refuses, or the reverse — would look like a
// format bug rather than a mismatched constant.
//
// This fails if someone replaces the alias with a number again, which is the only way the two can
// drift now.
func TestOfficeTotalCapTracksTheSharedBudget(t *testing.T) {
	if maxOfficeTotalBytes != embedded.BudgetBytes {
		t.Errorf("maxOfficeTotalBytes = %d but embedded.BudgetBytes = %d. These bound the same "+
			"archive from the read and write sides; if the write side genuinely needs a different "+
			"cap, give it its own named constant and say why, rather than letting the alias drift.",
			maxOfficeTotalBytes, embedded.BudgetBytes)
	}
}

// TestPerEntryCapIsBelowTheTotal pins the ordering the two caps need to make sense together.
//
// If the per-entry cap ever met or exceeded the cumulative one, a single entry could exhaust the
// whole budget and the total cap would stop being a distinct bound — the "many medium entries"
// shape it exists for would be unreachable, and the guard would read as active while doing nothing.
func TestPerEntryCapIsBelowTheTotal(t *testing.T) {
	if maxOfficeEntryBytes >= maxOfficeTotalBytes {
		t.Errorf("maxOfficeEntryBytes = %d is not below maxOfficeTotalBytes = %d, so one entry can "+
			"consume the entire cumulative budget and the total cap bounds nothing extra",
			maxOfficeEntryBytes, maxOfficeTotalBytes)
	}
}

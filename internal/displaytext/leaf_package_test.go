// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package displaytext_test

import (
	"go/build"
	"strings"
	"testing"
)

// This package must stay a LEAF, and that is a correctness property rather than tidiness.
//
// These functions used to live in internal/formatters/shared. shared imports
// internal/formatters, so internal/formatters could NOT import shared back — which meant the
// coverage and redaction disclosure emitters in internal/formatters and cmd had no way to reach
// the escaping at all. That is exactly where the control bytes were still landing (#544):
// escaping "at every sink" is only achievable if every sink can import the escaper.
//
// The build error is not subtle when it happens ("import cycle not allowed"), but it appears at
// the SINK being fixed, months later, and the natural response is to escape somewhere else or
// to skip that sink. This test moves the failure to the change that causes it.
func TestDisplayTextImportsNothingInternal(t *testing.T) {
	pkg, err := build.Default.Import("github.com/awslabs/ferret-scan/v2/internal/displaytext", "", 0)
	if err != nil {
		t.Fatalf("cannot inspect the package: %v", err)
	}

	// GoFiles only: a test file may import whatever it needs, and this one does.
	for _, imp := range pkg.Imports {
		if strings.Contains(imp, "ferret-scan") {
			t.Errorf("displaytext imports %q. It must import nothing from this repository: any "+
				"internal dependency reintroduces the import cycle for some future display "+
				"sink, which is the defect #544 fixed. If escaping needs something from another "+
				"package, pass it in as an argument instead.", imp)
		}
	}

	// Non-vacuity: if the inspection returned no imports at all, the loop above proves nothing.
	if len(pkg.Imports) == 0 {
		t.Fatal("the package reports zero imports, so this check is vacuous — it should at " +
			"least import strings and unicode/utf8")
	}
	t.Logf("displaytext imports %v — all stdlib", pkg.Imports)
}

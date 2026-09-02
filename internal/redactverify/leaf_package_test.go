// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactverify_test

import (
	"go/build"
	"strings"
	"testing"
)

const self = "github.com/awslabs/ferret-scan/v2/internal/redactverify"
const forbidden = "github.com/awslabs/ferret-scan/v2/internal/redactors"

// This package must stay a LEAF with no path to internal/redactors, and that is a correctness property
// rather than tidiness.
//
// internal/redactors/tagmeta already has residual helpers (ResidualAnywhere, ResidualEncoded) and this
// package cannot reuse them, because tagmeta imports internal/redactors — the arrow cannot point back.
// So the predicate lives here, where BOTH dispatch points can import it: internal/parallel (top-level
// files) and internal/redactors itself (embedded parts inside a container). If this package ever gained
// a path to internal/redactors, that second import becomes a cycle and the floor has to be duplicated or
// dropped — and a duplicated check is exactly how #449 shipped a file containing a reported SSN.
//
// Checked TRANSITIVELY, not on direct imports. internal/displaytext's precedent inspects pkg.Imports
// only, which is sufficient there because that package imports nothing internal at all; here the
// package legitimately imports internal/detector and internal/embedded, so a cycle could arrive through
// either of them and a direct-import check would not see it.
func TestRedactverifyIsATransitiveLeaf(t *testing.T) {
	seen := map[string]bool{}
	var path []string

	var walk func(pkgPath string, chain []string) bool
	walk = func(pkgPath string, chain []string) bool {
		if seen[pkgPath] {
			return false
		}
		seen[pkgPath] = true
		pkg, err := build.Default.Import(pkgPath, "", 0)
		if err != nil {
			// A package we cannot inspect (stdlib vendoring quirk) cannot reach back into this repo.
			return false
		}
		for _, imp := range pkg.Imports {
			if !strings.HasPrefix(imp, "github.com/awslabs/ferret-scan/v2/") {
				continue // stdlib and third-party cannot import this repo
			}
			next := append(append([]string{}, chain...), imp)
			if imp == forbidden || strings.HasPrefix(imp, forbidden+"/") {
				path = next
				return true
			}
			if walk(imp, next) {
				return true
			}
		}
		return false
	}

	if walk(self, []string{self}) {
		t.Errorf("internal/redactverify reaches internal/redactors through:\n  %s\n\n"+
			"That makes the import in internal/redactors/embedded.go a cycle, so the embedded-part floor "+
			"has to be duplicated or dropped. A duplicated residual check is how #449 shipped a file "+
			"containing a reported SSN at exit 0.", strings.Join(path, "\n    -> "))
	}

	// Non-vacuity: the walk must actually have traversed something, or an empty closure would pass.
	if len(seen) < 3 {
		t.Fatalf("the import walk visited only %d package(s); it is not inspecting the closure, so this "+
			"assertion would pass for any code", len(seen))
	}
	t.Logf("walked %d packages in the closure, none reaching internal/redactors", len(seen))
}

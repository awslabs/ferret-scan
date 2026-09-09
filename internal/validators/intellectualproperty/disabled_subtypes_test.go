// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package intellectualproperty

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
)

// TestRecognisedSubTypesCoversEveryLookup is the drift guard, and it is the reason this list is
// exported rather than duplicated at the disclosure site.
//
// The validator consults v.disabledTypes in two places 90 lines apart: once for "internal_url" and
// once over the four names in ValidateContent's ipPatterns slice. A sixth sub-type added to either
// would be honoured by the validator and INVISIBLE to the coverage disclosure — silently disablable
// detection, which is the exact defect #293 is about, reintroduced one sub-type at a time.
//
// Reads the source with go/ast rather than grepping: a regex over `v.disabledTypes\[` cannot
// distinguish a string literal key from a variable, and the ipPatterns loop uses a VARIABLE
// (`v.disabledTypes[ipType]`), so a text scan would either miss the four names or report the
// identifier as a name. The AST lets the test find the literals wherever they are — including the
// composite literal that feeds the loop.
func TestRecognisedSubTypesCoversEveryLookup(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "validator.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing validator.go: %v", err)
	}

	literalKeys := map[string]bool{}
	inspected := 0

	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.IndexExpr:
			// v.disabledTypes["internal_url"] — a direct literal lookup.
			if !isDisabledTypesSelector(node.X) {
				return true
			}
			inspected++
			if lit, ok := node.Index.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if s, err := strconv.Unquote(lit.Value); err == nil {
					literalKeys[s] = true
				}
			}
		case *ast.CompositeLit:
			// The ipPatterns slice: {"copyright", v.regexCopyright}, ... Its first element is the
			// key the loop then looks up, so those names are lookups too even though they never
			// appear inside brackets.
			for _, elt := range node.Elts {
				inner, ok := elt.(*ast.CompositeLit)
				if !ok || len(inner.Elts) == 0 {
					continue
				}
				lit, ok := inner.Elts[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				if s, err := strconv.Unquote(lit.Value); err == nil && looksLikeIPSubType(s) {
					literalKeys[s] = true
				}
			}
		}
		return true
	})

	// Non-vacuity: if the AST walk stopped finding the direct lookups, the assertion below would
	// pass on an empty set. Measured at 2 today (one write in Configure, one read for internal_url).
	if inspected < 2 {
		t.Fatalf("found only %d v.disabledTypes[...] expressions; the walk is not reading the "+
			"source it is meant to police", inspected)
	}
	if len(literalKeys) < len(recognisedSubTypes) {
		t.Fatalf("found only %d sub-type names in the source (%v) against %d in recognisedSubTypes; "+
			"the walk is missing lookups, so it cannot prove the list is complete",
			len(literalKeys), sortedSet(literalKeys), len(recognisedSubTypes))
	}

	known := map[string]bool{}
	for _, name := range recognisedSubTypes {
		known[name] = true
	}
	for name := range literalKeys {
		if !known[name] {
			t.Errorf("validator.go consults disabled_types[%q] but recognisedSubTypes does not list "+
				"it. The validator would honour it and the coverage disclosure would never mention "+
				"it — silently disablable detection, which is what #293 is about. Add it to "+
				"recognisedSubTypes in disabled_subtypes.go.", name)
		}
	}
	for _, name := range recognisedSubTypes {
		if !literalKeys[name] {
			t.Errorf("recognisedSubTypes lists %q but validator.go never consults it. The "+
				"disclosure would claim a sub-type can be disabled when nothing reads the flag, "+
				"and an operator disabling it would be told it took effect.", name)
		}
	}
}

func isDisabledTypesSelector(e ast.Expr) bool {
	sel, ok := e.(*ast.SelectorExpr)
	return ok && sel.Sel != nil && sel.Sel.Name == "disabledTypes"
}

// looksLikeIPSubType keeps the composite-literal sweep from hoovering up every string in the file.
// The four pattern names are lower-case words or snake_case; anything with a space, an upper-case
// letter or punctuation is some other literal.
func looksLikeIPSubType(s string) bool {
	if s == "" || len(s) > 24 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || c == '_' {
			continue
		}
		return false
	}
	return true
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func configWithDisabledTypes(values ...string) *config.Config {
	list := make([]any, 0, len(values))
	for _, v := range values {
		list = append(list, v)
	}
	return &config.Config{Validators: map[string]map[string]any{
		"intellectual_property": {"disabled_types": list},
	}}
}

func TestDisabledSubTypesReportsWhatWasActuallyDisabled(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		configured            []string
		wantDisabled, wantBad []string
	}{
		{"nothing configured", nil, nil, nil},
		{"one real sub-type", []string{"copyright"}, []string{"copyright"}, nil},
		{"two, reported in list order not config order",
			[]string{"trademark", "copyright"}, []string{"copyright", "trademark"}, nil},
		{"case and whitespace are normalised, as Configure does",
			[]string{"  COPYRIGHT  "}, []string{"copyright"}, nil},
		{"a typo disables nothing and is reported as ineffective",
			[]string{"copyrite"}, nil, []string{"copyrite"}},
		{"real and typo together", []string{"patent", "copyrite"},
			[]string{"patent"}, []string{"copyrite"}},
		{"every sub-type", []string{"copyright", "internal_url", "patent", "trade_secret", "trademark"},
			[]string{"copyright", "internal_url", "patent", "trade_secret", "trademark"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := NewValidator()
			if tc.configured != nil {
				v.Configure(configWithDisabledTypes(tc.configured...))
			}
			if got := v.DisabledSubTypes(); !reflect.DeepEqual(got, tc.wantDisabled) {
				t.Errorf("DisabledSubTypes() = %v, want %v", got, tc.wantDisabled)
			}
			if got := v.UnrecognisedDisabledSubTypes(); !reflect.DeepEqual(got, tc.wantBad) {
				t.Errorf("UnrecognisedDisabledSubTypes() = %v, want %v", got, tc.wantBad)
			}
		})
	}
}

// TestDisabledSubTypesAgreesWithBehaviour is the non-vacuity half: the accessor must describe what
// the validator DOES, not what it was told. An accessor that returns a name while the sub-type is
// still detected is a false disclosure, which is worse than none.
func TestDisabledSubTypesAgreesWithBehaviour(t *testing.T) {
	const notice = "Copyright (c) 2026 Acme Corporation. All rights reserved.\n"

	plain := NewValidator()
	before, err := plain.ValidateContent(notice, "notice.txt")
	if err != nil {
		t.Fatalf("baseline validate: %v", err)
	}
	if len(before) == 0 {
		t.Fatalf("the fixture produces no COPYRIGHT finding even undisabled, so the comparison " +
			"below would hold for a validator that detects nothing")
	}

	off := NewValidator()
	off.Configure(configWithDisabledTypes("copyright"))
	after, err := off.ValidateContent(notice, "notice.txt")
	if err != nil {
		t.Fatalf("disabled validate: %v", err)
	}

	if got := off.DisabledSubTypes(); !reflect.DeepEqual(got, []string{"copyright"}) {
		t.Fatalf("DisabledSubTypes() = %v, want [copyright]", got)
	}
	for _, m := range after {
		if strings.EqualFold(m.Type, "COPYRIGHT") {
			t.Errorf("DisabledSubTypes() reports copyright disabled, but a COPYRIGHT finding was "+
				"still produced (%d findings). The disclosure does not match the behaviour.", len(after))
			break
		}
	}

	// And the other direction: a typo must NOT be reported as disabled, because detection still runs.
	typo := NewValidator()
	typo.Configure(configWithDisabledTypes("copyrite"))
	still, err := typo.ValidateContent(notice, "notice.txt")
	if err != nil {
		t.Fatalf("typo validate: %v", err)
	}
	if len(still) != len(before) {
		t.Errorf("a typo'd disabled_types entry changed the finding count %d -> %d; it should be "+
			"inert, and UnrecognisedDisabledSubTypes exists to say so", len(before), len(still))
	}
	if got := typo.DisabledSubTypes(); len(got) != 0 {
		t.Errorf("DisabledSubTypes() = %v for a typo'd entry; nothing was disabled", got)
	}
}

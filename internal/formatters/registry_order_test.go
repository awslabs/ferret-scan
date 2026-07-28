// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package formatters

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// stubFormatter is a minimal Formatter used only to populate a registry.
type stubFormatter struct{ name string }

func (s stubFormatter) Format([]detector.Match, []detector.SuppressedMatch, FormatterOptions) (string, error) {
	return "", nil
}
func (s stubFormatter) Name() string          { return s.name }
func (s stubFormatter) Description() string   { return s.name + " output" }
func (s stubFormatter) FileExtension() string { return "." + s.name }

// TestRegistryList_StableOrder locks the order of Registry.List(). The order is
// user-visible: it backs the "Use one of: ..." hint printed for an unsupported
// --format and the equivalent web export error, both of which listed the formats
// in a different sequence on every invocation because List() ranged the
// registry map.
func TestRegistryList_StableOrder(t *testing.T) {
	names := []string{"text", "json", "yaml", "csv", "sarif", "junit", "gitlab-sast"}
	want := []string{"csv", "gitlab-sast", "json", "junit", "sarif", "text", "yaml"}

	for i := 0; i < 200; i++ {
		r := NewRegistry()
		for _, n := range names {
			r.Register(stubFormatter{name: n})
		}

		got := r.List()
		if len(got) != len(want) {
			t.Fatalf("iteration %d: got %d names, want %d: %v", i, len(got), len(want), got)
		}
		for j := range want {
			if got[j] != want[j] {
				t.Fatalf("iteration %d: name %d = %q, want %q\nfull order: %v",
					i, j, got[j], want[j], got)
			}
		}
	}
}

// TestExportError_StableFormatList checks the user-facing consequence: the
// error message for an unknown format lists the available formats in a fixed
// order, so the same mistake produces the same message every time.
func TestExportError_StableFormatList(t *testing.T) {
	// Export reads the package-global registry, and nothing in this test binary
	// imports the formatter subpackages that would normally populate it via
	// init() — so populate it here and restore it afterwards. Without this the
	// list is empty and the assertion is vacuous.
	saved := DefaultRegistry
	t.Cleanup(func() { DefaultRegistry = saved })
	DefaultRegistry = NewRegistry()
	for _, n := range []string{"text", "json", "yaml", "csv", "sarif", "junit", "gitlab-sast"} {
		Register(stubFormatter{name: n})
	}

	const wantList = "csv, gitlab-sast, json, junit, sarif, text, yaml"

	var first string
	for i := 0; i < 200; i++ {
		_, err := Export("nope", nil, nil, FormatterOptions{})
		if err == nil {
			t.Fatal("expected an error for an unknown format")
		}
		msg := err.Error()
		if !strings.Contains(msg, "Available formats: "+wantList) {
			t.Fatalf("iteration %d: want the format list %q, got message %q", i, wantList, msg)
		}
		if first == "" {
			first = msg
			continue
		}
		if msg != first {
			t.Fatalf("iteration %d: error message changed\ngot:   %q\nfirst: %q", i, msg, first)
		}
	}
}

// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package detector

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMatch_IsVirtual(t *testing.T) {
	cases := []struct {
		name string
		m    Match
		want bool
	}{
		{"zero value is file-backed", Match{}, false},
		{"explicit file kind is file-backed", Match{SourceKind: SourceKindFile}, false},
		{"virtual kind reports virtual", Match{SourceKind: SourceKindVirtual}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.m.IsVirtual(); got != tc.want {
				t.Errorf("IsVirtual()=%v, want %v", got, tc.want)
			}
		})
	}
}

// TestMatch_SourceKindOmittedWhenZero ensures the JSON serialization is
// backward-compatible: a Match without SourceKind set must serialize without
// the "source_kind" key, so consumers reading older Match JSON don't get a
// surprising new field with empty value.
func TestMatch_SourceKindOmittedWhenZero(t *testing.T) {
	m := Match{
		Type:       "EMAIL",
		Filename:   "/tmp/x.txt",
		LineNumber: 1,
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if strings.Contains(string(out), "source_kind") {
		t.Errorf("source_kind must be omitted when zero, got: %s", out)
	}
}

func TestMatch_SourceKindEmittedWhenVirtual(t *testing.T) {
	m := Match{
		Type:       "EMAIL",
		Filename:   "<stdin>",
		LineNumber: 1,
		SourceKind: SourceKindVirtual,
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if !strings.Contains(string(out), `"source_kind":"virtual"`) {
		t.Errorf("expected source_kind=virtual in JSON, got: %s", out)
	}
}

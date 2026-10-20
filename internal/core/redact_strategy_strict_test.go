// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
)

// TestRedactFile_MisspelledStrategyIsRefusedBeforeAnyOutput pins the core half of #772: a
// RedactConfig.Strategy that is set and is not one of the three names is an error returned before
// the output directory exists, and "" keeps its documented meaning (format_preserving) so in-process
// callers that never set it are unchanged. Before the fix the name went through a parser whose
// unknown branch returned format_preserving, so `Strategy: "simpel"` wrote a masked copy at err=nil.
func TestRedactFile_MisspelledStrategyIsRefusedBeforeAnyOutput(t *testing.T) {
	in := t.TempDir()
	src := writeTemp(t, in, "e.txt", "email jordan@example.com\n")

	for _, bad := range []string{"simpel", "SIMPLE", " simple", "bogus"} {
		out := filepath.Join(t.TempDir(), "red")
		res, err := RedactFile(RedactConfig{FilePath: src, OutputDir: out, Strategy: bad, Config: config.LoadConfigOrDefault("")})
		if err == nil {
			t.Errorf("Strategy %q: RedactFile returned nil error (applied %q); a misspelled strategy must not become a strategy", bad, res.Strategy)
			continue
		}
		if !strings.Contains(err.Error(), `"`+bad+`"`) {
			t.Errorf("Strategy %q: the error does not quote the value: %v", bad, err)
		}
		if _, statErr := os.Stat(out); statErr == nil {
			t.Errorf("Strategy %q: the output directory was created before the strategy was refused", bad)
		}
	}

	// The documented default is unchanged.
	res, err := RedactFile(RedactConfig{FilePath: src, OutputDir: t.TempDir(), Config: config.LoadConfigOrDefault("")})
	if err != nil || res.Strategy != "format_preserving" {
		t.Errorf("Strategy \"\": err=%v applied=%q, want format_preserving (the documented default for an unset field)", err, res.Strategy)
	}
}

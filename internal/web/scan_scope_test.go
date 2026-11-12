// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
	"github.com/awslabs/ferret-scan/v2/internal/goldencorpus"
)

// TestScanResponseCarriesTheScopeBlock is #904's web half: a narrowed /scan says what it did not look
// for in the same "scan" block the CLI's json report carries, and a full-scope /scan carries none, so
// its response keeps every key it had.
func TestScanResponseCarriesTheScopeBlock(t *testing.T) {
	h := parityServer(t)
	content := []byte("Contact: jane.doe@example.com\n")

	narrowed, _ := sessionScan(t, h, nil, "a.txt", content, []string{"SSN"})
	if narrowed.Scan == nil {
		t.Fatal("/scan with checks=SSN has no scan block, so a narrowed scan reads as a clean full one (#904)")
	}
	if !reflect.DeepEqual(narrowed.Scan.ChecksRun, []string{"SSN"}) {
		t.Errorf("checks_run = %v, want [SSN]", narrowed.Scan.ChecksRun)
	}
	if got, want := len(narrowed.Scan.ChecksNotRun), len(core.CheckNames())-1; got != want {
		t.Errorf("checks_not_run has %d entries, want %d (every known check but SSN)", got, want)
	}
	if narrowed.Scan.Config.Source != formatters.ConfigSourceExplicit {
		t.Errorf("config.source = %q, want %q (the server was given --config)", narrowed.Scan.Config.Source, formatters.ConfigSourceExplicit)
	}
	if narrowed.Scan.Profile != nil {
		t.Errorf("the web has no profile, yet the block names %+v", narrowed.Scan.Profile)
	}
	if !reflect.DeepEqual(narrowed.Scan, cliScope(goldencorpus.FileCase{Checks: []string{"SSN"}})) {
		t.Errorf("the /scan block differs from the CLI's for the same checks:\n web %+v\n cli %+v", narrowed.Scan, cliScope(goldencorpus.FileCase{Checks: []string{"SSN"}}))
	}

	full, _ := sessionScan(t, h, nil, "a.txt", content, nil)
	if full.Scan != nil {
		t.Errorf("a full-scope /scan carries a scan block %+v; the CLI's full-scope report has none", full.Scan)
	}
	raw, err := json.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"scan":`) {
		t.Error(`a full-scope /scan response has a "scan" key`)
	}
}

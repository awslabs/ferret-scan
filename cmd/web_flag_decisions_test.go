// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"strings"
	"testing"
)

// #925: which of the eight formerly undecided flags validateWebModeFlags refuses with --web, and which it
// lets through to the server. Identifiers carry the prefix wfd to stay distinct from other cmd tests.

func wfdValidate(t *testing.T, args ...string) error {
	t.Helper()
	saved := flag.CommandLine
	t.Cleanup(func() { flag.CommandLine = saved })
	flag.CommandLine = flag.NewFlagSet("wfd", flag.ContinueOnError)
	flag.Bool("respect-gitignore", false, "")
	flag.Int("limit", 200, "")
	flag.Bool("debug", false, "")
	flag.Bool("list-profiles", false, "")
	flag.String("profile", "", "")
	flag.String("max-live-bytes", "", "")
	flag.String("validator-budget", "", "")
	flag.String("disable-ip-types", "", "")
	if err := flag.CommandLine.Parse(args); err != nil {
		t.Fatalf("parse %v: %v", args, err)
	}
	return validateWebModeFlags()
}

func TestWebModeRefusesTheFlagsAnUploadCannotHonor(t *testing.T) {
	for _, tc := range []struct {
		args     []string
		flagName string
	}{
		{[]string{"-respect-gitignore"}, "--respect-gitignore"},
		{[]string{"-limit", "0"}, "--limit"},
		{[]string{"-list-profiles"}, "--list-profiles"},
		{[]string{"-max-live-bytes", "1MB"}, "--max-live-bytes"},
	} {
		err := wfdValidate(t, tc.args...)
		if err == nil || !strings.Contains(err.Error(), tc.flagName) {
			t.Errorf("--web with %v must be refused naming %s, got %v", tc.args, tc.flagName, err)
		}
	}
}

func TestWebModeAcceptsTheFlagsTheServerApplies(t *testing.T) {
	for _, args := range [][]string{
		{"-profile", "strict"},
		{"-disable-ip-types", "copyright"},
		{"-validator-budget", "SSN=1s"},
		{"-debug"},
	} {
		if err := wfdValidate(t, args...); err != nil {
			t.Errorf("--web with %v must be accepted (the server applies it), got %v", args, err)
		}
	}
}

func TestWebScanOptionsCarryTheFlags(t *testing.T) {
	t.Setenv("FERRET_DEBUG", "")
	o := webScanOptions(extractedFlags{profileName: "p", disableIPTypes: "copyright, trademark", debug: true}, nil)
	if o.ProfileName != "p" || !o.Debug || len(o.DisableIPTypes) != 2 || o.DisableIPTypes[1] != "trademark" {
		t.Errorf("webScanOptions dropped a flag: %+v", o)
	}
	if webScanOptions(extractedFlags{}, nil).DisableIPTypes != nil {
		t.Errorf("an unset --disable-ip-types must stay nil so the configured set is kept")
	}
}

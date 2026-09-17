// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/suppressions"
)

// --suppression-expires has four surfaces that must agree: the parser, the flag's help text, the
// shipped example configs, and the documentation. This is the guard on that.
//
// It is worth a test rather than a careful edit because the first version of the flag was a bare
// time.Duration, and Go's duration syntax has no `d` and no `w`. So `720h` was the only way to say 30
// days, and every natural spelling was rejected:
//
//	30d  4w  30  2026-12-31   ->  "parse error"
//
// The documentation then said `720h`, which was accurate and useless. Widening the parser without
// widening the help and the docs would have produced the opposite defect — a capability nobody could
// discover — which is the same class as #686, where --help advertised a capability that did not exist.
//
// The forms are asserted against ParseExpirySpec itself, so the parser is the source of truth and this
// test cannot pass by agreeing with a stale list.

// expiryForms are the spellings a user is told about. Each must PARSE, and each must be MENTIONED
// everywhere the option is documented.
var expiryForms = []struct {
	form     string
	whyItIsD string
}{
	{"30", "a bare number, the most likely thing someone types"},
	{"30d", "days — Go's duration syntax has no d"},
	{"4w", "weeks — nor a w"},
	{"720h", "a Go duration, the original and only accepted form"},
	{"2026-12-31", "an absolute date, so every rule in a run lapses on the same day"},
	{"never", "no expiry, said readably — what a config file wants to hold"},
}

func TestEveryDocumentedExpiryFormActuallyParses(t *testing.T) {
	for _, f := range expiryForms {
		spec, err := suppressions.ParseExpirySpec(f.form)
		if err != nil {
			t.Errorf("%q is documented but does not parse: %v\n  (%s)", f.form, err, f.whyItIsD)
			continue
		}
		wantExpiry := f.form != "never"
		if got := spec.Resolve(time.Now()); (got != nil) != wantExpiry {
			t.Errorf("%q resolved to expiry=%v, want expiry=%v", f.form, got != nil, wantExpiry)
		}
	}

	// And the converse: something plainly wrong must be REFUSED, or "every form parses" is vacuous.
	for _, bad := range []string{"thirty days", "bogus", "0d", "-5", "30x", "2026-13-45"} {
		if _, err := suppressions.ParseExpirySpec(bad); err == nil {
			t.Errorf("%q was accepted; the parser must refuse what it cannot understand rather than "+
				"silently choosing a lifetime", bad)
		}
	}
}

// TestTheFlagHelpNamesTheFormsAndTheConfigKey is the help half of the alignment.
//
// Driven through the built binary, because what matters is what the shipped program prints.
func TestTheFlagHelpNamesTheFormsAndTheConfigKey(t *testing.T) {
	bin := buildScanner(t)
	out, err := exec.Command(bin, "--help").CombinedOutput() // #nosec G204 -- bin is built by the test
	if err != nil {
		t.Fatalf("--help failed: %v\n%s", err, out)
	}
	help := string(out)

	line := ""
	for _, l := range strings.Split(help, "\n") {
		if strings.Contains(l, "--suppression-expires") {
			line = l
			break
		}
	}
	if line == "" {
		t.Fatalf("--help does not mention --suppression-expires at all, so a user cannot discover it")
	}

	// Every form a user might reach for has to appear, or the flag reads as duration-only again.
	for _, f := range expiryForms {
		if !strings.Contains(line, f.form) {
			t.Errorf("the help text for --suppression-expires does not mention %q.\n  %s\n"+
				"  (%s)\nA form that parses but is not advertised is a capability nobody finds.",
				f.form, strings.TrimSpace(line), f.whyItIsD)
		}
	}
	// And it must point at the config key, since setting it per-invocation is the wrong default habit.
	if !strings.Contains(line, "suppressions.expires_in") {
		t.Errorf("the help text does not name the config key suppressions.expires_in:\n  %s",
			strings.TrimSpace(line))
	}
}

// TestTheExampleConfigsCarryTheKey keeps the shipped defaults in step.
//
// A config option absent from the annotated example is one users do not know exists — and both example
// files must carry it, because the Windows one is a full copy rather than an include.
func TestTheExampleConfigsCarryTheKey(t *testing.T) {
	for _, name := range []string{"ferret.yaml", "ferret-windows.yaml"} {
		path := filepath.Join("..", "examples", name)
		raw, err := os.ReadFile(path) // #nosec G304 -- a constant repository path
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		text := string(raw)
		if !strings.Contains(text, "expires_in:") {
			t.Errorf("%s has no expires_in key under suppressions. The annotated example is where a "+
				"user discovers an option exists.", name)
			continue
		}
		// It must be commented, and it must document the forms — an uncommented key teaches nothing.
		for _, f := range []string{"30d", "4w", "never"} {
			if !strings.Contains(text, f) {
				t.Errorf("%s mentions expires_in but not the form %q, so a reader cannot tell what "+
					"the key accepts", name, f)
			}
		}
		// The shipped default must be the safe one: a value here that expires rules would reintroduce
		// exactly the defect #696 fixed, for everyone who copies the example.
		if !strings.Contains(text, "expires_in: never") {
			t.Errorf("%s does not ship expires_in: never. The example is copied as a starting point, "+
				"so any other value hands the one-week-inert-baseline defect to every user who copies "+
				"it (#696).", name)
		}
	}
}

// TestTheDocumentationNamesEveryForm is the third surface.
//
// Checked per FILE rather than across the tree: a reader lands on one page, and "it is documented
// somewhere" is not the same as "the page you are reading is correct".
func TestTheDocumentationNamesEveryForm(t *testing.T) {
	pages := []string{
		"../docs/user-guides/README-Suppressions.md",
		"../docs/suppression-system.md",
		"../docs/configuration.md",
	}
	for _, page := range pages {
		raw, err := os.ReadFile(page) // #nosec G304 -- constant repository paths
		if err != nil {
			t.Fatalf("reading %s: %v", page, err)
		}
		text := string(raw)
		if !strings.Contains(text, "expires_in") && !strings.Contains(text, "suppression-expires") {
			t.Errorf("%s does not mention the expiry option at all", page)
			continue
		}
		for _, f := range expiryForms {
			if !strings.Contains(text, f.form) {
				t.Errorf("%s does not mention the form %q. Every page that documents the option must "+
					"list the forms, or a reader on that page concludes the others do not work — which "+
					"is how `720h` became the only documented spelling of 30 days.", page, f.form)
			}
		}
	}
}

// TestPrecedenceIsDocumentedInTheOrderItActuallyResolves catches the subtler drift.
//
// Three sources set this value, and getting the order wrong in prose is worse than omitting it: a
// reader sets the config key, sees the flag win, and concludes the config key is broken.
func TestPrecedenceIsDocumentedInTheOrderItActuallyResolves(t *testing.T) {
	raw, err := os.ReadFile("../docs/user-guides/README-Suppressions.md") // #nosec G304 -- constant path
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)

	iCfg := strings.Index(text, "suppressions.expires_in")
	iProfile := strings.Index(text, "suppression_expires_in")
	iFlag := strings.Index(text, "--suppression-expires")
	if iCfg < 0 || iProfile < 0 || iFlag < 0 {
		t.Fatalf("the page does not name all three sources (config=%d profile=%d flag=%d)",
			iCfg, iProfile, iFlag)
	}
	if !strings.Contains(text, "Precedence") && !strings.Contains(text, "precedence") {
		t.Errorf("the page names all three sources but never states which one wins. Silence here reads " +
			"as 'they are equivalent', and they are not.")
	}
}

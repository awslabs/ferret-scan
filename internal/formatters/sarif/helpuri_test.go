// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package sarif

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/core"
)

// docsCheckPage is the generated reference every SARIF helpUri points into,
// relative to the repository root.
const docsCheckPage = "docs/checks.md"

// repoRoot walks up from the test's working directory to the module root, so these
// tests do not depend on how deep the package sits.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not locate the module root (no go.mod within 8 parents)")
	return ""
}

// renderCheckPage builds the expected contents of docs/checks.md from the SAME two
// sources the SARIF rule builder reads: core.KnownTypes() for the type set, and
// GetRuleDescription for the copy.
//
// Generated rather than hand-written precisely because the failure being fixed was a
// documentation target that drifted to nonexistence without anything noticing. A
// hand-maintained page would drift again the first time a validator gains a sub-type.
func renderCheckPage() string {
	var b strings.Builder
	b.WriteString("# Detection types\n\n")
	b.WriteString("Every type `ferret-scan` can report, with the description it puts in a SARIF rule.\n\n")
	b.WriteString("**This file is generated.** It is rendered from `core.KnownTypes()` and\n")
	b.WriteString("`sarif.GetRuleDescription` — the same sources the SARIF rule builder reads — so the\n")
	b.WriteString("page and the report cannot disagree about a type. Regenerate with:\n\n")
	b.WriteString("```\nUPDATE_CHECK_DOCS=1 go test ./internal/formatters/sarif/ -run TestCheckPageIsUpToDate\n```\n\n")
	b.WriteString("Each SARIF finding's `helpUri` links to the anchor for its type, so a reviewer\n")
	b.WriteString("reading a report in a code-scanning UI lands on the matching section here.\n\n")
	b.WriteString("Types whose entry reads the generic description simply have no bespoke copy in the\n")
	b.WriteString("registry yet; the detection itself is unaffected.\n\n")
	b.WriteString("## Index\n\n")
	types := core.KnownTypes()
	for _, t := range types {
		b.WriteString(fmt.Sprintf("- [%s](#%s)\n", t, strings.ToLower(t)))
	}
	b.WriteString("\n")
	for _, t := range types {
		d := GetRuleDescription(t)
		b.WriteString(fmt.Sprintf("## %s\n\n", t))
		b.WriteString(fmt.Sprintf("**%s**\n\n", d.Short))
		b.WriteString(d.Full + "\n\n")
		b.WriteString("*What to do:* " + d.Help + "\n\n")
		// The gitlab-sast remediation is rendered here too, so the page is the single
		// home for a type's copy rather than SARIF's half of it. It is deliberately
		// shorter and more imperative than the SARIF help — the two formats have
		// different audiences — and showing both makes a drifting pair visible.
		if meta, ok := core.TypeMeta(t); ok && strings.TrimSpace(meta.GitLabRemediation) != "" {
			b.WriteString("*Short form (gitlab-sast):* " + meta.GitLabRemediation + "\n\n")
		}
	}
	return b.String()
}

// TestCheckPageIsUpToDate keeps the generated page in step with the type registry.
//
// Golden-style, matching the repository's existing idiom: the test renders what the
// page should contain and diffs it against the committed file, and UPDATE_CHECK_DOCS=1
// rewrites it. So adding a detection type cannot leave a helpUri without a target —
// this test fails until the page is regenerated.
func TestCheckPageIsUpToDate(t *testing.T) {
	path := filepath.Join(repoRoot(t), docsCheckPage)
	want := renderCheckPage()

	if os.Getenv("UPDATE_CHECK_DOCS") == "1" {
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
			t.Fatalf("writing %s: %v", docsCheckPage, err)
		}
		t.Logf("regenerated %s (%d bytes, %d types)", docsCheckPage, len(want), len(core.KnownTypes()))
		return
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s is missing (%v). Every SARIF finding's helpUri points into this "+
			"file; without it every link 404s. Regenerate with "+
			"UPDATE_CHECK_DOCS=1 go test ./internal/formatters/sarif/", docsCheckPage, err)
	}
	if string(got) != want {
		t.Errorf("%s is out of date with the type registry.\nRegenerate with "+
			"UPDATE_CHECK_DOCS=1 go test ./internal/formatters/sarif/ -run TestCheckPageIsUpToDate\n"+
			"(committed %d bytes, expected %d)", docsCheckPage, len(got), len(want))
	}
}

// TestEveryHelpURIResolves is the invariant: a link the tool emits must point at
// something that exists.
//
// Stated over every type the tool can report, not over the types this package
// happens to have descriptions for — the defect was that ALL 59 emitted rules
// pointed into docs/checks/, a directory that never existed, and a test scoped to
// the 24 registry entries would have passed just as happily.
func TestEveryHelpURIResolves(t *testing.T) {
	root := repoRoot(t)
	page := filepath.Join(root, docsCheckPage)
	content, err := os.ReadFile(page)
	if err != nil {
		t.Fatalf("reading %s: %v", docsCheckPage, err)
	}

	// Collect the anchors the page actually defines, the way a Markdown renderer
	// would: one per "## Heading", slugged.
	anchors := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^## (.+)$`).FindAllStringSubmatch(string(content), -1) {
		anchors[githubSlug(m[1])] = true
	}
	if len(anchors) == 0 {
		t.Fatal("the page defines no headings, so anchor checking would assert nothing")
	}

	rm := NewRuleManager()
	var broken []string
	known := core.KnownTypes()
	if len(known) < 20 {
		t.Fatalf("core.KnownTypes() returned only %d types; this guard would cover almost nothing", len(known))
	}

	for _, typ := range known {
		rule := rm.buildRuleForType(typ)
		uri := rule.HelpURI

		// The path half: strip the repository/blob prefix and require the file.
		const marker = "/blob/main/"
		i := strings.Index(uri, marker)
		if i < 0 {
			broken = append(broken, fmt.Sprintf("%s: helpUri %q has no /blob/main/ path component", typ, uri))
			continue
		}
		rest := uri[i+len(marker):]
		relPath, frag := rest, ""
		if h := strings.Index(rest, "#"); h >= 0 {
			relPath, frag = rest[:h], rest[h+1:]
		}
		if _, err := os.Stat(filepath.Join(root, relPath)); err != nil {
			broken = append(broken, fmt.Sprintf("%s: helpUri targets %s, which is not committed", typ, relPath))
			continue
		}
		// The anchor half: a file that exists but has no matching heading is still a
		// link that lands nowhere useful, which is most of the value here.
		if frag == "" {
			broken = append(broken, fmt.Sprintf("%s: helpUri has no anchor", typ))
			continue
		}
		if !anchors[frag] {
			broken = append(broken, fmt.Sprintf("%s: helpUri anchor #%s is not a heading in %s", typ, frag, relPath))
		}
	}

	if len(broken) > 0 {
		sort.Strings(broken)
		t.Errorf("%d of %d helpUris do not resolve:\n  %s\n\n"+
			"A SARIF consumer follows this link from the finding; a dead one is the whole "+
			"documentation surface for that detection type. Regenerate the page with "+
			"UPDATE_CHECK_DOCS=1 go test ./internal/formatters/sarif/",
			len(broken), len(known), strings.Join(broken, "\n  "))
	}
}

// githubSlug reproduces GitHub's heading-anchor rule closely enough for these
// headings: lowercase, drop anything that is not a letter, digit, space or hyphen,
// then spaces to hyphens. For the all-caps underscore type names it reduces to the
// lowercased type, which is what the helpUri builds.
func githubSlug(heading string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(heading)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune('-')
		}
	}
	return b.String()
}

// TestEveryEmittedTypeIsKnown is the sync guard on core.KnownTypes().
//
// The first version of this test was CIRCULAR: it iterated core.KnownTypes() and
// asserted things about core.KnownTypes(), so it could not notice a type the tool
// emits and the list omits — which is the only thing that can go wrong here. It
// would have reported a clean run while the list was already missing five METADATA
// sub-types.
//
// The evidence is the committed golden SARIF corpus. Those files are regenerated
// whenever output changes, so a validator that starts emitting a new sub-type puts
// its rule ID there and this test fails until the list catches up. That is a source
// that maintains itself, rather than a list somebody has to remember to update.
//
// One-directional on purpose: emitted ⊆ known. The reverse would demand the golden
// corpus exercise all 64 types, which it does not and should not have to — 32 of
// them are never triggered by it.
func TestEveryEmittedTypeIsKnown(t *testing.T) {
	root := repoRoot(t)
	pattern := filepath.Join(root, "internal", "goldencorpus", "testdata", "golden", "*.sarif.json")
	files, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	// Non-vacuity: no golden files means this asserts nothing.
	if len(files) < 10 {
		t.Fatalf("found %d golden SARIF files at %s; too few for this guard to mean anything",
			len(files), pattern)
	}

	emitted := map[string][]string{} // type -> golden files that emitted it
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}
		var doc struct {
			Runs []struct {
				Tool struct {
					Driver struct {
						Rules []struct{ ID string } `json:"rules"`
					} `json:"driver"`
				} `json:"tool"`
			} `json:"runs"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			// A golden that is not valid JSON is a different problem, and the golden
			// test owns it. Skipping here rather than double-reporting.
			continue
		}
		for _, run := range doc.Runs {
			for _, r := range run.Tool.Driver.Rules {
				if r.ID != "" {
					emitted[r.ID] = append(emitted[r.ID], filepath.Base(f))
				}
			}
		}
	}
	if len(emitted) == 0 {
		t.Fatal("no rule IDs found in any golden SARIF file; the harvest is broken, " +
			"so this guard would pass no matter what the list contained")
	}

	var unknown []string
	for typ, where := range emitted {
		if !core.IsKnownType(typ) {
			unknown = append(unknown, fmt.Sprintf("%s (emitted by %s)", typ, where[0]))
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		t.Errorf("%d detection type(s) appear in the golden SARIF corpus but not in "+
			"core.KnownTypes():\n  %s\n\n"+
			"Add them to knownDetectionTypes and regenerate the page with "+
			"UPDATE_CHECK_DOCS=1 go test ./internal/formatters/sarif/. Until then their "+
			"helpUri links to docs/checks.md with no anchor — the link still works, but the "+
			"reviewer lands on the index instead of the section for their finding.",
			len(unknown), strings.Join(unknown, "\n  "))
	}
	t.Logf("golden corpus emits %d distinct types, all known; core.KnownTypes() has %d",
		len(emitted), len(core.KnownTypes()))
}

// TestUnknownTypeStillGetsAResolvingURI is the safety net that makes an incomplete
// list tolerable rather than a latent 404.
func TestUnknownTypeStillGetsAResolvingURI(t *testing.T) {
	root := repoRoot(t)
	rm := NewRuleManager()

	const invented = "A_TYPE_NOBODY_HAS_DOCUMENTED_YET"
	if core.IsKnownType(invented) {
		t.Fatalf("%s is unexpectedly a known type, so this test proves nothing", invented)
	}
	uri := rm.buildRuleForType(invented).HelpURI

	if strings.Contains(uri, "#") {
		t.Errorf("helpUri for an undocumented type carries an anchor (%q); that anchor "+
			"cannot exist, which is the 404 this change removed", uri)
	}
	const marker = "/blob/main/"
	i := strings.Index(uri, marker)
	if i < 0 {
		t.Fatalf("helpUri %q has no /blob/main/ path component", uri)
	}
	if _, err := os.Stat(filepath.Join(root, uri[i+len(marker):])); err != nil {
		t.Errorf("helpUri for an undocumented type targets %s, which is not committed: %v",
			uri[i+len(marker):], err)
	}

	// And a KNOWN type must still get its anchor, or the branch above has simply
	// disabled anchoring for everything.
	known := core.KnownTypes()[0]
	if u := rm.buildRuleForType(known).HelpURI; !strings.Contains(u, "#"+strings.ToLower(known)) {
		t.Errorf("known type %s lost its anchor: %q", known, u)
	}
}

// TestEveryTypeHasBespokeCopy is the gate #662 deliberately added LAST.
//
// GetRuleDescription falls back to a generated generic string for a type with no
// registry entry: "Sensitive data of type <TYPE> was detected in the scanned content."
// That fallback is correct and must stay — a type minted after this test should still
// produce a usable rule — but no type should be RELYING on it, because the generic text
// is the entire explanation a reviewer gets in a code-scanning UI.
//
// Measured before #662: 15 of the 64 types had bespoke copy and 49 did not, including
// every credential type, every card brand except the CREDIT_CARD parent, and all four
// banking sub-types. The generic string said nothing about what an AWS secret access key
// grants, or that an IBAN is a payment destination on its own.
//
// Added only with the last batch, on purpose: introduced earlier it would have been red
// until all 49 were written, blocking every unrelated change in the meantime.
func TestEveryTypeHasBespokeCopy(t *testing.T) {
	known := core.KnownTypes()
	if len(known) < 20 {
		t.Fatalf("core.KnownTypes() returned %d types; this gate would cover almost nothing", len(known))
	}

	var generic []string
	for _, typ := range known {
		d := GetRuleDescription(typ)
		// Compared against the fallback GetRuleDescription itself constructs rather than
		// against a copy of the string: keeping a second literal in step with the first
		// is the drift this file exists to prevent.
		if d.Full == "Sensitive data of type "+typ+" was detected in the scanned content." {
			generic = append(generic, typ)
			continue
		}
		// Present-but-empty is worse than the fallback: it renders a blank section in
		// docs/checks.md and an empty SARIF rule.
		if strings.TrimSpace(d.Short) == "" || strings.TrimSpace(d.Full) == "" || strings.TrimSpace(d.Help) == "" {
			t.Errorf("%s has an entry with an empty Short/Full/Help field", typ)
		}

		// gitlab-sast is covered by the SAME gate, deliberately.
		//
		// #662 was first scoped to SARIF alone, and that left gitlab-sast WORSE than the
		// problem being fixed: 45 of 64 types had no check description and 49 had no
		// remediation, so a gitlab consumer read "Sensitive data (X)" plus a generic
		// "Review the detected..." for two-thirds of everything reported. A gate covering
		// one formatter would have declared the class closed while half of it was open.
		meta, ok := core.TypeMeta(typ)
		if !ok {
			t.Errorf("%s is in KnownTypes() but has no registry entry at all", typ)
			continue
		}
		if strings.TrimSpace(meta.GitLabCheckDesc) == "" {
			t.Errorf("%s has no GitLabCheckDesc, so gitlab-sast renders the generic "+
				"\"Sensitive data (%s)\" for it", typ, typ)
		}
		if strings.TrimSpace(meta.GitLabRemediation) == "" {
			t.Errorf("%s has no GitLabRemediation, so its gitlab-sast finding tells a "+
				"reviewer what was found and nothing about what to do", typ)
		}
	}

	if len(generic) > 0 {
		sort.Strings(generic)
		t.Errorf("%d of %d detection type(s) still fall back to the generic description:\n  %s\n\n"+
			"That string is the whole explanation a reviewer sees for the finding. Add "+
			"SARIFShort/SARIFFull/SARIFHelp in internal/core/typemeta.go, then regenerate the "+
			"page with UPDATE_CHECK_DOCS=1 go test ./internal/formatters/sarif/.",
			len(generic), len(known), strings.Join(generic, "\n  "))
	}
}

// TestTheGenericFallbackStillWorks keeps the gate above from being read as "the fallback
// is gone". A type minted after this test must still produce a usable rule.
func TestTheGenericFallbackStillWorks(t *testing.T) {
	const invented = "A_TYPE_NOBODY_HAS_DOCUMENTED_YET"
	d := GetRuleDescription(invented)
	if d.Short == "" || d.Full == "" || d.Help == "" {
		t.Errorf("the generic fallback produced an empty field for an unknown type: %+v", d)
	}
	if !strings.Contains(d.Full, invented) {
		t.Errorf("the generic fallback does not name the type: %q", d.Full)
	}
}

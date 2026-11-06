// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/awslabs/ferret-scan/v2/internal/suppressions"
)

// The guard for the suppression files the documentation shows. A reader copies an example as the
// starting point of their own file, so an example the loader refuses, or one whose rules can never
// match, teaches the failure.
//
// It asks the loader's own strict pass, suppressions.CheckSuppressionFile (#866), rather than decoding
// the block with yaml KnownFields(true): a rule's `metadata` is an inline map, so KnownFields accepts
// every key, and it cannot see a hash that is not 64 lower-case hexadecimal digits. Measured before
// this guard existed: README-Suppressions.md's second example rule carried a 63-digit placeholder hash,
// which the loader names as "can never match", and nothing in the tree noticed.

// suppressionDocFence opens or closes a fenced code block, possibly indented, with its info string.
var suppressionDocFence = regexp.MustCompile("^(\\s*)(```+|~~~+)\\s*([A-Za-z0-9_+.-]*)")

// suppressionDocBlock is one fenced block that is a suppression file.
type suppressionDocBlock struct {
	file string
	line int // 1-indexed line of the block's first content line
	body string
}

// suppressionDocBlocks returns every fenced block in the markdown under root whose YAML is a
// suppression file: a top-level `rules:` sequence with at least one rule that has a `hash`. That test,
// not the info string, decides, so an example fenced as plain ``` is still checked, while a CI file's
// job-level `rules:` is not taken for one.
func suppressionDocBlocks(t *testing.T, root string) []suppressionDocBlock {
	t.Helper()
	var out []suppressionDocBlock
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// A proposal describes a design that may add rule keys, so its examples are not a claim about
		// the shipped loader (the same exemption the documented-flags guard makes).
		if d.IsDir() && d.Name() == "proposals" {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.EqualFold(filepath.Ext(path), ".md") {
			return nil
		}
		raw, err := os.ReadFile(path) // #nosec G304 -- a markdown file inside the repo's docs tree
		if err != nil {
			return err
		}
		out = append(out, suppressionDocBlocksIn(filepath.ToSlash(path), string(raw))...)
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	return out
}

// suppressionDocBlocksIn extracts the suppression files from one markdown text. Identifiers in this
// file carry the suppressionDoc prefix to stay distinct from the other documented_* guards in package main.
func suppressionDocBlocksIn(file, markdown string) []suppressionDocBlock {
	var out []suppressionDocBlock
	lines := strings.Split(markdown, "\n")
	for i := 0; i < len(lines); i++ {
		m := suppressionDocFence.FindStringSubmatch(lines[i])
		if m == nil {
			continue
		}
		indent, marker := m[1], m[2]
		var body []string
		j := i + 1
		for ; j < len(lines); j++ {
			if strings.HasPrefix(strings.TrimSpace(lines[j]), marker[:3]) {
				break
			}
			body = append(body, strings.TrimPrefix(lines[j], indent))
		}
		text := strings.Join(body, "\n") + "\n"
		if suppressionDocIsFile(text) {
			out = append(out, suppressionDocBlock{file: file, line: i + 2, body: text})
		}
		i = j
	}
	return out
}

func suppressionDocIsFile(text string) bool {
	var doc struct {
		Rules []map[string]any `yaml:"rules"`
	}
	if yaml.Unmarshal([]byte(text), &doc) != nil {
		return false
	}
	for _, rule := range doc.Rules {
		if _, ok := rule["hash"]; ok {
			return true
		}
	}
	return false
}

// TestEveryDocumentedSuppressionFileLoadsCleanly: the loader's strict pass names nothing in any example.
// Both kinds of problem fail it: a rule the loader refuses (an unknown key, a metadata key named like a
// rule key, a version other than "1.0") and one it applies but names because it can never match or is
// ambiguous (a malformed hash, a duplicated id).
func TestEveryDocumentedSuppressionFileLoadsCleanly(t *testing.T) {
	blocks := suppressionDocBlocks(t, docsRoot)
	// Non-vacuity: these three files show suppression files today. If the extraction stops finding
	// them, every assertion below passes having checked nothing.
	seen := map[string]bool{}
	for _, b := range blocks {
		seen[strings.TrimPrefix(b.file, "../")] = true
	}
	for _, want := range []string{
		"docs/user-guides/README-Suppressions.md",
		"docs/suppression-system.md",
		"docs/PRE_COMMIT_INTEGRATION.md",
	} {
		if !seen[want] {
			t.Errorf("no suppression-file example found in %s; the extraction has stopped matching, or the "+
				"example moved (update this list)", want)
		}
	}
	for _, b := range blocks {
		problems, err := suppressions.CheckSuppressionFile([]byte(b.body))
		if err != nil {
			t.Errorf("%s:%d: the example is not valid YAML: %v", b.file, b.line, err)
			continue
		}
		for _, p := range problems {
			verdict := "names it"
			if p.Refuses() {
				verdict = "REFUSES the rule"
			}
			// p's own line counts from the block's first line; the location printed first is the page's.
			t.Errorf("%s:%d: the loader %s: %s", b.file, b.line+p.Line-1, verdict, p)
		}
	}
}

// TestTheSuppressionDocGuardCatchesPlantedProblems: each planted shape is extracted as a suppression
// file and fails the strict pass, and a CI file's job-level rules: is not mistaken for one.
func TestTheSuppressionDocGuardCatchesPlantedProblems(t *testing.T) {
	const hash64 = "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
	rule := func(extra string) string {
		return "version: \"1.0\"\nrules:\n  - id: \"SUP-1\"\n    hash: \"" + hash64 + "\"\n    enabled: true\n" + extra
	}
	for name, body := range map[string]string{
		"a misspelled expiry":        rule("    expries_at: 2026-01-01T00:00:00Z\n"),
		"an expiry under metadata":   rule("    metadata:\n      expires_at: \"2026-01-01\"\n"),
		"a 63-digit hash":            strings.Replace(rule(""), hash64, hash64[:63], 1),
		"an unsupported version":     strings.Replace(rule(""), `"1.0"`, `"9.9"`, 1),
		"a duplicated id":            rule("  - id: \"SUP-1\"\n    hash: \"" + strings.Repeat("b", 64) + "\"\n"),
		"an unknown top-level key":   rule("notes: free text\n"),
		"indented inside a list":     "",
		"fenced without a language ": "",
	} {
		md := "# page\n\n```yaml\n" + body + "```\n"
		switch name {
		case "indented inside a list":
			md = "1. step\n\n   ```yaml\n" + strings.ReplaceAll(strings.TrimSuffix(rule("    reasn: typo\n"), "\n"), "\n", "\n   ") + "\n   ```\n"
		case "fenced without a language ":
			md = "```\n" + rule("    enabeld: true\n") + "```\n"
		}
		blocks := suppressionDocBlocksIn("planted.md", md)
		if len(blocks) != 1 {
			t.Errorf("%s: extracted %d suppression files, want 1", name, len(blocks))
			continue
		}
		if problems, err := suppressions.CheckSuppressionFile([]byte(blocks[0].body)); err != nil || len(problems) == 0 {
			t.Errorf("%s: the strict pass found nothing (%v); the guard would let it through", name, err)
		}
	}
	// Controls: a clean example passes, a free-form metadata key is allowed, and a CI file is not a
	// suppression file.
	clean := suppressionDocBlocksIn("clean.md", "```yaml\n"+rule("    metadata:\n      ticket: SEC-1234\n")+"```\n")
	if len(clean) != 1 {
		t.Fatalf("the clean control was not extracted")
	}
	if problems, err := suppressions.CheckSuppressionFile([]byte(clean[0].body)); err != nil || len(problems) != 0 {
		t.Errorf("a clean example with a free-form metadata key is named: %v %v", problems, err)
	}
	ci := "```yaml\nscan:\n  script: ./bin/ferret-scan --file .\n  rules:\n    - if: $CI_PIPELINE_SOURCE == \"merge_request_event\"\n```\n"
	if got := suppressionDocBlocksIn("ci.md", ci); len(got) != 0 {
		t.Errorf("a CI job's rules: was taken for a suppression file")
	}
}

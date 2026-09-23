// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The #729 defect, pinned at the unit level: a RELATIVE pattern containing a separator matched
// nothing (the path is absolutized before matching and `*` stops at separators), and `**` matched
// at exactly one level — both silently. The matcher gets a scan root and real globstar; this test
// is the truth table.
func TestExcludeMatcherRelativeAndGlobstar(t *testing.T) {
	root := filepath.Join(string(filepath.Separator)+"scan", "root")
	path := func(parts ...string) string { return filepath.Join(append([]string{root}, parts...)...) }

	cases := []struct {
		pattern string
		path    string
		want    bool
	}{
		// The headline: relative multi-segment patterns now work, including as subtree excludes.
		{"nest/sub", path("nest", "sub"), true},
		{"nest/sub", path("nest", "sub", "deep", "a.txt"), true},
		{"nest/sub", path("nest", "subX", "a.txt"), false},
		{"nest/*/a.txt", path("nest", "mid", "a.txt"), true},
		{"nest/*/a.txt", path("nest", "mid", "deep", "a.txt"), false}, // * does not cross /
		// Real globstar, any depth including zero.
		{"**/*.txt", path("a.txt"), true},
		{"**/*.txt", path("n", "s", "d", "a.txt"), true},
		{"**/sub/**", path("n", "sub", "x"), true},
		{"**/sub/**", path("n", "sub"), true}, // trailing ** matches zero segments; prefix arm covers the dir itself
		{"**/sub/**", path("n", "nosub", "x"), false},
		{"src/**/gen", path("src", "a", "b", "gen", "f"), true},
		// The arms that already worked must keep working.
		{".git", path("digits", ".git", "x"), true}, // segment arm
		{"*.pyc", path("a", "b", "c.pyc"), true},    // basename arm
		{".git", path("digits", "mygit", "x"), false},
		// Outside the root: the rel arm must not fire (and the other arms decide).
		{"nest/sub", filepath.Join(string(filepath.Separator)+"elsewhere", "nest", "sub"), false},
	}
	for _, tc := range cases {
		m := newExcludeMatcher([]string{tc.pattern}, root)
		if got := m.match(tc.path); got != tc.want {
			t.Errorf("pattern %q vs %q: got %v want %v", tc.pattern, tc.path, got, tc.want)
		}
	}
}

func TestExcludeMatcherZeroHitNote(t *testing.T) {
	m := newExcludeMatcher([]string{".venv", "*.txt", "no_such"}, "/r")
	_ = m.match(filepath.Join("/r", "a.txt")) // *.txt earns its keep
	note := m.zeroHitNote()
	if note == "" || !strings.Contains(note, ".venv") || !strings.Contains(note, "no_such") {
		t.Fatalf("note should name the two misses: %q", note)
	}
	if strings.Contains(note, "*.txt") {
		t.Fatalf("note names a pattern that DID match: %q", note)
	}
	if strings.Count(note, "\n") != 0 {
		t.Fatalf("one line for all misses, not one per pattern: %q", note)
	}
	// All patterns hit -> silence.
	m2 := newExcludeMatcher([]string{"*.txt"}, "/r")
	_ = m2.match("/r/a.txt")
	if n := m2.zeroHitNote(); n != "" {
		t.Fatalf("no misses must mean no note, got %q", n)
	}
	// No patterns -> silence, and nil-safety.
	if n := newExcludeMatcher(nil, "/r").zeroHitNote(); n != "" {
		t.Fatalf("empty matcher noted: %q", n)
	}
	var nilM *excludeMatcher
	if nilM.match("/r/x") || nilM.zeroHitNote() != "" {
		t.Fatal("nil matcher must be inert")
	}
}

// End to end through discovery: the exclusion must be DISCLOSED (files_skipped), never a silent
// vanish — the sink-rule half of #729. A newly-effective exclude means files that used to be
// scanned no longer are; that is the user's stated intent, and the accounting must say so.
func TestRelativeExcludeIsEffectiveAndDisclosed(t *testing.T) {
	dir := t.TempDir()
	mk := func(parts ...string) {
		p := filepath.Join(append([]string{dir}, parts...)...)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("ssn 456-78-9012\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mk("nest", "sub", "a.txt")
	mk("nest", "mid.txt")
	mk("other", "b.txt")

	base, err := getFilesToProcess(dir, true, newExcludeMatcher(nil, dir), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(base.FilesToProcess) != 3 {
		t.Fatalf("fixture should discover 3 files, got %d — every assertion below would be vacuous", len(base.FilesToProcess))
	}

	m := newExcludeMatcher([]string{"nest/sub"}, dir)
	res, err := getFilesToProcess(dir, true, m, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.FilesToProcess) != 2 {
		t.Fatalf("nest/sub should exclude exactly one file, discovered %d", len(res.FilesToProcess))
	}
	var excluded []SkippedFile
	for _, sk := range res.SkippedFiles {
		if strings.Contains(sk.Reason, "--exclude") {
			excluded = append(excluded, sk)
		}
	}
	if len(excluded) != 1 {
		t.Fatalf("the exclusion must be recorded once with its reason, got %+v", res.SkippedFiles)
	}
	if note := m.zeroHitNote(); note != "" {
		t.Fatalf("the pattern matched; no note expected, got %q", note)
	}
}

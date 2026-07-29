// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestShippedConfigPatternsCompile is the gate that was missing.
//
// Go's regexp package is RE2: it has NO lookahead, NO lookbehind, and no
// backreferences. A pattern written in PCRE style is not a syntax error at load
// time — it fails to compile at USE time, and every consumer of these patterns
// skips a failed pattern and carries on. The only trace is a debug-only log line,
// so a broken pattern is invisible in normal operation.
//
// That is not theoretical. The shipped twitter handle pattern was
//
//	(?i)(?<!\w)@[a-zA-Z0-9_]{1,15}(?!@|\.[a-zA-Z])
//
// which RE2 rejects ("invalid named capture", because it reads (?< as the start of
// a named group). twitter therefore loaded 2 of its 3 patterns and NO bare @handle
// was ever detected by SOCIAL_MEDIA, while the tool reported success. For a
// detection tool a silently inert pattern is a false negative on every document.
//
// This test compiles every regex in the shipped config with the same engine that
// will run it, so the failure surfaces here instead of as missing findings.
func TestShippedConfigPatternsCompile(t *testing.T) {
	path := shippedConfigPath(t)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig(%s): %v", path, err)
	}

	var checked int
	for validator, section := range cfg.Validators {
		for key, raw := range section {
			forEachPatternString(raw, func(pattern string) {
				checked++
				if _, err := regexp.Compile(pattern); err != nil {
					t.Errorf("%s / %s: pattern does not compile under Go's RE2 engine, so it "+
						"will be silently SKIPPED at runtime and can never match:\n  pattern: %s\n  error:   %v\n"+
						"  hint:    RE2 has no lookahead/lookbehind — express the constraint in code instead.",
						validator, key, pattern, err)
				}
			})
		}
	}

	// Non-vacuity: this must actually have examined the patterns. If the config
	// shape changes and the walk stops finding them, the test would otherwise pass
	// while checking nothing.
	if checked < 50 {
		t.Fatalf("only %d patterns examined; the shipped config carries far more than "+
			"that, so this test is no longer reaching them (config shape changed?)", checked)
	}
	t.Logf("compiled %d config patterns under RE2", checked)
}

// TestNoLookaroundInShippedConfig catches the mistake by SHAPE as well as by
// compilation.
//
// Compilation is the real gate, but some lookaround spellings happen to compile as
// something else entirely and are therefore worse than a hard failure: RE2 reads
// `(?<name>x)` as a syntax error, but a stray `(?=` or `(?!` can parse in ways that
// silently do not mean what the author intended. Flagging the syntax outright keeps
// a PCRE habit from reaching the file.
func TestNoLookaroundInShippedConfig(t *testing.T) {
	data, err := os.ReadFile(shippedConfigPath(t))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}

	// Only flag these inside what looks like a pattern line, so prose in comments
	// (including the comment explaining this very constraint) is not a false hit.
	lookaround := []string{"(?=", "(?!", "(?<", "(?'"}

	for i, line := range strings.Split(string(data), "\n") {
		code := line
		if h := strings.Index(code, " #"); h >= 0 {
			code = code[:h] // drop trailing comment
		}
		if !strings.Contains(code, "\"") {
			continue
		}
		for _, tok := range lookaround {
			if strings.Contains(code, tok) {
				t.Errorf("config.yaml:%d contains %q — Go's RE2 engine has no lookaround, "+
					"and a pattern using it is silently skipped at runtime:\n  %s",
					i+1, tok, strings.TrimSpace(line))
			}
		}
	}
}

// shippedConfigPath locates config.yaml at the repo root from this package's
// directory, failing loudly rather than silently skipping if it moves.
func shippedConfigPath(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "..", "config.yaml")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("shipped config not found at %s: %v (did it move? this test must not "+
			"silently stop checking it)", path, err)
	}
	return path
}

// forEachPatternString walks a decoded YAML value and calls fn for every string
// that looks like a regex. The config nests patterns as strings, []any of strings,
// and map[string]any of either, so the walk has to handle all three.
//
// "Looks like a regex" is deliberately loose — a plain keyword like "twitter" is
// also a valid regex, and compiling it costs nothing. The filter only skips
// obviously-not-a-pattern values so the non-vacuity floor stays meaningful.
func forEachPatternString(v any, fn func(string)) {
	switch val := v.(type) {
	case string:
		if looksLikeRegex(val) {
			fn(val)
		}
	case []any:
		for _, item := range val {
			forEachPatternString(item, fn)
		}
	case map[string]any:
		for _, item := range val {
			forEachPatternString(item, fn)
		}
	case map[any]any: // YAML can decode to this shape
		for _, item := range val {
			forEachPatternString(item, fn)
		}
	}
}

func looksLikeRegex(s string) bool {
	return strings.ContainsAny(s, `\[](){}|^$*+?`)
}

// TestEarliestPatternErrorIsActionable documents, with a live example, what this
// suite protects against: a PCRE-only pattern compiles fine in a PCRE engine and
// dies in RE2. Kept as a test so the claim stays true rather than becoming a stale
// comment.
func TestEarliestPatternErrorIsActionable(t *testing.T) {
	const pcreOnly = `(?i)(?<!\w)@[a-zA-Z0-9_]{1,15}(?!@|\.[a-zA-Z])`
	_, err := regexp.Compile(pcreOnly)
	if err == nil {
		t.Fatalf("premise broken: %s now compiles under RE2, so the lookaround "+
			"restriction this suite guards has changed", pcreOnly)
	}
	if !strings.Contains(fmt.Sprint(err), "invalid") {
		t.Logf("note: RE2 rejection message changed: %v", err)
	}
}
